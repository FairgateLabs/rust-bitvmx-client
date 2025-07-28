use crate::{
    errors::BitVMXError,
    program::{
        participant::{ParticipantKeys, ParticipantRole, PublicKeyType},
        protocols::{
            protocol_handler::{ProtocolContext, ProtocolHandler},
            union::types::*,
        },
        variables::{PartialUtxo, VariableTypes},
    },
    types::ProgramContext,
};

use bitcoin::{PublicKey, Transaction, Txid};
use bitcoin_coordinator::TransactionStatus;
use uuid::Uuid;
use protocol_builder::{
    builder::Protocol,
    graph::graph::GraphOptions,
    scripts::{self, SignMode},
    types::{
        connection::{InputSpec, OutputSpec},
        input::{SighashType, SpendMode},
        output::SpeedupData,
        OutputType,
    },
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::info;

const PEGOUT_ID_KEY: &str = "pegout_id";
const VALUE_0_KEY: &str = "value_0";
const VALUE_1_KEY: &str = "value_1";

#[derive(Clone, Serialize, Deserialize)]
pub struct DisputeCoreProtocol {
    ctx: ProtocolContext,
}

impl ProtocolHandler for DisputeCoreProtocol {
    fn context(&self) -> &ProtocolContext {
        &self.ctx
    }

    fn context_mut(&mut self) -> &mut ProtocolContext {
        &mut self.ctx
    }

    fn get_pregenerated_aggregated_keys(
        &self,
        context: &ProgramContext,
    ) -> Result<Vec<(String, PublicKey)>, BitVMXError> {
        Ok(vec![
            (
                "take_aggregated".to_string(),
                self.take_aggregated_key(context)?,
            ),
            (
                "dispute_aggregated".to_string(),
                self.dispute_aggregated_key(context)?,
            ),
        ])
    }

    fn generate_keys(
        &self,
        program_context: &mut ProgramContext,
    ) -> Result<ParticipantKeys, BitVMXError> {
        let packet_size = self.committee(program_context)?.packet_size;
        let mut keys = vec![];

        if self.prover(program_context)? {
            for i in 0..packet_size + 1 {
                keys.push((
                    format!("{}_{}", PEGOUT_ID_KEY, i),
                    PublicKeyType::Winternitz(
                        program_context.key_chain.derive_winternitz_hash160(20)?,
                    ),
                ));
                keys.push((
                    format!("{}_{}", VALUE_0_KEY, i),
                    PublicKeyType::Winternitz(
                        program_context.key_chain.derive_winternitz_hash160(1)?,
                    ),
                ));
                keys.push((
                    format!("{}_{}", VALUE_1_KEY, i),
                    PublicKeyType::Winternitz(
                        program_context.key_chain.derive_winternitz_hash160(1)?,
                    ),
                ));
            }
        }

        Ok(ParticipantKeys::new(keys, vec![]))
    }

    fn build(
        &self,
        keys: Vec<ParticipantKeys>,
        _computed_aggregated: HashMap<String, PublicKey>,
        context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        let mut protocol = self.load_or_create_protocol();
        let committee = self.committee(context)?;

        self.create_initial_deposit(&mut protocol, &committee, &keys, context)?;

        for i in 0..committee.packet_size as usize {
            self.create_dispute_core(&mut protocol, &committee, i, &keys, context)?;
        }

        protocol.build(&context.key_chain.key_manager, &self.ctx.protocol_name)?;
        info!("\n{}", protocol.visualize(GraphOptions::EdgeArrows)?);
        self.save_protocol(protocol)?;

        self.set_utxos(context)?;
        Ok(())
    }

    fn get_transaction_by_name(
        &self,
        name: &str,
        _context: &ProgramContext,
    ) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
        Err(BitVMXError::InvalidTransactionName(name.to_string()))
    }

    fn notify_news(
        &self,
        tx_id: Txid,
        _vout: Option<u32>,
        tx_status: TransactionStatus,
        context: String,
        program_context: &ProgramContext,
        _participant_keys: Vec<&ParticipantKeys>,
    ) -> Result<(), BitVMXError> {
        let transaction_name = self.get_transaction_name_by_id(tx_id)?;
        // Route to appropriate handler based on transaction type
        if transaction_name.starts_with("REIMBURSEMENT_KICKOFF_TX_") {
            self.handle_reimbursement_kickoff_transaction(tx_id, &tx_status, &context, program_context)?;
        }
        // TODO: Add more transaction type handlers here as needed

        // let a = AckNews::Monitor(AckMonitorNews::RskPeginTransaction(txid));
        // _program_context.bitcoin_coordinator.ack_news(a);

        Ok(())
    }

    fn setup_complete(&self, _program_context: &ProgramContext) -> Result<(), BitVMXError> {
        // This is called after the protocol is built and ready to be used
        info!(
            id = self.ctx.my_idx,
            "DisputeCoreProtocol setup complete for program {}", self.ctx.id
        );
        Ok(())
    }
}

impl DisputeCoreProtocol {
    pub fn new(ctx: ProtocolContext) -> Self {
        Self { ctx }
    }

    fn create_initial_deposit(
        &self,
        protocol: &mut Protocol,
        committee: &Committee,
        keys: &Vec<ParticipantKeys>,
        context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        let operator_count = committee.operator_count;

        let dispute_aggregated_key = self.dispute_aggregated_key(context)?;

        let prefixes = match committee.my_role {
            ParticipantRole::Prover => vec!["OP", "WT"],
            ParticipantRole::Verifier => vec!["WT"],
        };

        for prefix in prefixes {
            let funding_utxo_name = format!("{}{}", prefix, FUNDING_UTXO_SUFFIX);
            let funding_tx_name = format!("{}{}", prefix, FUNDING_TX_SUFFIX);
            let initial_deposit_tx_name = format!("{}{}", prefix, INITIAL_DEPOSIT_TX_SUFFIX);

            let funding_utxo = self.utxo(&funding_utxo_name, context)?;
            protocol.add_external_transaction(&funding_tx_name)?;
            protocol.add_transaction_output(&funding_tx_name, &funding_utxo.3.unwrap())?;

            protocol.add_connection(
                "initial_deposit",
                &funding_tx_name,
                (funding_utxo.1 as usize).into(),
                &initial_deposit_tx_name,
                InputSpec::Auto(SighashType::ecdsa_all(), SpendMode::None),
                None,
                Some(funding_utxo.0),
            )?;
        }

        //TODO add one output for each operator to the WT initial deposit transaction
        let mut operators_found = 0;
        for participant in keys.iter() {
            match participant.get_winternitz("pegout_id_0") {
                Ok(_) => {
                    let script =
                        scripts::verify_signature(&dispute_aggregated_key, SignMode::Aggregate)?;

                    // TODO change the output from segwit to taproot
                    // TODO change the output from segwit to taproot
                    protocol.add_transaction_output(
                        &format!("WT{}", INITIAL_DEPOSIT_TX_SUFFIX),
                        &OutputType::segwit_script(START_ENABLER_VALUE, &script)?,
                    )?;

                    operators_found += 1;
                }
                Err(_) => {
                    continue;
                }
            };
        }

        assert_eq!(
            operators_found, operator_count,
            "Expected {} operators, found {}",
            operator_count, operators_found
        );

        Ok(())
    }

    fn create_dispute_core(
        &self,
        protocol: &mut Protocol,
        committee: &Committee,
        dispute_core_index: usize,
        keys: &Vec<ParticipantKeys>,
        context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        let keys = keys[committee.member_index].clone();

        let take_aggregated_key = self.take_aggregated_key(context)?;
        let dispute_aggregated_key = self.dispute_aggregated_key(context)?;
        let pegout_id_pubkey = keys.get_winternitz(&var_name(PEGOUT_ID_KEY, dispute_core_index))?;
        let value_0_pubkey = keys.get_winternitz(&var_name(VALUE_0_KEY, dispute_core_index))?;
        let value_1_pubkey = keys.get_winternitz(&var_name(VALUE_1_KEY, dispute_core_index))?;

        let reimbursement_kickoff_tx = var_name(REIMBURSEMENT_KICKOFF_TX, dispute_core_index);
        let no_take_tx = var_name(NO_TAKE_TX, dispute_core_index);
        let challenge_tx = var_name(CHALLENGE_TX, dispute_core_index);
        let try_take_2_tx = var_name(TRY_TAKE_2_TX, dispute_core_index);
        let no_dispute_opened_tx = var_name(NO_DISPUTE_OPENED_TX, dispute_core_index);
        let you_cant_take_tx = var_name(YOU_CANT_TAKE_TX, dispute_core_index);
        let op_self_disabler_tx = var_name(OP_SELF_DISABLER_TX, dispute_core_index);

        let (initial_connection, output_spec) = if dispute_core_index == 0 {
            let start_dispute_core = scripts::start_dispute_core(
                dispute_aggregated_key,
                pegout_id_pubkey,
                value_0_pubkey,
                value_1_pubkey,
            )?;

            let output_spec = OutputType::taproot(
                DISPUTE_OPENER_VALUE,
                &take_aggregated_key,
                &[start_dispute_core],
            )?
            .into();
            (OP_INITIAL_DEPOSIT_TX.to_string(), output_spec)
        } else {
            let initial_connection = var_name(REIMBURSEMENT_KICKOFF_TX, dispute_core_index - 1);
            let output_spec = OutputSpec::Index(2);
            (initial_connection, output_spec)
        };

        protocol.add_connection(
            "dispute_core",
            &initial_connection,
            output_spec,
            &reimbursement_kickoff_tx,
            InputSpec::Auto(
                SighashType::taproot_all(),
                SpendMode::KeyOnly {
                    key_path_sign: SignMode::Aggregate,
                },
            ),
            None,
            None,
        )?;

        // Add the REIMBURSEMENT_KICKOFF_TX connections
        // Connection to prevent the take transactions to occur (No Take)
        protocol.add_connection(
            "no_take_connection",
            &reimbursement_kickoff_tx,
            OutputType::taproot(DUST_VALUE, &take_aggregated_key, &[])?.into(),
            &no_take_tx,
            InputSpec::Auto(
                SighashType::taproot_all(),
                SpendMode::KeyOnly {
                    key_path_sign: SignMode::Aggregate,
                },
            ),
            Some(DISPUTE_CORE_SHORT_TIMELOCK),
            None,
        )?;

        // Connections to move to the next dispute core (T)
        // TODO use the correct value of bit 1 and 0 for winternitz
        let value_0: Vec<u8> = vec![0];
        let value_1: Vec<u8> = vec![1];

        let value_0_script = scripts::verify_value(take_aggregated_key, value_0_pubkey, value_0)?;
        let value_1_script = scripts::verify_value(take_aggregated_key, value_1_pubkey, value_1)?;

        //CHALLENGE_TX connection (T)
        protocol.add_connection(
            "take_enabler",
            &reimbursement_kickoff_tx,
            OutputType::taproot(
                DUST_VALUE,
                &take_aggregated_key,
                &vec![value_0_script, value_1_script],
            )?
            .into(),
            &challenge_tx,
            InputSpec::Auto(SighashType::taproot_all(), SpendMode::Script { leaf: 1 }),
            Some(DISPUTE_CORE_LONG_TIMELOCK),
            None,
        )?;

        protocol.add_connection(
            "try_take_2",
            &challenge_tx,
            OutputType::taproot(DUST_VALUE, &take_aggregated_key, &[])?.into(),
            &try_take_2_tx,
            InputSpec::Auto(
                SighashType::taproot_all(),
                SpendMode::KeyOnly {
                    key_path_sign: SignMode::Aggregate,
                },
            ),
            None,
            None,
        )?;

        protocol.add_connection(
            "no_dispute_opened",
            &challenge_tx,
            OutputType::taproot(DUST_VALUE, &take_aggregated_key, &[])?.into(),
            &no_dispute_opened_tx,
            InputSpec::Auto(
                SighashType::taproot_all(),
                SpendMode::KeyOnly {
                    key_path_sign: SignMode::Aggregate,
                },
            ),
            Some(DISPUTE_CORE_LONG_TIMELOCK),
            None,
        )?;

        // YOU_CANT_TAKE_TX connection
        protocol.add_connection(
            "disable_take_enabler",
            &reimbursement_kickoff_tx,
            OutputSpec::Index(1),
            &you_cant_take_tx,
            InputSpec::Auto(SighashType::taproot_all(), SpendMode::Script { leaf: 0 }),
            Some(DISPUTE_CORE_LONG_TIMELOCK / 2),
            None,
        )?;

        // Connection to try to move to the next dispute core (Try Move On)
        // TODO this output must include the same taptree as the Operator initial deposit tx, plus the key spend
        let next_dispute_core = dispute_core_index + 1;
        let pegout_id_key = keys.get_winternitz(&var_name(PEGOUT_ID_KEY, next_dispute_core))?;
        let value_0_key = keys.get_winternitz(&var_name(VALUE_0_KEY, next_dispute_core))?;
        let value_1_key = keys.get_winternitz(&var_name(VALUE_1_KEY, next_dispute_core))?;

        let next_dispute_core = scripts::start_dispute_core(
            dispute_aggregated_key,
            pegout_id_key,
            value_0_key,
            value_1_key,
        )?;
        protocol.add_connection(
            "self_disable",
            &reimbursement_kickoff_tx,
            OutputType::taproot(DUST_VALUE, &dispute_aggregated_key, &[next_dispute_core])?.into(),
            &op_self_disabler_tx,
            InputSpec::Auto(
                SighashType::taproot_all(),
                SpendMode::KeyOnly {
                    key_path_sign: SignMode::Aggregate,
                },
            ),
            None,
            None,
        )?;

        // Connection to stop moving on to the next dispute core (X)
        protocol.add_connection(
            "penalize_no_challenge",
            &reimbursement_kickoff_tx,
            OutputType::taproot(DUST_VALUE, &dispute_aggregated_key, &[])?.into(),
            &no_dispute_opened_tx,
            InputSpec::Auto(
                SighashType::taproot_all(),
                SpendMode::KeyOnly {
                    key_path_sign: SignMode::Aggregate,
                },
            ),
            None,
            None,
        )?;

        // YOU_CANT_TAKE_TX connection
        protocol.add_connection(
            "disable_next_dispute_core",
            &reimbursement_kickoff_tx,
            OutputSpec::Index(2),
            &you_cant_take_tx,
            InputSpec::Auto(
                SighashType::taproot_all(),
                SpendMode::KeyOnly {
                    key_path_sign: SignMode::Aggregate,
                },
            ),
            None,
            None,
        )?;

        Ok(())
    }

    fn set_utxos(&self, context: &ProgramContext) -> Result<(), BitVMXError> {
        let committee = self.committee(context)?;
        let take_key = &self.take_aggregated_key(context)?;
        let protocol = self.load_or_create_protocol();

        let mut utxos_for_take = vec![];

        for i in 0..committee.packet_size as usize {
            let name = var_name(REIMBURSEMENT_KICKOFF_TX, i);
            let reimbursement_kickoff_tx = protocol.transaction_by_name(&name)?;
            let reimbursement_kickoff_txid = reimbursement_kickoff_tx.compute_txid();
            let take_enabler_output = OutputType::taproot(DUST_VALUE, &take_key, &[])?;
            let challenge_enabler_output = OutputType::taproot(DUST_VALUE, &take_key, &[])?;

            let operator_take_enabler = (
                reimbursement_kickoff_txid,
                0,
                Some(DUST_VALUE),
                Some(take_enabler_output),
            );
            let challenge_enabler = (
                reimbursement_kickoff_txid,
                1,
                Some(DUST_VALUE),
                Some(challenge_enabler_output),
            );

            let name = var_name(TRY_TAKE_2_TX, i);
            let try_take_2_tx = protocol.transaction_by_name(&name)?;
            let try_take_2_output = OutputType::taproot(DUST_VALUE, &take_key, &[])?;

            let operator_won_enabler = (
                try_take_2_tx.compute_txid(),
                0,
                Some(DUST_VALUE),
                Some(try_take_2_output),
            );

            context.globals.set_var(
                &self.ctx.id,
                &var_name(OPERATOR_TAKE_ENABLER, i),
                VariableTypes::Utxo(operator_take_enabler.clone()),
            )?;

            context.globals.set_var(
                &self.ctx.id,
                &var_name(OPERATOR_WON_ENABLER, i),
                VariableTypes::Utxo(operator_won_enabler.clone()),
            )?;

            context.globals.set_var(
                &self.ctx.id,
                &var_name(CHALLENGE_ENABLER, i),
                VariableTypes::Utxo(challenge_enabler.clone()),
            )?;

            utxos_for_take.push((
                operator_take_enabler,
                challenge_enabler,
                operator_won_enabler,
            ));
        }

        Ok(())
    }

    fn committee(&self, context: &ProgramContext) -> Result<Committee, BitVMXError> {
        info!(
            id = &self.ctx.my_idx,
            "Getting committee data for DisputeCore protocol {}", self.ctx.id
        );

        let committee = context
            .globals
            .get_var(&self.ctx.id, &Committee::name())?
            .unwrap()
            .string()?;

        let committee: Committee = serde_json::from_str(&committee)?;
        Ok(committee)
    }

    fn prover(&self, context: &ProgramContext) -> Result<bool, BitVMXError> {
        let members = self.committee(context)?;
        Ok(members.my_role == ParticipantRole::Prover)
    }

    fn utxo(&self, name: &str, context: &ProgramContext) -> Result<PartialUtxo, BitVMXError> {
        context.globals.get_var(&self.ctx.id, name)?.unwrap().utxo()
    }

    fn take_aggregated_key(&self, context: &ProgramContext) -> Result<PublicKey, BitVMXError> {
        Ok(self.committee(context)?.take_aggregated_key.clone())
    }

    fn dispute_aggregated_key(&self, context: &ProgramContext) -> Result<PublicKey, BitVMXError> {
        Ok(self.committee(context)?.dispute_aggregated_key.clone())
    }

    fn committee_id(&self, context: &ProgramContext) -> Result<Uuid, BitVMXError> {
        Ok(self.committee(context)?.committee_id)
    }

    fn extract_slot_id_from_context(&self, context: &str) -> Result<usize, BitVMXError> {
        if let Some(suffix) = context.strip_prefix("REIMBURSEMENT_KICKOFF_TX_") {
            suffix.parse::<usize>().map_err(|_| BitVMXError::InvalidTransactionName(context.to_string()))
        } else {
            Err(BitVMXError::InvalidTransactionName(context.to_string()))
        }
    }

    fn validate_transaction_signature(
        &self,
        _tx_id: Txid,
        _tx_status: &TransactionStatus,
        _expected_pubkey: PublicKey,
    ) -> Result<bool, BitVMXError> {
        // TODO: Implement actual signature validation
        // For now, return true as placeholder
        // In real implementation, this would:
        // 1. Extract the transaction from tx_status
        // 2. Verify the signature against expected_pubkey
        // 3. Return true if signature is valid, false otherwise
        info!("Validating transaction signature - placeholder implementation");
        Ok(true)
    }

    fn dispatch_op_disabler_tx(
        &self,
        slot_id: usize,
        _context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        // TODO: Implement OP Disabler transaction dispatch
        info!("Dispatching OP Disabler Tx for slot_id: {}", slot_id);
        // In real implementation, this would:
        // 1. Create the OP Disabler transaction
        // 2. Submit it to the Bitcoin network
        // 3. Handle any necessary coordination
        Ok(())
    }

    fn handle_reimbursement_kickoff_transaction(
        &self,
        tx_id: Txid,
        tx_status: &TransactionStatus,
        context: &str,
        program_context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        info!("Detected reimbursement kickoff transaction: {} with context: {}", tx_id, context);

        // Extract slot_id from the context
        let slot_id = self.extract_slot_id_from_context(context)?;

        // Get the committee_id to look up the selected operator key
        let committee_id = self.committee_id(program_context)?;

        // Get the selected operator's key for this slot
        let selected_operator_key_name = format!("SELECTED_OPERATOR_PUBKEY_{}", slot_id);

        match program_context.globals.get_var(&committee_id, &selected_operator_key_name)? {
            Some(selected_operator_var) => {
                let selected_operator_key = selected_operator_var.pubkey()?;

                // Validate transaction signature against selected operator's key
                let is_valid = self.validate_transaction_signature(tx_id, tx_status, selected_operator_key)?;

                if !is_valid {
                    info!("Invalid signature detected for slot {}, dispatching OP Disabler Tx", slot_id);
                    self.dispatch_op_disabler_tx(slot_id, program_context)?;
                } else {
                    info!("Valid signature confirmed for slot {}", slot_id);
                }
            }
            None => {
                info!("No selected operator key found for slot {}, allowing transaction", slot_id);
                // If no selected operator key is set, we allow the transaction
                // This handles cases where the variable hasn't been set yet
            }
        }

        Ok(())
    }
}

fn var_name(prefix: &str, index: usize) -> String {
    format!("{}_{}", prefix, index)
}
