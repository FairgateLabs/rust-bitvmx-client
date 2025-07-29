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
use uuid::Uuid;

const PEGOUT_ID_KEY: &str = "pegout_id";
const SECRET_KEY: &str = "secret";
const CHALLENGE_KEY: &str = "challenge_pubkey";
const REVEAL_KEY: &str = "reveal_pubkey";

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

        self.add_key(CHALLENGE_KEY, &mut keys, program_context)?;

        if self.prover(program_context)? {
            self.add_key(REVEAL_KEY, &mut keys, program_context)?;

            for i in 0..packet_size as usize {
                self.add_ot_key(
                    &indexed_name(PEGOUT_ID_KEY, i),
                    20,
                    &mut keys,
                    program_context,
                )?;
                self.add_ot_key(&indexed_name(SECRET_KEY, i), 1, &mut keys, program_context)?;
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

        self.create_initial_deposits(&mut protocol, &committee, &keys, context)?;

        for i in 0..committee.packet_size as usize {
            self.create_dispute_core(&mut protocol, &committee, i, &keys, context)?;
        }

        protocol.build(&context.key_chain.key_manager, &self.ctx.protocol_name)?;
        info!("\n{}", protocol.visualize(GraphOptions::EdgeArrows)?);
        self.save_protocol(protocol)?;

        self.save_take_utxos(context)?;

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
        if transaction_name.starts_with(REIMBURSEMENT_KICKOFF_TX) {
            self.handle_reimbursement_kickoff_transaction(
                tx_id,
                &tx_status,
                &context,
                program_context,
            )?;
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
            "DisputeCore {} setup complete", self.ctx.id
        );

        Ok(())
    }
}

impl DisputeCoreProtocol {
    pub fn new(ctx: ProtocolContext) -> Self {
        Self { ctx }
    }

    fn create_initial_deposits(
        &self,
        protocol: &mut Protocol,
        committee: &Committee,
        keys: &Vec<ParticipantKeys>,
        context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        let operator_count = committee.operator_count;

        let dispute_aggregated_key = self.dispute_aggregated_key(context)?;

        let prefixes = match committee.my_role {
            ParticipantRole::Prover => vec![OPERATOR, WATCHTOWER],
            ParticipantRole::Verifier => vec![WATCHTOWER],
        };

        // Connect the initial deposit transaction to the funding tx. An operator will have two initial deposit txs,
        // one for his operator role and anoter for his watchtower role. Watchtowers will have only one initial deposit tx.
        for prefix in prefixes {
            let funding_utxo_name = format!("{}{}", prefix, FUNDING_UTXO_SUFFIX);
            let funding = format!("{}{}", prefix, FUNDING_TX_SUFFIX);
            let initial_deposit = format!("{}{}", prefix, INITIAL_DEPOSIT_TX_SUFFIX);

            let funding_utxo = self.utxo(&funding_utxo_name, context)?;
            protocol.add_external_transaction(&funding)?;
            protocol.add_transaction_output(&funding, &funding_utxo.3.unwrap())?;

            // TODO: Change the spend mode the one required by the funding_utxo
            protocol.add_connection(
                "initial_deposit",
                &funding,
                (funding_utxo.1 as usize).into(),
                &initial_deposit,
                InputSpec::Auto(SighashType::ecdsa_all(), SpendMode::None),
                None,
                Some(funding_utxo.0),
            )?;
        }

        // Add one output for each operator to the watchtower initial deposit transaction.
        // Each output has a taptree with committee.packet_size leaves.
        let mut operators_found = 0;
        for participant in keys.iter() {
            match participant.get_winternitz(&indexed_name(PEGOUT_ID_KEY, 0)) {
                Ok(_) => {
                    let mut leaves = vec![];
                    for i in 0..committee.packet_size as usize {
                        let pegout_id_leaf = scripts::operator_pegout_id(
                            dispute_aggregated_key,
                            participant.get_winternitz(&indexed_name(PEGOUT_ID_KEY, i))?,
                            participant.get_winternitz(&indexed_name(SECRET_KEY, i))?,
                        )?;

                        leaves.push(pegout_id_leaf);
                    }

                    protocol.add_transaction_output(
                        &format!("{}{}", WATCHTOWER, INITIAL_DEPOSIT_TX_SUFFIX),
                        &OutputType::taproot(
                            START_ENABLER_VALUE,
                            &dispute_aggregated_key,
                            leaves.as_slice(),
                        )?,
                    )?;

                    operators_found += 1;
                }
                Err(_) => {
                    continue;
                }
            };
        }

        assert_eq!(
            operator_count, operators_found,
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
        let pegout_id_name = indexed_name(PEGOUT_ID_KEY, dispute_core_index);
        let secret_name = indexed_name(SECRET_KEY, dispute_core_index);

        let member_keys = keys[committee.member_index].clone();

        let take_aggregated_key = self.take_aggregated_key(context)?;
        let pegout_id_key = member_keys.get_winternitz(&pegout_id_name)?;
        let secret_key = member_keys.get_winternitz(&secret_name)?;

        let initial_deposit = format!("{}{}", OPERATOR, INITIAL_DEPOSIT_TX_SUFFIX);
        let reimbursement_kickoff = indexed_name(REIMBURSEMENT_KICKOFF_TX, dispute_core_index);
        let challenge = indexed_name(CHALLENGE_TX, dispute_core_index);
        let reveal_secret = indexed_name(REVEAL_SECRET_TX, dispute_core_index);
        let input_not_revealed = indexed_name(INPUT_NOT_REVEALED_TX, dispute_core_index);

        let start_reimbursement = scripts::start_reimbursement(take_aggregated_key, pegout_id_key)?;

        // TODO: Review the internal key, maybe we don't need an aggregated key here
        protocol.add_connection(
            "start_dispute_core",
            &initial_deposit,
            OutputType::taproot(
                DISPUTE_OPENER_VALUE,
                &take_aggregated_key,
                &[start_reimbursement],
            )?
            .into(),
            &reimbursement_kickoff,
            InputSpec::Auto(SighashType::taproot_all(), SpendMode::ScriptsOnly),
            None,
            None,
        )?;

        let mut challenge_requests = vec![];
        for i in 0..(committee.operator_count + committee.watchtower_count) as usize {
            challenge_requests.push(scripts::verify_signature(
                keys[i].get_public(CHALLENGE_KEY)?,
                SignMode::Single,
            )?);
        }

        // TODO: Review the internal key, maybe we don't need an aggregated key here
        protocol.add_connection(
            "challenge",
            &reimbursement_kickoff,
            OutputType::taproot(
                DISPUTE_OPENER_VALUE,
                &take_aggregated_key,
                challenge_requests.as_slice(),
            )?
            .into(),
            &challenge,
            InputSpec::Auto(SighashType::taproot_all(), SpendMode::None),
            Some(DISPUTE_CORE_LONG_TIMELOCK),
            None,
        )?;

        let secret = scripts::verify_winternitz_signature(
            member_keys.get_public(REVEAL_KEY)?,
            secret_key,
            SignMode::Skip,
        )?;

        // TODO: Review the internal key, maybe we don't need an aggregated key here
        protocol.add_connection(
            "reveal_input",
            &challenge,
            OutputType::taproot(DISPUTE_OPENER_VALUE, &take_aggregated_key, &[secret])?.into(),
            &reveal_secret,
            InputSpec::Auto(SighashType::taproot_all(), SpendMode::ScriptsOnly),
            None,
            None,
        )?;

        protocol.add_transaction_output(
            &reveal_secret,
            &OutputType::taproot(DUST_VALUE, &take_aggregated_key, &[])?,
        )?;

        protocol.add_connection(
            "input_not_revealed",
            &challenge,
            OutputSpec::Index(0),
            &input_not_revealed,
            InputSpec::Auto(
                SighashType::taproot_all(),
                SpendMode::KeyOnly {
                    key_path_sign: SignMode::Aggregate,
                },
            ),
            None,
            None,
        )?;

        protocol.add_transaction_output(
            &input_not_revealed,
            &OutputType::taproot(DUST_VALUE, &take_aggregated_key, &[])?,
        )?;

        Ok(())
    }

    fn committee(&self, context: &ProgramContext) -> Result<Committee, BitVMXError> {
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
        let prefix = format!("{}_", REIMBURSEMENT_KICKOFF_TX);
        if let Some(suffix) = context.strip_prefix(&prefix) {
            suffix
                .parse::<usize>()
                .map_err(|_| BitVMXError::InvalidTransactionName(context.to_string()))
        } else {
            Err(BitVMXError::InvalidTransactionName(context.to_string()))
        }
    }

    fn get_selected_operator_key(
        &self,
        slot_id: usize,
        program_context: &ProgramContext,
    ) -> Result<Option<PublicKey>, BitVMXError> {
        let committee_id = self.committee_id(program_context)?;
        let selected_operator_key_name = format!("{}_{}", SELECTED_OPERATOR_PUBKEY, slot_id);

        match program_context
            .globals
            .get_var(&committee_id, &selected_operator_key_name)?
        {
            Some(selected_operator_var) => Ok(Some(selected_operator_var.pubkey()?)),
            None => Ok(None),
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
        info!(
            "Detected reimbursement kickoff transaction: {} with context: {}",
            tx_id, context
        );

        // Extract slot_id from the context
        let slot_id = self.extract_slot_id_from_context(context)?;

        // Get the selected operator's key for this slot
        match self.get_selected_operator_key(slot_id, program_context)? {
            Some(selected_operator_key) => {
                // Validate transaction signature against selected operator's key
                let is_valid =
                    self.validate_transaction_signature(tx_id, tx_status, selected_operator_key)?;

                if !is_valid {
                    info!(
                        "Invalid signature detected for slot {}, dispatching OP Disabler Tx",
                        slot_id
                    );
                    self.dispatch_op_disabler_tx(slot_id, program_context)?;
                } else {
                    info!("Valid signature confirmed for slot {}", slot_id);
                }
            }
            None => {
                info!("No selected operator key found for slot {}", slot_id);
                // If no selected operator key is set, it means that someone triggered a reimbursment kickoff transaction but there was no advances of funds
                self.dispatch_op_disabler_tx(slot_id, program_context)?;
            }
        }

        Ok(())
    }

    fn save_take_utxos(&self, context: &ProgramContext) -> Result<(), BitVMXError> {
        let committee = self.committee(context)?;
        let take_key = &self.take_aggregated_key(context)?;
        let protocol = self.load_or_create_protocol();

        for i in 0..committee.packet_size as usize {
            let name = indexed_name(REIMBURSEMENT_KICKOFF_TX, i);
            let reimbursement_kickoff_tx = protocol.transaction_by_name(&name)?;
            let operator_take_output = OutputType::taproot(DUST_VALUE, &take_key, &[])?;

            let operator_take_utxo = (
                reimbursement_kickoff_tx.compute_txid(),
                0,
                Some(DUST_VALUE),
                Some(operator_take_output),
            );

            let name = indexed_name(REVEAL_SECRET_TX, i);
            let reveal_secret_tx = protocol.transaction_by_name(&name)?;
            let operator_won_output = OutputType::taproot(DUST_VALUE, &take_key, &[])?;

            let operator_won_utxo = (
                reveal_secret_tx.compute_txid(),
                0,
                Some(DUST_VALUE),
                Some(operator_won_output),
            );

            context.globals.set_var(
                &self.ctx.id,
                &indexed_name(OPERATOR_TAKE_ENABLER, i),
                VariableTypes::Utxo(operator_take_utxo.clone()),
            )?;

            context.globals.set_var(
                &self.ctx.id,
                &indexed_name(OPERATOR_WON_ENABLER, i),
                VariableTypes::Utxo(operator_won_utxo.clone()),
            )?;
        }

        Ok(())
    }

    fn add_key(
        &self,
        name: &str,
        keys: &mut Vec<(String, PublicKeyType)>,
        context: &mut ProgramContext,
    ) -> Result<(), BitVMXError> {
        keys.push((
            name.to_string(),
            PublicKeyType::Public(context.key_chain.derive_keypair()?),
        ));

        Ok(())
    }

    fn add_ot_key(
        &self,
        name: &str,
        bytes: usize,
        keys: &mut Vec<(String, PublicKeyType)>,
        context: &mut ProgramContext,
    ) -> Result<(), BitVMXError> {
        keys.push((
            name.to_string(),
            PublicKeyType::Winternitz(context.key_chain.derive_winternitz_hash160(bytes)?),
        ));

        Ok(())
    }
}

fn indexed_name(prefix: &str, index: usize) -> String {
    format!("{}_{}", prefix, index)
}
