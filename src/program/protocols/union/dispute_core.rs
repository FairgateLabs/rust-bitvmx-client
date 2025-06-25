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
        info!("{}", protocol.visualize()?);
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
        _tx_id: Txid,
        _vout: Option<u32>,
        _tx_status: TransactionStatus,
        _context: String,
        _program_context: &ProgramContext,
        _participant_keys: Vec<&ParticipantKeys>,
    ) -> Result<(), BitVMXError> {
        // TODO
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
        committee: &NewCommittee,
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

        let mut operators_found = 0;
        for participant in keys.iter() {
            match participant.get_winternitz("pegout_id_0") {
                Ok(_) => {
                    let script =
                        scripts::verify_signature(&dispute_aggregated_key, SignMode::Aggregate)?;

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
        _committee: &NewCommittee,
        dispute_core_index: usize,
        keys: &Vec<ParticipantKeys>,
        context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        let keys = keys[self.member_index(context)?].clone();

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

        // TODO: decide if we want to send the utxos for the take txs to the L2 client
        // let data = serde_json::to_string(&OutgoingBitVMXApiMessages::Variable(
        //     self.ctx.id,
        //     "utxos_for_take".to_string(),
        //     VariableTypes::String(serde_json::to_string(&(
        //         &self.ctx.protocol_name,
        //         &utxos_for_take,
        //     ))?),
        // ))?;

        // context.broker_channel.send(L2_ID, data)?;

        Ok(())
    }

    fn committee(&self, context: &ProgramContext) -> Result<NewCommittee, BitVMXError> {
        let committee = context
            .globals
            .get_var(&self.ctx.id, &NewCommittee::name())?
            .unwrap()
            .string()?;

        let committee: NewCommittee = serde_json::from_str(&committee)?;
        Ok(committee)
    }

    fn member_index(&self, context: &ProgramContext) -> Result<usize, BitVMXError> {
        let member_index = context
            .globals
            .get_var(&self.ctx.id, "member_index")?
            .unwrap()
            .number()?;
        Ok(member_index as usize)
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
}

fn var_name(prefix: &str, index: usize) -> String {
    format!("{}_{}", prefix, index)
}
