use crate::{
    errors::BitVMXError,
    program::{
        participant::{ParticipantKeys, ParticipantRole, PublicKeyType},
        protocols::{
            protocol_handler::{ProtocolContext, ProtocolHandler},
            union::types::*,
        },
        variables::PartialUtxo,
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
        let mut keys = vec![];
        if self.prover(program_context)? {
            keys.push((
                "pegout_id".to_string(),
                PublicKeyType::Winternitz(program_context.key_chain.derive_winternitz_hash160(20)?),
            ));
            keys.push((
                "value_0".to_string(),
                PublicKeyType::Winternitz(program_context.key_chain.derive_winternitz_hash160(1)?),
            ));
            keys.push((
                "value_1".to_string(),
                PublicKeyType::Winternitz(program_context.key_chain.derive_winternitz_hash160(1)?),
            ));
        }

        Ok(ParticipantKeys::new(keys, vec![]))
    }

    fn build(
        &self,
        keys: Vec<ParticipantKeys>,
        _computed_aggregated: HashMap<String, PublicKey>,
        context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        let committee = self.committee(context)?;
        let mut protocol = self.load_or_create_protocol();
        self.create_initial_deposit(
            &mut protocol,
            self.committee(context)?.my_role,
            &keys,
            context,
        )?;

        let member_keys = keys[committee.member_index as usize].clone();

        // TODO repeat slot count times connecting each dispute core to the previous one
        self.create_dispute_core(&mut protocol, &member_keys, context)?;

        protocol.build(&context.key_chain.key_manager, &self.ctx.protocol_name)?;
        info!("{}", protocol.visualize()?);
        self.save_protocol(protocol)?;

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
        role: ParticipantRole,
        keys: &Vec<ParticipantKeys>,
        context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        let dispute_aggregated_key = self.dispute_aggregated_key(context)?;

        let prefixes = match role {
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

        let members = self.committee(context)?;

        //TODO add one ouput for each operator to the WT initial deposit transaction
        let mut operators_found = 0;
        for participant in keys.iter() {
            match participant.get_winternitz("pegout_id") {
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
            operators_found, members.operator_count,
            "Expected {} operators, found {}",
            members.operator_count, operators_found
        );

        Ok(())
    }

    fn create_dispute_core(
        &self,
        protocol: &mut Protocol,
        keys: &ParticipantKeys,
        context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        let pegout_id_pubkey = keys.get_winternitz("pegout_id")?;
        let value_0_pubkey = keys.get_winternitz("value_0")?;
        let value_1_pubkey = keys.get_winternitz("value_1")?;
        let take_aggregated_key = self.take_aggregated_key(context)?;
        let dispute_aggregated_key = self.dispute_aggregated_key(context)?;

        let start_dispute_core = scripts::start_dispute_core(
            dispute_aggregated_key,
            pegout_id_pubkey,
            value_0_pubkey,
            value_1_pubkey,
        )?;

        protocol.add_connection(
            "dispute_core",
            OP_INITIAL_DEPOSIT_TX,
            OutputType::taproot(
                DISPUTE_OPENER_VALUE,
                &take_aggregated_key,
                &[start_dispute_core],
            )?
            .into(),
            REIMBURSEMENT_KICKOFF_TX,
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
            REIMBURSEMENT_KICKOFF_TX,
            OutputType::taproot(DUST_VALUE, &take_aggregated_key, &[])?.into(),
            NO_TAKE_TX,
            InputSpec::Auto(
                SighashType::taproot_all(),
                SpendMode::KeyOnly {
                    key_path_sign: SignMode::Aggregate,
                },
            ),
            None,
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
            REIMBURSEMENT_KICKOFF_TX,
            OutputType::taproot(
                DUST_VALUE,
                &take_aggregated_key,
                &vec![value_0_script, value_1_script],
            )?
            .into(),
            CHALLENGE_TX,
            InputSpec::Auto(SighashType::taproot_all(), SpendMode::Script { leaf: 1 }),
            Some(TAKE_ENABLER_TIMELOCK),
            None,
        )?;

        protocol.add_connection(
            "try_take_2",
            CHALLENGE_TX,
            OutputType::taproot(DUST_VALUE, &take_aggregated_key, &[])?.into(),
            TRY_TAKE_2_TX,
            InputSpec::Auto(
                SighashType::taproot_all(),
                SpendMode::KeyOnly {
                    key_path_sign: SignMode::Aggregate,
                },
            ),
            Some(TAKE_ENABLER_TIMELOCK),
            None,
        )?;

        protocol.add_connection(
            "no_dispute_opened",
            CHALLENGE_TX,
            OutputType::taproot(DUST_VALUE, &take_aggregated_key, &[])?.into(),
            NO_DISPUTE_OPENED_TX,
            InputSpec::Auto(
                SighashType::taproot_all(),
                SpendMode::KeyOnly {
                    key_path_sign: SignMode::Aggregate,
                },
            ),
            Some(TAKE_ENABLER_TIMELOCK),
            None,
        )?;

        // YOU_CANT_TAKE_TX connection
        protocol.add_connection(
            "take_enabler",
            REIMBURSEMENT_KICKOFF_TX,
            OutputSpec::Index(1),
            YOU_CANT_TAKE_TX,
            InputSpec::Auto(SighashType::taproot_all(), SpendMode::Script { leaf: 0 }),
            Some(TAKE_ENABLER_TIMELOCK / 2),
            None,
        )?;

        // Connection to try to move to the next dispute core (Try Move On)
        protocol.add_connection(
            "take_enabler",
            REIMBURSEMENT_KICKOFF_TX,
            OutputType::taproot(DUST_VALUE, &dispute_aggregated_key, &[])?.into(),
            OP_SELF_DISABLER_TX,
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
            "stop_move_on_enabler",
            REIMBURSEMENT_KICKOFF_TX,
            OutputType::taproot(DUST_VALUE, &dispute_aggregated_key, &[])?.into(),
            NO_DISPUTE_OPENED_TX,
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
            "take_enabler",
            REIMBURSEMENT_KICKOFF_TX,
            OutputSpec::Index(2),
            YOU_CANT_TAKE_TX,
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
            "take_enabler",
            REIMBURSEMENT_KICKOFF_TX,
            OutputSpec::Index(1),
            NO_CHALLENGE_TX,
            InputSpec::Auto(SighashType::taproot_all(), SpendMode::Script { leaf: 0 }),
            Some(TAKE_ENABLER_TIMELOCK / 2),
            None,
        )?;

        protocol.add_connection(
            "take_enabler",
            REIMBURSEMENT_KICKOFF_TX,
            OutputSpec::Index(3),
            NO_CHALLENGE_TX,
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

    fn committee(&self, context: &ProgramContext) -> Result<NewCommittee, BitVMXError> {
        let committee = context
            .globals
            .get_var(&self.ctx.id, &NewCommittee::name())?
            .unwrap()
            .string()?;

        let committee: NewCommittee = serde_json::from_str(&committee)?;
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
}
