use crate::{
    errors::BitVMXError,
    program::{
        participant::{ParticipantKeys, ParticipantRole, PublicKeyType},
        protocols::{
            protocol_handler::{ProtocolContext, ProtocolHandler},
            union::{constants::*, events::CommitteeCreated},
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
        _context: &ProgramContext,
    ) -> Result<Vec<(String, PublicKey)>, BitVMXError> {
        Ok(vec![
            (
                "take_aggregated".to_string(),
                self.public_key(TAKE_AGGREGATED_KEY, _context)?,
            ),
            (
                "dispute_aggregated".to_string(),
                self.public_key(DISPUTE_AGGREGATED_KEY, _context)?,
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
        let mut protocol = self.load_or_create_protocol();
        // self.create_initial_deposit(
        //     &mut protocol,
        //     self.committee(context)?.my_role,
        //     &keys,
        //     context,
        // )?;

        // TODO repeat slot count times connecting each dispute core to the previous one
        self.create_dispute_core(&mut protocol, &keys, context)?;

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
}

impl DisputeCoreProtocol {
    pub fn new(ctx: ProtocolContext) -> Self {
        Self { ctx }
    }

    fn committee(&self, context: &ProgramContext) -> Result<CommitteeCreated, BitVMXError> {
        let committee_created = context
            .globals
            .get_var(&self.ctx.id, &CommitteeCreated::name())?
            .unwrap()
            .string()?;

        let committee_created: CommitteeCreated = serde_json::from_str(&committee_created)?;
        Ok(committee_created)
    }

    fn prover(&self, context: &ProgramContext) -> Result<bool, BitVMXError> {
        let members = self.committee(context)?;
        Ok(members.my_role == ParticipantRole::Prover)
    }

    fn utxo(&self, name: &str, context: &ProgramContext) -> Result<PartialUtxo, BitVMXError> {
        context.globals.get_var(&self.ctx.id, name)?.unwrap().utxo()
    }

    fn public_key(&self, name: &str, context: &ProgramContext) -> Result<PublicKey, BitVMXError> {
        context
            .globals
            .get_var(&self.ctx.id, name)?
            .unwrap()
            .pubkey()
    }

    fn create_funding_tx(
        &self,
        protocol: &mut Protocol,
        funding_utxo_name: &str,
        funding_tx_name: &str,
        context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        // Retrieve the funding UTXO for the operator
        let funding_utxo = self.utxo(funding_utxo_name, context)?;
        protocol.add_external_transaction(funding_tx_name)?;
        protocol.add_transaction_output(funding_tx_name, &funding_utxo.3.unwrap())?;

        Ok(())
    }

    fn create_initial_deposit(
        &self,
        protocol: &mut Protocol,
        role: ParticipantRole,
        keys: &Vec<ParticipantKeys>,
        context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        let prefixes = match role {
            ParticipantRole::Prover => vec!["OP", "WT"],
            ParticipantRole::Verifier => vec!["WT"],
        };

        for prefix in prefixes {
            let funding_utxo_name = format!("{}{}", prefix, FUNDING_UTXO_SUFFIX);
            let funding_tx_name = format!("{}{}", prefix, FUNDING_TX_SUFFIX);
            let initial_deposit_tx_name = format!("{}{}", prefix, INITIAL_DEPOSIT_TX_SUFFIX);

            let funding_utxo = self.utxo(&funding_utxo_name, context)?;
            self.create_funding_tx(protocol, &funding_utxo_name, &funding_tx_name, context)?;

            protocol.add_connection(
                "initial_deposit",
                &funding_tx_name,
                (funding_utxo.1 as usize).into(),
                &initial_deposit_tx_name,
                InputSpec::Auto(SighashType::ecdsa_all(), SpendMode::Segwit),
                None,
                Some(funding_utxo.0),
            )?;
        }

        let members = self.committee(context)?;

        let mut operators_found = 0;
        for participant in keys.iter() {
            match participant.get_winternitz("pegout_id") {
                Ok(_) => {
                    let script =
                        scripts::verify_signature(&members.my_dispute_pubkey, SignMode::Single)?;

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
        keys: &Vec<ParticipantKeys>,
        context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        let members = self.committee(context)?;

        // Connect with REIMBURSEMENT_KICKOFF_TX
        let participant = &keys[self.ctx.my_idx];

        let pegout_id_pubkey = participant.get_winternitz("pegout_id")?;
        let value_0_pubkey = participant.get_winternitz("value_0")?;
        let value_1_pubkey = participant.get_winternitz("value_1")?;
        let my_dispute_pubkey = members.my_dispute_pubkey.clone();

        let script = scripts::start_dispute_core(
            my_dispute_pubkey,
            pegout_id_pubkey,
            value_0_pubkey,
            value_1_pubkey,
        )?;

        protocol.add_connection(
            "dispute_core",
            OP_INITIAL_DEPOSIT_TX,
            OutputType::taproot(
                DISPUTE_OPENER_VALUE,
                &self.public_key(TAKE_AGGREGATED_KEY, context)?,
                &[],
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
            OutputType::taproot(
                DUST_VALUE,
                &self.public_key(TAKE_AGGREGATED_KEY, context)?,
                &vec![],
            )?
            .into(),
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

        let value_0_script = scripts::verify_value(
            self.public_key(TAKE_AGGREGATED_KEY, context)?,
            value_0_pubkey,
            value_0,
        )?;

        let value_1_script = scripts::verify_value(
            self.public_key(TAKE_AGGREGATED_KEY, context)?,
            value_1_pubkey,
            value_1,
        )?;

        //CHALLENGE_TX connection (T)
        // TODO review the SpendMode
        protocol.add_connection(
            "take_enabler",
            REIMBURSEMENT_KICKOFF_TX,
            OutputType::taproot(
                DUST_VALUE,
                &self.public_key(TAKE_AGGREGATED_KEY, context)?,
                &vec![], //&vec![value_0_script, value_1_script],
            )?
            .into(),
            CHALLENGE_TX,
            //InputSpec::Auto(SighashType::taproot_all(), SpendMode::Script { leaf: 1 }),
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
            "try_take_2",
            CHALLENGE_TX,
            OutputType::taproot(
                DUST_VALUE,
                &self.public_key(TAKE_AGGREGATED_KEY, context)?,
                &vec![],
            )?
            .into(),
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
            OutputType::taproot(
                DUST_VALUE,
                &self.public_key(TAKE_AGGREGATED_KEY, context)?,
                &vec![],
            )?
            .into(),
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
            //InputSpec::Auto(SighashType::taproot_all(), SpendMode::Script { leaf: 0 }),
            InputSpec::Auto(
                SighashType::taproot_all(),
                SpendMode::All {
                    key_path_sign: SignMode::Aggregate,
                },
            ),
            Some(TAKE_ENABLER_TIMELOCK / 2),
            None,
        )?;

        // Connection to try to move to the next dispute core (Try Move On)
        protocol.add_connection(
            "take_enabler",
            REIMBURSEMENT_KICKOFF_TX,
            OutputType::taproot(
                DUST_VALUE,
                &self.public_key(DISPUTE_AGGREGATED_KEY, context)?,
                &vec![],
            )?
            .into(),
            TRY_MOVE_ON_TX,
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
            OutputType::taproot(
                DUST_VALUE,
                &self.public_key(DISPUTE_AGGREGATED_KEY, context)?,
                &vec![],
            )?
            .into(),
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

        // Connection to stop moving on to the next dispute core (Y)
        protocol.add_connection(
            "you_cant_take_enabler",
            REIMBURSEMENT_KICKOFF_TX,
            OutputType::taproot(
                DUST_VALUE,
                &self.public_key(DISPUTE_AGGREGATED_KEY, context)?,
                &vec![],
            )?
            .into(),
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

        Ok(())
    }
}
