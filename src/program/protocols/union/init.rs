use crate::{
    errors::BitVMXError,
    program::{
        participant::{ParticipantKeys, ParticipantRole, PublicKeyType},
        protocols::{
            protocol_handler::{ProtocolContext, ProtocolHandler},
            union::events::MembersSelected,
        },
        variables::PartialUtxo,
    },
    types::ProgramContext,
};
use bitcoin::{PublicKey, Transaction, Txid};
use bitcoin_coordinator::TransactionStatus;
use protocol_builder::{
    scripts::{self, SignMode},
    types::{
        connection::{InputSpec, OutputSpec},
        input::{SighashType, SpendMode},
        OutputType,
    },
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::info;

pub const OPERATOR_FUNDING_TX: &str = "OPERATOR_FUNDING_TX";
pub const WATCHTOWER_FUNDING_TX: &str = "WATCHTOWER_FUNDING_TX";
pub const OPERATOR_INITIAL_DEPOSIT_TX: &str = "OPERATOR_INITIAL_DEPOSIT_TX";
pub const WATCHTOWER_INITIAL_DEPOSIT_TX: &str = "WATCHTOWER_INITIAL_DEPOSIT_TX";
pub const REIMBURSEMENT_KICKOFF_TX: &str = "REIMBURSEMENT_KICKOFF_TX";
pub const NO_TAKE_TX: &str = "NO_TAKE_TX";
pub const CHALLENGE_TX: &str = "CHALLENGE_TX";
pub const YOU_CANT_TAKE_TX: &str = "YOU_CANT_TAKE_TX";
pub const TRY_MOVE_ON_TX: &str = "TRY_MOVE_ON_TX";
pub const TRY_TAKE_2_TX: &str = "TRY_TAKE_2_TX";
pub const NO_DISPUTE_OPENED_TX: &str = "NO_DISPUTE_OPENED_TX";

pub const TAKE_ENABLER_TIMELOCK: u16 = 144;

pub const DISPUTE_OPENER_VALUE: u64 = 1000;
pub const START_ENABLER_VALUE: u64 = 1000;
pub const DUST_VALUE: u64 = 546;

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
        Ok(vec![])
    }

    fn generate_keys(
        &self,
        program_context: &mut ProgramContext,
    ) -> Result<ParticipantKeys, BitVMXError> {
        let mut keys = vec![];
        if self.prover(program_context)? {
            keys.push((
                "ot_pegout_id".to_string(),
                PublicKeyType::Winternitz(program_context.key_chain.derive_winternitz_hash160(20)?),
            ));
            keys.push((
                "ot_bit0".to_string(),
                PublicKeyType::Winternitz(program_context.key_chain.derive_winternitz_hash160(1)?),
            ));
            keys.push((
                "ot_bit1".to_string(),
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
        let members = self.members(context)?;

        let mut protocol = self.load_or_create_protocol();

        if self.prover(context)? {
            let op_funding_utxo = self.utxo("op_funding_utxo", context)?;

            // External OPERATOR_FUNDING_TX transaction
            protocol.add_external_transaction(OPERATOR_FUNDING_TX)?;
            protocol.add_transaction_output(OPERATOR_FUNDING_TX, &op_funding_utxo.3.unwrap())?;

            // Connect with OPERATOR_INITIAL_DEPOSIT_TX
            protocol.add_connection(
                "initial_op_deposit",
                OPERATOR_FUNDING_TX,
                (op_funding_utxo.1 as usize).into(),
                OPERATOR_INITIAL_DEPOSIT_TX,
                InputSpec::Auto(SighashType::ecdsa_all(), SpendMode::Segwit),
                None,
                Some(op_funding_utxo.0),
            )?;

            // Connect with REIMBURSEMENT_KICKOFF_TX
            let participant = &keys[self.ctx.my_idx];

            let pegout_id_pubkey = participant.get_winternitz("ot_pegout_id")?;
            let bit0_pubkey = participant.get_winternitz("ot_bit0")?;
            let bit1_pubkey = participant.get_winternitz("ot_bit1")?;
            let my_dispute_pubkey = members.my_dispute_pubkey.clone();

            let script = scripts::start_dispute_core(
                my_dispute_pubkey,
                pegout_id_pubkey,
                bit0_pubkey,
                bit1_pubkey,
            )?;

            protocol.add_connection(
                "initial_op_deposit",
                OPERATOR_INITIAL_DEPOSIT_TX,
                OutputType::segwit_script(DISPUTE_OPENER_VALUE, &script)?.into(),
                REIMBURSEMENT_KICKOFF_TX,
                InputSpec::Auto(SighashType::ecdsa_all(), SpendMode::Segwit),
                None,
                None,
            )?;

            // Add the REIMBURSEMENT_KICKOFF_TX outputs
            // Take enable output
            protocol.add_transaction_output(
                REIMBURSEMENT_KICKOFF_TX,
                &OutputType::taproot(
                    DUST_VALUE,
                    &self.public_key("take_aggregated_key", context)?,
                    &vec![],
                )?,
            )?;

            // Connection to prevent the take transactions to occur (No Take)
            protocol.add_connection(
                "no_take_connection",
                REIMBURSEMENT_KICKOFF_TX,
                OutputType::taproot(
                    DUST_VALUE,
                    &self.public_key("take_aggregated_key", context)?,
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
            let bit0_value: Vec<u8> = vec![0];
            let bit1_value: Vec<u8> = vec![1];

            let bit_0_script = scripts::verify_bit(
                self.public_key("take_aggregated_key", context)?,
                bit1_pubkey,
                bit0_value,
            )?;

            let bit_1_script = scripts::verify_bit(
                self.public_key("take_aggregated_key", context)?,
                bit1_pubkey,
                bit1_value,
            )?;

            // CHALLENGE_TX connection (T)
            protocol.add_connection(
                "take_enabler",
                REIMBURSEMENT_KICKOFF_TX,
                OutputType::taproot(
                    DUST_VALUE,
                    &self.public_key("take_aggregated_key", context)?,
                    &vec![bit_0_script, bit_1_script],
                )?
                .into(),
                CHALLENGE_TX,
                //InputSpec::Auto(SighashType::taproot_all(), SpendMode::Script { leaf: 1 }),
                InputSpec::Auto(
                    SighashType::taproot_all(),
                    SpendMode::All {
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
                    &self.public_key("take_aggregated_key", context)?,
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
                    &self.public_key("take_aggregated_key", context)?,
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
                    &self.public_key("dispute_aggregated_key", context)?,
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
                    &self.public_key("dispute_aggregated_key", context)?,
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
                    &self.public_key("dispute_aggregated_key", context)?,
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

            // protocol.add_transaction_output(
            //     REIMBURSEMENT_KICKOFF_TX,
            //     &OutputType::taproot(
            //         DUST_VALUE,
            //         &self.public_key("take_aggregated_key", context)?,
            //         &vec![],
            //     )?,
            // )?;

            // // Next enabler output
            // protocol.add_transaction_output(
            //     REIMBURSEMENT_KICKOFF_TX,
            //     &OutputType::taproot(
            //         DUST_VALUE,
            //         &self.public_key("dispute_aggregated_key", context)?,
            //         &vec![],
            //     )?,
            // )?;

            // // No dispute opened output
            // protocol.add_transaction_output(
            //     REIMBURSEMENT_KICKOFF_TX,
            //     &OutputType::taproot(
            //         DUST_VALUE,
            //         &self.public_key("dispute_aggregated_key", context)?,
            //         &vec![],
            //     )?,
            // )?;

            // // Next dispute core output
            // protocol.add_transaction_output(
            //     REIMBURSEMENT_KICKOFF_TX,
            //     &OutputType::taproot(
            //         DUST_VALUE,
            //         &self.public_key("dispute_aggregated_key", context)?,
            //         &vec![],
            //     )?,
            // )?;
        }

        let wt_funding_utxo = self.utxo("wt_funding_utxo", context)?;

        // External WATCHTOWER_FUNDING_TX transaction
        protocol.add_external_transaction(WATCHTOWER_FUNDING_TX)?;
        protocol.add_transaction_output(WATCHTOWER_FUNDING_TX, &wt_funding_utxo.3.unwrap())?;

        // Connect with WATCHTOWER_FUNDING_TX
        protocol.add_connection(
            "initial_wt_deposit",
            WATCHTOWER_FUNDING_TX,
            (wt_funding_utxo.1 as usize).into(),
            WATCHTOWER_INITIAL_DEPOSIT_TX,
            InputSpec::Auto(SighashType::ecdsa_all(), SpendMode::Segwit),
            None,
            Some(wt_funding_utxo.0),
        )?;

        let mut operators_found = 0;
        for participant in keys.iter() {
            match participant.get_winternitz("ot_pegout_id") {
                Ok(_) => {
                    let my_dispute_pubkey = members.my_dispute_pubkey.clone();

                    let script = scripts::verify_signature(&my_dispute_pubkey, SignMode::Single)?;

                    protocol.add_transaction_output(
                        WATCHTOWER_INITIAL_DEPOSIT_TX,
                        &OutputType::segwit_script(START_ENABLER_VALUE, &script)?,
                    )?;

                    operators_found += 1;
                }
                Err(_) => {
                    continue;
                }
            };
        }

        assert!(
            operators_found == members.operator_count,
            "Expected {} operators, found {}",
            members.operator_count,
            operators_found
        );

        protocol.build(&context.key_chain.key_manager, &self.ctx.protocol_name)?;
        info!("{}", protocol.visualize()?);
        self.save_protocol(protocol)?;

        Ok(())
    }

    fn get_transaction_name(
        &self,
        name: &str,
        _context: &ProgramContext,
    ) -> Result<Transaction, BitVMXError> {
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

    fn members(&self, context: &ProgramContext) -> Result<MembersSelected, BitVMXError> {
        let members_selected = context
            .globals
            .get_var(&self.ctx.id, &MembersSelected::name())?
            .unwrap()
            .string()?;

        let members_selected: MembersSelected = serde_json::from_str(&members_selected)?;
        Ok(members_selected)
    }

    fn prover(&self, context: &ProgramContext) -> Result<bool, BitVMXError> {
        let members = self.members(context)?;
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
}
