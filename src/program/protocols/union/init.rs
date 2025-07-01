use crate::{
    errors::BitVMXError,
    program::{
        participant::{ParticipantKeys, ParticipantRole, PublicKeyType},
        protocols::{
            protocol_handler::{ProtocolContext, ProtocolHandler},
            union::{events::MembersSelected, take},
        },
        variables::PartialUtxo,
    },
    types::ProgramContext,
};
use bitcoin::{PublicKey, Transaction, Txid};
use bitcoin_coordinator::TransactionStatus;
use core::panic;
use protocol_builder::{
    scripts::{self, SignMode},
    types::{
        connection::InputSpec,
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

pub const DISPUTE_OPENER_VALUE: u64 = 1000;
pub const START_ENABLER_VALUE: u64 = 1000;
pub const DUST_VALUE: u64 = 546;

#[derive(Clone, Serialize, Deserialize)]
pub struct InitProtocol {
    ctx: ProtocolContext,
}

impl ProtocolHandler for InitProtocol {
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
        // let members = self.members(&program_context)?;

        // let take_aggregated_key = program_context
        //     .key_chain
        //     .new_musig2_session(members.take_pubkeys.clone(), members.my_take_pubkey.clone())?;

        // let dispute_aggregated_key = program_context.key_chain.new_musig2_session(
        //     members.dispute_pubkeys.clone(),
        //     members.my_dispute_pubkey.clone(),
        // )?;

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

        // keys.push((
        //     "take_aggregated_key".to_string(),
        //     PublicKeyType::Public(take_aggregated_key.clone()),
        // ));
        // keys.push((
        //     "dispute_aggregated_key".to_string(),
        //     PublicKeyType::Public(dispute_aggregated_key.clone()),
        // ));

        Ok(ParticipantKeys::new(
            keys,
            vec![
                // "take_aggregated_key".to_string(),
                // "dispute_aggregated_key".to_string(),
            ],
        ))
    }

    fn build(
        &self,
        keys: Vec<ParticipantKeys>,
        computed_aggregated: HashMap<String, PublicKey>,
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

            //TODO recover take_aggregated_key and dispute_aggregated_key

            // Add the REIMBURSEMENT_KICKOFF_TX outputs
            // Take enable output
            protocol.add_transaction_output(
                REIMBURSEMENT_KICKOFF_TX,
                &OutputType::taproot(DUST_VALUE, &take_aggregated_key, &vec![])?,
            )?;

            // Take output
            protocol.add_transaction_output(
                REIMBURSEMENT_KICKOFF_TX,
                &OutputType::taproot(DUST_VALUE, &computed_aggregated_key, &vec![])?,
            )?;

            // Next enabler output
            protocol.add_transaction_output(
                REIMBURSEMENT_KICKOFF_TX,
                &OutputType::taproot(
                    DUST_VALUE,
                    computed_aggregated.get("dispute_aggregated_key").unwrap(),
                    &vec![],
                )?,
            )?;

            // No dispute opened output
            protocol.add_transaction_output(
                REIMBURSEMENT_KICKOFF_TX,
                &OutputType::taproot(
                    DUST_VALUE,
                    computed_aggregated.get("dispute_aggregated_key").unwrap(),
                    &vec![],
                )?,
            )?;

            // Next dispute core output
            protocol.add_transaction_output(
                REIMBURSEMENT_KICKOFF_TX,
                &OutputType::taproot(
                    DUST_VALUE,
                    computed_aggregated.get("dispute_aggregated_key").unwrap(),
                    &vec![],
                )?,
            )?;
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

impl InitProtocol {
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
}
