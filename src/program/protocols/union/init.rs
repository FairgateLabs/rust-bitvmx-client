use crate::{
    errors::BitVMXError,
    program::{
        participant::{ParticipantKeys, ParticipantRole, PublicKeyType},
        protocols::{
            protocol_handler::{ProtocolContext, ProtocolHandler},
            union::events::events::MembersSelected,
        },
        variables::PartialUtxo,
    },
    types::ProgramContext,
};
use bitcoin::{psbt::Output, Amount, PublicKey, ScriptBuf, Transaction, Txid, WScriptHash};
use bitcoin_coordinator::TransactionStatus;
use protocol_builder::{
    scripts::{self, SignMode},
    types::{
        connection::{InputSpec, OutputSpec},
        input::{self, SighashType, SpendMode},
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
        todo!()
    }

    fn generate_keys(
        &self,
        program_context: &mut ProgramContext,
    ) -> Result<ParticipantKeys, BitVMXError> {
        let members = self.members(&program_context)?;

        let take_aggregated_key = program_context
            .key_chain
            .new_musig2_session(members.take_pubkeys.clone(), members.my_take_pubkey.clone())?;

        let dispute_aggregated_key = program_context.key_chain.new_musig2_session(
            members.dispute_pubkeys.clone(),
            members.my_dispute_pubkey.clone(),
        )?;

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

        keys.push((
            "take_aggregated_key".to_string(),
            PublicKeyType::Public(take_aggregated_key.clone()),
        ));
        keys.push((
            "dispute_aggregated_key".to_string(),
            PublicKeyType::Public(dispute_aggregated_key.clone()),
        ));

        Ok(ParticipantKeys::new(
            keys,
            vec![
                "take_aggregated_key".to_string(),
                "dispute_aggregated_key".to_string(),
            ],
        ))
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

            // Declare the external op_funding transaction
            protocol.add_external_transaction(OPERATOR_FUNDING_TX)?;
            protocol.add_transaction_output(OPERATOR_FUNDING_TX, &op_funding_utxo.3.unwrap())?;

            // Connect the operator initial deposit transaction with the op_funding transaction
            protocol.add_connection(
                "initial_op_deposit",
                OPERATOR_FUNDING_TX,
                (op_funding_utxo.1 as usize).into(),
                OPERATOR_INITIAL_DEPOSIT_TX,
                InputSpec::Auto(SighashType::ecdsa_all(), SpendMode::Segwit),
                None,
                Some(op_funding_utxo.0),
            )?;

            // Connect the operator reimbursement kickoff transaction with the initial deposit transaction
            let participant = &keys[self.ctx.my_idx];

            let pegout_id_pubkey = participant.get_winternitz("ot_pegout_id")?;
            let bit0_pubkey = participant.get_winternitz("ot_bit0")?;
            let bit1_pubkey = participant.get_winternitz("ot_bit1")?;
            let my_dispute_pubkey = self.members(context)?.my_dispute_pubkey.clone();

            let script = scripts::start_dispute_core(
                my_dispute_pubkey,
                pegout_id_pubkey,
                bit0_pubkey,
                bit1_pubkey,
            )?;

            let output = OutputType::SegwitScript {
                value: Amount::from_sat(DISPUTE_OPENER_VALUE),
                script_pubkey: ScriptBuf::new_p2wsh(&WScriptHash::from(
                    script.get_script().clone(),
                )),
                script,
            };

            protocol.add_connection(
                "initial_op_deposit",
                OPERATOR_INITIAL_DEPOSIT_TX,
                OutputSpec::Auto(output),
                REIMBURSEMENT_KICKOFF_TX,
                InputSpec::Auto(SighashType::ecdsa_all(), SpendMode::Segwit),
                None,
                None,
            )?;
        }

        let wt_funding_utxo = self.utxo("wt_funding_utxo", context)?;

        // Declare the external op_funding transaction
        protocol.add_external_transaction(WATCHTOWER_FUNDING_TX)?;
        protocol.add_transaction_output(WATCHTOWER_FUNDING_TX, &wt_funding_utxo.3.unwrap())?;

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
                    let my_dispute_pubkey = self.members(context)?.my_dispute_pubkey.clone();

                    let script = scripts::verify_signature(&my_dispute_pubkey, SignMode::Single)?;

                    protocol.add_transaction_output(
                        WATCHTOWER_INITIAL_DEPOSIT_TX,
                        &OutputType::SegwitScript {
                            value: Amount::from_sat(START_ENABLER_VALUE),
                            script_pubkey: ScriptBuf::new_p2wsh(&WScriptHash::from(
                                script.get_script().clone(),
                            )),
                            script,
                        },
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
        _name: &str,
        _context: &ProgramContext,
    ) -> Result<Transaction, BitVMXError> {
        todo!()
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
        todo!()
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
