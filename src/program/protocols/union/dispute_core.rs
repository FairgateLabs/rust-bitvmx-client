use std::collections::HashMap;

use bitcoin::{
    key::rand::{self, RngCore},
    Amount, PublicKey, ScriptBuf, Transaction, Txid, WScriptHash,
};
use bitcoin_coordinator::TransactionStatus;
use protocol_builder::{
    errors::ProtocolBuilderError,
    scripts::{self, SignMode},
    types::{
        connection::InputSpec,
        input::{SighashType, SpendMode},
        InputArgs, OutputType,
    },
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::info;

use crate::{
    errors::BitVMXError,
    program::{
        participant::ParticipantKeys,
        protocols::protocol_handler::{ProtocolContext, ProtocolHandler},
        variables::VariableTypes,
    },
    types::ProgramContext,
};

pub const OPERATOR_FUNDING_TX: &str = "OPERATOR_FUNDING_TX";
pub const WATCHTOWER_FUNDING_TX: &str = "WATCHTOWER_FUNDING_TX";
pub const OPERATOR_DISPUTE_OPENER_TX: &str = "OPERATOR_DISPUTE_OPENER_TX";
pub const WATCHTOWER_START_ENABLER_TX: &str = "WATCHTOWER_START_ENABLER_TX";
pub const REIMBURSEMENT_KICKOFF_TX: &str = "REIMBURSEMENT_KICKOFF_TX_";

pub const DISPUTE_OPENER_VALUE: u64 = 1000;
pub const START_ENABLER_VALUE: u64 = 1000;

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
        // Predefined aggregated keys for this protocol
        todo!()
    }

    fn generate_keys(
        &self,
        program_context: &mut ProgramContext,
    ) -> Result<ParticipantKeys, BitVMXError> {
        let mut take_pubkeys = Vec::new();
        let mut dispute_pubkeys = Vec::new();

        let my_take_public_key = program_context
            .globals
            .get_var(&self.ctx.id, "take_public_key")?
            .unwrap()
            .pubkey()?;

        let my_dispute_public_key = program_context
            .globals
            .get_var(&self.ctx.id, "dispute_public_key")?
            .unwrap()
            .pubkey()?;

        let member_count = program_context
            .globals
            .get_var(&self.ctx.id, "member_count")?
            .unwrap()
            .number()?;

        for i in 0..member_count {
            let take_public_key = program_context
                .globals
                .get_var(&self.ctx.id, &format!("take_public_key_{}", i))?
                .unwrap()
                .pubkey()?;

            let dispute_public_key = program_context
                .globals
                .get_var(&self.ctx.id, &format!("dispute_public_key_{}", i))?
                .unwrap()
                .pubkey()?;

            take_pubkeys.push(take_public_key);
            dispute_pubkeys.push(dispute_public_key);
        }

        let take_aggregated_key = program_context.key_chain.new_musig2_session(
            take_pubkeys.values().cloned().collect(),
            my_take_public_key.clone(),
        )?;

        let dispute_aggregated_key = program_context.key_chain.new_musig2_session(
            dispute_pubkeys.values().cloned().collect(),
            my_dispute_public_key.clone(),
        )?;

        Ok(ParticipantKeys::new(vec![], vec![take_aggregated_key, dispute_aggregated_key]))
    }

    fn build(
        &self,
        _keys: Vec<ParticipantKeys>,
        _computed_aggregated: HashMap<String, PublicKey>,
        context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        let my_take_public_key = context
            .globals
            .get_var(&self.ctx.id, "take_public_key")?
            .unwrap()
            .pubkey()?;

        let my_dispute_public_key = context
            .globals
            .get_var(&self.ctx.id, "dispute_public_key")?
            .unwrap()
            .pubkey()?;

        let my_role = context
            .globals
            .get_var(&self.ctx.id, "role")?
            .unwrap()
            .string()?;

        let wt_funding_utxo = context
            .globals
            .get_var(&self.ctx.id, "wt_funding_utxo")?
            .unwrap()
            .utxo()?;

        let member_count = context
            .globals
            .get_var(&self.ctx.id, "member_count")?
            .unwrap()
            .number()?;

        let operators_count = context
            .globals
            .get_var(&self.ctx.id, "op_count")?
            .unwrap()
            .number()?;

        //create the protocol
        let mut protocol = self.load_or_create_protocol();

        if my_role == "operator" {
            let op_funding_utxo = context
                .globals
                .get_var(&self.ctx.id, "op_funding_utxo")?
                .unwrap()
                .utxo()?;

                let slot_count = context
                .globals
                .get_var(&self.ctx.id, "slot_count")?
                .unwrap()
                .number()?;
    
            // Declare the external accept op_funding transaction
            protocol.add_external_transaction(OPERATOR_FUNDING_TX)?;
            protocol.add_transaction_output(OPERATOR_FUNDING_TX, &op_funding_utxo.3.unwrap())?;
    
            // Connect the operator dispute opener transaction with the op_funding transaction
            protocol.add_connection(
                "initial_op_deposit",
                OPERATOR_FUNDING_TX,
                (op_funding_utxo.1 as usize).into(),
                OPERATOR_DISPUTE_OPENER_TX,
                InputSpec::Auto(
                    SighashType::ecdsa_all(),
                    SpendMode::Segwit,
                ),
                None,
                Some(op_funding_utxo.0),
            )?;
    
            for i in 0..slot_count {
                let slot_preimage = rand::thread_rng().next_u32();
                context.globals.set_var(
                    &self.ctx.id,
                    &format!("slot_preimage_{}", i),
                    VariableTypes::String(slot_preimage.to_string()),
                )?;
    
                let slot_preimage_bytes = self.sha256(slot_preimage.to_le_bytes().to_vec());
                let script = scripts::reveal_secret(slot_preimage_bytes, &public_key, SignMode::Single);
                let script_pubkey =
                    ScriptBuf::new_p2wsh(&WScriptHash::from(script.get_script().clone()));
    
                protocol.add_transaction_output(
                    OPERATOR_DISPUTE_OPENER_TX,
                    &OutputType::SegwitScript {
                        value: Amount::from_sat(DISPUTE_OPENER_VALUE),
                        script_pubkey,
                        script,
                    },
                )?;
            }
    
        }

        // Declare the external accept wt_funding transaction
        protocol.add_external_transaction(WATCHTOWER_FUNDING_TX)?;
        protocol.add_transaction_output(WATCHTOWER_FUNDING_TX, &wt_funding_utxo.3.unwrap())?;

        protocol.add_connection(
            "initial_wt_deposit",
            WATCHTOWER_FUNDING_TX,
            (wt_funding_utxo.1 as usize).into(),
            WATCHTOWER_START_ENABLER_TX,
            InputSpec::Auto(
                SighashType::ecdsa_all(),
                SpendMode::Segwit,
            ),
            None,
            Some(wt_funding_utxo.0),
        )?;

        for i in 0..operators_count {
            protocol.add_transaction_output(
                WATCHTOWER_START_ENABLER_TX,
                &OutputType::SegwitScript {
                    value: Amount::from_sat(START_ENABLER_VALUE),
                    script_pubkey,
                    script,
                },
            )?;
        }

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
        // TODO include only the txs that need to be executed based on a decision from the L2
        if name.starts_with(REIMBURSEMENT_KICKOFF_TX) {
            let op_and_slot: Vec<u32> = name
                .strip_prefix(REIMBURSEMENT_KICKOFF_TX)
                .unwrap_or("0_0")
                .split('_')
                .map(|s| s.parse::<u32>().unwrap())
                .collect();
            return Ok(self.reimbursement(op_and_slot[0], op_and_slot[1])?);
        }

        match name {
            OPERATOR_DISPUTE_OPENER_TX => Ok(self.dispute_opener()?),
            WATCHTOWER_START_ENABLER_TX => Ok(self.start_enabler()?),
            _ => Err(BitVMXError::InvalidTransactionName(name.to_string())),
        }
    }

    fn notify_news(
        &self,
        tx_id: Txid,
        vout: Option<u32>,
        tx_status: TransactionStatus,
        context: String,
        program_context: &ProgramContext,
        participant_keys: Vec<&ParticipantKeys>,
    ) -> Result<(), BitVMXError> {
        todo!()
    }
}

impl DisputeCoreProtocol {
    pub fn new(ctx: ProtocolContext) -> Self {
        Self { ctx }
    }

    pub fn dispute_opener(&self) -> Result<Transaction, ProtocolBuilderError> {
        let args = InputArgs::new_taproot_key_args();

        // TODO add the necessary arguments to args

        self.load_protocol()?
            .transaction_to_send(OPERATOR_DISPUTE_OPENER_TX, &[args])
    }

    pub fn start_enabler(&self) -> Result<Transaction, ProtocolBuilderError> {
        let args = InputArgs::new_taproot_key_args();

        // TODO add the necessary arguments to args

        self.load_protocol()?
            .transaction_to_send(WATCHTOWER_START_ENABLER_TX, &[args])
    }

    pub fn reimbursement(&self, op: u32, slot: u32) -> Result<Transaction, ProtocolBuilderError> {
        let args = InputArgs::new_taproot_key_args();

        // TODO add the necessary arguments to args

        self.load_protocol()?
            .transaction_to_send(&self.reimbursement_tx_name(op, slot), &[args])
    }

    pub fn reimbursement_tx_name(&self, op: u32, slot: u32) -> String {
        format!("{}{}_{}", REIMBURSEMENT_KICKOFF_TX, op, slot)
    }

    pub fn sha256(&self, data: Vec<u8>) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(&data);
        hasher.finalize().to_vec()
    }
}
