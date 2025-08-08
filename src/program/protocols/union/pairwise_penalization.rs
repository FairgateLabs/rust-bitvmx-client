use std::collections::HashMap;

use bitcoin::{PublicKey, Transaction, Txid};
use bitcoin_coordinator::TransactionStatus;
use protocol_builder::types::output::SpeedupData;
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::{
    errors::BitVMXError,
    program::{
        participant::ParticipantKeys,
        protocols::protocol_handler::{ProtocolContext, ProtocolHandler},
    },
    types::ProgramContext,
};

#[derive(Clone, Serialize, Deserialize)]
pub struct PairwisePenalizationProtocol {
    ctx: ProtocolContext,
}

impl ProtocolHandler for PairwisePenalizationProtocol {
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
        _program_context: &mut ProgramContext,
    ) -> Result<ParticipantKeys, BitVMXError> {
        todo!()
    }

    fn build(
        &self,
        _keys: Vec<ParticipantKeys>,
        _computed_aggregated: HashMap<String, PublicKey>,
        _context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        todo!()
    }

    fn get_transaction_by_name(
        &self,
        _name: &str,
        _context: &ProgramContext,
    ) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
        todo!()
    }

    fn notify_news(
        &self,
        _tx_id: Txid,
        vout: Option<u32>,
        tx_status: TransactionStatus,
        _context: String,
        _program_context: &ProgramContext,
        _participant_keys: Vec<&ParticipantKeys>,
    ) -> Result<bool, BitVMXError> {
        //filter confirmations
        if tx_status.confirmations != 1 {
            return Ok(false);
        }
        // decide if vouts will be informed
        let inform_l2 = vout.is_none();

        Ok(inform_l2)
    }

    fn setup_complete(&self, _program_context: &ProgramContext) -> Result<(), BitVMXError> {
        // This is called after the protocol is built and ready to be used
        info!(
            id = self.ctx.my_idx,
            "PairwisePenalizationProtocol setup complete for program {}", self.ctx.id
        );
        Ok(())
    }
}

impl PairwisePenalizationProtocol {
    pub fn new(ctx: ProtocolContext) -> Self {
        Self { ctx }
    }
}
