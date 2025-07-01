use std::collections::HashMap;

use bitcoin::{PublicKey, Transaction, Txid};
use bitcoin_coordinator::TransactionStatus;
use protocol_builder::types::output::SpeedupData;
use serde::{Deserialize, Serialize};

use crate::{
    errors::BitVMXError,
    program::{
        participant::ParticipantKeys,
        protocols::protocol_handler::{ProtocolContext, ProtocolHandler},
    },
    types::ProgramContext,
};

#[derive(Clone, Serialize, Deserialize)]
pub struct MultipartyPenalizationProtocol {
    ctx: ProtocolContext,
}

impl ProtocolHandler for MultipartyPenalizationProtocol {
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
        name: &str,
        context: &ProgramContext,
    ) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
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

impl MultipartyPenalizationProtocol {
    pub fn new(ctx: ProtocolContext) -> Self {
        Self { ctx }
    }
}
