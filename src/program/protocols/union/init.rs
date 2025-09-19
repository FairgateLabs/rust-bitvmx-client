use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::program::protocols::protocol_handler::{ProtocolContext, ProtocolHandler};
use crate::program::participant::ParticipantKeys;
use crate::types::ProgramContext;
use crate::errors::BitVMXError;
use bitcoin::{PublicKey, Transaction, Txid};
use bitcoin_coordinator::TransactionStatus;
use protocol_builder::types::output::SpeedupData;

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

    fn get_pregenerated_aggregated_keys(&self, context: &ProgramContext) -> Result<Vec<(String, PublicKey)>, BitVMXError> {
        Ok(vec![])
    }
    
    fn generate_keys(&self, program_context: &mut ProgramContext) -> Result<ParticipantKeys, BitVMXError> {
        todo!()
    }

    fn build(&self, keys: Vec<ParticipantKeys>, computed_aggregated: HashMap<String, PublicKey>, context: &ProgramContext) -> Result<(), BitVMXError> {
        Ok(())
    }

    fn get_transaction_by_name(&self, transaction_name: &str, context: &ProgramContext) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
        todo!()
    }
    
    fn notify_news(&self, tx_id: Txid, vout: Option<u32>, tx_status: TransactionStatus, context: String, program_context: &ProgramContext, participant_keys: Vec<&ParticipantKeys>) -> Result<(), BitVMXError> {
        Ok(())
    }

    fn setup_complete(&self, context: &ProgramContext) -> Result<(), BitVMXError> {
        Ok(())
    }
}


impl InitProtocol {
    pub fn new(ctx: ProtocolContext) -> Self {
        Self { ctx }
    }
}
