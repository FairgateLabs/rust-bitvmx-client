use std::collections::HashMap;

use bitcoin::{PublicKey, Transaction, Txid};
use bitcoin_coordinator::TransactionStatus;
use serde::{Deserialize, Serialize};

use crate::{errors::BitVMXError, keychain::KeyChain, types::ProgramContext};

use super::{
    participant::ParticipantKeys,
    protocol_handler::{ProtocolContext, ProtocolHandler},
};

#[derive(Clone, Serialize, Deserialize)]
pub struct SlotProtocol {
    ctx: ProtocolContext,
}

impl ProtocolHandler for SlotProtocol {
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
        _my_idx: usize,
        _key_chain: &mut KeyChain,
    ) -> Result<ParticipantKeys, BitVMXError> {
        Err(BitVMXError::NotImplemented("generate_keys".to_string()))
    }

    fn get_transaction_name(
        &self,
        name: &str,
        _context: &ProgramContext,
    ) -> Result<Transaction, BitVMXError> {
        match name {
            _ => Err(BitVMXError::InvalidTransactionName(name.to_string())),
        }
    }
    fn notify_news(
        &self,
        _tx_id: Txid,
        _tx_status: TransactionStatus,
        _context: String,
        _program_context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        Ok(())
    }

    fn build(
        &self,
        _keys: Vec<ParticipantKeys>,
        _computed_aggregated: HashMap<String, PublicKey>,
        _context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        Ok(())
    }
}

pub const SETUP_TX: &str = "setup_tx";

impl SlotProtocol {
    pub fn new(context: ProtocolContext) -> Self {
        Self { ctx: context }
    }
}
