use bitcoin::{Transaction, Txid};
use bitcoin_coordinator::TransactionStatus;
use enum_dispatch::enum_dispatch;
use protocol_builder::{builder::Protocol, errors::ProtocolBuilderError};
use serde::{Deserialize, Serialize};
use std::rc::Rc;
use storage_backend::storage::Storage;
use uuid::Uuid;

use crate::errors::BitVMXError;
use crate::keychain::KeyChain;

use crate::program::dispute::DisputeResolutionProtocol;
use crate::types::ProgramContext;

use super::lock::LockProtocol;
use super::program::ProtocolParameters;

#[enum_dispatch]
pub trait ProtocolHandler {
    fn context(&self) -> &ProtocolContext;
    fn context_mut(&mut self) -> &mut ProtocolContext;

    fn set_storage(&mut self, storage: Rc<Storage>) {
        self.context_mut().storage = Some(storage);
    }

    fn sign(&mut self, key_chain: &KeyChain) -> Result<(), ProtocolBuilderError> {
        let mut protocol = self.load_protocol()?;
        protocol.sign(true, &key_chain.key_manager)?;
        self.save_protocol(protocol)?;
        Ok(())
    }

    fn get_hashed_message(
        &mut self,
        transaction_name: &str,
        input_index: u32,
        message_index: u32,
    ) -> Result<String, BitVMXError> {
        let ret = self.load_protocol()?.get_hashed_message(
            transaction_name,
            input_index,
            message_index,
        )?;
        if ret.is_none() {
            return Err(BitVMXError::InvalidTransactionName(
                transaction_name.to_string(),
            ));
        }
        Ok(format!("{}", ret.unwrap()))
    }

    fn get_transaction_by_id(&self, txid: &Txid) -> Result<Transaction, ProtocolBuilderError> {
        self.load_protocol()?.transaction_by_id(txid).cloned()
    }

    fn get_transaction_ids(&self) -> Result<Vec<Txid>, ProtocolBuilderError> {
        Ok(self.load_protocol()?.get_transaction_ids())
    }

    fn get_transaction_name_by_id(&self, txid: Txid) -> Result<String, ProtocolBuilderError> {
        self.load_protocol()?.transaction_name_by_id(txid).cloned()
    }

    fn load_protocol(&self) -> Result<Protocol, ProtocolBuilderError> {
        match Protocol::load(
            &self.context().protocol_name,
            self.context().storage.clone().unwrap(),
        )? {
            Some(protocol) => Ok(protocol),
            None => Err(ProtocolBuilderError::MissingProtocol),
        }
    }

    fn save_protocol(&self, protocol: Protocol) -> Result<(), ProtocolBuilderError> {
        protocol.save(self.context().storage.clone().unwrap())?;
        Ok(())
    }

    fn get_transaction_name(
        &self,
        name: &str,
        context: &ProgramContext,
    ) -> Result<Transaction, BitVMXError>;

    fn notify_news(
        &self,
        tx_id: Txid,
        tx_status: TransactionStatus,
        context: String,
        program_context: &ProgramContext,
        parameters: &ProtocolParameters,
    ) -> Result<(), BitVMXError>;
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ProtocolContext {
    pub protocol_name: String,
    pub id: Uuid,
    #[serde(skip)]
    pub storage: Option<Rc<Storage>>,
}

impl ProtocolContext {
    pub fn new(id: Uuid, name: String, storage: Rc<Storage>) -> Self {
        Self {
            id,
            protocol_name: name,
            storage: Some(storage),
        }
    }
}

#[enum_dispatch(ProtocolHandler)]
#[derive(Clone, Serialize, Deserialize)]
pub enum ProtocolType {
    DisputeResolutionProtocol,
    LockProtocol,
}

impl ProtocolType {
    pub fn as_drp(&self) -> Option<&DisputeResolutionProtocol> {
        match self {
            ProtocolType::DisputeResolutionProtocol(drp) => Some(drp),
            _ => None,
        }
    }
    pub fn as_drp_mut(&mut self) -> Option<&mut DisputeResolutionProtocol> {
        match self {
            ProtocolType::DisputeResolutionProtocol(drp) => Some(drp),
            _ => None,
        }
    }

    pub fn as_slot(&self) -> Option<&LockProtocol> {
        match self {
            ProtocolType::LockProtocol(slot) => Some(slot),
            _ => None,
        }
    }
    pub fn as_slot_mut(&mut self) -> Option<&mut LockProtocol> {
        match self {
            ProtocolType::LockProtocol(slot) => Some(slot),
            _ => None,
        }
    }
}
