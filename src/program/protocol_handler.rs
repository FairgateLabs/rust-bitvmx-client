use bitcoin::{Transaction, Txid};
use enum_dispatch::enum_dispatch;
use protocol_builder::{builder::Protocol, errors::ProtocolBuilderError};
use serde::{Deserialize, Serialize};
use std::rc::Rc;
use storage_backend::storage::Storage;

use crate::errors::BitVMXError;
use crate::keychain::KeyChain;

use crate::program::dispute::DisputeResolutionProtocol;
use crate::types::ProgramContext;

use super::slot::SlotProtocol;

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
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ProtocolContext {
    pub protocol_name: String,
    #[serde(skip)]
    pub storage: Option<Rc<Storage>>,
}

impl ProtocolContext {
    pub fn new(name: String, storage: Rc<Storage>) -> Self {
        Self {
            protocol_name: name,
            storage: Some(storage),
        }
    }
}

#[enum_dispatch(ProtocolHandler)]
#[derive(Clone, Serialize, Deserialize)]
pub enum ProtocolType {
    DisputeResolutionProtocol,
    SlotProtocol,
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

    pub fn as_slot(&self) -> Option<&SlotProtocol> {
        match self {
            ProtocolType::SlotProtocol(slot) => Some(slot),
            _ => None,
        }
    }
    pub fn as_slot_mut(&mut self) -> Option<&mut SlotProtocol> {
        match self {
            ProtocolType::SlotProtocol(slot) => Some(slot),
            _ => None,
        }
    }
}
