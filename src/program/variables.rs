use std::rc::Rc;

use bitcoin::{PublicKey, Txid};
use key_manager::winternitz::WinternitzSignature;
use serde::{Deserialize, Serialize};
use storage_backend::storage::{KeyValueStore, Storage};
use uuid::Uuid;

use crate::{errors::BitVMXError, types::IncomingBitVMXApiMessages};

/*
- winternitz
- lamport
- secret
- key (schnor pub)
- utxo [ txid, vout, optional(amount)]*/

pub type PartialUtxo = (Txid, u32, Option<u64>);

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub enum VariableTypes {
    Secret(Vec<u8>),
    PubKey(PublicKey),
    Utxo(PartialUtxo),
    Number(u32),
    String(String),
    Input(Vec<u8>),
}

impl VariableTypes {
    pub fn secret(&self) -> Result<Vec<u8>, BitVMXError> {
        match self {
            VariableTypes::Secret(secret) => Ok(secret.clone()),
            _ => Err(BitVMXError::InvalidVariableType),
        }
    }
    pub fn pubkey(&self) -> Result<PublicKey, BitVMXError> {
        match self {
            VariableTypes::PubKey(key) => Ok(key.clone()),
            _ => Err(BitVMXError::InvalidVariableType),
        }
    }
    pub fn utxo(&self) -> Result<PartialUtxo, BitVMXError> {
        match self {
            VariableTypes::Utxo(utxo) => Ok(utxo.clone()),
            _ => Err(BitVMXError::InvalidVariableType),
        }
    }
    pub fn number(&self) -> Result<u32, BitVMXError> {
        match self {
            VariableTypes::Number(num) => Ok(*num),
            _ => Err(BitVMXError::InvalidVariableType),
        }
    }
    pub fn string(&self) -> Result<String, BitVMXError> {
        match self {
            VariableTypes::String(string) => Ok(string.clone()),
            _ => Err(BitVMXError::InvalidVariableType),
        }
    }
    pub fn input(&self) -> Result<Vec<u8>, BitVMXError> {
        match self {
            VariableTypes::Input(input) => Ok(input.clone()),
            _ => Err(BitVMXError::InvalidVariableType),
        }
    }

    pub fn set_msg(self, id: Uuid, key: &str) -> Result<String, BitVMXError> {
        let msg = IncomingBitVMXApiMessages::SetVar(id, key.to_string(), self).to_string()?;
        Ok(msg)
    }
}
pub struct Globals {
    storage: Rc<Storage>,
}

impl Globals {
    pub fn new(storage: Rc<Storage>) -> Self {
        Self { storage }
    }

    pub fn set_var(&self, uuid: &Uuid, key: &str, value: VariableTypes) -> Result<(), BitVMXError> {
        let key = format!("{}:{}", uuid, key);
        Ok(self.storage.set(&key, value, None)?)
    }

    pub fn get_var(&self, uuid: &Uuid, key: &str) -> Result<VariableTypes, BitVMXError> {
        let key = format!("{}:{}", uuid, key);
        let value: Option<VariableTypes> = self.storage.get(&key)?;
        // this halts bitvmx if the var that the client is looking for is not found
        // TODO shouldn't this return an option instead?
        if value.is_none() {
            return Err(BitVMXError::VariableNotFound(*uuid, key));
        }
        Ok(value.unwrap())
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub enum WitnessTypes {
    Secret(Vec<u8>),
    Winternitz(Vec<WinternitzSignature>),
}

impl WitnessTypes {
    pub fn secret(&self) -> Result<Vec<u8>, BitVMXError> {
        match self {
            WitnessTypes::Secret(secret) => Ok(secret.clone()),
            _ => Err(BitVMXError::InvalidWitnessType),
        }
    }

    pub fn winternitz(&self) -> Result<Vec<WinternitzSignature>, BitVMXError> {
        match self {
            WitnessTypes::Winternitz(winternitz) => Ok(winternitz.clone()),
            _ => Err(BitVMXError::InvalidWitnessType),
        }
    }
}
pub struct WitnessVars {
    storage: Rc<Storage>,
}

impl WitnessVars {
    pub fn new(storage: Rc<Storage>) -> Self {
        Self { storage }
    }

    pub fn set_witness(
        &self,
        uuid: &Uuid,
        key: &str,
        value: WitnessTypes,
    ) -> Result<(), BitVMXError> {
        let key = format!("{}:{}", uuid, key);
        Ok(self.storage.set(&key, value, None)?)
    }

    pub fn get_witness(&self, uuid: &Uuid, key: &str) -> Result<Option<WitnessTypes>, BitVMXError> {
        let key = format!("{}:{}", uuid, key);
        let value = self.storage.get(&key)?;
        Ok(value)
    }
}
