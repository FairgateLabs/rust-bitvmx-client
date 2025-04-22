use std::rc::Rc;

use serde::{Deserialize, Serialize};
use storage_backend::storage::{KeyValueStore, Storage};
use uuid::Uuid;

use crate::errors::BitVMXError;

/*
- winternitz
- lamport
- secret
- key (schnor pub)
- utxo [ txid, vout, optional(amount)]*/

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub enum VariableTypes {
    Secret(Vec<u8>),
}

impl VariableTypes {
    pub fn secret(&self) -> Result<Vec<u8>, BitVMXError> {
        match self {
            VariableTypes::Secret(secret) => Ok(secret.clone()),
        }
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

    pub fn get_var(&self, uuid: &Uuid, key: &str) -> Result<Option<VariableTypes>, BitVMXError> {
        let key = format!("{}:{}", uuid, key);
        let value = self.storage.get(&key)?;
        Ok(value)
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub enum WitnessTypes {
    Secret(Vec<u8>),
}

impl WitnessTypes {
    pub fn secret(&self) -> Result<Vec<u8>, BitVMXError> {
        match self {
            WitnessTypes::Secret(secret) => Ok(secret.clone()),
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
