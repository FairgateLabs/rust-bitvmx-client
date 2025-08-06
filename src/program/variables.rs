use std::rc::Rc;

use bitcoin::{PublicKey, Txid};
use emulator::executor::utils::FailConfiguration;
use key_manager::winternitz::{WinternitzPublicKey, WinternitzSignature};
use protocol_builder::types::OutputType;
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

pub type PartialUtxo = (Txid, u32, Option<u64>, Option<OutputType>);

#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum VariableTypes {
    Secret(Vec<u8>),
    PubKey(PublicKey),
    WinternitzPubKey(WinternitzPublicKey),
    Utxo(PartialUtxo),
    Number(u32),
    String(String),
    VecStr(Vec<String>),
    VecNumber(Vec<u32>),
    Input(Vec<u8>),
    Uuid(Uuid),
    FailConfiguration(
        Option<FailConfiguration>,
        Option<FailConfiguration>,
        emulator::decision::challenge::ForceChallenge,
        emulator::decision::challenge::ForceCondition,
    ),
}

impl VariableTypes {
    pub fn err(&self) -> String {
        format!("{:?}", self)
    }

    pub fn secret(&self) -> Result<Vec<u8>, BitVMXError> {
        match self {
            VariableTypes::Secret(secret) => Ok(secret.clone()),
            _ => Err(BitVMXError::InvalidVariableType(self.err())),
        }
    }
    pub fn pubkey(&self) -> Result<PublicKey, BitVMXError> {
        match self {
            VariableTypes::PubKey(key) => Ok(key.clone()),
            _ => Err(BitVMXError::InvalidVariableType(self.err())),
        }
    }
    pub fn wots_pubkey(&self) -> Result<WinternitzPublicKey, BitVMXError> {
        match self {
            VariableTypes::WinternitzPubKey(key) => Ok(key.clone()),
            _ => Err(BitVMXError::InvalidVariableType(self.err())),
        }
    }
    pub fn utxo(&self) -> Result<PartialUtxo, BitVMXError> {
        match self {
            VariableTypes::Utxo(utxo) => Ok(utxo.clone()),
            _ => Err(BitVMXError::InvalidVariableType(self.err())),
        }
    }
    pub fn number(&self) -> Result<u32, BitVMXError> {
        match self {
            VariableTypes::Number(num) => Ok(*num),
            _ => Err(BitVMXError::InvalidVariableType(self.err())),
        }
    }
    pub fn string(&self) -> Result<String, BitVMXError> {
        match self {
            VariableTypes::String(string) => Ok(string.clone()),
            _ => Err(BitVMXError::InvalidVariableType(self.err())),
        }
    }
    pub fn vec_string(&self) -> Result<Vec<String>, BitVMXError> {
        match self {
            VariableTypes::VecStr(v) => Ok(v.clone()),
            _ => Err(BitVMXError::InvalidVariableType(self.err())),
        }
    }
    pub fn vec_number(&self) -> Result<Vec<u32>, BitVMXError> {
        match self {
            VariableTypes::VecNumber(v) => Ok(v.clone()),
            _ => Err(BitVMXError::InvalidVariableType(self.err())),
        }
    }
    pub fn input(&self) -> Result<Vec<u8>, BitVMXError> {
        match self {
            VariableTypes::Input(input) => Ok(input.clone()),
            _ => Err(BitVMXError::InvalidVariableType(self.err())),
        }
    }
    pub fn uuid(&self) -> Result<Uuid, BitVMXError> {
        match self {
            VariableTypes::Uuid(id) => Ok(id.clone()),
            _ => Err(BitVMXError::InvalidVariableType(self.err())),
        }
    }

    pub fn fail_configuration(
        &self,
    ) -> Result<
        (
            Option<FailConfiguration>,
            Option<FailConfiguration>,
            emulator::decision::challenge::ForceChallenge,
            emulator::decision::challenge::ForceCondition,
        ),
        BitVMXError,
    > {
        match self {
            VariableTypes::FailConfiguration(fc_prover, fc_verifier, force, condition) => Ok((
                fc_prover.clone(),
                fc_verifier.clone(),
                force.clone(),
                condition.clone(),
            )),
            _ => Err(BitVMXError::InvalidVariableType(self.err())),
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
        let key = format!("{}:var:{}", uuid, key);
        Ok(self.storage.set(&key, value, None)?)
    }

    pub fn get_var(&self, uuid: &Uuid, key: &str) -> Result<Option<VariableTypes>, BitVMXError> {
        let key = format!("{}:var:{}", uuid, key);
        let value: Option<VariableTypes> = self.storage.get(&key)?;
        Ok(value)
    }

    pub fn copy_var(&self, from: &Uuid, to: &Uuid, key: &str) -> Result<(), BitVMXError> {
        let value = self.get_var(from, key)?;
        if let Some(value) = value {
            self.set_var(to, key, value)?;
        } else {
            return Err(BitVMXError::VariableNotFound(from.clone(), key.to_string()));
        }
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub enum WitnessTypes {
    Secret(Vec<u8>),
    Winternitz(WinternitzSignature),
}

impl WitnessTypes {
    pub fn secret(&self) -> Result<Vec<u8>, BitVMXError> {
        match self {
            WitnessTypes::Secret(secret) => Ok(secret.clone()),
            _ => Err(BitVMXError::InvalidWitnessType),
        }
    }

    pub fn winternitz(&self) -> Result<WinternitzSignature, BitVMXError> {
        match self {
            WitnessTypes::Winternitz(winternitz) => Ok(winternitz.clone()),
            _ => Err(BitVMXError::InvalidWitnessType),
        }
    }

    pub fn set_msg(self, id: Uuid, key: &str) -> Result<String, BitVMXError> {
        let msg = IncomingBitVMXApiMessages::SetWitness(id, key.to_string(), self).to_string()?;
        Ok(msg)
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
        let key = format!("{}:witness:{}", uuid, key);
        Ok(self.storage.set(&key, value, None)?)
    }

    pub fn get_witness(&self, uuid: &Uuid, key: &str) -> Result<Option<WitnessTypes>, BitVMXError> {
        let key = format!("{}:witness:{}", uuid, key);
        let value = self.storage.get(&key)?;
        Ok(value)
    }

    pub fn copy_witness(&self, from: &Uuid, to: &Uuid, key: &str) -> Result<(), BitVMXError> {
        let value = self.get_witness(from, key)?;
        if let Some(value) = value {
            self.set_witness(to, key, value)?;
        } else {
            return Err(BitVMXError::VariableNotFound(from.clone(), key.to_string()));
        }
        Ok(())
    }
}
