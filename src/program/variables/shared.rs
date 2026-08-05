//! Shared with `rust-bitvmx-client-types` — this file is copied verbatim on release.
//! Node-only code does not belong here; put it in the sibling `mod.rs`.

use crate::{errors::BitVMXError, types::IncomingBitVMXApiMessages};
use bitcoin::{PublicKey, Txid};
use key_manager::{
    lamport::{LamportPublicKey, LamportSignature},
    winternitz::{WinternitzPublicKey, WinternitzSignature},
};
use protocol_builder::types::OutputType;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

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
    LamportPubKey(LamportPublicKey),
    Utxo(PartialUtxo),
    Number(u32),
    Amount(u64),
    String(String),
    VecStr(Vec<String>),
    VecNumber(Vec<u32>),
    Input(Vec<u8>),
    GcInput(Vec<bool>),
    Uuid(Uuid),
    Bool(bool),
    JsonValue(serde_json::Value),
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
    pub fn lamport_pubkey(&self) -> Result<LamportPublicKey, BitVMXError> {
        match self {
            VariableTypes::LamportPubKey(key) => Ok(key.clone()),
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
    pub fn amount(&self) -> Result<u64, BitVMXError> {
        match self {
            VariableTypes::Amount(num) => Ok(*num),
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
    pub fn gc_input(&self) -> Result<Vec<bool>, BitVMXError> {
        match self {
            VariableTypes::GcInput(input) => Ok(input.clone()),
            _ => Err(BitVMXError::InvalidVariableType(self.err())),
        }
    }
    pub fn uuid(&self) -> Result<Uuid, BitVMXError> {
        match self {
            VariableTypes::Uuid(id) => Ok(id.clone()),
            _ => Err(BitVMXError::InvalidVariableType(self.err())),
        }
    }

    pub fn bool(&self) -> Result<bool, BitVMXError> {
        match self {
            VariableTypes::Bool(flag) => Ok(flag.clone()),
            _ => Err(BitVMXError::InvalidVariableType(self.err())),
        }
    }
    pub fn json_value(&self) -> Result<serde_json::Value, BitVMXError> {
        match self {
            VariableTypes::JsonValue(value) => Ok(value.clone()),
            _ => Err(BitVMXError::InvalidVariableType(self.err())),
        }
    }

    pub fn set_msg(self, id: Uuid, key: &str) -> Result<String, BitVMXError> {
        let msg = IncomingBitVMXApiMessages::SetVar(id, key.to_string(), self).to_string()?;
        Ok(msg)
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub enum WitnessTypes {
    Secret(Vec<u8>),
    Winternitz(WinternitzSignature),
    Lamport(LamportSignature),
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

    pub fn lamport(&self) -> Result<LamportSignature, BitVMXError> {
        match self {
            WitnessTypes::Lamport(lamport) => Ok(lamport.clone()),
            _ => Err(BitVMXError::InvalidWitnessType),
        }
    }

    pub fn set_msg(self, id: Uuid, key: &str) -> Result<String, BitVMXError> {
        let msg = IncomingBitVMXApiMessages::SetWitness(id, key.to_string(), self).to_string()?;
        Ok(msg)
    }
}
