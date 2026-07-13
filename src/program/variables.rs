use std::rc::Rc;

use crate::{
    errors::BitVMXError,
    ports::store::{KeyValueStoreExt, KeyValueStorePort},
    types::IncomingBitVMXApiMessages,
};
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

    pub fn set_msg(self, id: Uuid, key: &str) -> Result<String, BitVMXError> {
        let msg = IncomingBitVMXApiMessages::SetVar(id, key.to_string(), self).to_string()?;
        Ok(msg)
    }
}
pub struct Globals {
    storage: Rc<dyn KeyValueStorePort>,
}

impl Globals {
    pub fn new(storage: Rc<dyn KeyValueStorePort>) -> Self {
        Self { storage }
    }

    pub fn contains_var(&self, uuid: &Uuid, key: &str) -> Result<bool, BitVMXError> {
        let key = format!("{}:var:{}", uuid, key);
        Ok(self.storage.has_key(&key, None)?)
    }

    pub fn set_var(&self, uuid: &Uuid, key: &str, value: VariableTypes) -> Result<(), BitVMXError> {
        let key = format!("{}:var:{}", uuid, key);
        Ok(self.storage.set(&key, value, None)?)
    }

    pub fn get_var(&self, uuid: &Uuid, key: &str) -> Result<Option<VariableTypes>, BitVMXError> {
        let key = format!("{}:var:{}", uuid, key);
        let value: Option<VariableTypes> = self.storage.get(&key, None)?;
        Ok(value)
    }

    pub fn get_var_or_err(&self, uuid: &Uuid, key: &str) -> Result<VariableTypes, BitVMXError> {
        self.get_var(uuid, key)?
            .ok_or_else(|| BitVMXError::VariableNotFound(*uuid, key.to_string()))
    }

    pub fn copy_var(&self, from: &Uuid, to: &Uuid, key: &str) -> Result<(), BitVMXError> {
        let value = self.get_var_or_err(from, key)?;
        self.set_var(to, key, value)?;
        Ok(())
    }

    pub fn unset_var(&self, uuid: &Uuid, key: &str) -> Result<(), BitVMXError> {
        let key = format!("{}:var:{}", uuid, key);
        Ok(self.storage.remove(&key, None)?)
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
pub struct WitnessVars {
    storage: Rc<dyn KeyValueStorePort>,
}

impl WitnessVars {
    pub fn new(storage: Rc<dyn KeyValueStorePort>) -> Self {
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
        let value = self.storage.get(&key, None)?;
        Ok(value)
    }

    pub fn get_witness_or_err(&self, uuid: &Uuid, key: &str) -> Result<WitnessTypes, BitVMXError> {
        self.get_witness(uuid, key)?
            .ok_or_else(|| BitVMXError::VariableNotFound(*uuid, key.to_string()))
    }

    pub fn copy_witness(&self, from: &Uuid, to: &Uuid, key: &str) -> Result<(), BitVMXError> {
        let value = self.get_witness_or_err(from, key)?;
        self.set_witness(to, key, value)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_adapters::InMemoryStore;
    use std::str::FromStr;

    fn globals() -> Globals {
        Globals::new(Rc::new(InMemoryStore::new()))
    }

    fn assert_round_trip(value: VariableTypes) {
        let globals = globals();
        let id = Uuid::new_v4();
        globals.set_var(&id, "k", value.clone()).unwrap();
        let read = globals.get_var(&id, "k").unwrap().unwrap();
        assert_eq!(format!("{:?}", read), format!("{:?}", value));
    }

    #[test]
    fn variable_types_round_trip() {
        let pubkey = PublicKey::from_str(
            "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
        )
        .unwrap();
        let txid =
            Txid::from_str("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        for value in [
            VariableTypes::Secret(vec![1, 2, 3]),
            VariableTypes::PubKey(pubkey),
            VariableTypes::Utxo((txid, 1, Some(10_000), None)),
            VariableTypes::Number(7),
            VariableTypes::Amount(21_000_000),
            VariableTypes::String("hello".to_string()),
            VariableTypes::VecStr(vec!["a".to_string(), "b".to_string()]),
            VariableTypes::VecNumber(vec![1, 2, 3]),
            VariableTypes::Input(vec![0xde, 0xad]),
            VariableTypes::GcInput(vec![true, false, true]),
            VariableTypes::Uuid(Uuid::new_v4()),
            VariableTypes::Bool(true),
        ] {
            assert_round_trip(value);
        }
    }

    #[test]
    fn typed_accessors_reject_wrong_variant() {
        let value = VariableTypes::Number(1);
        assert!(value.number().is_ok());
        assert!(value.string().is_err());
        assert!(value.secret().is_err());
        assert!(value.utxo().is_err());
    }

    #[test]
    fn contains_and_unset_var() {
        let globals = globals();
        let id = Uuid::new_v4();
        assert!(!globals.contains_var(&id, "k").unwrap());
        globals
            .set_var(&id, "k", VariableTypes::Bool(true))
            .unwrap();
        assert!(globals.contains_var(&id, "k").unwrap());
        globals.unset_var(&id, "k").unwrap();
        assert!(!globals.contains_var(&id, "k").unwrap());
        assert!(globals.get_var(&id, "k").unwrap().is_none());
    }

    #[test]
    fn vars_are_scoped_per_program_id() {
        let globals = globals();
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        globals.set_var(&a, "k", VariableTypes::Number(1)).unwrap();
        assert!(globals.get_var(&b, "k").unwrap().is_none());
        globals.copy_var(&a, &b, "k").unwrap();
        assert_eq!(
            globals.get_var(&b, "k").unwrap().unwrap().number().unwrap(),
            1
        );
    }

    #[test]
    fn get_var_or_err_reports_id_and_key() {
        let globals = globals();
        let id = Uuid::new_v4();
        match globals.get_var_or_err(&id, "missing") {
            Err(BitVMXError::VariableNotFound(err_id, key)) => {
                assert_eq!(err_id, id);
                assert_eq!(key, "missing");
            }
            other => panic!(
                "expected VariableNotFound, got {:?}",
                other.map(|v| v.err())
            ),
        }
    }

    #[test]
    fn witness_round_trip_and_error() {
        let store: Rc<InMemoryStore> = Rc::new(InMemoryStore::new());
        let witness = WitnessVars::new(store);
        let id = Uuid::new_v4();
        witness
            .set_witness(&id, "w", WitnessTypes::Secret(vec![9, 9]))
            .unwrap();
        assert_eq!(
            witness.get_witness(&id, "w").unwrap(),
            Some(WitnessTypes::Secret(vec![9, 9]))
        );
        assert!(witness.get_witness_or_err(&id, "nope").is_err());

        let other = Uuid::new_v4();
        witness.copy_witness(&id, &other, "w").unwrap();
        assert_eq!(
            witness.get_witness(&other, "w").unwrap(),
            Some(WitnessTypes::Secret(vec![9, 9]))
        );
    }
}
