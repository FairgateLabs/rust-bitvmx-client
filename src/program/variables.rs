use std::rc::Rc;

use crate::{errors::BitVMXError, types::IncomingBitVMXApiMessages};
use bitcoin::{PublicKey, Txid};
use key_manager::{
    lamport::{LamportPublicKey, LamportSignature},
    winternitz::{WinternitzPublicKey, WinternitzSignature},
};
use protocol_builder::types::OutputType;
use serde::{Deserialize, Serialize};
use storage_backend::storage::{KeyValueStore, Storage};
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
    storage: Rc<Storage>,
}

impl Globals {
    pub fn new(storage: Rc<Storage>) -> Self {
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
    use crate::test_utils::TestStorageDir;
    use key_manager::{
        lamport::LamportType,
        winternitz::{WinternitzSignature, WinternitzType},
    };
    use std::str::FromStr;

    fn test_storage_dir() -> TestStorageDir {
        TestStorageDir::new("bitvmx-variables-test")
    }

    fn sample_pubkey() -> PublicKey {
        PublicKey::from_str(
            "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
        )
        .unwrap()
    }

    fn sample_txid() -> Txid {
        Txid::from_str("e2769b09e784f32f62ef849763d4f45b98e07ba658647343b915ff832b110436")
            .unwrap()
    }

    fn sample_wots_pubkey() -> WinternitzPublicKey {
        WinternitzPublicKey::from_bytes(&[7u8; 20], WinternitzType::HASH160).unwrap()
    }

    fn sample_wots_signature() -> WinternitzSignature {
        WinternitzSignature::from_bytes(&[9u8; 20], 1, WinternitzType::HASH160).unwrap()
    }

    fn sample_lamport_pubkey() -> LamportPublicKey {
        LamportPublicKey::new(LamportType::SHA256, None)
    }

    fn sample_lamport_signature() -> LamportSignature {
        LamportSignature::new(8, LamportType::SHA256)
    }

    #[test]
    fn test_variable_accessors_return_inner_values() {
        assert_eq!(
            VariableTypes::Secret(vec![1, 2, 3]).secret().unwrap(),
            vec![1, 2, 3]
        );
        assert_eq!(
            VariableTypes::PubKey(sample_pubkey()).pubkey().unwrap(),
            sample_pubkey()
        );
        assert_eq!(
            VariableTypes::WinternitzPubKey(sample_wots_pubkey())
                .wots_pubkey()
                .unwrap()
                .to_bytes(),
            sample_wots_pubkey().to_bytes()
        );
        assert_eq!(
            VariableTypes::LamportPubKey(sample_lamport_pubkey())
                .lamport_pubkey()
                .unwrap()
                .to_bytes(),
            sample_lamport_pubkey().to_bytes()
        );

        let utxo = VariableTypes::Utxo((sample_txid(), 1, Some(42), None))
            .utxo()
            .unwrap();
        assert_eq!(utxo.0, sample_txid());
        assert_eq!(utxo.1, 1);
        assert_eq!(utxo.2, Some(42));
        assert!(utxo.3.is_none());

        assert_eq!(VariableTypes::Number(7).number().unwrap(), 7);
        assert_eq!(VariableTypes::Amount(1_000).amount().unwrap(), 1_000);
        assert_eq!(
            VariableTypes::String("hello".to_string()).string().unwrap(),
            "hello"
        );
        assert_eq!(
            VariableTypes::VecStr(vec!["a".to_string(), "b".to_string()])
                .vec_string()
                .unwrap(),
            vec!["a".to_string(), "b".to_string()]
        );
        assert_eq!(
            VariableTypes::VecNumber(vec![1, 2, 3]).vec_number().unwrap(),
            vec![1, 2, 3]
        );
        assert_eq!(
            VariableTypes::Input(vec![4, 5, 6]).input().unwrap(),
            vec![4, 5, 6]
        );
        assert_eq!(
            VariableTypes::GcInput(vec![true, false]).gc_input().unwrap(),
            vec![true, false]
        );

        let id = Uuid::new_v4();
        assert_eq!(VariableTypes::Uuid(id).uuid().unwrap(), id);
        assert_eq!(VariableTypes::Bool(true).bool().unwrap(), true);
    }

    #[test]
    fn test_variable_accessors_reject_wrong_variant() {
        let wrong = VariableTypes::Number(1);
        assert!(matches!(
            wrong.secret(),
            Err(BitVMXError::InvalidVariableType(_))
        ));
        assert!(matches!(
            wrong.pubkey(),
            Err(BitVMXError::InvalidVariableType(_))
        ));
        assert!(matches!(
            wrong.wots_pubkey(),
            Err(BitVMXError::InvalidVariableType(_))
        ));
        assert!(matches!(
            wrong.lamport_pubkey(),
            Err(BitVMXError::InvalidVariableType(_))
        ));
        assert!(matches!(
            wrong.utxo(),
            Err(BitVMXError::InvalidVariableType(_))
        ));
        assert!(matches!(
            wrong.amount(),
            Err(BitVMXError::InvalidVariableType(_))
        ));
        assert!(matches!(
            wrong.string(),
            Err(BitVMXError::InvalidVariableType(_))
        ));
        assert!(matches!(
            wrong.vec_string(),
            Err(BitVMXError::InvalidVariableType(_))
        ));
        assert!(matches!(
            wrong.vec_number(),
            Err(BitVMXError::InvalidVariableType(_))
        ));
        assert!(matches!(
            wrong.input(),
            Err(BitVMXError::InvalidVariableType(_))
        ));
        assert!(matches!(
            wrong.gc_input(),
            Err(BitVMXError::InvalidVariableType(_))
        ));
        assert!(matches!(
            wrong.uuid(),
            Err(BitVMXError::InvalidVariableType(_))
        ));
        assert!(matches!(
            wrong.bool(),
            Err(BitVMXError::InvalidVariableType(_))
        ));
        assert!(matches!(
            VariableTypes::Bool(true).number(),
            Err(BitVMXError::InvalidVariableType(_))
        ));
    }

    #[test]
    fn test_variable_err_describes_variant() {
        assert_eq!(VariableTypes::Number(5).err(), "Number(5)");
        assert_eq!(VariableTypes::Bool(true).err(), "Bool(true)");
    }

    #[test]
    fn test_variable_set_msg_round_trips() {
        let id = Uuid::new_v4();
        let msg = VariableTypes::Number(9).set_msg(id, "my_key").unwrap();

        let parsed: IncomingBitVMXApiMessages = serde_json::from_str(&msg).unwrap();
        match parsed {
            IncomingBitVMXApiMessages::SetVar(parsed_id, key, value) => {
                assert_eq!(parsed_id, id);
                assert_eq!(key, "my_key");
                assert_eq!(value.number().unwrap(), 9);
            }
            other => panic!("expected SetVar, got {:?}", other),
        }
    }

    #[test]
    fn test_globals_set_get_contains_unset() {
        let dir = test_storage_dir();
        let globals = Globals::new(dir.storage());
        let id = Uuid::new_v4();

        assert!(!globals.contains_var(&id, "num").unwrap());
        assert!(globals.get_var(&id, "num").unwrap().is_none());

        globals.set_var(&id, "num", VariableTypes::Number(3)).unwrap();
        assert!(globals.contains_var(&id, "num").unwrap());
        assert_eq!(
            globals.get_var(&id, "num").unwrap().unwrap().number().unwrap(),
            3
        );

        // Overwrite with a different variant
        globals
            .set_var(&id, "num", VariableTypes::String("now a string".to_string()))
            .unwrap();
        assert_eq!(
            globals.get_var(&id, "num").unwrap().unwrap().string().unwrap(),
            "now a string"
        );

        globals.unset_var(&id, "num").unwrap();
        assert!(!globals.contains_var(&id, "num").unwrap());
        assert!(globals.get_var(&id, "num").unwrap().is_none());
    }

    #[test]
    fn test_globals_vars_are_scoped_by_uuid() {
        let dir = test_storage_dir();
        let globals = Globals::new(dir.storage());
        let id_a = Uuid::new_v4();
        let id_b = Uuid::new_v4();

        globals.set_var(&id_a, "key", VariableTypes::Number(1)).unwrap();
        assert!(!globals.contains_var(&id_b, "key").unwrap());
    }

    #[test]
    fn test_globals_get_var_or_err() {
        let dir = test_storage_dir();
        let globals = Globals::new(dir.storage());
        let id = Uuid::new_v4();

        let result = globals.get_var_or_err(&id, "missing");
        match result {
            Err(BitVMXError::VariableNotFound(err_id, err_key)) => {
                assert_eq!(err_id, id);
                assert_eq!(err_key, "missing");
            }
            other => panic!("expected VariableNotFound, got {:?}", other),
        }

        globals.set_var(&id, "present", VariableTypes::Bool(true)).unwrap();
        assert!(globals
            .get_var_or_err(&id, "present")
            .unwrap()
            .bool()
            .unwrap());
    }

    #[test]
    fn test_globals_copy_var() {
        let dir = test_storage_dir();
        let globals = Globals::new(dir.storage());
        let from = Uuid::new_v4();
        let to = Uuid::new_v4();

        globals
            .set_var(&from, "shared", VariableTypes::Amount(21))
            .unwrap();
        globals.copy_var(&from, &to, "shared").unwrap();
        assert_eq!(
            globals
                .get_var(&to, "shared")
                .unwrap()
                .unwrap()
                .amount()
                .unwrap(),
            21
        );

        assert!(matches!(
            globals.copy_var(&from, &to, "missing"),
            Err(BitVMXError::VariableNotFound(_, _))
        ));
    }

    #[test]
    fn test_witness_accessors_return_inner_values() {
        assert_eq!(
            WitnessTypes::Secret(vec![1, 2]).secret().unwrap(),
            vec![1, 2]
        );
        assert_eq!(
            WitnessTypes::Winternitz(sample_wots_signature())
                .winternitz()
                .unwrap(),
            sample_wots_signature()
        );
        assert_eq!(
            WitnessTypes::Lamport(sample_lamport_signature())
                .lamport()
                .unwrap(),
            sample_lamport_signature()
        );
    }

    #[test]
    fn test_witness_accessors_reject_wrong_variant() {
        let wrong = WitnessTypes::Secret(vec![]);
        assert!(matches!(
            wrong.winternitz(),
            Err(BitVMXError::InvalidWitnessType)
        ));
        assert!(matches!(
            wrong.lamport(),
            Err(BitVMXError::InvalidWitnessType)
        ));
        assert!(matches!(
            WitnessTypes::Lamport(sample_lamport_signature()).secret(),
            Err(BitVMXError::InvalidWitnessType)
        ));
    }

    #[test]
    fn test_witness_set_msg_round_trips() {
        let id = Uuid::new_v4();
        let msg = WitnessTypes::Secret(vec![7, 8])
            .set_msg(id, "wit_key")
            .unwrap();

        let parsed: IncomingBitVMXApiMessages = serde_json::from_str(&msg).unwrap();
        match parsed {
            IncomingBitVMXApiMessages::SetWitness(parsed_id, key, value) => {
                assert_eq!(parsed_id, id);
                assert_eq!(key, "wit_key");
                assert_eq!(value, WitnessTypes::Secret(vec![7, 8]));
            }
            other => panic!("expected SetWitness, got {:?}", other),
        }
    }

    #[test]
    fn test_witness_set_get() {
        let dir = test_storage_dir();
        let witnesses = WitnessVars::new(dir.storage());
        let id = Uuid::new_v4();

        assert!(witnesses.get_witness(&id, "sig").unwrap().is_none());

        witnesses
            .set_witness(&id, "sig", WitnessTypes::Winternitz(sample_wots_signature()))
            .unwrap();
        assert_eq!(
            witnesses.get_witness(&id, "sig").unwrap().unwrap(),
            WitnessTypes::Winternitz(sample_wots_signature())
        );
    }

    #[test]
    fn test_witness_get_or_err() {
        let dir = test_storage_dir();
        let witnesses = WitnessVars::new(dir.storage());
        let id = Uuid::new_v4();

        assert!(matches!(
            witnesses.get_witness_or_err(&id, "missing"),
            Err(BitVMXError::VariableNotFound(_, _))
        ));

        witnesses
            .set_witness(&id, "secret", WitnessTypes::Secret(vec![3]))
            .unwrap();
        assert_eq!(
            witnesses.get_witness_or_err(&id, "secret").unwrap(),
            WitnessTypes::Secret(vec![3])
        );
    }

    #[test]
    fn test_witness_copy() {
        let dir = test_storage_dir();
        let witnesses = WitnessVars::new(dir.storage());
        let from = Uuid::new_v4();
        let to = Uuid::new_v4();

        witnesses
            .set_witness(&from, "sig", WitnessTypes::Lamport(sample_lamport_signature()))
            .unwrap();
        witnesses.copy_witness(&from, &to, "sig").unwrap();
        assert_eq!(
            witnesses.get_witness(&to, "sig").unwrap().unwrap(),
            WitnessTypes::Lamport(sample_lamport_signature())
        );

        assert!(matches!(
            witnesses.copy_witness(&from, &to, "missing"),
            Err(BitVMXError::VariableNotFound(_, _))
        ));
    }
}
