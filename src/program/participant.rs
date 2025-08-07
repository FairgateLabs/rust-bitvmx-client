use bitcoin::PublicKey;
use key_manager::winternitz::{message_bytes_length, WinternitzPublicKey};
use p2p_handler::p2p_handler::PubKeyHash;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fmt, net::SocketAddr, str::FromStr};
use uuid::Uuid;

use crate::{
    errors::BitVMXError,
    helper::{PartialSignatureMessage, PubNonceMessage},
};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ParticipantData {
    pub p2p_address: P2PAddress,
    pub keys: Option<ParticipantKeys>,
    pub nonces: Option<PubNonceMessage>,
    pub partial: Option<PartialSignatureMessage>,
}

impl ParticipantData {
    pub fn new(address: &P2PAddress, keys: Option<ParticipantKeys>) -> Self {
        ParticipantData {
            p2p_address: address.clone(),
            keys,
            nonces: None,
            partial: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ParticipantRole {
    Prover,
    Verifier,
}

impl fmt::Display for ParticipantRole {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ParticipantRole::Prover => write!(f, "Prover"),
            ParticipantRole::Verifier => write!(f, "Verifier"),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub enum PublicKeyType {
    Public(PublicKey),
    Winternitz(WinternitzPublicKey),
}

impl PublicKeyType {
    pub fn public(&self) -> Option<&PublicKey> {
        match self {
            PublicKeyType::Public(key) => Some(key),
            _ => None,
        }
    }
    pub fn winternitz(&self) -> Option<&WinternitzPublicKey> {
        match self {
            PublicKeyType::Winternitz(key) => Some(key),
            _ => None,
        }
    }
}

impl Into<PublicKeyType> for PublicKey {
    fn into(self) -> PublicKeyType {
        PublicKeyType::Public(self)
    }
}

impl Into<PublicKeyType> for WinternitzPublicKey {
    fn into(self) -> PublicKeyType {
        PublicKeyType::Winternitz(self)
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct ParticipantKeys {
    pub mapping: HashMap<String, PublicKeyType>,
    pub aggregated: Vec<String>,
    pub computed_aggregated: HashMap<String, PublicKey>,
}

impl ParticipantKeys {
    pub fn new(keys: Vec<(String, PublicKeyType)>, aggregated: Vec<String>) -> Self {
        let mut mapping = HashMap::new();
        for (name, key) in keys {
            mapping.insert(name.to_string(), key);
        }
        Self {
            mapping,
            aggregated,
            computed_aggregated: HashMap::new(),
        }
    }

    pub fn get_winternitz(&self, name: &str) -> Result<&WinternitzPublicKey, BitVMXError> {
        Ok(self
            .mapping
            .get(name)
            .ok_or(BitVMXError::InvalidMessageFormat)?
            .winternitz()
            .ok_or(BitVMXError::InvalidMessageFormat)?)
    }

    pub fn get_public(&self, name: &str) -> Result<&PublicKey, BitVMXError> {
        Ok(self
            .mapping
            .get(name)
            .ok_or(BitVMXError::InvalidMessageFormat)?
            .public()
            .ok_or(BitVMXError::InvalidMessageFormat)?)
    }

    pub fn speedup(&self) -> &PublicKey {
        self.get_public("speedup").unwrap()
    }
}
pub trait ParticipantKeysExt {
    fn get_key_size(&self, name: &str) -> Result<usize, BitVMXError>;
}

//It might be inneficient to iterate over all keys. It would be better to store the information in the keys struct.
impl ParticipantKeysExt for &Vec<&ParticipantKeys> {
    fn get_key_size(&self, name: &str) -> Result<usize, BitVMXError> {
        for keys in self.iter() {
            if let Some(key) = keys.mapping.get(name) {
                return match key {
                    PublicKeyType::Winternitz(winternitz_key) => {
                        Ok(message_bytes_length(winternitz_key.message_size()?))
                    }
                    _ => return Err(BitVMXError::KeysNotFound(Uuid::default())),
                };
            }
        }
        Err(BitVMXError::InvalidMessageFormat)
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Serialize, Deserialize, Debug)]
pub struct P2PAddress {
    pub address: SocketAddr,
    pub pubkey_hash: PubKeyHash,
}

impl P2PAddress {
    pub fn new(address: SocketAddr, pubkey_hash: PubKeyHash) -> Self {
        Self {
            address,
            pubkey_hash,
        }
    }
}

impl fmt::Display for P2PAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{},{}", self.address, self.pubkey_hash)
    }
}

impl FromStr for P2PAddress {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.splitn(2, ',').collect();
        if parts.len() != 2 {
            return Err("Invalid format. Expected <socket_addr>,<pubkey_hash>".to_string());
        }

        let address: SocketAddr = parts[0]
            .parse()
            .map_err(|e| format!("Invalid socket address: {}", e))?;

        let pubkey_hash = parts[1].to_string();

        Ok(P2PAddress::new(address, pubkey_hash))
    }
}
