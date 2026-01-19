use bitcoin::PublicKey;
use bitvmx_broker::identification::identifier::PubkHash;
use key_manager::winternitz::WinternitzPublicKey;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fmt, net::SocketAddr, str::FromStr};

use crate::{
    errors::BitVMXError,
    helper::{PartialSignatureMessage, PubNonceMessage},
};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ParticipantData {
    pub comms_address: CommsAddress,
    pub keys: Option<ParticipantKeys>,
    pub nonces: Option<PubNonceMessage>,
    pub partial: Option<PartialSignatureMessage>,
}

impl ParticipantData {
    pub fn new(address: &CommsAddress, keys: Option<ParticipantKeys>) -> Self {
        ParticipantData {
            comms_address: address.clone(),
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
impl ParticipantRole {
    pub fn is_prover(&self) -> bool {
        matches!(self, ParticipantRole::Prover)
    }

    pub fn is_verifier(&self) -> bool {
        matches!(self, ParticipantRole::Verifier)
    }

    pub fn to_string(&self) -> String {
        match self {
            ParticipantRole::Prover => "prover".to_string(),
            ParticipantRole::Verifier => "verifier".to_string(),
        }
    }

    pub fn opposite(&self) -> ParticipantRole {
        match self {
            ParticipantRole::Prover => ParticipantRole::Verifier,
            ParticipantRole::Verifier => ParticipantRole::Prover,
        }
    }
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

    pub fn speedup(&self) -> Result<&PublicKey, BitVMXError> {
        self.get_public("speedup")
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Serialize, Deserialize, Debug)]
pub struct CommsAddress {
    pub address: SocketAddr,
    pub pubkey_hash: PubkHash,
}

impl CommsAddress {
    pub fn new(address: SocketAddr, pubkey_hash: PubkHash) -> Self {
        Self {
            address,
            pubkey_hash,
        }
    }
}

impl fmt::Display for CommsAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{},{}", self.address, self.pubkey_hash)
    }
}

impl FromStr for CommsAddress {
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

        Ok(CommsAddress::new(address, pubkey_hash))
    }
}
