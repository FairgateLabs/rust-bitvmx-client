use bitcoin::PublicKey;
use key_manager::winternitz::WinternitzPublicKey;
use p2p_handler::PeerId;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fmt};

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

#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Serialize, Deserialize, Debug)]
pub struct P2PAddress {
    pub address: String,
    pub peer_id: PeerId,
}

impl P2PAddress {
    pub fn new(address: &str, peer_id: PeerId) -> Self {
        Self {
            address: address.to_string(),
            peer_id,
        }
    }

    pub fn address_bytes(&self) -> Vec<u8> {
        self.address.as_bytes().to_vec().clone()
    }

    pub fn peer_id_bytes(&self) -> Vec<u8> {
        self.peer_id.to_string().as_bytes().to_vec().clone()
    }

    pub fn peer_id_bs58(&self) -> String {
        self.peer_id.to_base58()
    }
}
