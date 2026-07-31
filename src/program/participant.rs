use bitcoin::PublicKey;
use bitvmx_broker::identification::identifier::PubkHash;
use key_manager::{lamport::LamportPublicKey, winternitz::WinternitzPublicKey};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    fmt,
    net::SocketAddr,
    str::FromStr,
};
use tracing::warn;

use crate::errors::BitVMXError;

impl TryFrom<&str> for ParticipantRole {
    type Error = BitVMXError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s {
            "verifier" => Ok(ParticipantRole::Verifier),
            "prover" => Ok(ParticipantRole::Prover),
            _ => Err(BitVMXError::InvalidConversion(format!(
                "Invalid role: {}",
                s
            ))),
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
    Lamport(LamportPublicKey),
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

    pub fn lamport(&self) -> Option<&LamportPublicKey> {
        match self {
            PublicKeyType::Lamport(key) => Some(key),
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

impl Into<PublicKeyType> for LamportPublicKey {
    fn into(self) -> PublicKeyType {
        PublicKeyType::Lamport(self)
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct ParticipantKeys {
    pub mapping: HashMap<String, PublicKeyType>,
    pub aggregated: Vec<String>,
    pub computed_aggregated: HashMap<String, PublicKey>,
}

impl ParticipantKeys {
    pub fn new(
        keys: Vec<(String, PublicKeyType)>,
        aggregated: Vec<String>,
    ) -> Result<Self, BitVMXError> {
        let mut mapping = HashMap::new();
        for (name, key) in keys {
            if mapping.insert(name.clone(), key).is_some() {
                return Err(BitVMXError::InvalidMessage(format!(
                    "Duplicate participant key name: {name}"
                )));
            }
        }
        Ok(Self {
            mapping,
            aggregated,
            computed_aggregated: HashMap::new(),
        })
    }

    pub fn get_winternitz(&self, name: &str) -> Result<&WinternitzPublicKey, BitVMXError> {
        Ok(self
            .mapping
            .get(name)
            .ok_or_else(|| {
                warn!("Winternitz {} not found.", name);
                BitVMXError::InvalidMessageFormat
            })?
            .winternitz()
            .ok_or_else(|| {
                warn!("Winternitz {} not found.", name);
                BitVMXError::InvalidMessageFormat
            })?)
    }

    pub fn get_lamport(&self, name: &str) -> Result<&LamportPublicKey, BitVMXError> {
        Ok(self
            .mapping
            .get(name)
            .ok_or_else(|| BitVMXError::InvalidMessageFormat)?
            .lamport()
            .ok_or_else(|| BitVMXError::InvalidMessageFormat)?)
    }

    pub fn get_public(&self, name: &str) -> Result<&PublicKey, BitVMXError> {
        Ok(self
            .mapping
            .get(name)
            .ok_or_else(|| BitVMXError::InvalidMessageFormat)?
            .public()
            .ok_or_else(|| BitVMXError::InvalidMessageFormat)?)
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

/// Validates the identity invariants required by participant-indexed protocol state.
///
/// A public-key hash identifies exactly one logical participant. Allowing the
/// same hash at multiple indices would make hash-based lookups ambiguous and
/// leave later indices impossible to complete during setup.
pub fn validate_participants(participants: &[CommsAddress]) -> Result<(), BitVMXError> {
    if participants.is_empty() {
        return Err(BitVMXError::InvalidMessage(
            "Participant list cannot be empty".to_string(),
        ));
    }

    let mut identities = HashSet::with_capacity(participants.len());
    for participant in participants {
        if !identities.insert(&participant.pubkey_hash) {
            return Err(BitVMXError::InvalidMessage(format!(
                "Duplicate participant public-key hash: {}",
                participant.pubkey_hash
            )));
        }
    }

    Ok(())
}

pub fn get_comms_address_by_pubkey_hash(
    participants: &[CommsAddress],
    pubkey_hash: &PubkHash,
) -> Result<CommsAddress, BitVMXError> {
    for p in participants {
        if &p.pubkey_hash == pubkey_hash {
            return Ok(p.clone());
        }
    }
    Err(BitVMXError::InvalidCommsAddress(pubkey_hash.clone()))
}

pub fn get_index_by_pubkey_hash(
    participants: &[CommsAddress],
    pubkey_hash: &PubkHash,
) -> Result<usize, BitVMXError> {
    for (i, p) in participants.iter().enumerate() {
        if &p.pubkey_hash == pubkey_hash {
            return Ok(i);
        }
    }
    Err(BitVMXError::InvalidCommsAddress(pubkey_hash.clone()))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn participant(port: u16, pubkey_hash: &str) -> CommsAddress {
        CommsAddress::new(
            format!("127.0.0.1:{port}").parse().unwrap(),
            pubkey_hash.to_string(),
        )
    }

    #[test]
    fn rejects_empty_participant_list() {
        assert!(matches!(
            validate_participants(&[]),
            Err(BitVMXError::InvalidMessage(_))
        ));
    }

    #[test]
    fn rejects_duplicate_participant_identities() {
        let participants = vec![participant(1000, "alice"), participant(2000, "alice")];

        assert!(matches!(
            validate_participants(&participants),
            Err(BitVMXError::InvalidMessage(message))
                if message.contains("Duplicate participant public-key hash")
        ));
    }

    #[test]
    fn accepts_unique_participant_identities() {
        let participants = vec![participant(1000, "alice"), participant(2000, "bob")];

        assert!(validate_participants(&participants).is_ok());
    }

    #[test]
    fn participant_keys_reject_duplicate_names() {
        let key = PublicKey::from_str(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        )
        .unwrap();

        let result = ParticipantKeys::new(
            vec![
                ("duplicate".to_string(), key.into()),
                ("duplicate".to_string(), key.into()),
            ],
            vec![],
        );

        assert!(matches!(
            result,
            Err(BitVMXError::InvalidMessage(message))
                if message == "Duplicate participant key name: duplicate"
        ));
    }
}
