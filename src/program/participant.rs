use crate::errors::BitVMXError;
use bitcoin::PublicKey;
use bitvmx_broker::identification::identifier::PubkHash;
use key_manager::{lamport::LamportPublicKey, winternitz::WinternitzPublicKey};
use serde::{
    de::{MapAccess, Visitor},
    Deserialize, Deserializer, Serialize,
};
use std::{
    collections::{HashMap, HashSet},
    fmt,
    net::SocketAddr,
    str::FromStr,
};

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

impl From<PublicKey> for PublicKeyType {
    fn from(key: PublicKey) -> Self {
        PublicKeyType::Public(key)
    }
}

impl From<WinternitzPublicKey> for PublicKeyType {
    fn from(key: WinternitzPublicKey) -> Self {
        PublicKeyType::Winternitz(key)
    }
}

impl From<LamportPublicKey> for PublicKeyType {
    fn from(key: LamportPublicKey) -> Self {
        PublicKeyType::Lamport(key)
    }
}

/// Public-key material declared by a participant and exchanged on the wire.
///
/// Locally derived values intentionally do not belong in this type so peers
/// cannot provide values such as computed aggregated keys.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ParticipantKeyDeclaration {
    #[serde(deserialize_with = "deserialize_unique_key_mapping")]
    pub mapping: HashMap<String, PublicKeyType>,
    #[serde(deserialize_with = "deserialize_unique_aggregated_names")]
    pub aggregated: HashSet<String>,
}

fn deserialize_unique_key_mapping<'de, D>(
    deserializer: D,
) -> Result<HashMap<String, PublicKeyType>, D::Error>
where
    D: Deserializer<'de>,
{
    struct UniqueKeyMappingVisitor;

    impl<'de> Visitor<'de> for UniqueKeyMappingVisitor {
        type Value = HashMap<String, PublicKeyType>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a participant key mapping with unique names")
        }

        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            let mut keys = HashMap::with_capacity(map.size_hint().unwrap_or(0));
            while let Some((name, key)) = map.next_entry::<String, PublicKeyType>()? {
                if keys.insert(name.clone(), key).is_some() {
                    return Err(serde::de::Error::custom(format!(
                        "Duplicate participant key name: {name}"
                    )));
                }
            }
            Ok(keys)
        }
    }

    deserializer.deserialize_map(UniqueKeyMappingVisitor)
}

fn deserialize_unique_aggregated_names<'de, D>(deserializer: D) -> Result<HashSet<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let names = Vec::<String>::deserialize(deserializer)?;
    let mut unique_names = HashSet::with_capacity(names.len());
    for name in names {
        if !unique_names.insert(name.clone()) {
            return Err(serde::de::Error::custom(format!(
                "Duplicate aggregated key name: {name}"
            )));
        }
    }
    Ok(unique_names)
}

impl ParticipantKeyDeclaration {
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

        let mut aggregated_names = HashSet::with_capacity(aggregated.len());
        for name in aggregated {
            if !aggregated_names.insert(name.clone()) {
                return Err(BitVMXError::InvalidMessage(format!(
                    "Duplicate aggregated key name: {name}"
                )));
            }
        }

        Ok(Self {
            mapping,
            aggregated: aggregated_names,
        })
    }

    pub fn empty() -> Self {
        Self {
            mapping: HashMap::new(),
            aggregated: HashSet::new(),
        }
    }
}

/// A participant's declared keys together with locally derived key material.
///
/// This type is persisted locally but must not be deserialized directly from
/// participant messages. Use [`ParticipantKeyDeclaration`] at that boundary.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct ParticipantKeys {
    #[serde(deserialize_with = "deserialize_unique_key_mapping")]
    pub mapping: HashMap<String, PublicKeyType>,
    #[serde(deserialize_with = "deserialize_unique_aggregated_names")]
    pub aggregated: HashSet<String>,
    pub computed_aggregated: HashMap<String, PublicKey>,
}

impl From<ParticipantKeyDeclaration> for ParticipantKeys {
    fn from(declaration: ParticipantKeyDeclaration) -> Self {
        Self {
            mapping: declaration.mapping,
            aggregated: declaration.aggregated,
            computed_aggregated: HashMap::new(),
        }
    }
}

impl From<&ParticipantKeys> for ParticipantKeyDeclaration {
    fn from(keys: &ParticipantKeys) -> Self {
        Self {
            mapping: keys.mapping.clone(),
            aggregated: keys.aggregated.clone(),
        }
    }
}

impl ParticipantKeys {
    pub fn new(
        keys: Vec<(String, PublicKeyType)>,
        aggregated: Vec<String>,
    ) -> Result<Self, BitVMXError> {
        Ok(ParticipantKeyDeclaration::new(keys, aggregated)?.into())
    }

    pub fn empty() -> Result<Self, BitVMXError> {
        Ok(ParticipantKeyDeclaration::empty().into())
    }

    pub fn get_winternitz(&self, name: &str) -> Result<&WinternitzPublicKey, BitVMXError> {
        const EXPECTED: &str = "Winternitz public key";
        let key = self.get_key(name, EXPECTED)?;
        key.winternitz()
            .ok_or_else(|| Self::wrong_key_type(name, EXPECTED, key))
    }

    pub fn get_lamport(&self, name: &str) -> Result<&LamportPublicKey, BitVMXError> {
        const EXPECTED: &str = "Lamport public key";
        let key = self.get_key(name, EXPECTED)?;
        key.lamport()
            .ok_or_else(|| Self::wrong_key_type(name, EXPECTED, key))
    }

    pub fn get_public(&self, name: &str) -> Result<&PublicKey, BitVMXError> {
        const EXPECTED: &str = "Bitcoin public key";
        let key = self.get_key(name, EXPECTED)?;
        key.public()
            .ok_or_else(|| Self::wrong_key_type(name, EXPECTED, key))
    }

    fn get_key(
        &self,
        name: &str,
        expected_type: &'static str,
    ) -> Result<&PublicKeyType, BitVMXError> {
        self.mapping
            .get(name)
            .ok_or_else(|| BitVMXError::ParticipantKeyNotFound {
                name: name.to_string(),
                expected_type,
            })
    }

    fn wrong_key_type(name: &str, expected_type: &'static str, key: &PublicKeyType) -> BitVMXError {
        let actual_type = match key {
            PublicKeyType::Public(_) => "Bitcoin public key",
            PublicKeyType::Winternitz(_) => "Winternitz public key",
            PublicKeyType::Lamport(_) => "Lamport public key",
        };
        BitVMXError::ParticipantKeyTypeMismatch {
            name: name.to_string(),
            expected_type,
            actual_type,
        }
    }

    pub fn speedup(&self) -> Result<&PublicKey, BitVMXError> {
        self.get_public("speedup")
    }
}

const PUBKEY_HASH_HEX_LEN: usize = 64;

fn validate_pubkey_hash(pubkey_hash: &str) -> Result<(), String> {
    if pubkey_hash.len() != PUBKEY_HASH_HEX_LEN {
        return Err(format!(
            "Invalid public-key hash length: expected {PUBKEY_HASH_HEX_LEN} lowercase hex characters, got {}",
            pubkey_hash.len()
        ));
    }

    if !pubkey_hash
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("Invalid public-key hash: expected lowercase hexadecimal SHA-256".to_string());
    }

    Ok(())
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Serialize, Deserialize, Debug)]
#[serde(try_from = "UncheckedCommsAddress")]
pub struct CommsAddress {
    pub address: SocketAddr,
    pub pubkey_hash: PubkHash,
}

#[derive(Deserialize)]
struct UncheckedCommsAddress {
    address: SocketAddr,
    pubkey_hash: PubkHash,
}

impl TryFrom<UncheckedCommsAddress> for CommsAddress {
    type Error = String;

    fn try_from(value: UncheckedCommsAddress) -> Result<Self, Self::Error> {
        CommsAddress::try_new(value.address, value.pubkey_hash)
    }
}

impl CommsAddress {
    /// Constructs an address without validation for compatibility with trusted internal callers.
    /// External input must use `try_new`, `FromStr`, or serde deserialization.
    pub fn new(address: SocketAddr, pubkey_hash: PubkHash) -> Self {
        Self {
            address,
            pubkey_hash,
        }
    }

    pub fn try_new(address: SocketAddr, pubkey_hash: PubkHash) -> Result<Self, String> {
        validate_pubkey_hash(&pubkey_hash)?;
        Ok(Self {
            address,
            pubkey_hash,
        })
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
        validate_pubkey_hash(&participant.pubkey_hash).map_err(BitVMXError::InvalidMessage)?;

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

        CommsAddress::try_new(address, pubkey_hash)
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
        let hash = "7005e4a0325b644baa2b66c3fa2ed2a795cae584b6d3a57ca45ebf5d0eb0011f";
        let participants = vec![participant(1000, hash), participant(2000, hash)];

        assert!(matches!(
            validate_participants(&participants),
            Err(BitVMXError::InvalidMessage(message))
                if message.contains("Duplicate participant public-key hash")
        ));
    }

    #[test]
    fn accepts_unique_participant_identities() {
        let participants = vec![
            participant(
                1000,
                "7005e4a0325b644baa2b66c3fa2ed2a795cae584b6d3a57ca45ebf5d0eb0011f",
            ),
            participant(
                2000,
                "1d10fa43ebbf6674d74caa3e9032711ade09d98ea7d20f89459f61152bebda1e",
            ),
        ];

        assert!(validate_participants(&participants).is_ok());
    }

    #[test]
    fn participant_validation_rejects_unchecked_malformed_hash() {
        let participants = vec![participant(1000, "not-a-fingerprint")];

        assert!(matches!(
            validate_participants(&participants),
            Err(BitVMXError::InvalidMessage(message))
                if message.contains("Invalid public-key hash")
        ));
    }

    #[test]
    fn parses_valid_comms_address() {
        let hash = "7005e4a0325b644baa2b66c3fa2ed2a795cae584b6d3a57ca45ebf5d0eb0011f";
        let parsed: CommsAddress = format!("127.0.0.1:1000,{hash}").parse().unwrap();

        assert_eq!(parsed.pubkey_hash, hash);
    }

    #[test]
    fn rejects_malformed_comms_address_hashes() {
        for hash in [
            "",
            "abc123",
            "7005E4A0325B644BAA2B66C3FA2ED2A795CAE584B6D3A57CA45EBF5D0EB0011F",
            "g005e4a0325b644baa2b66c3fa2ed2a795cae584b6d3a57ca45ebf5d0eb0011f",
            " 005e4a0325b644baa2b66c3fa2ed2a795cae584b6d3a57ca45ebf5d0eb0011f",
        ] {
            assert!(format!("127.0.0.1:1000,{hash}")
                .parse::<CommsAddress>()
                .is_err());
        }
    }

    #[test]
    fn serde_rejects_malformed_comms_address_hash() {
        let value = serde_json::json!({
            "address": "127.0.0.1:1000",
            "pubkey_hash": "not-a-fingerprint"
        });

        assert!(serde_json::from_value::<CommsAddress>(value).is_err());
    }

    #[test]
    fn participant_key_declaration_deserialization_rejects_duplicate_mapping_names() {
        let key = PublicKey::from_str(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        )
        .unwrap();
        let serialized_key = serde_json::to_string(&PublicKeyType::Public(key)).unwrap();
        let duplicate = format!(
            r#"{{"mapping":{{"duplicate":{serialized_key},"duplicate":{serialized_key}}},"aggregated":[]}}"#
        );

        let error = serde_json::from_str::<ParticipantKeyDeclaration>(&duplicate).unwrap_err();
        assert!(error
            .to_string()
            .contains("Duplicate participant key name: duplicate"));
    }

    #[test]
    fn participant_key_declaration_rejects_duplicate_aggregated_names() {
        let duplicate = serde_json::json!({
            "mapping": {},
            "aggregated": ["aggregate", "aggregate"]
        });

        let error = serde_json::from_value::<ParticipantKeyDeclaration>(duplicate).unwrap_err();
        assert!(error
            .to_string()
            .contains("Duplicate aggregated key name: aggregate"));

        assert!(matches!(
            ParticipantKeyDeclaration::new(
                vec![],
                vec!["aggregate".to_string(), "aggregate".to_string()]
            ),
            Err(BitVMXError::InvalidMessage(message))
                if message == "Duplicate aggregated key name: aggregate"
        ));
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

    #[test]
    fn participant_key_getters_distinguish_missing_and_wrong_types() {
        let key = PublicKey::from_str(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        )
        .unwrap();
        let keys = ParticipantKeys::new(vec![("bitcoin".to_string(), key.into())], vec![]).unwrap();

        assert!(matches!(
            keys.get_public("missing"),
            Err(BitVMXError::ParticipantKeyNotFound {
                name,
                expected_type: "Bitcoin public key",
            }) if name == "missing"
        ));
        assert!(matches!(
            keys.get_winternitz("bitcoin"),
            Err(BitVMXError::ParticipantKeyTypeMismatch {
                name,
                expected_type: "Winternitz public key",
                actual_type: "Bitcoin public key",
            }) if name == "bitcoin"
        ));
    }
}
