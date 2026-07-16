use crate::bitvmx::Context;
use crate::{errors::BitVMXError, program::participant::CommsAddress};
use bitvmx_broker::channel::queue_channel::QueueChannel;
use chrono::Utc;
use key_manager::key_manager::KeyManager;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use signature::SignatureEncoding;
use std::rc::Rc;
use uuid::Uuid;

const MIN_EXPECTED_MSG_LEN: usize = 4; // 2 bytes for version + 2 bytes for message type
const CURRENT_PROTOCOL_VERSION: &str = "1.0";

// Public function for signature verification
pub fn serialize_with_sorted_keys_for_verification(value: &Value) -> Result<String, BitVMXError> {
    let sorted_json = sort_json_keys(value);
    serde_json::to_string(&sorted_json).map_err(|_| BitVMXError::SerializationError)
}

// Recursively sort all keys in a JSON value
fn sort_json_keys(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut sorted_map = serde_json::Map::new();
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for key in keys {
                sorted_map.insert(key.clone(), sort_json_keys(&map[key]));
            }
            Value::Object(sorted_map)
        }
        Value::Array(vec) => Value::Array(vec.iter().map(sort_json_keys).collect()),
        _ => value.clone(),
    }
}

pub fn construct_message(
    program_id: &str,
    version: &str,
    msg_type: CommsMessageType,
    data: &Value,
    timestamp: i64,
) -> Result<String, BitVMXError> {
    let version_bytes = Version::to_bytes(version)?;
    let msg_type_bytes = msg_type.to_bytes()?;
    let msg_string = serialize_with_sorted_keys_for_verification(data)?;
    Ok(format!(
        "{}|{:02X}{:02X}|{:02X}{:02X}|{}|{}",
        program_id,
        version_bytes[0],
        version_bytes[1],
        msg_type_bytes[0],
        msg_type_bytes[1],
        msg_string,
        timestamp
    ))
}

pub fn prepare_message(
    key_manager: &Rc<KeyManager>,
    rsa_public_key: &str,
    program_id: &Uuid,
    msg_type: CommsMessageType,
    msg: Value,
) -> Result<(String, Value, i64, Vec<u8>), BitVMXError> {
    let timestamp = Utc::now().timestamp_millis();
    let message = construct_message(
        &program_id.to_string(),
        CURRENT_PROTOCOL_VERSION,
        msg_type,
        &msg,
        timestamp,
    )?;

    let signature = &key_manager
        .sign_rsa_message(message.as_bytes(), rsa_public_key)?
        .to_bytes()
        .to_vec();
    Ok((
        CURRENT_PROTOCOL_VERSION.to_string(),
        msg,
        timestamp,
        signature.to_vec(),
    ))
}

pub fn request<T: Serialize>(
    comms: &QueueChannel,
    key_manager: &Rc<KeyManager>,
    rsa_public_key: &str,
    program_id: &Uuid,
    comms_address: CommsAddress,
    msg_type: CommsMessageType,
    msg: T,
) -> Result<(), BitVMXError> {
    // Serialize with sorted keys for consistent ordering during signature verification
    let msg_value = serde_json::to_value(&msg).map_err(|_| BitVMXError::SerializationError)?;
    let timestamp = Utc::now().timestamp_millis();
    let message = construct_message(
        &program_id.to_string(),
        CURRENT_PROTOCOL_VERSION,
        msg_type,
        &msg_value,
        timestamp,
    )?;

    let signature = &key_manager
        .sign_rsa_message(message.as_bytes(), rsa_public_key)?
        .to_bytes()
        .to_vec();

    let serialize_msg = serialize_msg(
        CURRENT_PROTOCOL_VERSION,
        msg_type,
        program_id,
        msg,
        timestamp,
        signature.to_vec(),
    )?;
    comms.send(
        &Context::ProgramId(*program_id).to_string()?,
        &comms_address.pubkey_hash,
        comms_address.address,
        serialize_msg,
    )?;
    Ok(())
}

pub fn response<T: Serialize>(
    comms: &QueueChannel,
    key_manager: &Rc<KeyManager>,
    rsa_public_key: &str,
    program_id: &Uuid,
    comms_address: CommsAddress,
    msg_type: CommsMessageType,
    msg: T,
) -> Result<(), BitVMXError> {
    request(
        comms,
        key_manager,
        rsa_public_key,
        program_id,
        comms_address,
        msg_type,
        msg,
    ) // In this version, response is identical to request. Keeping it separate for clarity.
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy, Serialize, Deserialize)]
pub enum CommsMessageType {
    Keys,
    PublicNonces,
    PartialSignatures,
    GarbledCircuit,
    VerificationKey,
    VerificationKeyRequest,
    Broadcasted,
}

impl CommsMessageType {
    // Define a mapping between message kinds and their byte representations
    const KIND_MAP: &'static [(&'static CommsMessageType, [u8; 2])] = &[
        (&CommsMessageType::Keys, [0x00, 0x01]),
        (&CommsMessageType::PublicNonces, [0x00, 0x02]),
        (&CommsMessageType::PartialSignatures, [0x00, 0x03]),
        (&CommsMessageType::GarbledCircuit, [0x00, 0x04]),
        (&CommsMessageType::VerificationKey, [0x00, 0x05]),
        (&CommsMessageType::VerificationKeyRequest, [0x00, 0x06]),
        (&CommsMessageType::Broadcasted, [0x00, 0x07]),
    ];

    pub fn should_store(self) -> bool {
        matches!(
            self,
            CommsMessageType::Keys
                | CommsMessageType::PublicNonces
                | CommsMessageType::PartialSignatures
                | CommsMessageType::GarbledCircuit
        )
    }

    // Convert message type to 2-byte representation
    fn to_bytes(&self) -> Result<[u8; 2], BitVMXError> {
        Self::KIND_MAP
            .iter()
            .find(|(kind, _)| kind == &self)
            .map(|(_, bytes)| *bytes)
            .ok_or_else(|| BitVMXError::InvalidMessageType)
    }

    // Convert 2-byte representation to message type
    fn from_bytes(bytes: [u8; 2]) -> Result<Self, BitVMXError> {
        Self::KIND_MAP
            .iter()
            .find(|(_, kind_bytes)| kind_bytes == &bytes)
            .map(|(kind, _)| *kind)
            .cloned()
            .ok_or_else(|| BitVMXError::InvalidMessageType)
    }
}

struct Version;

impl Version {
    // Define a mapping between version strings and their byte representations
    const VERSION_MAP: &'static [(&'static str, [u8; 2])] = &[
        ("1.0", [0x01, 0x00]),
        // Add more versions here
    ];

    // Convert version string to 2-byte representation
    fn to_bytes(version: &str) -> Result<[u8; 2], BitVMXError> {
        Self::VERSION_MAP
            .iter()
            .find(|(v, _)| *v == version)
            .map(|(_, bytes)| *bytes)
            .ok_or_else(|| BitVMXError::InvalidMsgVersion)
    }

    // Convert 2-byte representation to version string
    fn from_bytes(bytes: [u8; 2]) -> Result<String, BitVMXError> {
        Self::VERSION_MAP
            .iter()
            .find(|(_, version_bytes)| version_bytes == &bytes)
            .map(|(version, _)| version.to_string())
            .ok_or_else(|| BitVMXError::InvalidMsgVersion)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VerificationKeyAnnouncement {
    pub verification_key: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VerificationKeyRequestPayload;

pub fn send_verification_key_to_peer(
    comms: &QueueChannel,
    key_manager: &Rc<KeyManager>,
    rsa_public_key: &str,
    program_id: &Uuid,
    destination: CommsAddress,
) -> Result<(), BitVMXError> {
    let announcement = VerificationKeyAnnouncement {
        verification_key: rsa_public_key.to_string(),
    };

    response(
        comms,
        key_manager,
        rsa_public_key,
        program_id,
        destination,
        CommsMessageType::VerificationKey,
        announcement,
    )
}

impl VerificationKeyAnnouncement {
    pub fn to_value(&self) -> Result<Value, BitVMXError> {
        serde_json::to_value(self).map_err(|_| {
            BitVMXError::InvalidMessage(
                format!(
                    "Failed to serialize VerificationKeyAnnouncement: {:?}",
                    self
                )
                .to_string(),
            )
        })
    }

    pub fn from_value(value: &Value) -> Result<Self, BitVMXError> {
        serde_json::from_value(value.clone()).map_err(|_| {
            BitVMXError::InvalidMessage(
                format!("Invalid VerificationKeyAnnouncement: {:?}", value).to_string(),
            )
        })
    }
}

// Serialize the message into the required format
pub fn serialize_msg<T: Serialize>(
    version: &str,
    msg_type: CommsMessageType,
    program_id: &Uuid,
    data: T,
    timestamp: i64,
    signature: Vec<u8>,
) -> Result<Vec<u8>, BitVMXError> {
    // Convert version and message type to bytes
    let version_bytes = Version::to_bytes(version)?;
    let msg_type_bytes = msg_type.to_bytes()?;

    // Serialize the payload as JSON
    let payload = json!({
        "program_id": program_id.to_string(),
        "msg": data,
        "timestamp": timestamp,
        "signature": signature,
    });
    let json_payload = serde_json::to_vec(&payload).map_err(|_| BitVMXError::SerializationError)?;

    // Combine all parts into a single Vec<u8>
    let mut result = Vec::new();
    result.extend_from_slice(&version_bytes); // Add version
    result.extend_from_slice(&msg_type_bytes); // Add message type
    result.extend_from_slice(&json_payload); // Add JSON payload

    Ok(result)
}

pub fn deserialize_msg(
    data: Vec<u8>,
    max_expected_msg_len_kb: usize,
) -> Result<(String, CommsMessageType, Uuid, Value, i64, Vec<u8>), BitVMXError> {
    // Minimum length check: 4 bytes (2 for version + 2 for message type) + payload
    let max_expected_msg_len = max_expected_msg_len_kb * 1024; // Convert KB to bytes
    if data.len() < MIN_EXPECTED_MSG_LEN || data.len() > max_expected_msg_len {
        return Err(BitVMXError::InvalidMessage(
            format!("Invalid message length: {}", data.len()).to_string(),
        ));
    }

    // Extract the version (first 2 bytes) and message type (next 2 bytes)
    let version_bytes = [data[0], data[1]];
    let msg_type_bytes = [data[2], data[3]];
    let json_payload = &data[4..]; // Remaining bytes are the JSON payload

    // Validate and convert version and message type
    let version = Version::from_bytes(version_bytes)?;
    let msg_type = CommsMessageType::from_bytes(msg_type_bytes)?;

    // Validate and parse JSON payload
    let payload: Value = serde_json::from_slice(json_payload).map_err(|_| {
        BitVMXError::InvalidMessage(format!("Invalid JSON payload: {:?}", json_payload).to_string())
    })?;

    // Extract program ID and message
    let program_id = payload
        .get("program_id")
        .and_then(|id| id.as_str())
        .ok_or_else(|| BitVMXError::InvalidMessage(format!("Missing program ID").to_string()))?;

    let data = payload
        .get("msg")
        .ok_or_else(|| BitVMXError::InvalidMessage(format!("Missing message").to_string()))?;
    // Convert program ID to Uuid
    let program_id = Uuid::parse_str(program_id).map_err(|_| {
        BitVMXError::InvalidMessage(format!("Invalid program ID: {:?}", program_id).to_string())
    })?;

    let timestamp = payload
        .get("timestamp")
        .and_then(|t| t.as_i64())
        .ok_or_else(|| {
            BitVMXError::InvalidMessage("Missing or invalid timestamp field".to_string())
        })?;

    let signature_values = payload
        .get("signature")
        .and_then(|s| s.as_array())
        .ok_or_else(|| {
            BitVMXError::InvalidMessage(
                "Missing or invalid signature field (expected array)".to_string(),
            )
        })?;

    if signature_values.is_empty() {
        return Err(BitVMXError::InvalidMessage(
            "Signature array is empty".to_string(),
        ));
    }

    // Reject signatures that are unexpectedly large to prevent malformed payloads.
    // Check the length before inspecting every value, in case someone is sending large vectors of garbage.
    const MAX_SIGNATURE_LEN: usize = 512;
    if signature_values.len() > MAX_SIGNATURE_LEN {
        return Err(BitVMXError::InvalidMessage(format!(
            "Signature length ({}) exceeds maximum allowed length ({})",
            signature_values.len(),
            MAX_SIGNATURE_LEN
        )));
    }

    let mut signature = Vec::with_capacity(signature_values.len());
    for (idx, value) in signature_values.iter().enumerate() {
        let byte = value.as_u64().ok_or_else(|| {
            BitVMXError::InvalidMessage(format!(
                "Signature byte at index {} is not a valid u64",
                idx
            ))
        })?;
        if byte > u8::MAX as u64 {
            return Err(BitVMXError::InvalidMessage(format!(
                "Signature byte at index {} exceeds maximum u8 value ({} > {})",
                idx,
                byte,
                u8::MAX
            )));
        }
        signature.push(byte as u8);
    }

    Ok((
        version,
        msg_type,
        program_id,
        data.clone(),
        timestamp,
        signature,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TestProgramContextEnv;

    #[test]
    fn test_prepare_message_signs_payload() -> Result<(), BitVMXError> {
        let env = TestProgramContextEnv::new("comms-helper-prepare")?;
        let program_id = Uuid::new_v4();
        let msg = json!({"key": "value"});

        let (version, returned_msg, timestamp, signature) = prepare_message(
            &env.context.key_manager,
            &env.context.rsa_public_key,
            &program_id,
            CommsMessageType::Keys,
            msg.clone(),
        )?;

        assert_eq!(version, CURRENT_PROTOCOL_VERSION);
        assert_eq!(returned_msg, msg);
        assert!(timestamp > 0);
        assert!(!signature.is_empty());
        Ok(())
    }

    #[test]
    fn test_request_round_trip_delivers_verifiable_message() -> Result<(), BitVMXError> {
        let mut env = TestProgramContextEnv::new("comms-helper-request")?;
        let program_id = Uuid::new_v4();
        let payload = json!({"key": "value"});
        // Send to the channel's own address so the message comes back to us.
        let destination = env.self_address()?;

        request(
            &env.context.comms,
            &env.context.key_manager,
            &env.context.rsa_public_key,
            &program_id,
            destination,
            CommsMessageType::Keys,
            payload.clone(),
        )?;

        let (sender, raw) = env.receive_one()?;
        assert_eq!(sender.pubkey_hash, env.context.comms.get_pubk_hash()?);

        let (version, msg_type, received_program_id, data, timestamp, signature) =
            deserialize_msg(raw, 200000)?;
        assert_eq!(version, CURRENT_PROTOCOL_VERSION);
        assert_eq!(msg_type, CommsMessageType::Keys);
        assert_eq!(received_program_id, program_id);
        assert_eq!(data, payload);
        assert!(!signature.is_empty());

        // The signature must verify against the reconstructed message.
        let message = construct_message(
            &program_id.to_string(),
            &version,
            msg_type,
            &data,
            timestamp,
        )?;
        let rsa_signature = key_manager::rsa::Signature::try_from(signature.as_slice())
            .expect("signature bytes should form a valid RSA signature");
        let verified = key_manager::verifier::SignatureVerifier::new().verify_rsa_signature(
            &rsa_signature,
            message.as_bytes(),
            &env.context.rsa_public_key,
        )?;
        assert!(verified);
        Ok(())
    }

    #[test]
    fn test_send_verification_key_to_peer_delivers_announcement() -> Result<(), BitVMXError> {
        let mut env = TestProgramContextEnv::new("comms-helper-vk")?;
        let program_id = Uuid::new_v4();
        let destination = env.self_address()?;

        send_verification_key_to_peer(
            &env.context.comms,
            &env.context.key_manager,
            &env.context.rsa_public_key,
            &program_id,
            destination,
        )?;

        let (_, raw) = env.receive_one()?;
        let (version, msg_type, received_program_id, data, _, signature) =
            deserialize_msg(raw, 200000)?;
        assert_eq!(version, CURRENT_PROTOCOL_VERSION);
        assert_eq!(msg_type, CommsMessageType::VerificationKey);
        assert_eq!(received_program_id, program_id);
        assert!(!signature.is_empty());

        let announcement = VerificationKeyAnnouncement::from_value(&data)?;
        assert_eq!(announcement.verification_key, env.context.rsa_public_key);
        Ok(())
    }

    #[test]
    fn test_comms_message_kind_to_bytes() {
        assert_eq!(CommsMessageType::Keys.to_bytes().unwrap(), [0x00, 0x01]);
        assert_eq!(
            CommsMessageType::PublicNonces.to_bytes().unwrap(),
            [0x00, 0x02]
        );
        assert_eq!(
            CommsMessageType::PartialSignatures.to_bytes().unwrap(),
            [0x00, 0x03]
        );
        assert_eq!(
            CommsMessageType::GarbledCircuit.to_bytes().unwrap(),
            [0x00, 0x04]
        );
        assert_eq!(
            CommsMessageType::VerificationKey.to_bytes().unwrap(),
            [0x00, 0x05]
        );
        assert_eq!(
            CommsMessageType::VerificationKeyRequest.to_bytes().unwrap(),
            [0x00, 0x06]
        );
        assert_eq!(
            CommsMessageType::Broadcasted.to_bytes().unwrap(),
            [0x00, 0x07]
        );
    }

    #[test]
    fn test_comms_message_kind_from_bytes() {
        assert_eq!(
            CommsMessageType::from_bytes([0x00, 0x01]).unwrap(),
            CommsMessageType::Keys
        );
        assert_eq!(
            CommsMessageType::from_bytes([0x00, 0x02]).unwrap(),
            CommsMessageType::PublicNonces
        );
        assert_eq!(
            CommsMessageType::from_bytes([0x00, 0x03]).unwrap(),
            CommsMessageType::PartialSignatures
        );
        assert_eq!(
            CommsMessageType::from_bytes([0x00, 0x04]).unwrap(),
            CommsMessageType::GarbledCircuit
        );
        assert_eq!(
            CommsMessageType::from_bytes([0x00, 0x05]).unwrap(),
            CommsMessageType::VerificationKey
        );
        assert_eq!(
            CommsMessageType::from_bytes([0x00, 0x06]).unwrap(),
            CommsMessageType::VerificationKeyRequest
        );
        assert_eq!(
            CommsMessageType::from_bytes([0x00, 0x07]).unwrap(),
            CommsMessageType::Broadcasted
        );
    }

    #[test]
    fn test_version_to_bytes() {
        assert_eq!(Version::to_bytes("1.0").unwrap(), [0x01, 0x00]);
    }

    #[test]
    fn test_version_from_bytes() {
        assert_eq!(Version::from_bytes([0x01, 0x00]).unwrap(), "1.0");
    }

    #[test]
    fn test_parse_msg() {
        let version = "1.0";
        let msg_type = CommsMessageType::Keys;
        let program_id = Uuid::new_v4();
        let msg = vec![0x01, 0x02, 0x03];
        let timestamp = 0;
        let signature = vec![];

        let result = serialize_msg(
            version,
            msg_type,
            &program_id,
            msg.clone(),
            timestamp,
            signature.clone(),
        )
        .unwrap();

        let expected_version = Version::to_bytes(version).unwrap();
        let expected_msg_type = msg_type.to_bytes().unwrap();
        let expected_payload = json!({
            "program_id": program_id.to_string(),
            "msg": msg,
            "timestamp": timestamp,
            "signature": signature,
        });
        let expected_json_payload =
            serde_json::to_vec(&expected_payload).expect("Failed to serialize JSON payload");

        let mut expected_result = Vec::new();
        expected_result.extend_from_slice(&expected_version);
        expected_result.extend_from_slice(&expected_msg_type);
        expected_result.extend_from_slice(&expected_json_payload);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn test_deserialize_msg() {
        let version = "1.0";
        let msg_type = CommsMessageType::Keys;
        let program_id = Uuid::new_v4();
        let msg = "Hello, world!";
        let signature = vec![0x01, 0x02, 0x03]; // Non-empty signature required

        let serialized_msg =
            serialize_msg(version, msg_type, &program_id, msg, 0, signature.clone()).unwrap();
        let (
            deserialized_version,
            deserialized_msg_type,
            deserialized_program_id,
            deserialized_msg,
            _deserialized_timestamp,
            deserialized_signature,
        ) = deserialize_msg(serialized_msg, 200000).unwrap();

        assert_eq!(deserialized_version, version);
        assert_eq!(deserialized_msg_type, msg_type);
        assert_eq!(deserialized_program_id, program_id);
        assert_eq!(deserialized_msg, msg);
        assert_eq!(deserialized_signature, signature);
    }

    // TODO: This code section was commented out since it is no longer needed.
    // Need to review with Kevin
    // #[test]
    // fn test_message_contains_invalid_byte_value() {
    //     let version = "1.0";
    //     let msg_type = CommsMessageType::Keys;
    //     let program_id = Uuid::new_v4();

    //     // Create a JSON payload with an invalid value (>255)
    //     let payload = json!({
    //         "program_id": program_id.to_string(),
    //         "msg": [0, 255, 256] // 256 is invalid
    //     });
    //     let mut serialized_msg = Vec::new();
    //     serialized_msg.extend_from_slice(&Version::to_bytes(version).unwrap());
    //     serialized_msg.extend_from_slice(&msg_type.to_bytes().unwrap());
    //     serialized_msg.extend_from_slice(&serde_json::to_vec(&payload).unwrap());

    //     // Expect deserialization to fail due to an invalid byte (>255)
    //     let result = deserialize_msg(serialized_msg);
    //     assert!(matches!(result, Err(BitVMXError::InvalidMessageFormat)));
    // }

    #[test]
    fn test_should_store() {
        assert!(CommsMessageType::Keys.should_store());
        assert!(CommsMessageType::PublicNonces.should_store());
        assert!(CommsMessageType::PartialSignatures.should_store());
        assert!(CommsMessageType::GarbledCircuit.should_store());
        assert!(!CommsMessageType::VerificationKey.should_store());
        assert!(!CommsMessageType::VerificationKeyRequest.should_store());
        assert!(!CommsMessageType::Broadcasted.should_store());
    }

    #[test]
    fn test_verification_key_announcement_round_trip() {
        let announcement = VerificationKeyAnnouncement {
            verification_key: "some-rsa-public-key".to_string(),
        };

        let value = announcement.to_value().unwrap();
        let decoded = VerificationKeyAnnouncement::from_value(&value).unwrap();

        assert_eq!(decoded.verification_key, announcement.verification_key);
    }

    #[test]
    fn test_verification_key_announcement_from_invalid_value() {
        let result = VerificationKeyAnnouncement::from_value(&json!(42));
        assert!(matches!(result, Err(BitVMXError::InvalidMessage(_))));

        let result = VerificationKeyAnnouncement::from_value(&json!({"wrong_field": "x"}));
        assert!(matches!(result, Err(BitVMXError::InvalidMessage(_))));
    }

    // Build a serialized message with a valid header and an arbitrary JSON payload,
    // to exercise deserialize_msg error paths on malformed payloads.
    fn msg_with_payload(payload: &Value) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&Version::to_bytes("1.0").unwrap());
        data.extend_from_slice(&CommsMessageType::Keys.to_bytes().unwrap());
        data.extend_from_slice(&serde_json::to_vec(payload).unwrap());
        data
    }

    fn valid_payload() -> Value {
        json!({
            "program_id": Uuid::new_v4().to_string(),
            "msg": "hello",
            "timestamp": 1234567890,
            "signature": [1, 2, 3],
        })
    }

    fn assert_invalid_message(
        result: Result<(String, CommsMessageType, Uuid, Value, i64, Vec<u8>), BitVMXError>,
        expected_fragment: &str,
    ) {
        match result {
            Err(BitVMXError::InvalidMessage(msg)) => {
                assert!(
                    msg.contains(expected_fragment),
                    "expected error containing {:?}, got {:?}",
                    expected_fragment,
                    msg
                );
            }
            other => panic!("expected InvalidMessage error, got {:?}", other.map(|_| ())),
        }
    }

    #[test]
    fn test_deserialize_msg_too_short() {
        assert_invalid_message(
            deserialize_msg(vec![0x01, 0x00, 0x00], 200000),
            "Invalid message length",
        );
    }

    #[test]
    fn test_deserialize_msg_too_long() {
        // 1 KB limit, 2 KB message
        let data = vec![0u8; 2048];
        assert_invalid_message(deserialize_msg(data, 1), "Invalid message length");
    }

    #[test]
    fn test_deserialize_msg_invalid_version() {
        let mut data = msg_with_payload(&valid_payload());
        data[0] = 0xFF;
        data[1] = 0xFF;
        assert!(matches!(
            deserialize_msg(data, 200000),
            Err(BitVMXError::InvalidMsgVersion)
        ));
    }

    #[test]
    fn test_deserialize_msg_invalid_message_type() {
        let mut data = msg_with_payload(&valid_payload());
        data[2] = 0xFF;
        data[3] = 0xFF;
        assert!(matches!(
            deserialize_msg(data, 200000),
            Err(BitVMXError::InvalidMessageType)
        ));
    }

    #[test]
    fn test_deserialize_msg_invalid_json_payload() {
        let mut data = Vec::new();
        data.extend_from_slice(&Version::to_bytes("1.0").unwrap());
        data.extend_from_slice(&CommsMessageType::Keys.to_bytes().unwrap());
        data.extend_from_slice(b"not json at all");
        assert_invalid_message(deserialize_msg(data, 200000), "Invalid JSON payload");
    }

    #[test]
    fn test_deserialize_msg_missing_program_id() {
        let mut payload = valid_payload();
        payload.as_object_mut().unwrap().remove("program_id");
        assert_invalid_message(
            deserialize_msg(msg_with_payload(&payload), 200000),
            "Missing program ID",
        );
    }

    #[test]
    fn test_deserialize_msg_non_string_program_id() {
        let mut payload = valid_payload();
        payload["program_id"] = json!(42);
        assert_invalid_message(
            deserialize_msg(msg_with_payload(&payload), 200000),
            "Missing program ID",
        );
    }

    #[test]
    fn test_deserialize_msg_invalid_uuid_program_id() {
        let mut payload = valid_payload();
        payload["program_id"] = json!("not-a-uuid");
        assert_invalid_message(
            deserialize_msg(msg_with_payload(&payload), 200000),
            "Invalid program ID",
        );
    }

    #[test]
    fn test_deserialize_msg_missing_msg() {
        let mut payload = valid_payload();
        payload.as_object_mut().unwrap().remove("msg");
        assert_invalid_message(
            deserialize_msg(msg_with_payload(&payload), 200000),
            "Missing message",
        );
    }

    #[test]
    fn test_deserialize_msg_missing_timestamp() {
        let mut payload = valid_payload();
        payload.as_object_mut().unwrap().remove("timestamp");
        assert_invalid_message(
            deserialize_msg(msg_with_payload(&payload), 200000),
            "timestamp",
        );
    }

    #[test]
    fn test_deserialize_msg_non_integer_timestamp() {
        let mut payload = valid_payload();
        payload["timestamp"] = json!("yesterday");
        assert_invalid_message(
            deserialize_msg(msg_with_payload(&payload), 200000),
            "timestamp",
        );
    }

    #[test]
    fn test_deserialize_msg_missing_signature() {
        let mut payload = valid_payload();
        payload.as_object_mut().unwrap().remove("signature");
        assert_invalid_message(
            deserialize_msg(msg_with_payload(&payload), 200000),
            "signature field",
        );
    }

    #[test]
    fn test_deserialize_msg_signature_not_array() {
        let mut payload = valid_payload();
        payload["signature"] = json!("abc");
        assert_invalid_message(
            deserialize_msg(msg_with_payload(&payload), 200000),
            "signature field",
        );
    }

    #[test]
    fn test_deserialize_msg_empty_signature() {
        let mut payload = valid_payload();
        payload["signature"] = json!([]);
        assert_invalid_message(
            deserialize_msg(msg_with_payload(&payload), 200000),
            "Signature array is empty",
        );
    }

    #[test]
    fn test_deserialize_msg_signature_too_long() {
        let mut payload = valid_payload();
        payload["signature"] = json!(vec![0u8; 513]);
        assert_invalid_message(
            deserialize_msg(msg_with_payload(&payload), 200000),
            "exceeds maximum allowed length",
        );
    }

    #[test]
    fn test_deserialize_msg_signature_byte_not_u64() {
        let mut payload = valid_payload();
        payload["signature"] = json!([1, "x", 3]);
        assert_invalid_message(
            deserialize_msg(msg_with_payload(&payload), 200000),
            "is not a valid u64",
        );

        let mut payload = valid_payload();
        payload["signature"] = json!([1, -2, 3]);
        assert_invalid_message(
            deserialize_msg(msg_with_payload(&payload), 200000),
            "is not a valid u64",
        );
    }

    #[test]
    fn test_deserialize_msg_signature_byte_out_of_range() {
        let mut payload = valid_payload();
        payload["signature"] = json!([1, 256, 3]);
        assert_invalid_message(
            deserialize_msg(msg_with_payload(&payload), 200000),
            "exceeds maximum u8 value",
        );
    }

    #[test]
    fn test_sort_json_keys_simple_object() {
        // Test sorting keys in a simple object
        let input = json!({
            "zebra": 1,
            "apple": 2,
            "banana": 3
        });

        let sorted = sort_json_keys(&input);

        // Keys should be sorted alphabetically
        let sorted_str = serde_json::to_string(&sorted).unwrap();
        assert_eq!(sorted_str, r#"{"apple":2,"banana":3,"zebra":1}"#);
    }

    #[test]
    fn test_sort_json_keys_nested_object() {
        // Test sorting keys in nested objects
        let input = json!({
            "zebra": {
                "c": 1,
                "a": 2,
                "b": 3
            },
            "apple": {
                "z": 1,
                "y": 2,
                "x": 3
            }
        });

        let sorted = sort_json_keys(&input);

        // Both outer and inner keys should be sorted
        let sorted_str = serde_json::to_string(&sorted).unwrap();
        assert_eq!(
            sorted_str,
            r#"{"apple":{"x":3,"y":2,"z":1},"zebra":{"a":2,"b":3,"c":1}}"#
        );
    }

    #[test]
    fn test_sort_json_keys_array_with_objects() {
        // Test sorting keys in objects within arrays
        let input = json!([
            {
                "c": 1,
                "a": 2,
                "b": 3
            },
            {
                "z": 1,
                "y": 2,
                "x": 3
            }
        ]);

        let sorted = sort_json_keys(&input);

        // Keys in each object within the array should be sorted
        let sorted_str = serde_json::to_string(&sorted).unwrap();
        assert_eq!(sorted_str, r#"[{"a":2,"b":3,"c":1},{"x":3,"y":2,"z":1}]"#);
    }

    #[test]
    fn test_sort_json_keys_primitive_values() {
        // Test that primitive values remain unchanged
        assert_eq!(sort_json_keys(&json!(42)), json!(42));
        assert_eq!(sort_json_keys(&json!("hello")), json!("hello"));
        assert_eq!(sort_json_keys(&json!(true)), json!(true));
        assert_eq!(sort_json_keys(&json!(null)), json!(null));
    }

    #[test]
    fn test_sort_json_keys_array_of_primitives() {
        // Test that arrays of primitives remain unchanged (order preserved)
        let input = json!([1, 2, 3, "a", "b", "c"]);
        let sorted = sort_json_keys(&input);
        assert_eq!(sorted, input);
    }

    #[test]
    fn test_sort_json_keys_complex_nested_structure() {
        // Test complex nested structure with arrays and objects
        let input = json!({
            "z": {
                "items": [
                    {"c": 1, "a": 2, "b": 3},
                    {"x": 4, "z": 5, "y": 6}
                ]
            },
            "a": {
                "nested": {
                    "zebra": 1,
                    "apple": 2
                }
            }
        });

        let sorted = sort_json_keys(&input);
        let sorted_str = serde_json::to_string(&sorted).unwrap();

        // Verify the structure is sorted correctly at all levels
        assert!(sorted_str.contains(r#""a":{"nested":{"#));
        assert!(sorted_str.contains(r#""z":{"items":["#));
    }

    #[test]
    fn test_serialize_with_sorted_keys_for_verification_simple() {
        // Test serialization with sorted keys for a simple object
        let input = json!({
            "zebra": 1,
            "apple": 2,
            "banana": 3
        });

        let result = serialize_with_sorted_keys_for_verification(&input).unwrap();

        // Result should be a JSON string with sorted keys
        assert_eq!(result, r#"{"apple":2,"banana":3,"zebra":1}"#);

        // Verify it's valid JSON by parsing it back
        let parsed: Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["apple"], 2);
        assert_eq!(parsed["banana"], 3);
        assert_eq!(parsed["zebra"], 1);
    }

    #[test]
    fn test_serialize_with_sorted_keys_for_verification_nested() {
        // Test serialization with nested structures
        let input = json!({
            "c": {
                "z": 1,
                "a": 2,
                "b": 3
            },
            "a": {
                "x": 4,
                "y": 5
            }
        });

        let result = serialize_with_sorted_keys_for_verification(&input).unwrap();

        // Verify keys are sorted at all levels
        assert_eq!(result, r#"{"a":{"x":4,"y":5},"c":{"a":2,"b":3,"z":1}}"#);
    }

    #[test]
    fn test_serialize_with_sorted_keys_for_verification_consistency() {
        // Test that same input always produces same output (deterministic)
        let input = json!({
            "zebra": 1,
            "apple": 2,
            "banana": 3
        });

        let result1 = serialize_with_sorted_keys_for_verification(&input).unwrap();
        let result2 = serialize_with_sorted_keys_for_verification(&input).unwrap();

        // Results should be identical
        assert_eq!(result1, result2);
    }

    #[test]
    fn test_serialize_with_sorted_keys_for_verification_different_order() {
        // Test that objects with same keys in different order produce same output
        let input1 = json!({
            "zebra": 1,
            "apple": 2,
            "banana": 3
        });

        let input2 = json!({
            "apple": 2,
            "banana": 3,
            "zebra": 1
        });

        let result1 = serialize_with_sorted_keys_for_verification(&input1).unwrap();
        let result2 = serialize_with_sorted_keys_for_verification(&input2).unwrap();

        // Results should be identical regardless of input order
        assert_eq!(result1, result2);
    }

    #[test]
    fn test_construct_message_basic() {
        // Test basic message construction
        let program_id = "test-program-id";
        let version = CURRENT_PROTOCOL_VERSION;
        let msg_type = CommsMessageType::Keys;
        let data = json!({"key": "value"});
        let timestamp = 1234567890;

        let result = construct_message(program_id, version, msg_type, &data, timestamp).unwrap();

        // Message should include program_id, version bytes, message type bytes, serialized data, and timestamp
        let expected_data_str = serialize_with_sorted_keys_for_verification(&data).unwrap();
        let version_bytes = Version::to_bytes(version).unwrap();
        let msg_type_bytes = msg_type.to_bytes().unwrap();
        let expected = format!(
            "{}|{:02X}{:02X}|{:02X}{:02X}|{}|{}",
            program_id,
            version_bytes[0],
            version_bytes[1],
            msg_type_bytes[0],
            msg_type_bytes[1],
            expected_data_str,
            timestamp
        );

        assert_eq!(result, expected);
    }

    #[test]
    fn test_construct_message_different_program_ids() {
        // Test with different program IDs
        let version = CURRENT_PROTOCOL_VERSION;
        let msg_type = CommsMessageType::Keys;
        let data = json!({"test": "data"});
        let timestamp = 1234567890;

        let result1 = construct_message("program-1", version, msg_type, &data, timestamp).unwrap();
        let result2 = construct_message("program-2", version, msg_type, &data, timestamp).unwrap();

        // Results should differ due to different program IDs
        assert_ne!(result1, result2);

        // But both should share the same payload portion
        let data_str = serialize_with_sorted_keys_for_verification(&data).unwrap();
        let version_bytes = Version::to_bytes(version).unwrap();
        let msg_type_bytes = msg_type.to_bytes().unwrap();
        let expected_suffix = format!(
            "|{:02X}{:02X}|{:02X}{:02X}|{}|{}",
            version_bytes[0],
            version_bytes[1],
            msg_type_bytes[0],
            msg_type_bytes[1],
            data_str,
            timestamp
        );
        assert!(result1.ends_with(&expected_suffix));
        assert!(result2.ends_with(&expected_suffix));
    }

    #[test]
    fn test_construct_message_different_timestamps() {
        // Test with different timestamps
        let program_id = "test-program";
        let version = CURRENT_PROTOCOL_VERSION;
        let msg_type = CommsMessageType::Keys;
        let data = json!({"test": "data"});

        let result1 = construct_message(program_id, version, msg_type, &data, 1000).unwrap();
        let result2 = construct_message(program_id, version, msg_type, &data, 2000).unwrap();

        // Results should differ due to different timestamps
        assert_ne!(result1, result2);

        // But both should share the same prefix up to the payload
        let data_str = serialize_with_sorted_keys_for_verification(&data).unwrap();
        let version_bytes = Version::to_bytes(version).unwrap();
        let msg_type_bytes = msg_type.to_bytes().unwrap();
        let expected_prefix = format!(
            "{}|{:02X}{:02X}|{:02X}{:02X}|{}|",
            program_id,
            version_bytes[0],
            version_bytes[1],
            msg_type_bytes[0],
            msg_type_bytes[1],
            data_str
        );
        assert!(result1.starts_with(&expected_prefix));
        assert!(result2.starts_with(&expected_prefix));
    }

    #[test]
    fn test_construct_message_empty_program_id() {
        // Test with empty program ID
        let program_id = "";
        let version = CURRENT_PROTOCOL_VERSION;
        let msg_type = CommsMessageType::Keys;
        let data = json!({"key": "value"});
        let timestamp = 1234567890;

        let result = construct_message(program_id, version, msg_type, &data, timestamp).unwrap();

        // Should still work, producing a string that starts with the delimiter
        let data_str = serialize_with_sorted_keys_for_verification(&data).unwrap();
        let version_bytes = Version::to_bytes(version).unwrap();
        let msg_type_bytes = msg_type.to_bytes().unwrap();
        let expected = format!(
            "|{:02X}{:02X}|{:02X}{:02X}|{}|{}",
            version_bytes[0],
            version_bytes[1],
            msg_type_bytes[0],
            msg_type_bytes[1],
            data_str,
            timestamp
        );
        assert_eq!(result, expected);
    }

    #[test]
    fn test_construct_message_with_sorted_keys() {
        // Test that construct_message uses sorted keys for serialization
        let program_id = "test-program";
        let version = CURRENT_PROTOCOL_VERSION;
        let msg_type = CommsMessageType::Keys;
        let data = json!({
            "zebra": 1,
            "apple": 2,
            "banana": 3
        });
        let timestamp = 1234567890;

        let result = construct_message(program_id, version, msg_type, &data, timestamp).unwrap();

        // The serialized data portion should have sorted keys
        let expected_data_str = serialize_with_sorted_keys_for_verification(&data).unwrap();
        let parts: Vec<&str> = result.splitn(5, '|').collect();
        assert_eq!(parts.len(), 5);

        assert_eq!(parts[0], program_id);
        assert_eq!(parts[3], expected_data_str);
        assert_eq!(parts[3], r#"{"apple":2,"banana":3,"zebra":1}"#);
    }

    #[test]
    fn test_construct_message_integration() {
        // Integration test: construct message and verify format
        let program_id = "abc-123-def";
        let version = CURRENT_PROTOCOL_VERSION;
        let msg_type = CommsMessageType::Keys;
        let data = json!({
            "msg": "Hello",
            "type": "test",
            "value": 42
        });
        let timestamp = 987654321;

        let result = construct_message(program_id, version, msg_type, &data, timestamp).unwrap();

        // Verify the structure: program_id + sorted_json + timestamp
        // Program ID should be at the start
        assert!(result.starts_with(program_id));

        // Timestamp should be at the end
        assert!(result.ends_with(&timestamp.to_string()));

        // The middle part should be valid JSON with sorted keys
        let data_str = serialize_with_sorted_keys_for_verification(&data).unwrap();
        let version_bytes = Version::to_bytes(version).unwrap();
        let msg_type_bytes = msg_type.to_bytes().unwrap();
        let expected = format!(
            "{}|{:02X}{:02X}|{:02X}{:02X}|{}|{}",
            program_id,
            version_bytes[0],
            version_bytes[1],
            msg_type_bytes[0],
            msg_type_bytes[1],
            data_str,
            timestamp
        );
        assert_eq!(result, expected);
    }
}
