use crate::keychain::KeyChain;
use crate::{errors::BitVMXError, program::participant::CommsAddress};
use bitvmx_operator_comms::operator_comms::{OperatorComms, PubKeyHash};
use chrono::Utc;
use serde::Serialize;
use serde_json::{json, Value};
use uuid::Uuid;

const MIN_EXPECTED_MSG_LEN: usize = 4; // 2 bytes for version + 2 bytes for message type
const MAX_EXPECTED_MSG_LEN: usize = 1000000; // Maximum length for a message //TODO: Change this value

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
    data: &Value,
    timestamp: i64,
) -> Result<String, BitVMXError> {
    let msg_string = serialize_with_sorted_keys_for_verification(data)?;
    Ok(format!("{}{}{}", program_id, msg_string, timestamp))
}

pub fn request<T: Serialize>(
    comms: &OperatorComms,
    key_chain: &KeyChain,
    program_id: &Uuid,
    comms_address: CommsAddress,
    msg_type: CommsMessageType,
    msg: T,
) -> Result<(), BitVMXError> {
    // Serialize with sorted keys for consistent ordering during signature verification
    let msg_value = serde_json::to_value(&msg).map_err(|_| BitVMXError::SerializationError)?;
    let timestamp = Utc::now().timestamp_millis();
    let message = construct_message(&program_id.to_string(), &msg_value, timestamp)?;

    let signature = &key_chain.sign_rsa_message(message.as_bytes())?;

    let serialize_msg = serialize_msg(msg_type, program_id, msg, timestamp, signature.to_vec())?;
    comms
        .send(
            &comms_address.pubkey_hash,
            comms_address.address,
            serialize_msg,
        )
        .unwrap();
    Ok(())
}

pub fn response<T: Serialize>(
    comms: &OperatorComms,
    key_chain: &KeyChain,
    program_id: &Uuid,
    comms_address: CommsAddress,
    msg_type: CommsMessageType,
    msg: T,
) -> Result<(), BitVMXError> {
    request(comms, key_chain, program_id, comms_address, msg_type, msg) // In this version, response is identical to request. Keeping it separate for clarity.
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum CommsMessageType {
    Keys,
    KeysAck,
    PublicNonces,
    PublicNoncesAck,
    PartialSignatures,
    PartialSignaturesAck,
    VerificationKey,
}

impl CommsMessageType {
    // Define a mapping between message kinds and their byte representations
    const KIND_MAP: &'static [(&'static CommsMessageType, [u8; 2])] = &[
        (&CommsMessageType::Keys, [0x00, 0x01]),
        (&CommsMessageType::KeysAck, [0x00, 0x02]),
        (&CommsMessageType::PublicNonces, [0x00, 0x03]),
        (&CommsMessageType::PublicNoncesAck, [0x00, 0x04]),
        (&CommsMessageType::PartialSignatures, [0x00, 0x05]),
        (&CommsMessageType::PartialSignaturesAck, [0x00, 0x06]),
        (&CommsMessageType::VerificationKey, [0x00, 0x07]),
    ];

    // Convert message type to 2-byte representation
    fn to_bytes(&self) -> Result<[u8; 2], BitVMXError> {
        Self::KIND_MAP
            .iter()
            .find(|(kind, _)| kind == &self)
            .map(|(_, bytes)| *bytes)
            .ok_or(BitVMXError::InvalidMessageType)
    }

    // Convert 2-byte representation to message type
    fn from_bytes(bytes: [u8; 2]) -> Result<Self, BitVMXError> {
        Self::KIND_MAP
            .iter()
            .find(|(_, kind_bytes)| kind_bytes == &bytes)
            .map(|(kind, _)| *kind)
            .cloned()
            .ok_or(BitVMXError::InvalidMessageType)
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
            .ok_or(BitVMXError::InvalidMsgVersion)
    }

    // Convert 2-byte representation to version string
    fn from_bytes(bytes: [u8; 2]) -> Result<String, BitVMXError> {
        Self::VERSION_MAP
            .iter()
            .find(|(_, version_bytes)| version_bytes == &bytes)
            .map(|(version, _)| version.to_string())
            .ok_or(BitVMXError::InvalidMsgVersion)
    }
}

// Serialize the message into the required format
pub fn serialize_msg<T: Serialize>(
    msg_type: CommsMessageType,
    program_id: &Uuid,
    data: T,
    timestamp: i64,
    signature: Vec<u8>,
) -> Result<Vec<u8>, BitVMXError> {
    let version = "1.0";
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
) -> Result<(String, CommsMessageType, Uuid, Value, i64, Vec<u8>), BitVMXError> {
    // Minimum length check: 4 bytes (2 for version + 2 for message type) + payload
    if data.len() < MIN_EXPECTED_MSG_LEN || data.len() > MAX_EXPECTED_MSG_LEN {
        return Err(BitVMXError::InvalidMessageFormat);
    }

    // Extract the version (first 2 bytes) and message type (next 2 bytes)
    let version_bytes = [data[0], data[1]];
    let msg_type_bytes = [data[2], data[3]];
    let json_payload = &data[4..]; // Remaining bytes are the JSON payload

    // Validate and convert version and message type
    let version = Version::from_bytes(version_bytes)?;
    let msg_type = CommsMessageType::from_bytes(msg_type_bytes)?;

    // Validate and parse JSON payload
    let payload: Value =
        serde_json::from_slice(json_payload).map_err(|_| BitVMXError::InvalidMessageFormat)?;

    // Extract program ID and message
    let program_id = payload
        .get("program_id")
        .and_then(|id| id.as_str())
        .ok_or(BitVMXError::InvalidMessageFormat)?;

    let data = payload
        .get("msg")
        .ok_or(BitVMXError::InvalidMessageFormat)?;
    // Convert program ID to Uuid
    let program_id = Uuid::parse_str(program_id).map_err(|_| BitVMXError::InvalidMessageFormat)?;

    let timestamp = payload
        .get("timestamp")
        .and_then(|t| t.as_i64())
        .ok_or(BitVMXError::InvalidMessageFormat)?;

    let signature = payload
        .get("signature")
        .and_then(|s| s.as_array())
        .ok_or(BitVMXError::InvalidMessageFormat)?
        .iter()
        .filter_map(|v| {
            v.as_u64()
                .and_then(|b| if b <= 255 { Some(b as u8) } else { None })
        })
        .collect::<Vec<u8>>();

    //TODO: CHECK THIS WITH @KEVIN
    // Validate that "msg" is a byte array by filtering out invalid values
    // let message = to_vec(&msg)
    //     .unwrap()
    //     .iter()
    //     .filter_map(|v| {
    //         v.as_u64()
    //             .and_then(|b| if b <= 255 { Some(b as u8) } else { None })
    //     })
    //     .collect();

    // if message.len() != msg.len() {
    //     return Err(BitVMXError::InvalidMessageFormat); // Ensure no invalid bytes after filtering previously
    // }

    Ok((
        version,
        msg_type,
        program_id,
        data.clone(),
        timestamp,
        signature,
    ))
}

pub fn publish_verification_key(
    my_pubkey_hash: PubKeyHash,
    my_verification_key: String,
    comms: &OperatorComms,
    key_chain: &KeyChain,
    program_id: &Uuid,
    participants: Vec<CommsAddress>,
) -> Result<(), BitVMXError> {
    for peer in &participants {
        if peer.pubkey_hash == my_pubkey_hash {
            continue;
        }
        request(
            comms,
            key_chain,
            program_id,
            peer.clone(),
            CommsMessageType::VerificationKey,
            my_verification_key.clone(),
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_comms_message_kind_to_bytes() {
        assert_eq!(CommsMessageType::Keys.to_bytes().unwrap(), [0x00, 0x01]);
        assert_eq!(CommsMessageType::KeysAck.to_bytes().unwrap(), [0x00, 0x02]);
        assert_eq!(
            CommsMessageType::PublicNonces.to_bytes().unwrap(),
            [0x00, 0x03]
        );
        assert_eq!(
            CommsMessageType::PublicNoncesAck.to_bytes().unwrap(),
            [0x00, 0x04]
        );
        assert_eq!(
            CommsMessageType::PartialSignatures.to_bytes().unwrap(),
            [0x00, 0x05]
        );
        assert_eq!(
            CommsMessageType::PartialSignaturesAck.to_bytes().unwrap(),
            [0x00, 0x06]
        );
        assert_eq!(
            CommsMessageType::VerificationKey.to_bytes().unwrap(),
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
            CommsMessageType::KeysAck
        );
        assert_eq!(
            CommsMessageType::from_bytes([0x00, 0x03]).unwrap(),
            CommsMessageType::PublicNonces
        );
        assert_eq!(
            CommsMessageType::from_bytes([0x00, 0x04]).unwrap(),
            CommsMessageType::PublicNoncesAck
        );
        assert_eq!(
            CommsMessageType::from_bytes([0x00, 0x05]).unwrap(),
            CommsMessageType::PartialSignatures
        );
        assert_eq!(
            CommsMessageType::from_bytes([0x00, 0x06]).unwrap(),
            CommsMessageType::PartialSignaturesAck
        );
        assert_eq!(
            CommsMessageType::from_bytes([0x00, 0x07]).unwrap(),
            CommsMessageType::VerificationKey
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
            msg_type.clone(),
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

        let serialized_msg = serialize_msg(msg_type.clone(), &program_id, msg, 0, vec![]).unwrap();
        let (
            deserialized_version,
            deserialized_msg_type,
            deserialized_program_id,
            deserialized_msg,
            _deserialized_timestamp,
            _deserialized_signature,
        ) = deserialize_msg(serialized_msg).unwrap();

        assert_eq!(deserialized_version, version);
        assert_eq!(deserialized_msg_type, msg_type);
        assert_eq!(deserialized_program_id, program_id);
        assert_eq!(deserialized_msg, msg);
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
        let data = json!({"key": "value"});
        let timestamp = 1234567890;

        let result = construct_message(program_id, &data, timestamp).unwrap();

        // Message should be: program_id + serialized_data + timestamp
        let expected_data_str = serialize_with_sorted_keys_for_verification(&data).unwrap();
        let expected = format!("{}{}{}", program_id, expected_data_str, timestamp);

        assert_eq!(result, expected);
    }

    #[test]
    fn test_construct_message_different_program_ids() {
        // Test with different program IDs
        let data = json!({"test": "data"});
        let timestamp = 1234567890;

        let result1 = construct_message("program-1", &data, timestamp).unwrap();
        let result2 = construct_message("program-2", &data, timestamp).unwrap();

        // Results should differ due to different program IDs
        assert_ne!(result1, result2);

        // But both should end with the same serialized data + timestamp
        let data_str = serialize_with_sorted_keys_for_verification(&data).unwrap();
        let expected_suffix = format!("{}{}", data_str, timestamp);
        assert!(result1.ends_with(&expected_suffix));
        assert!(result2.ends_with(&expected_suffix));
    }

    #[test]
    fn test_construct_message_different_timestamps() {
        // Test with different timestamps
        let program_id = "test-program";
        let data = json!({"test": "data"});

        let result1 = construct_message(program_id, &data, 1000).unwrap();
        let result2 = construct_message(program_id, &data, 2000).unwrap();

        // Results should differ due to different timestamps
        assert_ne!(result1, result2);

        // But both should start with the same program_id + serialized data
        let data_str = serialize_with_sorted_keys_for_verification(&data).unwrap();
        let expected_prefix = format!("{}{}", program_id, data_str);
        assert!(result1.starts_with(&expected_prefix));
        assert!(result2.starts_with(&expected_prefix));
    }

    #[test]
    fn test_construct_message_empty_program_id() {
        // Test with empty program ID
        let program_id = "";
        let data = json!({"key": "value"});
        let timestamp = 1234567890;

        let result = construct_message(program_id, &data, timestamp).unwrap();

        // Should still work, just with empty prefix
        let data_str = serialize_with_sorted_keys_for_verification(&data).unwrap();
        let expected = format!("{}{}", data_str, timestamp);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_construct_message_with_sorted_keys() {
        // Test that construct_message uses sorted keys for serialization
        let program_id = "test-program";
        let data = json!({
            "zebra": 1,
            "apple": 2,
            "banana": 3
        });
        let timestamp = 1234567890;

        let result = construct_message(program_id, &data, timestamp).unwrap();

        // The serialized data portion should have sorted keys
        let expected_data_str = serialize_with_sorted_keys_for_verification(&data).unwrap();

        // Extract the serialized data portion (between program_id and timestamp)
        let data_start = program_id.len();
        let data_end = result.len() - timestamp.to_string().len();
        let extracted_data_str = &result[data_start..data_end];

        assert_eq!(extracted_data_str, expected_data_str);
        assert_eq!(extracted_data_str, r#"{"apple":2,"banana":3,"zebra":1}"#);
    }

    #[test]
    fn test_construct_message_integration() {
        // Integration test: construct message and verify format
        let program_id = "abc-123-def";
        let data = json!({
            "msg": "Hello",
            "type": "test",
            "value": 42
        });
        let timestamp = 987654321;

        let result = construct_message(program_id, &data, timestamp).unwrap();

        // Verify the structure: program_id + sorted_json + timestamp
        // Program ID should be at the start
        assert!(result.starts_with(program_id));

        // Timestamp should be at the end
        assert!(result.ends_with(&timestamp.to_string()));

        // The middle part should be valid JSON with sorted keys
        let data_str = serialize_with_sorted_keys_for_verification(&data).unwrap();
        let expected = format!("{}{}{}", program_id, data_str, timestamp);
        assert_eq!(result, expected);
    }
}
