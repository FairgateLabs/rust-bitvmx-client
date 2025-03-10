use crate::{errors::BitVMXError, program::participant::P2PAddress};
use p2p_handler::{P2pHandler, PeerId};
use serde::Serialize;
use serde_json::{json, Value};
use uuid::Uuid;

const MIN_EXPECTED_MSG_LEN: usize = 4; // 2 bytes for version + 2 bytes for message type
const MAX_EXPECTED_MSG_LEN: usize = 1000000; // Maximum length for a message //TODO: Change this value

pub fn request<T: Serialize>(
    comms: &P2pHandler,
    program_id: &Uuid,
    p2p_address: P2PAddress,
    msg_type: P2PMessageType,
    msg: T,
) -> Result<(), BitVMXError> {
    let serialize_msg = serialize_msg(msg_type, program_id, msg)?;
    comms
        .request(p2p_address.peer_id, p2p_address.address, serialize_msg)
        .unwrap();
    Ok(())
}

pub fn response<T: Serialize>(
    comms: &P2pHandler,
    program_id: &Uuid,
    peer_id: PeerId,
    msg_type: P2PMessageType,
    msg: T,
) -> Result<(), BitVMXError> {
    let serialize_msg = serialize_msg(msg_type, program_id, msg)?;
    comms.response(peer_id, serialize_msg).unwrap();
    Ok(())
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum P2PMessageType {
    Keys,
    KeysAck,
    PublicNonces,
    PublicNoncesAck,
    PartialSignatures,
    PartialSignaturesAck,
}

impl P2PMessageType {
    // Define a mapping between message kinds and their byte representations
    const KIND_MAP: &'static [(&'static P2PMessageType, [u8; 2])] = &[
        (&P2PMessageType::Keys, [0x00, 0x01]),
        (&P2PMessageType::KeysAck, [0x00, 0x02]),
        (&P2PMessageType::PublicNonces, [0x00, 0x03]),
        (&P2PMessageType::PublicNoncesAck, [0x00, 0x04]),
        (&P2PMessageType::PartialSignatures, [0x00, 0x05]),
        (&P2PMessageType::PartialSignaturesAck, [0x00, 0x06]),
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
    msg_type: P2PMessageType,
    program_id: &Uuid,
    data: T,
) -> Result<Vec<u8>, BitVMXError> {
    let version = "1.0";
    // Convert version and message type to bytes
    let version_bytes = Version::to_bytes(version)?;
    let msg_type_bytes = msg_type.to_bytes()?;

    // Serialize the payload as JSON
    let payload = json!({
        "program_id": program_id.to_string(),
        "msg": data,
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
) -> Result<(String, P2PMessageType, Uuid, Value), BitVMXError> {
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
    let msg_type = P2PMessageType::from_bytes(msg_type_bytes)?;

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

    Ok((version, msg_type, program_id, data.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_p2p_message_kind_to_bytes() {
        assert_eq!(P2PMessageType::Keys.to_bytes().unwrap(), [0x00, 0x01]);
        assert_eq!(P2PMessageType::KeysAck.to_bytes().unwrap(), [0x00, 0x02]);
        assert_eq!(
            P2PMessageType::PublicNonces.to_bytes().unwrap(),
            [0x00, 0x03]
        );
        assert_eq!(
            P2PMessageType::PublicNoncesAck.to_bytes().unwrap(),
            [0x00, 0x04]
        );
        assert_eq!(
            P2PMessageType::PartialSignatures.to_bytes().unwrap(),
            [0x00, 0x05]
        );
        assert_eq!(
            P2PMessageType::PartialSignaturesAck.to_bytes().unwrap(),
            [0x00, 0x06]
        );
    }

    #[test]
    fn test_p2p_message_kind_from_bytes() {
        assert_eq!(
            P2PMessageType::from_bytes([0x00, 0x01]).unwrap(),
            P2PMessageType::Keys
        );
        assert_eq!(
            P2PMessageType::from_bytes([0x00, 0x02]).unwrap(),
            P2PMessageType::KeysAck
        );
        assert_eq!(
            P2PMessageType::from_bytes([0x00, 0x03]).unwrap(),
            P2PMessageType::PublicNonces
        );
        assert_eq!(
            P2PMessageType::from_bytes([0x00, 0x04]).unwrap(),
            P2PMessageType::PublicNoncesAck
        );
        assert_eq!(
            P2PMessageType::from_bytes([0x00, 0x05]).unwrap(),
            P2PMessageType::PartialSignatures
        );
        assert_eq!(
            P2PMessageType::from_bytes([0x00, 0x06]).unwrap(),
            P2PMessageType::PartialSignaturesAck
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
        let msg_type = P2PMessageType::Keys;
        let program_id = Uuid::new_v4();
        let msg = vec![0x01, 0x02, 0x03];

        let result = serialize_msg(msg_type.clone(), &program_id, msg.clone()).unwrap();

        let expected_version = Version::to_bytes(version).unwrap();
        let expected_msg_type = msg_type.to_bytes().unwrap();
        let expected_payload = json!({
            "program_id": program_id.to_string(),
            "msg": msg,
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
        let msg_type = P2PMessageType::Keys;
        let program_id = Uuid::new_v4();
        let msg = "Hello, world!";

        let serialized_msg = serialize_msg(msg_type.clone(), &program_id, msg.clone()).unwrap();
        let (
            deserialized_version,
            deserialized_msg_type,
            deserialized_program_id,
            deserialized_msg,
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
    //     let msg_type = P2PMessageType::Keys;
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
}
