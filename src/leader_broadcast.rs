use crate::comms_helper::CommsMessageType;
use crate::errors::BitVMXError;
use bitvmx_operator_comms::operator_comms::PubKeyHash;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Message containing all original messages received by the leader
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BroadcastedMessage {
    /// Type of original message being broadcast (Keys, PublicNonces, etc.)
    pub original_msg_type: CommsMessageType,

    /// List of original messages received, with their sender and data
    /// Each original message can be processed individually by process_msg
    pub original_messages: Vec<OriginalMessage>,

    /// Timestamp when the leader created this broadcast
    pub broadcast_timestamp: i64,
}

/// Represents an original message received by the leader
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OriginalMessage {
    /// Hash of the original sender's pubkey
    pub sender_pubkey_hash: PubKeyHash,

    /// Type of original message (must match original_msg_type of BroadcastedMessage)
    pub msg_type: CommsMessageType,

    /// Original message data (unmodified)
    pub data: Value,

    /// Original message timestamp
    pub original_timestamp: i64,

    /// Original message signature (for additional verification)
    pub original_signature: Vec<u8>,

    /// Protocol version of the original message
    pub version: String,
}

impl BroadcastedMessage {
    /// Validates that the BroadcastedMessage is valid
    pub fn validate(&self) -> Result<(), BitVMXError> {
        // Validate that there is at least one original message
        if self.original_messages.is_empty() {
            return Err(BitVMXError::InvalidMessageFormat);
        }

        // Validate that all original messages have the same type as original_msg_type
        for msg in &self.original_messages {
            if msg.msg_type != self.original_msg_type {
                return Err(BitVMXError::InvalidMessageFormat);
            }
        }

        // Validate that there are no duplicate messages (same sender_pubkey_hash)
        let mut seen_senders = std::collections::HashSet::new();
        for msg in &self.original_messages {
            if !seen_senders.insert(&msg.sender_pubkey_hash) {
                return Err(BitVMXError::InvalidMessageFormat);
            }
        }

        // Validate that the broadcast timestamp is reasonable (not negative, not too far in the future)
        if self.broadcast_timestamp < 0 {
            return Err(BitVMXError::InvalidMessageFormat);
        }

        // Validate each original message
        for msg in &self.original_messages {
            msg.validate()?;
        }

        Ok(())
    }
}

impl OriginalMessage {
    /// Validates that the OriginalMessage is valid
    pub fn validate(&self) -> Result<(), BitVMXError> {
        // Validate that the timestamp is not negative
        if self.original_timestamp < 0 {
            return Err(BitVMXError::InvalidMessageFormat);
        }

        // Validate that the signature is not empty
        if self.original_signature.is_empty() {
            return Err(BitVMXError::InvalidMessageFormat);
        }

        // Validate that the version is not empty
        if self.version.is_empty() {
            return Err(BitVMXError::InvalidMessageFormat);
        }

        // Validate that the pubkey_hash is not empty
        if self.sender_pubkey_hash.is_empty() {
            return Err(BitVMXError::InvalidMessageFormat);
        }

        // Validate that the message type is not Broadcasted (cannot broadcast a broadcast)
        if self.msg_type == CommsMessageType::Broadcasted {
            return Err(BitVMXError::InvalidMessageFormat);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_broadcasted_message_validation_empty_messages() {
        let msg = BroadcastedMessage {
            original_msg_type: CommsMessageType::Keys,
            original_messages: vec![],
            broadcast_timestamp: 1234567890,
        };
        assert!(msg.validate().is_err());
    }

    #[test]
    fn test_broadcasted_message_validation_mismatched_types() {
        let msg = BroadcastedMessage {
            original_msg_type: CommsMessageType::Keys,
            original_messages: vec![OriginalMessage {
                sender_pubkey_hash: "test_hash".to_string(),
                msg_type: CommsMessageType::PublicNonces, // Different type
                data: json!({}),
                original_timestamp: 1234567890,
                original_signature: vec![1, 2, 3],
                version: "1.0".to_string(),
            }],
            broadcast_timestamp: 1234567890,
        };
        assert!(msg.validate().is_err());
    }

    #[test]
    fn test_broadcasted_message_validation_duplicate_senders() {
        let msg = BroadcastedMessage {
            original_msg_type: CommsMessageType::Keys,
            original_messages: vec![
                OriginalMessage {
                    sender_pubkey_hash: "test_hash".to_string(),
                    msg_type: CommsMessageType::Keys,
                    data: json!({}),
                    original_timestamp: 1234567890,
                    original_signature: vec![1, 2, 3],
                    version: "1.0".to_string(),
                },
                OriginalMessage {
                    sender_pubkey_hash: "test_hash".to_string(), // Duplicate
                    msg_type: CommsMessageType::Keys,
                    data: json!({}),
                    original_timestamp: 1234567890,
                    original_signature: vec![4, 5, 6],
                    version: "1.0".to_string(),
                },
            ],
            broadcast_timestamp: 1234567890,
        };
        assert!(msg.validate().is_err());
    }

    #[test]
    fn test_broadcasted_message_validation_valid() {
        let msg = BroadcastedMessage {
            original_msg_type: CommsMessageType::Keys,
            original_messages: vec![OriginalMessage {
                sender_pubkey_hash: "test_hash".to_string(),
                msg_type: CommsMessageType::Keys,
                data: json!({}),
                original_timestamp: 1234567890,
                original_signature: vec![1, 2, 3],
                version: "1.0".to_string(),
            }],
            broadcast_timestamp: 1234567890,
        };
        assert!(msg.validate().is_ok());
    }

    #[test]
    fn test_original_message_validation_empty_signature() {
        let msg = OriginalMessage {
            sender_pubkey_hash: "test_hash".to_string(),
            msg_type: CommsMessageType::Keys,
            data: json!({}),
            original_timestamp: 1234567890,
            original_signature: vec![], // Empty
            version: "1.0".to_string(),
        };
        assert!(msg.validate().is_err());
    }

    #[test]
    fn test_original_message_validation_empty_version() {
        let msg = OriginalMessage {
            sender_pubkey_hash: "test_hash".to_string(),
            msg_type: CommsMessageType::Keys,
            data: json!({}),
            original_timestamp: 1234567890,
            original_signature: vec![1, 2, 3],
            version: "".to_string(), // Empty
        };
        assert!(msg.validate().is_err());
    }

    #[test]
    fn test_original_message_validation_negative_timestamp() {
        let msg = OriginalMessage {
            sender_pubkey_hash: "test_hash".to_string(),
            msg_type: CommsMessageType::Keys,
            data: json!({}),
            original_timestamp: -1, // Negative
            original_signature: vec![1, 2, 3],
            version: "1.0".to_string(),
        };
        assert!(msg.validate().is_err());
    }

    #[test]
    fn test_original_message_validation_broadcasted_type() {
        let msg = OriginalMessage {
            sender_pubkey_hash: "test_hash".to_string(),
            msg_type: CommsMessageType::Broadcasted, // Not allowed
            data: json!({}),
            original_timestamp: 1234567890,
            original_signature: vec![1, 2, 3],
            version: "1.0".to_string(),
        };
        assert!(msg.validate().is_err());
    }

    #[test]
    fn test_original_message_validation_valid() {
        let msg = OriginalMessage {
            sender_pubkey_hash: "test_hash".to_string(),
            msg_type: CommsMessageType::Keys,
            data: json!({}),
            original_timestamp: 1234567890,
            original_signature: vec![1, 2, 3],
            version: "1.0".to_string(),
        };
        assert!(msg.validate().is_ok());
    }

    #[test]
    fn test_broadcasted_message_serialization() {
        let msg = BroadcastedMessage {
            original_msg_type: CommsMessageType::Keys,
            original_messages: vec![OriginalMessage {
                sender_pubkey_hash: "test_hash".to_string(),
                msg_type: CommsMessageType::Keys,
                data: json!({"key": "value"}),
                original_timestamp: 1234567890,
                original_signature: vec![1, 2, 3],
                version: "1.0".to_string(),
            }],
            broadcast_timestamp: 1234567890,
        };

        // Serialize
        let serialized = serde_json::to_string(&msg).unwrap();
        assert!(!serialized.is_empty());

        // Deserialize
        let deserialized: BroadcastedMessage = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.original_msg_type, msg.original_msg_type);
        assert_eq!(
            deserialized.original_messages.len(),
            msg.original_messages.len()
        );
        assert_eq!(
            deserialized.original_messages[0].sender_pubkey_hash,
            msg.original_messages[0].sender_pubkey_hash
        );
    }

    #[test]
    fn test_original_message_serialization() {
        let msg = OriginalMessage {
            sender_pubkey_hash: "test_hash".to_string(),
            msg_type: CommsMessageType::Keys,
            data: json!({"key": "value"}),
            original_timestamp: 1234567890,
            original_signature: vec![1, 2, 3, 4, 5],
            version: "1.0".to_string(),
        };

        // Serialize
        let serialized = serde_json::to_string(&msg).unwrap();
        assert!(!serialized.is_empty());

        // Deserialize
        let deserialized: OriginalMessage = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.sender_pubkey_hash, msg.sender_pubkey_hash);
        assert_eq!(deserialized.msg_type, msg.msg_type);
        assert_eq!(deserialized.original_timestamp, msg.original_timestamp);
        assert_eq!(deserialized.original_signature, msg.original_signature);
        assert_eq!(deserialized.version, msg.version);
    }
}
