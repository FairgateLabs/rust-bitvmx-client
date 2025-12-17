use crate::comms_helper::{prepare_message, request, serialize_msg, CommsMessageType};
use crate::errors::BitVMXError;
use crate::keychain::KeyChain;
use crate::message_queue::MessageQueue;
use crate::program::participant::CommsAddress;
use crate::signature_verifier::SignatureVerifier;
use crate::types::ProgramContext;
use bitvmx_broker::identification::identifier::Identifier;
use bitvmx_operator_comms::operator_comms::{OperatorComms, PubKeyHash};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::rc::Rc;
use storage_backend::storage::{KeyValueStore, Storage};
use tracing::{error, info, warn};
use uuid::Uuid;

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
            return Err(BitVMXError::InvalidMessage(
                format!("No original messages").to_string(),
            ));
        }

        // Validate that all original messages have the same type as original_msg_type
        for msg in &self.original_messages {
            if msg.msg_type != self.original_msg_type {
                return Err(BitVMXError::InvalidMessage(
                    format!("Original message type mismatch: {:?}", msg.msg_type).to_string(),
                ));
            }
        }

        // Validate that there are no duplicate messages (same sender_pubkey_hash)
        let mut seen_senders = std::collections::HashSet::new();
        for msg in &self.original_messages {
            if !seen_senders.insert(&msg.sender_pubkey_hash) {
                return Err(BitVMXError::InvalidMessage(
                    format!("Duplicate original message: {:?}", msg.sender_pubkey_hash).to_string(),
                ));
            }
        }

        // Validate that the broadcast timestamp is reasonable (not negative, not too far in the future)
        if self.broadcast_timestamp < 0 {
            return Err(BitVMXError::InvalidMessage(
                format!(
                    "Broadcast timestamp is negative: {:?}",
                    self.broadcast_timestamp
                )
                .to_string(),
            ));
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
            return Err(BitVMXError::InvalidMessage(
                format!(
                    "Original timestamp is negative: {:?}",
                    self.original_timestamp
                )
                .to_string(),
            ));
        }

        // Validate that the signature is not empty
        if self.original_signature.is_empty() {
            return Err(BitVMXError::InvalidMessage(
                format!("Original signature is empty: {:?}", self.original_signature).to_string(),
            ));
        }

        // Validate that the version is not empty
        if self.version.is_empty() {
            return Err(BitVMXError::InvalidMessage(
                format!("Version is empty: {:?}", self.version).to_string(),
            ));
        }

        // Validate that the pubkey_hash is not empty
        if self.sender_pubkey_hash.is_empty() {
            return Err(BitVMXError::InvalidMessage(
                format!("Sender pubkey hash is empty: {:?}", self.sender_pubkey_hash).to_string(),
            ));
        }

        // Validate that the message type is not Broadcasted (cannot broadcast a broadcast)
        if self.msg_type == CommsMessageType::Broadcasted {
            return Err(BitVMXError::InvalidMessage(
                format!("Message type is Broadcasted: {:?}", self.msg_type).to_string(),
            ));
        }

        Ok(())
    }
}

// ============================================================================
// Leader Broadcast Helper
// ============================================================================

/// Helper function to generate storage key for original messages
fn get_original_messages_key(context_id: &Uuid, msg_type: CommsMessageType) -> String {
    format!("bitvmx/original_messages/{}/{:?}", context_id, msg_type)
}

/// Helper for managing leader broadcast functionality
/// Encapsulates storage, communication, and message queue operations
pub struct LeaderBroadcastHelper {
    store: Rc<Storage>,
}

impl LeaderBroadcastHelper {
    /// Create a new LeaderBroadcastHelper
    pub fn new(store: Rc<Storage>) -> Self {
        Self { store }
    }

    // If I'm the leader, prepare and store the message
    // If I'm not the leader, send the message to the leader
    pub fn request_or_store<T: Serialize>(
        &self,
        comms: &OperatorComms,
        key_chain: &KeyChain,
        program_id: &Uuid,
        comms_address: CommsAddress,
        msg_type: CommsMessageType,
        msg: T,
        im_leader: bool,
    ) -> Result<(), BitVMXError> {
        if im_leader {
            let (version, data, timestamp, signature) =
                prepare_message(key_chain, program_id, msg_type, msg)?;
            let original_msg = OriginalMessage {
                sender_pubkey_hash: comms.get_pubk_hash()?,
                msg_type,
                data: data.clone(),
                original_timestamp: timestamp,
                original_signature: signature.clone(),
                version: version.clone(),
            };
            self.store_original_message(program_id, msg_type, original_msg)?;
        } else {
            request(comms, key_chain, program_id, comms_address, msg_type, &msg)?;
        }
        Ok(())
    }

    /// Store an original message received from a non-leader participant
    /// Messages are stored by context_id (program_id or collaboration_id) and message type
    pub fn store_original_message(
        &self,
        context_id: &Uuid,
        msg_type: CommsMessageType,
        original_msg: OriginalMessage,
    ) -> Result<(), BitVMXError> {
        let key = get_original_messages_key(context_id, msg_type);
        let mut messages: Vec<OriginalMessage> = self.store.get(&key)?.unwrap_or_else(|| vec![]);

        // Check if message from this sender already exists
        if messages
            .iter()
            .any(|m| m.sender_pubkey_hash == original_msg.sender_pubkey_hash)
        {
            warn!(
                "Original message from {} already stored for context {} and type {:?}",
                original_msg.sender_pubkey_hash, context_id, msg_type
            );
            return Ok(()); // Don't error, just skip duplicate
        }

        messages.push(original_msg);
        self.store.set(&key, messages, None)?;
        Ok(())
    }

    /// Get all original messages stored for a given context and message type
    pub fn get_original_messages(
        &self,
        context_id: &Uuid,
        msg_type: CommsMessageType,
    ) -> Result<Vec<OriginalMessage>, BitVMXError> {
        let key = get_original_messages_key(context_id, msg_type);
        let messages: Vec<OriginalMessage> = self.store.get(&key)?.unwrap_or_else(|| vec![]);
        Ok(messages)
    }

    /// Check if all expected messages have been received
    /// expected_participants should be a list of pubkey_hashes of non-leader participants
    /// Returns an error if duplicate messages (same sender) are detected
    pub fn has_all_expected_messages(
        &self,
        context_id: &Uuid,
        msg_type: CommsMessageType,
        expected_participants: &[PubKeyHash],
    ) -> Result<bool, BitVMXError> {
        let messages = self.get_original_messages(context_id, msg_type)?;

        // Check for duplicate messages (same sender_pubkey_hash)
        let mut seen_senders = std::collections::HashSet::new();
        for msg in &messages {
            if !seen_senders.insert(&msg.sender_pubkey_hash) {
                return Err(BitVMXError::InvalidMessage(
                    format!("Duplicate original message: {:?}", msg.sender_pubkey_hash).to_string(),
                ));
            }
        }

        let received_senders: std::collections::HashSet<&PubKeyHash> =
            messages.iter().map(|m| &m.sender_pubkey_hash).collect();

        for expected in expected_participants {
            if !received_senders.contains(expected) {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Clear all stored original messages for a given context and message type
    pub fn clear_original_messages(
        &self,
        context_id: &Uuid,
        msg_type: CommsMessageType,
    ) -> Result<(), BitVMXError> {
        let key = get_original_messages_key(context_id, msg_type);
        self.store.delete(&key)?;
        Ok(())
    }

    /// Broadcast stored original messages to all non-leader participants
    /// This function:
    /// 1. Retrieves all stored original messages for the context and message type
    /// 2. Creates a BroadcastedMessage
    /// 3. Sends it to all non-leader participants
    /// 4. Clears the stored messages after successful broadcast
    pub fn broadcast_to_non_leaders(
        &self,
        program_context: &ProgramContext,
        context_id: &Uuid,
        msg_type: CommsMessageType,
        non_leader_participants: &[CommsAddress],
    ) -> Result<(), BitVMXError> {
        // Get all stored original messages
        let original_messages = self.get_original_messages(context_id, msg_type)?;

        if original_messages.is_empty() {
            warn!(
                "No original messages to broadcast for context {} and type {:?}",
                context_id, msg_type
            );
            return Ok(());
        }

        // Create BroadcastedMessage
        let broadcast_timestamp = Utc::now().timestamp_millis();
        let broadcasted_msg = BroadcastedMessage {
            original_msg_type: msg_type,
            original_messages: original_messages.clone(),
            broadcast_timestamp,
        };

        // Validate the broadcasted message
        broadcasted_msg.validate()?;

        // Send to all non-leader participants
        for participant in non_leader_participants {
            info!("Sending leader aggregated key to peer: {:?}", participant);

            request(
                &program_context.comms,
                &program_context.key_chain,
                context_id,
                participant.clone(),
                CommsMessageType::Broadcasted,
                &broadcasted_msg,
            )?;
        }

        // Clear stored messages after successful broadcast
        self.clear_original_messages(context_id, msg_type)?;

        info!(
            "Successfully broadcasted {} messages to {} non-leaders for context {} and type {:?}",
            original_messages.len(),
            non_leader_participants.len(),
            context_id,
            msg_type
        );

        Ok(())
    }

    /// Process a BroadcastedMessage by recursively processing each original message
    /// This function:
    /// 1. Deserializes the BroadcastedMessage
    /// 2. Validates the BroadcastedMessage structure
    /// 3. Verifies the leader's signature (already done in process_msg)
    /// 4. For each OriginalMessage:
    ///    - Verifies the original message signature
    ///    - Reconstructs the serialized message
    ///    - Queues the message for processing
    pub fn process_broadcasted_message(
        &self,
        program_context: &ProgramContext,
        leader_identifier: Identifier,
        program_id: Uuid,
        data: Value,
        message_queue: &MessageQueue,
    ) -> Result<(), BitVMXError> {
        // Deserialize BroadcastedMessage from data
        let broadcasted_msg: BroadcastedMessage =
            serde_json::from_value(data.clone()).map_err(|e| {
                error!("Failed to deserialize BroadcastedMessage: {:?}", e);
                BitVMXError::InvalidMessage(
                    format!("Failed to deserialize BroadcastedMessage: {:?}", e).to_string(),
                )
            })?;

        // Validate the BroadcastedMessage structure
        broadcasted_msg.validate()?;

        info!(
            "Processing BroadcastedMessage from leader {} for context {} with {} original messages",
            leader_identifier.pubkey_hash,
            program_id,
            broadcasted_msg.original_messages.len()
        );

        // Process each original message recursively
        for original_msg in &broadcasted_msg.original_messages {
            // Verify the original message signature
            let original_verified = Self::verify_original_message_signature(
                program_context,
                &original_msg.sender_pubkey_hash,
                &program_id,
                &original_msg.version,
                &original_msg.msg_type,
                &original_msg.data,
                original_msg.original_timestamp,
                &original_msg.original_signature,
            )?;

            if !original_verified {
                warn!(
                    "Original message from {} failed signature verification, skipping",
                    original_msg.sender_pubkey_hash
                );
                continue;
            }

            // Reconstruct the full serialized message from OriginalMessage
            let full_message = serialize_msg(
                &original_msg.version,
                original_msg.msg_type,
                &program_id,
                &original_msg.data,
                original_msg.original_timestamp,
                original_msg.original_signature.clone(),
            )?;

            info!(
                "Pending message to back: {:?} from {}",
                original_msg.msg_type, original_msg.sender_pubkey_hash
            );
            message_queue.push_back(
                Identifier::new(original_msg.sender_pubkey_hash.clone(), 0).to_string(),
                full_message,
            )?;
        }

        info!(
            "Successfully queued BroadcastedMessage from leader {} with {} original messages",
            leader_identifier.pubkey_hash,
            broadcasted_msg.original_messages.len()
        );

        Ok(())
    }

    /// Verify the signature of an original message
    /// This is similar to verify_message_signature but works with OriginalMessage data
    fn verify_original_message_signature(
        program_context: &ProgramContext,
        sender_pubkey_hash: &PubKeyHash,
        program_id: &Uuid,
        version: &String,
        msg_type: &CommsMessageType,
        data: &Value,
        timestamp: i64,
        signature: &Vec<u8>,
    ) -> Result<bool, BitVMXError> {
        match SignatureVerifier::verify_and_get_key(
            &program_context.comms,
            &program_context.globals,
            &program_context.key_chain,
            sender_pubkey_hash,
            program_id,
            msg_type,
            data,
            timestamp,
            signature,
            version,
        ) {
            Ok(_) => Ok(true),
            Err(BitVMXError::MissingVerificationKey { .. }) => Ok(false),
            Err(err) => Err(err),
        }
    }
}

/// Get list of non-leader participants from a list of all participants
/// Returns CommsAddress of all participants except the leader
pub fn get_non_leader_participants(
    all_participants: &[CommsAddress],
    leader_pubkey_hash: &PubKeyHash,
) -> Vec<CommsAddress> {
    all_participants
        .iter()
        .filter(|p| &p.pubkey_hash != leader_pubkey_hash)
        .cloned()
        .collect()
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
