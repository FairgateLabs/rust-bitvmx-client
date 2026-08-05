use crate::comms_helper::{request, serialize_msg, CommsMessageType};
use crate::errors::BitVMXError;
use crate::message_queue::MessageQueue;
use crate::ports::bitcoin_coordinator::BitcoinCoordinatorApi;
use crate::program::participant::CommsAddress;
use crate::signature_verifier::SignatureVerifier;
use crate::types::ProgramContext;
use bitvmx_broker::identification::identifier::{Identifier, PubkHash};
use bitvmx_broker::settings::COMMS_ID;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;
use std::rc::Rc;
use storage_backend::storage::{KeyValueStore, Storage};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// Message containing all original messages received by the leader
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BroadcastedMessage {
    /// Type of original message being broadcast (Keys, PublicNonces, etc.)
    pub original_msg_type: CommsMessageType,

    /// List of original messages received, with their sender and data
    /// Each original message can be processed individually by process_msg
    pub original_messages: Vec<OriginalMessage>,
}

/// Represents an original message received by the leader
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OriginalMessage {
    /// Hash of the original sender's pubkey
    pub sender_pubkey_hash: PubkHash,

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
                "No original messages".to_string(),
            ));
        }

        // Single pass over the messages: type matches original_msg_type,
        // no duplicate senders, and each message is valid on its own
        let mut seen_senders = HashSet::new();
        for msg in &self.original_messages {
            if msg.msg_type != self.original_msg_type {
                return Err(BitVMXError::InvalidMessage(format!(
                    "Original message type mismatch: {:?}",
                    msg.msg_type
                )));
            }
            if !seen_senders.insert(&msg.sender_pubkey_hash) {
                return Err(BitVMXError::InvalidMessage(format!(
                    "Duplicate original message: {:?}",
                    msg.sender_pubkey_hash
                )));
            }
            msg.validate()?;
        }

        Ok(())
    }
}

impl OriginalMessage {
    /// Validates that the OriginalMessage is valid
    pub fn validate(&self) -> Result<(), BitVMXError> {
        // Validate that the signature is not empty
        if self.original_signature.is_empty() {
            return Err(BitVMXError::InvalidMessage(format!(
                "Original signature is empty: {:?}",
                self.original_signature
            )));
        }

        // Validate that the version is not empty
        if self.version.is_empty() {
            return Err(BitVMXError::InvalidMessage(format!(
                "Version is empty: {:?}",
                self.version
            )));
        }

        // Validate that the pubkey_hash is not empty
        if self.sender_pubkey_hash.is_empty() {
            return Err(BitVMXError::InvalidMessage(format!(
                "Sender pubkey hash is empty: {:?}",
                self.sender_pubkey_hash
            )));
        }

        // Validate that the message type is not Broadcasted (cannot broadcast a broadcast)
        if self.msg_type == CommsMessageType::Broadcasted {
            return Err(BitVMXError::InvalidMessage(format!(
                "Message type is Broadcasted: {:?}",
                self.msg_type
            )));
        }

        Ok(())
    }
}

// ============================================================================
// Leader Broadcast Helper
// ============================================================================

/// Helper function to generate storage key prefix for original messages
/// Used to iterate over all messages for a given context and message type
fn get_original_messages_prefix(context_id: &Uuid, msg_type: CommsMessageType) -> String {
    format!("bitvmx/original_messages/{}/{:?}/", context_id, msg_type)
}

/// Helper function to generate storage key for a specific original message
/// Format: bitvmx/original_messages/{context_id}/{msg_type}/{pub_key_hash}
fn get_original_message_key(
    context_id: &Uuid,
    msg_type: CommsMessageType,
    pub_key_hash: &PubkHash,
) -> String {
    format!(
        "bitvmx/original_messages/{}/{:?}/{}",
        context_id, msg_type, pub_key_hash
    )
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

    /// Store an original message received from a non-leader participant
    /// Messages are stored individually by context_id, message type, and pub_key_hash
    /// This avoids serializing/deserializing all messages when adding a new one
    pub fn store_original_message(
        &self,
        context_id: &Uuid,
        msg_type: CommsMessageType,
        original_msg: OriginalMessage,
    ) -> Result<bool, BitVMXError> {
        // Reject invalid messages at the boundary, before they reach storage.
        // A stored invalid message would make broadcast_to_non_leaders fail on
        // every attempt, with the error attributed to the wrong place.
        original_msg.validate()?;
        if original_msg.msg_type != msg_type {
            return Err(BitVMXError::InvalidMessage(format!(
                "Original message type mismatch: expected {:?}, got {:?}",
                msg_type, original_msg.msg_type
            )));
        }

        let key = get_original_message_key(context_id, msg_type, &original_msg.sender_pubkey_hash);

        debug!("New message: {:?}", original_msg.msg_type);
        // Check if message from this sender already exists
        let existing: Option<OriginalMessage> = self.store.get(&key, None)?;
        if existing.is_some() {
            warn!(
                "Original message from {} already stored for context {} and type {:?}",
                original_msg.sender_pubkey_hash, context_id, msg_type
            );
            return Ok(false); // Don't error, just skip duplicate
        }

        // Store the message directly - O(1) operation, only serializes this one message
        self.store.set(&key, original_msg, None)?;
        Ok(true)
    }

    /// Get all original messages stored for a given context and message type
    /// Iterates over all keys with the prefix to collect individual messages
    /// Each message is deserialized individually, avoiding large bulk operations
    fn get_original_messages(
        &self,
        context_id: &Uuid,
        msg_type: CommsMessageType,
    ) -> Result<Vec<OriginalMessage>, BitVMXError> {
        let prefix = get_original_messages_prefix(context_id, msg_type);
        let stored_messages = self.store.partial_compare(&prefix, None)?;

        let mut messages = Vec::new();
        for (_, msg_json) in stored_messages.iter() {
            // Deserialize each message individually
            let msg: OriginalMessage = serde_json::from_str(msg_json).map_err(|e| {
                BitVMXError::InvalidMessage(format!(
                    "Failed to deserialize original message: {:?}",
                    e
                ))
            })?;
            messages.push(msg);
        }

        Ok(messages)
    }

    /// Check if all expected messages have been received
    /// expected_participants should be a list of pubkey_hashes of non-leader participants
    ///
    /// No duplicate-sender check is needed here: messages are stored under a key
    /// that includes the sender's pubkey hash (see get_original_message_key), so
    /// storage can hold at most one message per sender. Duplicates crafted by a
    /// malicious leader are caught on the receiving side by
    /// BroadcastedMessage::validate.
    pub fn has_all_expected_messages(
        &self,
        context_id: &Uuid,
        msg_type: CommsMessageType,
        expected_participants: &[PubkHash],
    ) -> Result<bool, BitVMXError> {
        let messages = self.get_original_messages(context_id, msg_type)?;
        let received_senders: HashSet<&PubkHash> =
            messages.iter().map(|m| &m.sender_pubkey_hash).collect();

        Ok(expected_participants
            .iter()
            .all(|expected| received_senders.contains(expected)))
    }

    /// Clear all stored original messages for a given context and message type
    /// Deletes all individual message keys with the matching prefix
    fn clear_original_messages(
        &self,
        context_id: &Uuid,
        msg_type: CommsMessageType,
    ) -> Result<(), BitVMXError> {
        let prefix = get_original_messages_prefix(context_id, msg_type);
        let stored_messages = self.store.partial_compare(&prefix, None)?;

        // Delete each individual message key
        for (key, _) in stored_messages.iter() {
            self.store.remove(key, None)?;
        }

        Ok(())
    }

    /// Broadcast stored original messages to all non-leader participants
    /// This function:
    /// 1. Retrieves all stored original messages for the context and message type
    /// 2. Creates a BroadcastedMessage
    /// 3. Sends it to all non-leader participants
    /// 4. Clears the stored messages after successful broadcast
    pub fn broadcast_to_non_leaders<BC: BitcoinCoordinatorApi>(
        &self,
        program_context: &ProgramContext<BC>,
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

        // Validate the full message set before sending anything
        let broadcasted_msg = BroadcastedMessage {
            original_msg_type: msg_type,
            original_messages,
        };
        broadcasted_msg.validate()?;

        // Send to all non-leader participants, excluding each participant's
        // own message from the copy it receives
        for participant in non_leader_participants {
            let msg_for_participant = BroadcastedMessage {
                original_msg_type: msg_type,
                original_messages: broadcasted_msg
                    .original_messages
                    .iter()
                    .filter(|m| m.sender_pubkey_hash != participant.pubkey_hash)
                    .cloned()
                    .collect(),
            };

            request(
                &program_context.comms,
                &program_context.key_manager,
                &program_context.rsa_public_key,
                context_id,
                participant.clone(),
                CommsMessageType::Broadcasted,
                &msg_for_participant,
            )?;
        }

        // Clear stored messages after successful broadcast
        self.clear_original_messages(context_id, msg_type)?;

        info!(
            "Successfully broadcasted {} messages to {} non-leaders for context {} and type {:?}",
            broadcasted_msg.original_messages.len(),
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
    pub fn process_broadcasted_message<BC: BitcoinCoordinatorApi>(
        &self,
        program_context: &ProgramContext<BC>,
        leader_identifier: Identifier,
        program_id: Uuid,
        data: Value,
        message_queue: &MessageQueue,
    ) -> Result<(), BitVMXError> {
        // Deserialize BroadcastedMessage from data
        let broadcasted_msg: BroadcastedMessage = serde_json::from_value(data).map_err(|e| {
            error!("Failed to deserialize BroadcastedMessage: {:?}", e);
            BitVMXError::InvalidMessage(format!(
                "Failed to deserialize BroadcastedMessage: {:?}",
                e
            ))
        })?;

        // Validate the BroadcastedMessage structure
        broadcasted_msg.validate()?;

        info!(
            "Processing BroadcastedMessage from leader {} for context {} with {} original messages",
            leader_identifier.pubkey_hash,
            program_id,
            broadcasted_msg.original_messages.len()
        );

        // Phase 1: verify and reconstruct every original message before queueing
        // anything, so an invalid message rejects the whole broadcast atomically
        // and nothing from it enters the system.
        let mut queued_messages = Vec::with_capacity(broadcasted_msg.original_messages.len());
        for original_msg in &broadcasted_msg.original_messages {
            // Verify the original message signature
            let original_verified = Self::verify_original_message_signature(
                program_context,
                &program_id,
                original_msg,
            )?;

            if !original_verified {
                warn!(
                    "Original message from {} failed signature verification (missing key). Added to the queue to be retried later",
                    original_msg.sender_pubkey_hash
                );
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

            queued_messages.push((
                Identifier::new(original_msg.sender_pubkey_hash.clone(), COMMS_ID),
                full_message,
            ));
        }

        // Phase 2: all messages passed, queue them for processing
        for (original_msg, (identifier, full_message)) in broadcasted_msg
            .original_messages
            .iter()
            .zip(queued_messages)
        {
            info!(
                "Pending message to back: {:?} from {}",
                original_msg.msg_type, original_msg.sender_pubkey_hash
            );
            message_queue.push_new(identifier, full_message)?;
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
    fn verify_original_message_signature<BC: BitcoinCoordinatorApi>(
        program_context: &ProgramContext<BC>,
        program_id: &Uuid,
        original_msg: &OriginalMessage,
    ) -> Result<bool, BitVMXError> {
        match SignatureVerifier::verify_and_get_key(
            &program_context.comms,
            &program_context.globals,
            &program_context.rsa_public_key,
            &original_msg.sender_pubkey_hash,
            program_id,
            &original_msg.msg_type,
            &original_msg.data,
            original_msg.original_timestamp,
            &original_msg.original_signature,
            &original_msg.version,
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
    leader_pubkey_hash: &PubkHash,
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
    use crate::comms_helper::{deserialize_msg, prepare_message};
    use crate::signature_verifier::OperatorVerificationStore;
    use crate::test_utils::{TestProgramContextEnv, TestStorageDir};
    use bitvmx_broker::retry::RetryPolicy;
    use bitvmx_broker::rpc::config::BrokerNodeConfig;
    use serde_json::json;

    const MAX_MSG_LEN_KB: usize = 200000;

    fn test_message_queue(store: Rc<Storage>) -> MessageQueue {
        MessageQueue::new(
            store,
            RetryPolicy::new(&BrokerNodeConfig::default()).unwrap(),
        )
    }

    fn test_original_message(sender: &str) -> OriginalMessage {
        OriginalMessage {
            sender_pubkey_hash: sender.to_string(),
            msg_type: CommsMessageType::Keys,
            data: json!({"key": "value"}),
            original_timestamp: 1234567890,
            original_signature: vec![1, 2, 3],
            version: "1.0".to_string(),
        }
    }

    #[test]
    fn store_original_message_rejects_invalid_message() {
        let dir = TestStorageDir::new("leader-broadcast-invalid");
        let helper = LeaderBroadcastHelper::new(dir.storage());
        let context_id = Uuid::new_v4();

        let mut msg = test_original_message("sender");
        msg.original_signature = vec![];
        assert!(helper
            .store_original_message(&context_id, CommsMessageType::Keys, msg)
            .is_err());

        // The invalid message must not reach storage
        assert!(helper
            .get_original_messages(&context_id, CommsMessageType::Keys)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn store_original_message_rejects_type_mismatch() {
        let dir = TestStorageDir::new("leader-broadcast-mismatch");
        let helper = LeaderBroadcastHelper::new(dir.storage());
        let context_id = Uuid::new_v4();

        let msg = test_original_message("sender");
        assert!(helper
            .store_original_message(&context_id, CommsMessageType::PublicNonces, msg)
            .is_err());
    }

    /// has_all_expected_messages performs no duplicate-sender check because
    /// storage keys include the sender's pubkey hash, making duplicates
    /// impossible. This test guards that invariant: if it ever fails, the
    /// duplicate check must be reinstated there.
    #[test]
    fn store_original_message_upholds_unique_sender_invariant() {
        let dir = TestStorageDir::new("leader-broadcast-unique");
        let helper = LeaderBroadcastHelper::new(dir.storage());
        let context_id = Uuid::new_v4();

        assert!(helper
            .store_original_message(
                &context_id,
                CommsMessageType::Keys,
                test_original_message("alice")
            )
            .unwrap());

        // Repeated stores from the same sender, with different payloads
        for i in 0..3u8 {
            let mut msg = test_original_message("alice");
            msg.original_signature = vec![i + 10];
            let stored = helper
                .store_original_message(&context_id, CommsMessageType::Keys, msg)
                .unwrap();
            assert!(!stored, "invariant broken: duplicate sender was stored");
        }

        let messages = helper
            .get_original_messages(&context_id, CommsMessageType::Keys)
            .unwrap();
        let unique_senders: HashSet<_> = messages.iter().map(|m| &m.sender_pubkey_hash).collect();
        assert_eq!(
            unique_senders.len(),
            messages.len(),
            "invariant broken: storage returned duplicate senders; \
             has_all_expected_messages relies on one message per sender"
        );
        assert_eq!(
            messages.len(),
            1,
            "invariant broken: expected exactly one stored message for the sender"
        );
    }

    #[test]
    fn store_original_message_skips_duplicates_and_tracks_expected() {
        let dir = TestStorageDir::new("leader-broadcast-store");
        let helper = LeaderBroadcastHelper::new(dir.storage());
        let context_id = Uuid::new_v4();
        let expected = ["alice".to_string(), "bob".to_string()];

        assert!(helper
            .store_original_message(
                &context_id,
                CommsMessageType::Keys,
                test_original_message("alice")
            )
            .unwrap());

        // Duplicate sender is skipped without error
        assert!(!helper
            .store_original_message(
                &context_id,
                CommsMessageType::Keys,
                test_original_message("alice")
            )
            .unwrap());

        assert!(!helper
            .has_all_expected_messages(&context_id, CommsMessageType::Keys, &expected)
            .unwrap());

        assert!(helper
            .store_original_message(
                &context_id,
                CommsMessageType::Keys,
                test_original_message("bob")
            )
            .unwrap());

        assert!(helper
            .has_all_expected_messages(&context_id, CommsMessageType::Keys, &expected)
            .unwrap());
    }

    #[test]
    fn test_broadcasted_message_validation_empty_messages() {
        let msg = BroadcastedMessage {
            original_msg_type: CommsMessageType::Keys,
            original_messages: vec![],
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
    fn test_original_message_validation_empty_pubkey_hash() {
        let mut msg = test_original_message("");
        msg.sender_pubkey_hash = String::new();
        assert!(msg.validate().is_err());
    }

    #[test]
    fn get_original_messages_surfaces_corrupt_stored_entry() {
        let dir = TestStorageDir::new("leader-broadcast-corrupt");
        let storage = dir.storage();
        let helper = LeaderBroadcastHelper::new(storage.clone());
        let context_id = Uuid::new_v4();

        // Write a value under the messages prefix that is not an
        // OriginalMessage, bypassing store_original_message validation.
        let key = get_original_message_key(&context_id, CommsMessageType::Keys, &"alice".into());
        storage.set(&key, 42u32, None).unwrap();

        assert!(helper
            .get_original_messages(&context_id, CommsMessageType::Keys)
            .is_err());
        // Callers relying on the readback see the same error instead of a
        // silently wrong completeness answer
        assert!(helper
            .has_all_expected_messages(&context_id, CommsMessageType::Keys, &["alice".into()])
            .is_err());
    }

    #[test]
    fn get_non_leader_participants_filters_out_leader() {
        let leader = CommsAddress::new("127.0.0.1:1000".parse().unwrap(), "leader".into());
        let bob = CommsAddress::new("127.0.0.1:1001".parse().unwrap(), "bob".into());
        let carol = CommsAddress::new("127.0.0.1:1002".parse().unwrap(), "carol".into());

        let non_leaders = get_non_leader_participants(
            &[leader.clone(), bob.clone(), carol.clone()],
            &leader.pubkey_hash,
        );

        let hashes: Vec<_> = non_leaders.iter().map(|p| p.pubkey_hash.as_str()).collect();
        assert_eq!(hashes, vec!["bob", "carol"]);
    }

    #[test]
    fn broadcast_sends_filtered_envelope_to_each_peer_and_clears_storage() {
        let mut env = TestProgramContextEnv::new_with_peers("leader-broadcast-send", 2).unwrap();
        let context_id = Uuid::new_v4();
        let peer0 = env.peer_address(0).unwrap();
        let peer1 = env.peer_address(1).unwrap();
        let helper = &env.context.leader_broadcast_helper;

        for peer in [&peer0, &peer1] {
            assert!(helper
                .store_original_message(
                    &context_id,
                    CommsMessageType::Keys,
                    test_original_message(&peer.pubkey_hash),
                )
                .unwrap());
        }

        helper
            .broadcast_to_non_leaders(
                &env.context,
                &context_id,
                CommsMessageType::Keys,
                &[peer0.clone(), peer1.clone()],
            )
            .unwrap();

        // Each peer receives a Broadcasted envelope from the leader that
        // excludes its own contribution and carries the other peer's message
        let leader_hash = env.context.comms.get_pubk_hash().unwrap();
        for (index, own, other) in [(0, &peer0, &peer1), (1, &peer1, &peer0)] {
            let (sender, raw) = env.receive_via_peer(index).unwrap();
            assert_eq!(sender.pubkey_hash, leader_hash);

            let (_, msg_type, received_context, data, _, _) =
                deserialize_msg(raw, MAX_MSG_LEN_KB).unwrap();
            assert_eq!(msg_type, CommsMessageType::Broadcasted);
            assert_eq!(received_context, context_id);

            let broadcast: BroadcastedMessage = serde_json::from_value(data).unwrap();
            assert_eq!(broadcast.original_msg_type, CommsMessageType::Keys);
            let senders: Vec<_> = broadcast
                .original_messages
                .iter()
                .map(|m| m.sender_pubkey_hash.as_str())
                .collect();
            assert_eq!(senders, vec![other.pubkey_hash.as_str()]);
            assert!(!senders.contains(&own.pubkey_hash.as_str()));
        }

        // Stored messages are cleared after a successful broadcast
        assert!(env
            .context
            .leader_broadcast_helper
            .get_original_messages(&context_id, CommsMessageType::Keys)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn broadcast_with_no_stored_messages_sends_nothing() {
        let mut env = TestProgramContextEnv::new_with_peers("leader-broadcast-none", 1).unwrap();
        let context_id = Uuid::new_v4();
        let peer0 = env.peer_address(0).unwrap();

        env.context
            .leader_broadcast_helper
            .broadcast_to_non_leaders(&env.context, &context_id, CommsMessageType::Keys, &[peer0])
            .unwrap();

        env.assert_no_delivery_via_peer(0);
    }

    #[test]
    fn broadcast_rejects_corrupt_message_set_and_keeps_storage() {
        let mut env = TestProgramContextEnv::new_with_peers("leader-broadcast-reject", 1).unwrap();
        let context_id = Uuid::new_v4();
        let peer0 = env.peer_address(0).unwrap();

        // Plant a stored message whose type contradicts its storage prefix,
        // bypassing the store-time validation
        let mut bad = test_original_message("mallory");
        bad.msg_type = CommsMessageType::PublicNonces;
        let key =
            get_original_message_key(&context_id, CommsMessageType::Keys, &bad.sender_pubkey_hash);
        env.context
            .leader_broadcast_helper
            .store
            .set(&key, bad, None)
            .unwrap();

        assert!(env
            .context
            .leader_broadcast_helper
            .broadcast_to_non_leaders(&env.context, &context_id, CommsMessageType::Keys, &[peer0],)
            .is_err());

        // Nothing was sent and the stored messages were not cleared
        env.assert_no_delivery_via_peer(0);
        assert_eq!(
            env.context
                .leader_broadcast_helper
                .store
                .partial_compare(
                    &get_original_messages_prefix(&context_id, CommsMessageType::Keys),
                    None
                )
                .unwrap()
                .len(),
            1
        );
    }

    /// Build an OriginalMessage whose payload is really signed by the env's
    /// own key, so signature verification succeeds via the self-key path.
    fn signed_self_original(
        env: &TestProgramContextEnv,
        program_id: &Uuid,
        payload: Value,
    ) -> OriginalMessage {
        let (version, data, timestamp, signature) = prepare_message(
            &env.context.key_manager,
            &env.context.rsa_public_key,
            program_id,
            CommsMessageType::Keys,
            payload,
        )
        .unwrap();
        OriginalMessage {
            sender_pubkey_hash: env.context.comms.get_pubk_hash().unwrap(),
            msg_type: CommsMessageType::Keys,
            data,
            original_timestamp: timestamp,
            original_signature: signature,
            version,
        }
    }

    #[test]
    fn process_broadcasted_message_queues_verified_original() {
        let env = TestProgramContextEnv::new("leader-broadcast-process").unwrap();
        let program_id = Uuid::new_v4();
        let payload = json!({"step": "keys", "n": 1});
        let original = signed_self_original(&env, &program_id, payload.clone());
        let sender_hash = original.sender_pubkey_hash.clone();

        let broadcast = BroadcastedMessage {
            original_msg_type: CommsMessageType::Keys,
            original_messages: vec![original],
        };
        let queue = test_message_queue(env.context.leader_broadcast_helper.store.clone());

        env.context
            .leader_broadcast_helper
            .process_broadcasted_message(
                &env.context,
                Identifier::new("leader-hash".into(), COMMS_ID),
                program_id,
                serde_json::to_value(&broadcast).unwrap(),
                &queue,
            )
            .unwrap();

        // The reconstructed original is queued and round-trips back to the
        // exact message the sender signed
        let queued = queue
            .pop_front()
            .unwrap()
            .expect("verified original must be queued");
        assert_eq!(queued.identifier.pubkey_hash, sender_hash);
        let (_, msg_type, queued_program_id, data, _, _) =
            deserialize_msg(queued.data, MAX_MSG_LEN_KB).unwrap();
        assert_eq!(msg_type, CommsMessageType::Keys);
        assert_eq!(queued_program_id, program_id);
        assert_eq!(data, payload);
        assert!(queue.is_empty().unwrap());
    }

    #[test]
    fn process_broadcasted_message_queues_original_with_missing_key_for_retry() {
        let env = TestProgramContextEnv::new("leader-broadcast-missing-key").unwrap();
        let program_id = Uuid::new_v4();

        // Sender whose verification key has not arrived yet: verification
        // returns "missing key", and the message must still be queued so it
        // can be retried once the key shows up
        let mut original = test_original_message("unknown-peer");
        original.data = json!({"step": "keys"});
        let broadcast = BroadcastedMessage {
            original_msg_type: CommsMessageType::Keys,
            original_messages: vec![original],
        };
        let queue = test_message_queue(env.context.leader_broadcast_helper.store.clone());

        env.context
            .leader_broadcast_helper
            .process_broadcasted_message(
                &env.context,
                Identifier::new("leader-hash".into(), COMMS_ID),
                program_id,
                serde_json::to_value(&broadcast).unwrap(),
                &queue,
            )
            .unwrap();

        let queued = queue
            .pop_front()
            .unwrap()
            .expect("missing-key original must be queued for retry");
        assert_eq!(queued.identifier.pubkey_hash, "unknown-peer");
    }

    #[test]
    fn process_broadcasted_message_rejects_whole_broadcast_on_bad_signature() {
        let env = TestProgramContextEnv::new("leader-broadcast-bad-sig").unwrap();
        let program_id = Uuid::new_v4();

        let good = signed_self_original(&env, &program_id, json!({"step": "keys"}));

        // "mallory" has a known verification key (the env's own RSA key), but
        // her message carries a signature taken from a different payload, so
        // verification runs and fails
        OperatorVerificationStore::store(
            &env.context.globals,
            &"mallory".into(),
            &env.context.rsa_public_key,
        )
        .unwrap();
        let mut forged = signed_self_original(&env, &program_id, json!({"step": "forged"}));
        forged.sender_pubkey_hash = "mallory".into();
        forged.data = json!({"step": "tampered"});

        let broadcast = BroadcastedMessage {
            original_msg_type: CommsMessageType::Keys,
            original_messages: vec![good, forged],
        };
        let queue = test_message_queue(env.context.leader_broadcast_helper.store.clone());

        assert!(env
            .context
            .leader_broadcast_helper
            .process_broadcasted_message(
                &env.context,
                Identifier::new("leader-hash".into(), COMMS_ID),
                program_id,
                serde_json::to_value(&broadcast).unwrap(),
                &queue,
            )
            .is_err());

        // All-or-nothing: the valid message must not have been queued either
        assert!(queue.is_empty().unwrap());
    }

    #[test]
    fn process_broadcasted_message_rejects_malformed_data() {
        let env = TestProgramContextEnv::new("leader-broadcast-malformed").unwrap();
        let queue = test_message_queue(env.context.leader_broadcast_helper.store.clone());

        assert!(env
            .context
            .leader_broadcast_helper
            .process_broadcasted_message(
                &env.context,
                Identifier::new("leader-hash".into(), COMMS_ID),
                Uuid::new_v4(),
                json!("not a broadcasted message"),
                &queue,
            )
            .is_err());
        assert!(queue.is_empty().unwrap());
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
