use crate::{
    comms_helper::{construct_message, CommsMessageType, VerificationKeyAnnouncement},
    errors::BitVMXError,
    keychain::KeyChain,
};
use bitvmx_operator_comms::operator_comms::PubKeyHash;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tracing::{debug, error};

/// Centralized signature verification module
///
/// This module provides centralized RSA signature verification for all communication messages.
/// All message signature verification should go through this module to ensure consistency.
pub struct SignatureVerifier;

impl SignatureVerifier {
    /// Verifies the RSA signature of a communication message
    ///
    /// # Parameters
    /// - `program_id`: ID of the program or collaboration (as String)
    /// - `version`: Protocol version (e.g., "1.0")
    /// - `msg_type`: Message type
    /// - `data`: Message data (JSON Value)
    /// - `timestamp`: Message timestamp
    /// - `signature`: RSA signature of the message (Vec<u8>)
    /// - `sender_pubkey_hash`: Hash of the sender's public key
    /// - `verification_key`: RSA public key of the sender for verification (PEM string)
    /// - `key_chain`: KeyChain for verification operations
    ///
    /// # Returns
    /// - `Ok(true)` if the signature is valid
    /// - `Ok(false)` if the signature is invalid
    /// - `Err` if there's an error in the process
    ///
    /// # Note
    /// The message is reconstructed using `construct_message` which creates:
    /// `{program_id}|{version_bytes}|{msg_type_bytes}|{sorted_json}|{timestamp}`
    pub fn verify_message_signature(
        program_id: &str,
        version: &str,
        msg_type: &CommsMessageType,
        data: &Value,
        timestamp: i64,
        signature: &[u8],
        sender_pubkey_hash: &PubKeyHash,
        verification_key: &str,
        key_chain: &KeyChain,
    ) -> Result<bool, BitVMXError> {
        // Reconstruct the message that was signed (must match request/response)
        let message = construct_message(program_id, version, msg_type.clone(), data, timestamp)
            .map_err(|e| match e {
                BitVMXError::InvalidMsgVersion
                | BitVMXError::InvalidMessageType
                | BitVMXError::SerializationError => {
                    BitVMXError::MessageReconstructionError {
                        reason: format!("Failed to reconstruct message: {}", e),
                    }
                }
                other => other,
            })?;

        // Verify the RSA signature
        let verified =
            key_chain.verify_rsa_signature(verification_key, message.as_bytes(), signature)?;

        if !verified {
            error!(
                "Invalid RSA signature from peer: {} for message type: {:?} in program: {}",
                sender_pubkey_hash, msg_type, program_id
            );
        } else {
            debug!(
                "Message signature verified successfully from {} for message type: {:?}",
                sender_pubkey_hash, msg_type
            );
        }

        Ok(verified)
    }

    /// Gets the verification key of the sender
    ///
    /// Search strategy in priority order:
    /// 1. If it's VerificationKey: extracts the key from the message (first contact)
    /// 2. If it's our own message: uses our own RSA key
    /// 3. If it exists in participant_verification_keys: uses the previously stored key
    /// 4. Error if not found
    ///
    /// # Parameters
    /// - `msg_type`: Type of message received
    /// - `data`: Message data (to extract VerificationKey if applicable)
    /// - `sender_pubkey_hash`: Hash of the sender's public key
    /// - `participant_verification_keys`: Map of known verification keys (Arc<Mutex<HashMap<PubKeyHash, String>>>)
    /// - `key_chain`: KeyChain to get our own key
    /// - `my_pubkey_hash`: pubkey hash of the local operator (to detect self-messages)
    ///
    /// # Returns
    /// - `Ok(String)` with the RSA public key in PEM format
    /// - `Err` if the key cannot be obtained
    ///
    /// # Note about storage:
    /// - Keys are stored in `ProgramContext.participant_verification_keys: Arc<Mutex<HashMap<PubKeyHash, String>>>`
    /// - They are stored when a `VerificationKey` message is received and verified in `process_comms_message`
    /// - `VerificationKeyAnnouncement` is only temporary (DTO) for deserialization, NOT stored
    /// - Only `announcement.verification_key` (String) is extracted and stored in the shared HashMap
    /// - The HashMap is shared between all `Program` and `Collaboration` through `ProgramContext`
    pub fn get_verification_key(
        msg_type: &CommsMessageType,
        data: &Value,
        sender_pubkey_hash: &PubKeyHash,
        participant_verification_keys: &Arc<Mutex<HashMap<PubKeyHash, String>>>,
        key_chain: &KeyChain,
        my_pubkey_hash: &PubKeyHash,
    ) -> Result<String, BitVMXError> {
        match msg_type {
            CommsMessageType::VerificationKey => {
                // First contact: the key comes in the message itself
                // VerificationKeyAnnouncement is only temporary for deserialization
                let announcement = VerificationKeyAnnouncement::from_value(data).map_err(|e| {
                    BitVMXError::VerificationKeyExtractionError {
                        reason: format!("Failed to extract verification key from message: {}", e),
                    }
                })?;
                // Return the key to verify this message
                // It will be stored in participant_verification_keys in process_comms_message
                Ok(announcement.verification_key)
            }
            _ => {
                // Check if it's our own message first
                if sender_pubkey_hash == my_pubkey_hash {
                    return key_chain.get_rsa_public_key();
                }

                // Search in the HashMap of previously stored keys (from ProgramContext)
                // These keys were stored when VerificationKey was received previously
                let keys = participant_verification_keys.lock().unwrap();
                let known_count = keys.len();
                if let Some(key) = keys.get(sender_pubkey_hash) {
                    Ok(key.clone())
                } else {
                    error!(
                        "No verification key found for sender: {}. Known keys: {}",
                        sender_pubkey_hash, known_count
                    );
                    Err(BitVMXError::MissingVerificationKey {
                        peer: sender_pubkey_hash.clone(),
                        known_count,
                    })
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use serde_json::json;
    use std::rc::Rc;
    use std::time::{SystemTime, UNIX_EPOCH};
    use storage_backend::storage::Storage;
    use uuid::Uuid;

    fn build_keychain() -> Result<KeyChain, BitVMXError> {
        let mut config = Config::new(Some("config/development.yaml".to_string()))?;
        let unique_dir = std::env::temp_dir()
            .join("bitvmx-signature-tests")
            .join(Uuid::new_v4().to_string());
        std::fs::create_dir_all(&unique_dir).map_err(|_| BitVMXError::InvalidMessageFormat)?;
        config.storage.path = unique_dir.join("storage.db").to_string_lossy().to_string();
        config.key_storage.path = unique_dir.join("keys.db").to_string_lossy().to_string();
        let store = Rc::new(Storage::new(&config.storage)?);
        KeyChain::new(&config, store)
    }

    fn default_maps() -> Arc<Mutex<HashMap<PubKeyHash, String>>> {
        Arc::new(Mutex::new(HashMap::new()))
    }

    fn verify_message_signature_accepts_valid_payload_case() -> Result<(), BitVMXError> {
        let key_chain = build_keychain()?;
        let program_id = Uuid::new_v4();
        let msg_type = CommsMessageType::Keys;
        let data = json!({ "payload": "value" });
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        let signature = {
            let message = construct_message(
                &program_id.to_string(),
                "1.0",
                msg_type.clone(),
                &data,
                timestamp,
            )?;
            key_chain.sign_rsa_message(message.as_bytes())?
        };

        let verified = SignatureVerifier::verify_message_signature(
            &program_id.to_string(),
            "1.0",
            &msg_type,
            &data,
            timestamp,
            &signature,
            &"peer-1".to_string(),
            &key_chain.get_rsa_public_key()?,
            &key_chain,
        )?;
        assert!(verified);
        Ok(())
    }

    fn verify_message_signature_detects_tampering_case() -> Result<(), BitVMXError> {
        let key_chain = build_keychain()?;
        let program_id = Uuid::new_v4();
        let msg_type = CommsMessageType::Keys;
        let original_data = json!({ "payload": "value" });
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        let signature = {
            let message = construct_message(
                &program_id.to_string(),
                "1.0",
                msg_type.clone(),
                &original_data,
                timestamp,
            )?;
            key_chain.sign_rsa_message(message.as_bytes())?
        };

        let tampered_data = json!({ "payload": "tampered" });
        let verified = SignatureVerifier::verify_message_signature(
            &program_id.to_string(),
            "1.0",
            &msg_type,
            &tampered_data,
            timestamp,
            &signature,
            &"peer-1".to_string(),
            &key_chain.get_rsa_public_key()?,
            &key_chain,
        )?;
        assert!(!verified);
        Ok(())
    }

    fn get_verification_key_from_announcement_case() -> Result<(), BitVMXError> {
        let key_chain = build_keychain()?;
        let map = default_maps();
        let sender = "peer-1".to_string();
        let my_pubkey_hash = "self".to_string();
        let verification_key = key_chain.get_rsa_public_key()?;

        let data = json!({
            "pubkey_hash": sender.clone(),
            "verification_key": verification_key.clone()
        });

        let key = SignatureVerifier::get_verification_key(
            &CommsMessageType::VerificationKey,
            &data,
            &sender,
            &map,
            &key_chain,
            &my_pubkey_hash,
        )?;
        assert_eq!(key, verification_key);
        Ok(())
    }

    fn get_verification_key_for_self_message_case() -> Result<(), BitVMXError> {
        let key_chain = build_keychain()?;
        let map = default_maps();
        let my_pubkey_hash = "self".to_string();
        let data = json!({});

        let key = SignatureVerifier::get_verification_key(
            &CommsMessageType::Keys,
            &data,
            &my_pubkey_hash,
            &map,
            &key_chain,
            &my_pubkey_hash,
        )?;
        assert_eq!(key, key_chain.get_rsa_public_key()?);
        Ok(())
    }

    fn get_verification_key_from_shared_map_case() -> Result<(), BitVMXError> {
        let key_chain = build_keychain()?;
        let map = default_maps();
        let sender = "peer-2".to_string();
        let my_pubkey_hash = "self".to_string();
        let verification_key = "peer-2-key".to_string();
        map.lock()
            .unwrap()
            .insert(sender.clone(), verification_key.clone());

        let key = SignatureVerifier::get_verification_key(
            &CommsMessageType::Keys,
            &json!({}),
            &sender,
            &map,
            &key_chain,
            &my_pubkey_hash,
        )?;
        assert_eq!(key, verification_key);
        Ok(())
    }

    #[test]
    fn verify_message_signature_accepts_valid_payload() -> Result<(), BitVMXError> {
        verify_message_signature_accepts_valid_payload_case()
    }

    #[test]
    fn verify_message_signature_detects_tampering() -> Result<(), BitVMXError> {
        verify_message_signature_detects_tampering_case()
    }

    #[test]
    fn get_verification_key_from_announcement() -> Result<(), BitVMXError> {
        get_verification_key_from_announcement_case()
    }

    #[test]
    fn get_verification_key_for_self_message() -> Result<(), BitVMXError> {
        get_verification_key_for_self_message_case()
    }

    #[test]
    fn get_verification_key_from_shared_map() -> Result<(), BitVMXError> {
        get_verification_key_from_shared_map_case()
    }

    #[test]
    fn get_verification_key_missing_entry_errors() -> Result<(), BitVMXError> {
        let key_chain = build_keychain()?;
        let map = default_maps();
        let sender = "peer-3".to_string();
        let my_pubkey_hash = "self".to_string();

        let result = SignatureVerifier::get_verification_key(
            &CommsMessageType::Keys,
            &json!({}),
            &sender,
            &map,
            &key_chain,
            &my_pubkey_hash,
        );
        assert!(matches!(
            result,
            Err(BitVMXError::MissingVerificationKey { .. })
        ));
        Ok(())
    }
}
