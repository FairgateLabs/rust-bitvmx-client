use crate::{
    comms_helper::{construct_message, CommsMessageType, VerificationKeyAnnouncement},
    errors::BitVMXError,
    keychain::KeyChain,
    program::variables::{Globals, VariableTypes},
};
use bitvmx_operator_comms::operator_comms::PubKeyHash;
use serde_json::Value;
use tracing::{debug, error};
use uuid::Uuid;

/// Centralized signature verification module
///
/// This module provides centralized RSA signature verification for all communication messages.
/// All message signature verification should go through this module to ensure consistency.
pub struct SignatureVerifier;

pub struct OperatorVerificationStore;

const GLOBAL_VERIFICATIONS_KEYS_UUID: Uuid = Uuid::from_u128(0xfeedfeedfeedfeedfeedfeedfeedfeed);

impl OperatorVerificationStore {
    fn storage_key(pubkey_hash: &PubKeyHash) -> String {
        format!("operator_verification_key_{}", pubkey_hash)
    }

    pub fn store(
        globals: &Globals,
        pubkey_hash: &PubKeyHash,
        verification_key: &str,
    ) -> Result<(), BitVMXError> {
        globals.set_var(
            &GLOBAL_VERIFICATIONS_KEYS_UUID,
            &Self::storage_key(pubkey_hash),
            VariableTypes::String(verification_key.to_string()),
        )
    }

    pub fn get(globals: &Globals, pubkey_hash: &PubKeyHash) -> Result<Option<String>, BitVMXError> {
        match globals.get_var(
            &GLOBAL_VERIFICATIONS_KEYS_UUID,
            &Self::storage_key(pubkey_hash),
        )? {
            Some(value) => Ok(Some(value.string()?)),
            None => Ok(None),
        }
    }
}

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
        globals: &Globals,
        program_id: &str,
        version: &str,
        msg_type: &CommsMessageType,
        data: &Value,
        timestamp: i64,
        signature: &[u8],
        sender_pubkey_hash: &PubKeyHash,
        key_chain: &KeyChain,
        my_pubkey_hash: &PubKeyHash,
    ) -> Result<bool, BitVMXError> {
        // Reconstruct the message that was signed
        let message = construct_message(program_id, version, msg_type.clone(), data, timestamp)
            .map_err(|e| match e {
                BitVMXError::InvalidMsgVersion
                | BitVMXError::InvalidMessageType
                | BitVMXError::SerializationError => BitVMXError::MessageReconstructionError {
                    reason: format!("Failed to reconstruct message: {}", e),
                },
                other => other,
            })?;

        // Obtain the verification key for the sender
        let verification_key = Self::get_verification_key(
            msg_type,
            data,
            sender_pubkey_hash,
            globals,
            key_chain,
            my_pubkey_hash,
        )?;

        // Verify the RSA signature
        let verified = key_chain.verify_rsa_signature(
            verification_key.as_str(),
            message.as_bytes(),
            signature,
        )?;

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
    /// 3. If it exists in storage (Globals): uses the previously stored key
    /// 4. Error if not found
    ///
    /// # Parameters
    /// - `msg_type`: Type of message received
    /// - `data`: Message data (to extract VerificationKey if applicable)
    /// - `sender_pubkey_hash`: Hash of the sender's public key
    /// - `key_chain`: KeyChain to get our own key
    /// - `my_pubkey_hash`: pubkey hash of the local operator (to detect self-messages)
    ///
    /// # Returns
    /// - `Ok(String)` with the RSA public key in PEM format
    /// - `Err` if the key cannot be obtained
    ///
    /// # Note about storage:
    /// - Keys are stored through `Globals` under `operator_verification_key_{pubkey_hash}`
    /// - They are stored when a `VerificationKey` message is received and verified in `process_comms_message`
    /// - `VerificationKeyAnnouncement` is only temporary (DTO) for deserialization, NOT stored
    /// - Only `announcement.verification_key` (String) is extracted and stored via `OperatorVerificationStore`
    pub fn get_verification_key(
        msg_type: &CommsMessageType,
        data: &Value,
        sender_pubkey_hash: &PubKeyHash,
        globals: &Globals,
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
                // It will be stored via OperatorVerificationStore in process_comms_message
                Ok(announcement.verification_key)
            }
            _ => {
                // Check if it's our own message first
                if sender_pubkey_hash == my_pubkey_hash {
                    return key_chain.get_rsa_public_key();
                }

                match OperatorVerificationStore::get(globals, sender_pubkey_hash)? {
                    Some(key) => Ok(key),
                    None => {
                        error!(
                            "No verification key found for sender: {}",
                            sender_pubkey_hash
                        );
                        Err(BitVMXError::MissingVerificationKey {
                            peer: sender_pubkey_hash.clone(),
                            known_count: 0,
                        })
                    }
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

    fn build_test_env() -> Result<(KeyChain, Globals), BitVMXError> {
        let mut config = Config::new(Some("config/development.yaml".to_string()))?;
        let unique_dir = std::env::temp_dir()
            .join("bitvmx-signature-tests")
            .join(Uuid::new_v4().to_string());
        std::fs::create_dir_all(&unique_dir).map_err(|_| BitVMXError::InvalidMessageFormat)?;
        config.storage.path = unique_dir.join("storage.db").to_string_lossy().to_string();
        config.key_storage.path = unique_dir.join("keys.db").to_string_lossy().to_string();
        let store = Rc::new(Storage::new(&config.storage)?);
        let globals = Globals::new(store.clone());
        let key_chain = KeyChain::new(&config, store)?;
        Ok((key_chain, globals))
    }

    fn verify_message_signature_accepts_valid_payload_case() -> Result<(), BitVMXError> {
        let (key_chain, globals) = build_test_env()?;
        let program_id = Uuid::new_v4();
        let msg_type = CommsMessageType::Keys;
        let data = json!({ "payload": "value" });
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        let my_pubkey_hash = "self".to_string();
        let sender_pubkey_hash = my_pubkey_hash.clone();
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
            &globals,
            &program_id.to_string(),
            "1.0",
            &msg_type,
            &data,
            timestamp,
            &signature,
            &sender_pubkey_hash,
            &key_chain,
            &my_pubkey_hash,
        )?;
        assert!(verified);
        Ok(())
    }

    fn verify_message_signature_detects_tampering_case() -> Result<(), BitVMXError> {
        let (key_chain, globals) = build_test_env()?;
        let program_id = Uuid::new_v4();
        let msg_type = CommsMessageType::Keys;
        let original_data = json!({ "payload": "value" });
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        let my_pubkey_hash = "self".to_string();
        let sender_pubkey_hash = my_pubkey_hash.clone();
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
            &globals,
            &program_id.to_string(),
            "1.0",
            &msg_type,
            &tampered_data,
            timestamp,
            &signature,
            &sender_pubkey_hash,
            &key_chain,
            &my_pubkey_hash,
        )?;
        assert!(!verified);
        Ok(())
    }

    fn get_verification_key_from_announcement_case() -> Result<(), BitVMXError> {
        let (key_chain, globals) = build_test_env()?;
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
            &globals,
            &key_chain,
            &my_pubkey_hash,
        )?;
        assert_eq!(key, verification_key);
        Ok(())
    }

    fn get_verification_key_for_self_message_case() -> Result<(), BitVMXError> {
        let (key_chain, globals) = build_test_env()?;
        let my_pubkey_hash = "self".to_string();
        let data = json!({});

        let key = SignatureVerifier::get_verification_key(
            &CommsMessageType::Keys,
            &data,
            &my_pubkey_hash,
            &globals,
            &key_chain,
            &my_pubkey_hash,
        )?;
        assert_eq!(key, key_chain.get_rsa_public_key()?);
        Ok(())
    }

    fn get_verification_key_from_shared_map_case() -> Result<(), BitVMXError> {
        let (key_chain, globals) = build_test_env()?;
        let sender = "peer-2".to_string();
        let my_pubkey_hash = "self".to_string();
        let verification_key = "peer-2-key".to_string();
        OperatorVerificationStore::store(&globals, &sender, &verification_key)?;

        let key = SignatureVerifier::get_verification_key(
            &CommsMessageType::Keys,
            &json!({}),
            &sender,
            &globals,
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
        let (key_chain, globals) = build_test_env()?;
        let sender = "peer-3".to_string();
        let my_pubkey_hash = "self".to_string();

        let result = SignatureVerifier::get_verification_key(
            &CommsMessageType::Keys,
            &json!({}),
            &sender,
            &globals,
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
