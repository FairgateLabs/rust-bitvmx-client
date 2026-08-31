use crate::{
    comms_helper::{
        construct_message, request, send_verification_key_to_peer, CommsMessageType,
        VerificationKeyAnnouncement, VerificationKeyRequestPayload,
    },
    errors::BitVMXError,
    helper::compute_pubkey_hash,
    ports::bitcoin_coordinator::BitcoinCoordinatorApi,
    program::{
        participant::CommsAddress,
        variables::{Globals, VariableTypes},
    },
    types::ProgramContext,
};
use bitvmx_broker::{
    identification::identifier::{Identifier, PubkHash},
    BrokerNode,
};
use key_manager::key_manager::KeyManager;
use serde_json::Value;
use std::{
    collections::{HashSet, VecDeque},
    rc::Rc,
};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// Centralized signature verification module
///
/// This module provides centralized RSA signature verification for all communication messages.
/// All message signature verification should go through this module to ensure consistency.
pub struct SignatureVerifier;

pub struct OperatorVerificationStore;

const GLOBAL_VERIFICATIONS_KEYS_UUID: Uuid = Uuid::from_u128(0xfeedfeedfeedfeedfeedfeedfeedfeed);

impl OperatorVerificationStore {
    fn storage_key(pubkey_hash: &PubkHash) -> String {
        format!("operator_verification_key_{}", pubkey_hash)
    }

    pub fn store(
        globals: &Globals,
        pubkey_hash: &PubkHash,
        verification_key: &str,
    ) -> Result<(), BitVMXError> {
        globals.set_var(
            &GLOBAL_VERIFICATIONS_KEYS_UUID,
            &Self::storage_key(pubkey_hash),
            VariableTypes::String(verification_key.to_string()),
        )
    }

    pub fn get(globals: &Globals, pubkey_hash: &PubkHash) -> Result<Option<String>, BitVMXError> {
        match globals.get_var(
            &GLOBAL_VERIFICATIONS_KEYS_UUID,
            &Self::storage_key(pubkey_hash),
        )? {
            Some(value) => Ok(Some(value.string()?)),
            None => Ok(None),
        }
    }

    pub fn has(globals: &Globals, pubkey_hash: &PubkHash) -> Result<bool, BitVMXError> {
        Ok(Self::get(globals, pubkey_hash)?.is_some())
    }

    pub fn missing(
        globals: &Globals,
        pubkey_hashes: &[PubkHash],
    ) -> Result<Vec<PubkHash>, BitVMXError> {
        let mut missing = Vec::new();
        for hash in pubkey_hashes {
            if !Self::has(globals, hash)? {
                missing.push(hash.clone());
            }
        }
        Ok(missing)
    }

    pub fn has_all_keys(
        globals: &Globals,
        pubkey_hashes: &[PubkHash],
    ) -> Result<bool, BitVMXError> {
        let missing = Self::missing(globals, pubkey_hashes)?;
        Ok(missing.is_empty())
    }

    pub fn request_missing_verification_keys(
        globals: &Globals,
        comms: &BrokerNode,
        key_manager: &Rc<KeyManager>,
        rsa_public_key: &str,
        program_id: &Uuid,
        peers: &[CommsAddress],
    ) -> Result<(), BitVMXError> {
        let my_pubkey_hash = comms.get_pubk_hash()?;
        let peer_hashes: Vec<PubkHash> = peers
            .iter()
            .filter(|peer| peer.pubkey_hash != my_pubkey_hash)
            .map(|peer| peer.pubkey_hash.clone())
            .collect();

        if peer_hashes.is_empty() {
            return Ok(());
        }

        let missing = OperatorVerificationStore::missing(globals, &peer_hashes)?;
        if missing.is_empty() {
            return Ok(());
        }

        let missing_set: HashSet<_> = missing.into_iter().collect();
        for peer in peers {
            if peer.pubkey_hash == my_pubkey_hash {
                continue;
            }
            if missing_set.contains(&peer.pubkey_hash) {
                info!(
                    "I'm {:?} requesting verification key from peer: {:?}",
                    my_pubkey_hash, peer.pubkey_hash
                );
                request(
                    comms,
                    key_manager,
                    rsa_public_key,
                    program_id,
                    peer.clone(),
                    CommsMessageType::VerificationKeyRequest,
                    VerificationKeyRequestPayload,
                )?;
            }
        }
        Ok(())
    }

    pub fn respond_with_verification_key(
        comms: &BrokerNode,
        key_manager: &Rc<KeyManager>,
        rsa_public_key: &str,
        program_id: &Uuid,
        peer_address: CommsAddress,
    ) -> Result<(), BitVMXError> {
        send_verification_key_to_peer(comms, key_manager, rsa_public_key, program_id, peer_address)
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
    /// - `rsa_public_key`: for verification operations
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
        sender_pubkey_hash: &PubkHash,
        rsa_public_key: &str,
        my_pubkey_hash: &PubkHash,
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
            rsa_public_key,
            my_pubkey_hash,
        )?;

        // Verify the RSA signature
        let rsa_signature = key_manager::rsa::Signature::try_from(signature).map_err(|_e| {
            BitVMXError::InvalidMessage(
                format!("Invalid RSA signature: {:?}", hex::encode(signature)).to_string(),
            )
        })?;
        let verified = key_manager::verifier::SignatureVerifier::new().verify_rsa_signature(
            &rsa_signature,
            message.as_bytes(),
            verification_key.as_str(),
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
    /// - `rsa_public_key`: rsa_public_key to get our own key
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
        sender_pubkey_hash: &PubkHash,
        globals: &Globals,
        rsa_public_key: &str,
        my_pubkey_hash: &PubkHash,
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
                    return Ok(rsa_public_key.to_string());
                }

                match OperatorVerificationStore::get(globals, sender_pubkey_hash)? {
                    Some(key) => Ok(key),
                    None => {
                        warn!(
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

    pub fn verify_and_get_key(
        comms: &BrokerNode,
        globals: &Globals,
        rsa_public_key: &str,
        sender_pubkey_hash: &PubkHash,
        program_id: &Uuid,
        msg_type: &CommsMessageType,
        data: &Value,
        timestamp: i64,
        signature: &[u8],
        version: &str,
    ) -> Result<String, BitVMXError> {
        if *msg_type == CommsMessageType::VerificationKeyRequest {
            // Skip verification because the requester cannot be verified yet.
            return Ok(String::new());
        }

        // Retrieve verification key from shared ProgramContext
        let my_pubkey_hash = comms.get_pubk_hash()?;
        let verification_key = Self::get_verification_key(
            msg_type,
            data,
            sender_pubkey_hash,
            globals,
            rsa_public_key,
            &my_pubkey_hash,
        )?;

        // Verify message signature (except for VerificationKey which is verified later)
        if *msg_type != CommsMessageType::VerificationKey {
            let verified = Self::verify_message_signature(
                globals,
                &program_id.to_string(),
                version,
                msg_type,
                data,
                timestamp,
                signature,
                sender_pubkey_hash,
                rsa_public_key,
                &my_pubkey_hash,
            )?;

            if !verified {
                error!(
                    "Message signature verification failed from {} for {}. Message rejected.",
                    sender_pubkey_hash, program_id
                );
                return Err(BitVMXError::InvalidSignature {
                    peer: sender_pubkey_hash.clone(),
                    msg_type: format!("{:?}", msg_type),
                    program_id: program_id.to_string(),
                });
            }
        }

        Ok(verification_key)
    }

    /// Handles verification messages (VerificationKey and VerificationKeyRequest).
    /// Returns Ok(()) if the message was processed, or Err if there was an error.
    pub fn handle_verification_messages<BC: BitcoinCoordinatorApi>(
        program_context: &ProgramContext<BC>,
        program_id: &Uuid,
        msg_type: &CommsMessageType,
        data: &Value,
        peer_address: &CommsAddress,
    ) -> Result<(), BitVMXError> {
        match msg_type {
            CommsMessageType::VerificationKey => {
                Self::handle_verification_key_announcement(program_context, peer_address, data)
            }
            CommsMessageType::VerificationKeyRequest => Self::handle_verification_key_request(
                program_context,
                program_id,
                peer_address.clone(),
            ),
            _ => Ok(()),
        }
    }

    fn handle_verification_key_announcement<BC: BitcoinCoordinatorApi>(
        program_context: &ProgramContext<BC>,
        peer_address: &CommsAddress,
        data: &Value,
    ) -> Result<(), BitVMXError> {
        let pubkey_hash = peer_address.pubkey_hash.clone();
        let announcement = VerificationKeyAnnouncement::from_value(data)?;

        let computed_hash = compute_pubkey_hash(&announcement.verification_key)?;
        if computed_hash != peer_address.pubkey_hash {
            error!(
                "Verification key fingerprint mismatch for peer {}",
                pubkey_hash
            );
            return Err(BitVMXError::VerificationKeyFingerprintMismatch {
                peer: pubkey_hash.clone(),
                computed: computed_hash,
            });
        }

        info!(
            "Verification key received and validated for peer: {}",
            pubkey_hash
        );

        OperatorVerificationStore::store(
            &program_context.globals,
            &pubkey_hash,
            &announcement.verification_key,
        )?;

        Ok(())
    }

    fn handle_verification_key_request<BC: BitcoinCoordinatorApi>(
        program_context: &ProgramContext<BC>,
        context_id: &Uuid,
        peer_address: CommsAddress,
    ) -> Result<(), BitVMXError> {
        OperatorVerificationStore::respond_with_verification_key(
            &program_context.comms,
            &program_context.key_manager,
            &program_context.rsa_public_key,
            context_id,
            peer_address,
        )
    }

    pub fn has_all_keys(
        globals: &Globals,
        pubkey_hashes: &[PubkHash],
    ) -> Result<bool, BitVMXError> {
        OperatorVerificationStore::has_all_keys(globals, pubkey_hashes)
    }

    /// Handles the MissingVerificationKey error by requesting the key and buffering the message
    pub fn handle_missing_verification_key<BC: BitcoinCoordinatorApi>(
        program_context: &ProgramContext<BC>,
        program_id: &Uuid,
        address: &CommsAddress,
        identifier: &Identifier,
        msg: String,
        pending_messages: &mut VecDeque<(PubkHash, String)>,
    ) -> Result<(), BitVMXError> {
        warn!("Missing verification key for: {:?}", program_id);
        OperatorVerificationStore::request_missing_verification_keys(
            &program_context.globals,
            &program_context.comms,
            &program_context.key_manager,
            &program_context.rsa_public_key,
            program_id,
            std::slice::from_ref(address),
        )?;
        pending_messages.push_back((identifier.to_string(), msg));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TestProgramContextEnv;
    use serde_json::json;
    use rsa::signature::SignatureEncoding;
    use std::time::{SystemTime, UNIX_EPOCH};
    use uuid::Uuid;

    fn build_test_env() -> Result<TestProgramContextEnv, BitVMXError> {
        TestProgramContextEnv::new("sigver-unit")
    }

    #[test]
    fn verify_message_signature_accepts_valid_payload() -> Result<(), BitVMXError> {
        let env = build_test_env()?;
        let (key_manager, rsa_public_key, globals) = (
            &env.context.key_manager,
            &env.context.rsa_public_key,
            &env.context.globals,
        );
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
            key_manager
                .sign_rsa_message(message.as_bytes(), &rsa_public_key)?
                .to_bytes()
                .to_vec()
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
            &rsa_public_key,
            &my_pubkey_hash,
        )?;
        assert!(verified);
        Ok(())
    }

    #[test]
    fn verify_message_signature_detects_tampering() -> Result<(), BitVMXError> {
        let env = build_test_env()?;
        let (key_manager, rsa_public_key, globals) = (
            &env.context.key_manager,
            &env.context.rsa_public_key,
            &env.context.globals,
        );
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
            key_manager
                .sign_rsa_message(message.as_bytes(), &rsa_public_key)?
                .to_bytes()
                .to_vec()
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
            &rsa_public_key,
            &my_pubkey_hash,
        )?;
        assert!(!verified);
        Ok(())
    }

    #[test]
    fn get_verification_key_from_announcement() -> Result<(), BitVMXError> {
        let env = build_test_env()?;
        let (rsa_public_key, globals) = (&env.context.rsa_public_key, &env.context.globals);
        let sender = "peer-1".to_string();
        let my_pubkey_hash = "self".to_string();
        let verification_key = rsa_public_key.clone();

        let data = json!({
            "pubkey_hash": sender.clone(),
            "verification_key": verification_key.clone()
        });

        let key = SignatureVerifier::get_verification_key(
            &CommsMessageType::VerificationKey,
            &data,
            &sender,
            &globals,
            &rsa_public_key,
            &my_pubkey_hash,
        )?;
        assert_eq!(key, verification_key);
        Ok(())
    }

    #[test]
    fn get_verification_key_for_self_message() -> Result<(), BitVMXError> {
        let env = build_test_env()?;
        let (rsa_public_key, globals) = (&env.context.rsa_public_key, &env.context.globals);
        let my_pubkey_hash = "self".to_string();
        let data = json!({});

        let key = SignatureVerifier::get_verification_key(
            &CommsMessageType::Keys,
            &data,
            &my_pubkey_hash,
            &globals,
            &rsa_public_key,
            &my_pubkey_hash,
        )?;
        assert_eq!(&key, rsa_public_key);
        Ok(())
    }

    #[test]
    fn get_verification_key_from_shared_map() -> Result<(), BitVMXError> {
        let env = build_test_env()?;
        let (rsa_public_key, globals) = (&env.context.rsa_public_key, &env.context.globals);
        let sender = "peer-2".to_string();
        let my_pubkey_hash = "self".to_string();
        let verification_key = "peer-2-key".to_string();
        OperatorVerificationStore::store(&globals, &sender, &verification_key)?;

        let key = SignatureVerifier::get_verification_key(
            &CommsMessageType::Keys,
            &json!({}),
            &sender,
            &globals,
            &rsa_public_key,
            &my_pubkey_hash,
        )?;
        assert_eq!(key, verification_key);
        Ok(())
    }

    #[test]
    fn get_verification_key_missing_entry_errors() -> Result<(), BitVMXError> {
        let env = build_test_env()?;
        let (rsa_public_key, globals) = (&env.context.rsa_public_key, &env.context.globals);
        let sender = "peer-3".to_string();
        let my_pubkey_hash = "self".to_string();

        let result = SignatureVerifier::get_verification_key(
            &CommsMessageType::Keys,
            &json!({}),
            &sender,
            &globals,
            &rsa_public_key,
            &my_pubkey_hash,
        );
        assert!(matches!(
            result,
            Err(BitVMXError::MissingVerificationKey { .. })
        ));
        Ok(())
    }

    #[test]
    fn operator_verification_store_has_and_missing() -> Result<(), BitVMXError> {
        let env = build_test_env()?;
        let globals = &env.context.globals;
        let stored_peer = "peer-stored".to_string();
        let missing_peer = "peer-missing".to_string();

        assert!(!OperatorVerificationStore::has(&globals, &stored_peer)?);
        OperatorVerificationStore::store(&globals, &stored_peer, "stored-key")?;
        assert!(OperatorVerificationStore::has(&globals, &stored_peer)?);

        let missing = OperatorVerificationStore::missing(
            &globals,
            &[stored_peer.clone(), missing_peer.clone()],
        )?;
        assert_eq!(missing, vec![missing_peer]);
        Ok(())
    }

    #[test]
    fn has_all_keys_reports_missing_and_complete() -> Result<(), BitVMXError> {
        let env = build_test_env()?;
        let globals = &env.context.globals;
        let peers = vec!["peer-a".to_string(), "peer-b".to_string()];

        assert!(!SignatureVerifier::has_all_keys(&globals, &peers)?);
        OperatorVerificationStore::store(&globals, &peers[0], "key-a")?;
        assert!(!SignatureVerifier::has_all_keys(&globals, &peers)?);
        OperatorVerificationStore::store(&globals, &peers[1], "key-b")?;
        assert!(SignatureVerifier::has_all_keys(&globals, &peers)?);
        Ok(())
    }

    #[test]
    fn verify_message_signature_maps_reconstruction_error() -> Result<(), BitVMXError> {
        let env = build_test_env()?;
        let (rsa_public_key, globals) = (&env.context.rsa_public_key, &env.context.globals);
        let my_pubkey_hash = "self".to_string();

        let result = SignatureVerifier::verify_message_signature(
            &globals,
            &Uuid::new_v4().to_string(),
            "9.9",
            &CommsMessageType::Keys,
            &json!({}),
            0,
            &[0u8; 4],
            &my_pubkey_hash,
            &rsa_public_key,
            &my_pubkey_hash,
        );
        assert!(matches!(
            result,
            Err(BitVMXError::MessageReconstructionError { .. })
        ));
        Ok(())
    }

    #[test]
    fn verify_message_signature_rejects_empty_signature() -> Result<(), BitVMXError> {
        let env = build_test_env()?;
        let (rsa_public_key, globals) = (&env.context.rsa_public_key, &env.context.globals);
        let my_pubkey_hash = "self".to_string();

        let verified = SignatureVerifier::verify_message_signature(
            &globals,
            &Uuid::new_v4().to_string(),
            "1.0",
            &CommsMessageType::Keys,
            &json!({}),
            0,
            &[],
            &my_pubkey_hash,
            &rsa_public_key,
            &my_pubkey_hash,
        )?;
        assert!(!verified);
        Ok(())
    }

    #[test]
    fn get_verification_key_rejects_malformed_announcement() -> Result<(), BitVMXError> {
        let env = build_test_env()?;
        let (rsa_public_key, globals) = (&env.context.rsa_public_key, &env.context.globals);
        let sender = "peer-bad".to_string();
        let my_pubkey_hash = "self".to_string();

        let result = SignatureVerifier::get_verification_key(
            &CommsMessageType::VerificationKey,
            &json!({ "unexpected": "shape" }),
            &sender,
            &globals,
            &rsa_public_key,
            &my_pubkey_hash,
        );
        assert!(matches!(
            result,
            Err(BitVMXError::VerificationKeyExtractionError { .. })
        ));
        Ok(())
    }

    #[test]
    fn request_missing_verification_keys_skips_self_and_known_peers() -> Result<(), BitVMXError> {
        let mut env = TestProgramContextEnv::new_with_peers("sigver-req-skip", 1)?;
        let program_id = Uuid::new_v4();
        let self_peer = env.self_address()?;
        let known_peer = env.peer_address(0)?;
        OperatorVerificationStore::store(
            &env.context.globals,
            &known_peer.pubkey_hash,
            "known-key",
        )?;

        // Only ourselves in the peer list: nothing to request.
        OperatorVerificationStore::request_missing_verification_keys(
            &env.context.globals,
            &env.context.comms,
            &env.context.key_manager,
            &env.context.rsa_public_key,
            &program_id,
            &[self_peer.clone()],
        )?;

        // Peer whose key is already stored: nothing to request either.
        OperatorVerificationStore::request_missing_verification_keys(
            &env.context.globals,
            &env.context.comms,
            &env.context.key_manager,
            &env.context.rsa_public_key,
            &program_id,
            &[self_peer, known_peer],
        )?;

        // Neither call may have queued a request to us or to the known peer.
        env.assert_no_delivery_via_peer(0);
        Ok(())
    }

    #[test]
    fn request_missing_verification_keys_sends_request_for_missing_peer() -> Result<(), BitVMXError>
    {
        let mut env = TestProgramContextEnv::new_with_peers("sigver-req-send", 1)?;
        let program_id = Uuid::new_v4();
        let missing_peer = env.peer_address(0)?;
        // Include ourselves in the list: we must be skipped, not requested.
        let self_peer = env.self_address()?;

        OperatorVerificationStore::request_missing_verification_keys(
            &env.context.globals,
            &env.context.comms,
            &env.context.key_manager,
            &env.context.rsa_public_key,
            &program_id,
            &[self_peer, missing_peer],
        )?;

        let (_, raw) = env.receive_via_peer(0)?;
        let (_, msg_type, received_program_id, _, _, _) =
            crate::comms_helper::deserialize_msg(raw, 200000)?;
        assert_eq!(msg_type, CommsMessageType::VerificationKeyRequest);
        assert_eq!(received_program_id, program_id);
        Ok(())
    }

    #[test]
    fn verify_and_get_key_skips_verification_key_request() -> Result<(), BitVMXError> {
        let env = TestProgramContextEnv::new("sigver-vgk-req")?;

        let key = SignatureVerifier::verify_and_get_key(
            &env.context.comms,
            &env.context.globals,
            &env.context.rsa_public_key,
            &"any-peer".to_string(),
            &Uuid::new_v4(),
            &CommsMessageType::VerificationKeyRequest,
            &json!({}),
            0,
            &[],
            "1.0",
        )?;
        assert_eq!(key, String::new());
        Ok(())
    }

    #[test]
    fn verify_and_get_key_returns_announced_key_without_verification() -> Result<(), BitVMXError> {
        let env = TestProgramContextEnv::new("sigver-vgk-vk")?;
        let data = json!({ "verification_key": "announced-key" });

        // VerificationKey messages return the announced key; the signature is
        // verified later against the announced key, so none is needed here.
        let key = SignatureVerifier::verify_and_get_key(
            &env.context.comms,
            &env.context.globals,
            &env.context.rsa_public_key,
            &"peer-vk".to_string(),
            &Uuid::new_v4(),
            &CommsMessageType::VerificationKey,
            &data,
            0,
            &[],
            "1.0",
        )?;
        assert_eq!(key, "announced-key");
        Ok(())
    }

    #[test]
    fn verify_and_get_key_accepts_valid_and_rejects_tampered() -> Result<(), BitVMXError> {
        let env = TestProgramContextEnv::new("sigver-vgk-sig")?;
        let program_id = Uuid::new_v4();
        let my_hash = env.context.comms.get_pubk_hash()?;
        let data = json!({ "payload": "value" });
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        let message = construct_message(
            &program_id.to_string(),
            "1.0",
            CommsMessageType::Keys,
            &data,
            timestamp,
        )?;
        let signature = env
            .context
            .key_manager
            .sign_rsa_message(message.as_bytes(), &env.context.rsa_public_key)?
            .to_bytes()
            .to_vec();

        let key = SignatureVerifier::verify_and_get_key(
            &env.context.comms,
            &env.context.globals,
            &env.context.rsa_public_key,
            &my_hash,
            &program_id,
            &CommsMessageType::Keys,
            &data,
            timestamp,
            &signature,
            "1.0",
        )?;
        assert_eq!(key, env.context.rsa_public_key);

        let result = SignatureVerifier::verify_and_get_key(
            &env.context.comms,
            &env.context.globals,
            &env.context.rsa_public_key,
            &my_hash,
            &program_id,
            &CommsMessageType::Keys,
            &json!({ "payload": "tampered" }),
            timestamp,
            &signature,
            "1.0",
        );
        assert!(matches!(result, Err(BitVMXError::InvalidSignature { .. })));
        Ok(())
    }

    #[test]
    fn handle_verification_messages_stores_valid_announcement() -> Result<(), BitVMXError> {
        let env = TestProgramContextEnv::new("sigver-hvm-store")?;
        let program_id = Uuid::new_v4();
        let peer_hash = compute_pubkey_hash(&env.context.rsa_public_key)?;
        let peer_address = CommsAddress::new(env.context.comms.get_address(), peer_hash.clone());
        let data = VerificationKeyAnnouncement {
            verification_key: env.context.rsa_public_key.clone(),
        }
        .to_value()?;

        SignatureVerifier::handle_verification_messages(
            &env.context,
            &program_id,
            &CommsMessageType::VerificationKey,
            &data,
            &peer_address,
        )?;

        assert_eq!(
            OperatorVerificationStore::get(&env.context.globals, &peer_hash)?,
            Some(env.context.rsa_public_key.clone())
        );
        Ok(())
    }

    #[test]
    fn handle_verification_messages_rejects_fingerprint_mismatch() -> Result<(), BitVMXError> {
        let env = TestProgramContextEnv::new("sigver-hvm-mismatch")?;
        let peer_address = CommsAddress::new(
            env.context.comms.get_address(),
            "not-the-key-fingerprint".to_string(),
        );
        let data = VerificationKeyAnnouncement {
            verification_key: env.context.rsa_public_key.clone(),
        }
        .to_value()?;

        let result = SignatureVerifier::handle_verification_messages(
            &env.context,
            &Uuid::new_v4(),
            &CommsMessageType::VerificationKey,
            &data,
            &peer_address,
        );
        assert!(matches!(
            result,
            Err(BitVMXError::VerificationKeyFingerprintMismatch { .. })
        ));
        assert!(!OperatorVerificationStore::has(
            &env.context.globals,
            &peer_address.pubkey_hash
        )?);
        Ok(())
    }

    #[test]
    fn handle_verification_messages_responds_to_key_request() -> Result<(), BitVMXError> {
        let mut env = TestProgramContextEnv::new_with_peers("sigver-hvm-request", 1)?;
        let program_id = Uuid::new_v4();
        let peer_address = env.peer_address(0)?;

        SignatureVerifier::handle_verification_messages(
            &env.context,
            &program_id,
            &CommsMessageType::VerificationKeyRequest,
            &json!({}),
            &peer_address,
        )?;

        let (_, raw) = env.receive_via_peer(0)?;
        let (_, msg_type, received_program_id, data, _, _) =
            crate::comms_helper::deserialize_msg(raw, 200000)?;
        assert_eq!(msg_type, CommsMessageType::VerificationKey);
        assert_eq!(received_program_id, program_id);
        let announcement = VerificationKeyAnnouncement::from_value(&data)?;
        assert_eq!(announcement.verification_key, env.context.rsa_public_key);
        Ok(())
    }

    #[test]
    fn handle_verification_messages_ignores_other_types() -> Result<(), BitVMXError> {
        let mut env = TestProgramContextEnv::new_with_peers("sigver-hvm-other", 1)?;
        let peer_address = env.peer_address(0)?;

        SignatureVerifier::handle_verification_messages(
            &env.context,
            &Uuid::new_v4(),
            &CommsMessageType::Keys,
            &json!({}),
            &peer_address,
        )?;

        // Non-verification types are ignored: no key stored, nothing sent.
        assert!(!OperatorVerificationStore::has(
            &env.context.globals,
            &peer_address.pubkey_hash
        )?);
        env.assert_no_delivery_via_peer(0);
        Ok(())
    }

    #[test]
    fn handle_missing_verification_key_requests_and_buffers() -> Result<(), BitVMXError> {
        let mut env = TestProgramContextEnv::new_with_peers("sigver-missing-key", 1)?;
        let program_id = Uuid::new_v4();
        let peer_address = env.peer_address(0)?;
        let identifier = Identifier::new(peer_address.pubkey_hash.clone(), 0);
        let msg = "pending-payload".to_string();
        let mut pending = VecDeque::new();

        SignatureVerifier::handle_missing_verification_key(
            &env.context,
            &program_id,
            &peer_address,
            &identifier,
            msg.clone(),
            &mut pending,
        )?;

        // The original message is buffered for reprocessing.
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].1, msg);

        // A key request went out to the peer.
        let (_, raw) = env.receive_via_peer(0)?;
        let (_, msg_type, received_program_id, _, _, _) =
            crate::comms_helper::deserialize_msg(raw, 200000)?;
        assert_eq!(msg_type, CommsMessageType::VerificationKeyRequest);
        assert_eq!(received_program_id, program_id);
        Ok(())
    }
}
