use crate::{
    comms_helper::{construct_message, CommsMessageType, VerificationKeyAnnouncement},
    errors::BitVMXError,
    keychain::KeyChain,
};
use bitvmx_operator_comms::operator_comms::{OperatorComms, PubKeyHash};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tracing::{error, debug};

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
        let message = construct_message(program_id, version, msg_type.clone(), data, timestamp)?;

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
    /// - `comms`: OperatorComms to get our pubkey_hash
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
        comms: &OperatorComms,
    ) -> Result<String, BitVMXError> {
        match msg_type {
            CommsMessageType::VerificationKey => {
                // First contact: the key comes in the message itself
                // VerificationKeyAnnouncement is only temporary for deserialization
                let announcement: VerificationKeyAnnouncement =
                    serde_json::from_value(data.clone())
                        .map_err(|_| BitVMXError::InvalidMessageFormat)?;
                // Return the key to verify this message
                // It will be stored in participant_verification_keys in process_comms_message
                Ok(announcement.verification_key)
            }
            _ => {
                // Check if it's our own message first
                let my_pubkey_hash = comms.get_pubk_hash()?;
                if sender_pubkey_hash == &my_pubkey_hash {
                    return key_chain.get_rsa_public_key();
                }

                // Search in the HashMap of previously stored keys (from ProgramContext)
                // These keys were stored when VerificationKey was received previously
                let keys = participant_verification_keys.lock().unwrap();
                if let Some(key) = keys.get(sender_pubkey_hash) {
                    Ok(key.clone())
                } else {
                    error!(
                        "No verification key found for sender: {}. Known keys: {}",
                        sender_pubkey_hash,
                        keys.len()
                    );
                    Err(BitVMXError::InvalidMessageFormat)
                }
            }
        }
    }
}
