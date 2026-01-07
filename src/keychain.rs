use std::{collections::HashMap, path::Path, rc::Rc};

use bitcoin::{secp256k1::rand::thread_rng, PublicKey, XOnlyPublicKey};
use key_manager::{
    create_key_manager_from_config,
    key_manager::KeyManager,
    key_type::BitcoinKeyType,
    musig2::{types::MessageId, PartialSignature, PubNonce},
    winternitz::{WinternitzPublicKey, WinternitzType},
};
use signature::SignatureEncoding;

use protocol_builder::unspendable::unspendable_key;
use storage_backend::storage::{KeyValueStore, Storage};

use crate::{
    config::Config,
    errors::{BitVMXError, ConfigError},
};

pub struct KeyChain {
    pub key_manager: Rc<KeyManager>,
    pub store: Rc<Storage>,
    pub rsa_public_key: Option<String>,
}

pub type Index = u32;

#[derive(Debug)]
pub enum KeyChainStorageKeys {
    EcdsaIndex,
    WinternitzIndex,
}

impl KeyChainStorageKeys {
    pub fn get_key(&self) -> String {
        let prefix = "keychain";

        match self {
            KeyChainStorageKeys::EcdsaIndex => format!("{prefix}/ecdsa"),
            KeyChainStorageKeys::WinternitzIndex => format!("{prefix}/winternitz"),
        }
    }
}

impl KeyChain {
    pub fn new(config: &Config, store: Rc<Storage>) -> Result<KeyChain, BitVMXError> {
        let key_manager =
            create_key_manager_from_config(&config.key_manager, &config.key_storage.clone())?;

        let key_manager = Rc::new(key_manager);

        let path = config.comms_key();
        if !Path::new(path).exists() {
            return Err(BitVMXError::ConfigurationError(ConfigError::InvalidConfigPath(
                format!(
                    "Failed to read PEM file at path {}. Please ensure the file exists and is accessible.",
                    path
                )
            )));
        }
        let pem_file = std::fs::read_to_string(path).unwrap();
        let rsa_pubkey_pem = key_manager.import_rsa_private_key(&pem_file)?;

        Ok(Self {
            key_manager,
            store,
            rsa_public_key: Some(rsa_pubkey_pem),
        })
    }

    pub fn get_new_ecdsa_index(&self) -> Result<Index, BitVMXError> {
        let key = KeyChainStorageKeys::EcdsaIndex.get_key();
        let index: Option<Index> = self.store.get(&key)?;

        let next_index = match index {
            Some(current_index) => current_index + 1,
            None => 0,
        };

        self.store.set(&key, next_index, None)?;

        Ok(next_index)
    }

    // TODO remove
    // pub fn get_new_winternitz_index(&self) -> Result<Index, BitVMXError> {
    //     let key = KeyChainStorageKeys::WinternitzIndex.get_key();
    //     let index: Option<Index> = self.store.get(&key)?;

    //     let next_index = match index {
    //         Some(current_index) => current_index + 1,
    //         None => 0,
    //     };

    //     self.store.set(&key, next_index, None)?;

    //     Ok(next_index)
    // }

    pub fn derive_keypair(&mut self, key_type: BitcoinKeyType) -> Result<PublicKey, BitVMXError> {
        let index = self.get_new_ecdsa_index()?;

        Ok(self.key_manager.derive_keypair(key_type, index)?)
    }

    pub fn derive_winternitz_hash160(
        &mut self,
        message_bytes: usize,
    ) -> Result<WinternitzPublicKey, BitVMXError> {
        Ok(self
            .key_manager
            .next_winternitz(message_bytes, WinternitzType::HASH160)?)
    }

    pub fn derive_winternitz_sha256(
        &mut self,
        message_bytes: usize,
    ) -> Result<WinternitzPublicKey, BitVMXError> {
        Ok(self
            .key_manager
            .next_winternitz(message_bytes, WinternitzType::SHA256)?)
    }

    pub fn derive_winternitz_sha256_keys(
        &mut self,
        size_in_bytes: usize,
        quantity: u32,
    ) -> Result<Vec<WinternitzPublicKey>, BitVMXError> {
        self.derive_winternitz_keys(size_in_bytes, WinternitzType::SHA256, quantity)
    }

    pub fn derive_winternitz_hash160_keys(
        &mut self,
        size_in_bytes: usize,
        quantity: u32,
    ) -> Result<Vec<WinternitzPublicKey>, BitVMXError> {
        self.derive_winternitz_keys(size_in_bytes, WinternitzType::HASH160, quantity)
    }

    pub fn unspendable_key(&self) -> Result<XOnlyPublicKey, BitVMXError> {
        let mut rng = thread_rng();
        Ok(XOnlyPublicKey::from(unspendable_key(&mut rng)?))
    }

    fn derive_winternitz_keys(
        &mut self,
        size_in_bytes: usize,
        key_type: WinternitzType,
        quantity: u32,
    ) -> Result<Vec<WinternitzPublicKey>, BitVMXError> {
        Ok(self
            .key_manager
            .next_multiple_winternitz(size_in_bytes, key_type, quantity)?)
    }

    pub fn add_nonces(
        &self,
        aggregated_pubkey: &PublicKey,
        nonces_map: HashMap<PublicKey, Vec<(MessageId, PubNonce)>>,
        id: &str,
    ) -> Result<(), BitVMXError> {
        /*let participant_pubkey = match participant_pubkey {
            Some(key) => *key,
            None => self.key_manager.get_my_public_key(aggregated_pubkey)?,
        };*/

        //let mut pubkey_nonce_map = HashMap::new();
        //pubkey_nonce_map.insert(participant_pubkey, nonces);
        self.key_manager
            .aggregate_nonces(aggregated_pubkey, id, nonces_map)?;

        Ok(())
    }

    pub fn new_musig2_session(
        &self,
        //program_id: uuid::Uuid,
        participant_pubkeys: Vec<PublicKey>,
        my_pubkey: PublicKey,
    ) -> Result<PublicKey, BitVMXError> {
        Ok(self
            .key_manager
            .new_musig2_session(participant_pubkeys, my_pubkey)?)
    }

    /*pub fn get_aggregated_pubkey(&self, program_id: uuid::Uuid) -> Result<PublicKey, BitVMXError> {
        self.key_manager
            .get_aggregated_pubkey(&program_id.to_string())
            .map_err(BitVMXError::MuSig2SignerError)
    }*/

    pub fn add_signatures(
        &self,
        aggregated_pubkey: &PublicKey,
        partial_signature_mapping: HashMap<PublicKey, Vec<(MessageId, PartialSignature)>>,
        id: &str,
    ) -> Result<(), BitVMXError> {
        self.key_manager.save_partial_signatures_multi(
            aggregated_pubkey,
            id,
            partial_signature_mapping,
        )?;

        Ok(())
    }

    pub fn get_nonces(
        &self,
        aggregated_pubkey: &PublicKey,
        id: &str,
    ) -> Result<Vec<(MessageId, PubNonce)>, BitVMXError> {
        Ok(self.key_manager.get_my_pub_nonces(aggregated_pubkey, id)?)
    }

    pub fn get_nonce(
        &self,
        aggregated_pubkey: &PublicKey,
        id: &str,
        message_id: &str,
    ) -> Result<PubNonce, BitVMXError> {
        Ok(self
            .key_manager
            .get_my_pub_nonce(aggregated_pubkey, id, message_id)?)
    }

    pub fn get_aggregated_signature(
        &self,
        aggregated_pubkey: &PublicKey,
        message_id: &str,
        id: &str,
    ) -> Result<bitcoin::secp256k1::schnorr::Signature, BitVMXError> {
        Ok(self
            .key_manager
            .get_aggregated_signature(aggregated_pubkey, id, message_id)?)
    }

    pub fn get_signatures(
        &self,
        aggregated_pubkey: &PublicKey,
        id: &str,
    ) -> Result<Vec<(MessageId, PartialSignature)>, BitVMXError> {
        Ok(self
            .key_manager
            .get_my_partial_signatures(aggregated_pubkey, id)?)
    }

    pub fn get_signature(
        &self,
        aggregated_pubkey: &PublicKey,
        id: &str,
        message_id: &str,
    ) -> Result<PartialSignature, BitVMXError> {
        Ok(self
            .key_manager
            .get_my_partial_signature(aggregated_pubkey, id, message_id)?)
    }

    // pub fn generate_pub_nonce(&self, program_id: uuid::Uuid, message_id: &str, message: Message) -> Result<(), BitVMXError> {
    //     self.key_manager
    //         .generate_pub_nonce(&program_id.to_string(), message_id, message.as_ref().to_vec(), &self.key_manager)
    //         .map_err(BitVMXError::MuSig2SignerError)?;
    //     Ok(())
    // }

    /// Sign a message using a pre-loaded RSA private key (optimized version)
    /// This method assumes the RSA key is already loaded in the key manager at the specified index
    fn sign_with_rsa_key(&self, message: &[u8], pub_key_pem: &str) -> Result<Vec<u8>, BitVMXError> {
        // Sign the message using the pre-loaded key
        // Sign the message using the default RSA key index
        let signature = self.key_manager.sign_rsa_message(message, pub_key_pem)?;

        // Convert signature to bytes using the signature encoding
        Ok(signature.to_bytes().to_vec())
    }

    /// Sign a message using RSA with the default key index (for compatibility)
    pub fn sign_rsa_message(
        &self,
        message: &[u8],
        pub_key_pem: Option<&str>,
    ) -> Result<Vec<u8>, BitVMXError> {
        // Sign the message using the default RSA key index
        let pub_key_pem = match pub_key_pem {
            Some(key) => key,
            None => self.rsa_public_key.as_deref().ok_or_else(|| {
                BitVMXError::KeyChainError("Not default key in keyChain".to_string())
            })?,
        };
        self.sign_with_rsa_key(message, pub_key_pem)
    }

    /// Verify an RSA signature using a public key
    pub fn verify_rsa_signature(
        &self,
        rsa_pub_key: &str,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, BitVMXError> {
        // Create a Signature from the bytes using try_from
        let rsa_signature = key_manager::rsa::Signature::try_from(signature).map_err(|_e| {
            BitVMXError::InvalidMessage(
                format!("Invalid RSA signature: {:?}", hex::encode(signature)).to_string(),
            )
        })?;

        // Verify the signature using SignatureVerifier with the provided RSA public key
        Ok(
            key_manager::verifier::SignatureVerifier::new().verify_rsa_signature(
                &rsa_signature,
                message,
                rsa_pub_key,
            )?,
        )
    }

    pub fn get_rsa_public_key(&self) -> Result<String, BitVMXError> {
        Ok(self
            .rsa_public_key
            .clone()
            .ok_or(BitVMXError::InvalidMessage(
                "No RSA public key found".to_string(),
            ))?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{path::PathBuf, rc::Rc};
    use uuid::Uuid;

    fn build_test_keychain() -> Result<(KeyChain, PathBuf), BitVMXError> {
        let mut config = Config::new(Some("config/development.yaml".to_string()))?;
        let unique_dir = std::env::temp_dir()
            .join("bitvmx-keychain-tests")
            .join(Uuid::new_v4().to_string());
        std::fs::create_dir_all(&unique_dir).map_err(|_| {
            BitVMXError::InvalidMessage(
                format!("Failed to create directory: {:?}", unique_dir).to_string(),
            )
        })?;
        config.storage.path = unique_dir.join("storage.db").to_string_lossy().to_string();
        config.key_storage.path = unique_dir.join("keys.db").to_string_lossy().to_string();
        let store = Rc::new(Storage::new(&config.storage)?);
        let keychain = KeyChain::new(&config, store)?;
        Ok((keychain, unique_dir))
    }

    fn remove_test_keychain(path: &PathBuf) {
        let _ = std::fs::remove_dir_all(path);
    }

    struct TestKeychainCleanup(PathBuf);

    impl Drop for TestKeychainCleanup {
        fn drop(&mut self) {
            remove_test_keychain(&self.0);
        }
    }

    #[test]
    fn test_encrypt_and_decrypt_messages() -> Result<(), BitVMXError> {
        // Create KeyChain with unique database paths
        let (keychain, test_dir) = build_test_keychain()?;
        let _cleanup = TestKeychainCleanup(test_dir);

        // Test message
        let original_message = b"Hello, this is a test message for encryption!".to_vec();

        // Get the public key for encryption
        let rng = &mut thread_rng();
        let pub_key = keychain.key_manager.generate_rsa_keypair(rng)?;

        // Encrypt the message
        let encrypted_message = keychain
            .key_manager
            .encrypt_rsa_message(&original_message.clone(), &pub_key)?;

        // Verify encryption changed the data
        assert_ne!(original_message, encrypted_message);
        assert!(!encrypted_message.is_empty());

        // Decrypt the message
        let decrypted_message = keychain
            .key_manager
            .decrypt_rsa_message(&encrypted_message, &pub_key)?;

        // Verify decryption restored the original message
        assert_eq!(original_message, decrypted_message);

        Ok(())
    }

    #[test]
    fn test_verify_rsa_signature_valid() -> Result<(), BitVMXError> {
        // Create KeyChain with unique database paths
        let (keychain, test_dir) = build_test_keychain()?;
        let _cleanup = TestKeychainCleanup(test_dir);

        // Test message
        let message = b"Hello, this is a test message for RSA signature verification!";

        // Get the public key (this is the key loaded from the config)
        let rsa_pub_key = keychain.get_rsa_public_key()?;

        // Sign the message using the default RSA key
        let signature = keychain.sign_rsa_message(message, None)?;

        // Verify the signature - should succeed
        let is_valid = keychain.verify_rsa_signature(&rsa_pub_key, message, &signature)?;
        assert!(is_valid, "Valid RSA signature should verify successfully");

        Ok(())
    }

    #[test]
    fn test_verify_rsa_signature_invalid_signature() -> Result<(), BitVMXError> {
        // Create KeyChain with unique database paths
        let (keychain, test_dir) = build_test_keychain()?;
        let _cleanup = TestKeychainCleanup(test_dir);

        // Test message
        let message = b"Hello, this is a test message for RSA signature verification!";

        // Get the public key
        let rsa_pub_key = keychain.get_rsa_public_key()?;

        // Create an invalid signature (wrong bytes)
        let invalid_signature = vec![0u8; 256]; // Invalid signature bytes

        // Verify the signature - should fail
        let is_valid = keychain.verify_rsa_signature(&rsa_pub_key, message, &invalid_signature)?;
        assert!(!is_valid, "Invalid RSA signature should fail verification");

        Ok(())
    }

    #[test]
    fn test_verify_rsa_signature_wrong_message() -> Result<(), BitVMXError> {
        // Create KeyChain with unique database paths
        let (keychain, test_dir) = build_test_keychain()?;
        let _cleanup = TestKeychainCleanup(test_dir);

        // Original message
        let original_message = b"Hello, this is a test message for RSA signature verification!";

        // Tampered message
        let tampered_message = b"Hello, this is a TAMPERED message for RSA signature verification!";

        // Get the public key
        let rsa_pub_key = keychain.get_rsa_public_key()?;

        // Sign the original message
        let signature = keychain.sign_rsa_message(original_message, None)?;

        // Verify the signature with the tampered message - should fail
        let is_valid = keychain.verify_rsa_signature(&rsa_pub_key, tampered_message, &signature)?;
        assert!(
            !is_valid,
            "RSA signature should fail verification when message is tampered"
        );

        Ok(())
    }

    #[test]
    fn test_verify_rsa_signature_wrong_public_key() -> Result<(), BitVMXError> {
        // Create KeyChain with unique database paths
        let (keychain, test_dir) = build_test_keychain()?;
        let _cleanup = TestKeychainCleanup(test_dir);

        // Test message
        let message = b"Hello, this is a test message for RSA signature verification!";

        let rng = &mut thread_rng();

        // Generate a different RSA keypair for testing
        let wrong_pub_key = keychain.key_manager.generate_rsa_keypair(rng)?;

        // Sign the message using the default RSA key (RSA_KEY_INDEX)
        let signature = keychain.sign_rsa_message(message, None)?;

        // Verify the signature with the wrong public key - should fail
        let is_valid = keychain.verify_rsa_signature(&wrong_pub_key, message, &signature)?;
        assert!(
            !is_valid,
            "RSA signature should fail verification with wrong public key"
        );

        Ok(())
    }

    #[test]
    fn test_verify_rsa_signature_invalid_signature_format() -> Result<(), BitVMXError> {
        // Create KeyChain with unique database paths
        let (keychain, test_dir) = build_test_keychain()?;
        let _cleanup = TestKeychainCleanup(test_dir);

        // Test message
        let message = b"Hello, this is a test message for RSA signature verification!";

        // Get the public key
        let rsa_pub_key = keychain.get_rsa_public_key()?;

        // Create invalid signature format (too short, not valid signature bytes)
        let invalid_signature = vec![0u8; 10]; // Too short to be a valid RSA signature

        // Verify the signature - should either return an error due to invalid format
        // or return false if it manages to parse but verification fails
        let result = keychain.verify_rsa_signature(&rsa_pub_key, message, &invalid_signature);

        // Should return an error when signature format is invalid, or false if parsing succeeds but verification fails
        match result {
            Err(BitVMXError::InvalidMessage(e)) => {
                // Expected error type when signature format cannot be parsed
                assert!(e.contains("Invalid RSA signature"));
            }
            Ok(false) => {
                // Also acceptable: signature parsed but verification failed
            }
            Ok(true) => {
                panic!("Invalid signature format should not verify successfully");
            }
            Err(e) => {
                panic!(
                    "Expected InvalidMessage error or Ok(false), got different error: {:?}",
                    e
                );
            }
        }

        Ok(())
    }

    #[test]
    fn test_verify_rsa_signature_empty_message() -> Result<(), BitVMXError> {
        // Create KeyChain with unique database paths
        let (keychain, test_dir) = build_test_keychain()?;
        let _cleanup = TestKeychainCleanup(test_dir);

        // Empty message
        let message = b"";

        // Get the public key
        let rsa_pub_key = keychain.get_rsa_public_key()?;

        // Sign the empty message
        let signature = keychain.sign_rsa_message(message, None)?;

        // Verify the signature - should succeed even with empty message
        let is_valid = keychain.verify_rsa_signature(&rsa_pub_key, message, &signature)?;
        assert!(
            is_valid,
            "RSA signature should verify successfully even for empty message"
        );

        Ok(())
    }
}
