use std::{collections::HashMap, path::Path, rc::Rc};

use bitcoin::{secp256k1::rand::thread_rng, PublicKey, XOnlyPublicKey};
use key_manager::{
    create_key_manager_from_config, key_manager::KeyManager, key_type::BitcoinKeyType, musig2::{PartialSignature, PubNonce, types::MessageId}, winternitz::{WinternitzPublicKey, WinternitzType}
};

use protocol_builder::unspendable::unspendable_key;
use storage_backend::storage::{KeyValueStore, Storage};

use crate::{
    config::Config,
    errors::{BitVMXError, ConfigError},
};


pub struct KeyChain {
    pub key_manager: Rc<KeyManager>,
    pub store: Rc<Storage>,
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
            create_key_manager_from_config(&config.key_manager, config.key_storage.clone())?;

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
        let _pub_key = key_manager.import_rsa_private_key(&pem_file)?;

        Ok(Self { key_manager, store })
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

    pub fn get_new_winternitz_index(&self) -> Result<Index, BitVMXError> {
        let key = KeyChainStorageKeys::WinternitzIndex.get_key();
        let index: Option<Index> = self.store.get(&key)?;

        let next_index = match index {
            Some(current_index) => current_index + 1,
            None => 0,
        };

        self.store.set(&key, next_index, None)?;

        Ok(next_index)
    }

    pub fn derive_keypair(&mut self, key_type: BitcoinKeyType) -> Result<PublicKey, BitVMXError> {
        let index = self.get_new_ecdsa_index()?;

        Ok(self.key_manager.derive_keypair(key_type, index)?)
    }

    pub fn derive_winternitz_hash160(
        &mut self,
        message_bytes: usize,
    ) -> Result<WinternitzPublicKey, BitVMXError> {
        let index = self.get_new_winternitz_index()?;

        Ok(self
            .key_manager
            .derive_winternitz(message_bytes, WinternitzType::HASH160, index)?)
    }

    pub fn derive_winternitz_sha256(
        &mut self,
        message_bytes: usize,
    ) -> Result<WinternitzPublicKey, BitVMXError> {
        let index = self.get_new_winternitz_index()?;

        Ok(self
            .key_manager
            .derive_winternitz(message_bytes, WinternitzType::SHA256, index)?)
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
        let mut keys = Vec::new();

        for _ in 0..quantity {
            let index = self.get_new_winternitz_index()?;
            let pk = self
                .key_manager
                .derive_winternitz(size_in_bytes, key_type, index)?;
            keys.push(pk);
        }

        Ok(keys)
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::rc::Rc;

    #[test]
    fn test_encrypt_and_decrypt_messages() -> Result<(), BitVMXError> {
        // Create config and storage for testing
        let config = Config::new(Some("config/development.yaml".to_string()))?;
        let store = Rc::new(Storage::new(&config.storage)?);

        // Create KeyChain using the existing constructor
        let keychain = KeyChain::new(&config, store)?;

        // Test message
        let original_message = b"Hello, this is a test message for encryption!".to_vec();

        // Get the public key for encryption
        let rng = &mut thread_rng();
        let pub_key = keychain
            .key_manager
            .generate_rsa_keypair(rng)?;

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
}
