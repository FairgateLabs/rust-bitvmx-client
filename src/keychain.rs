use std::{collections::HashMap, rc::Rc};

use bitcoin::{
    secp256k1::{rand::thread_rng},
    PublicKey, XOnlyPublicKey,
};
use key_manager::{
    create_key_manager_from_config,
    key_manager::KeyManager,
    key_store::KeyStore,
    musig2::{types::MessageId, PartialSignature, PubNonce},
    winternitz::{WinternitzPublicKey, WinternitzType},
};
use rcgen::{CertificateParams, Certificate, KeyPair, PKCS_RSA_SHA256};
use rsa::{pkcs8::{DecodePrivateKey, DecodePublicKey}, Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};

use protocol_builder::unspendable::unspendable_key;
use storage_backend::storage::{KeyValueStore, Storage};

use crate::{config::Config, errors::BitVMXError};

pub struct KeyChain {
    pub key_manager: Rc<KeyManager>,
    pub communications_key: Vec<u8>,
    pub store: Rc<Storage>,
    //TODO: move cert and communications_key to key manager
    pub cert: Certificate,
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
    pub fn new(config: &Config, store: Arc<Storage>) -> Result<KeyChain, BitVMXError> {
        let key_storage = Arc::new(Storage::new(&config.key_storage)?);
        let keystore = KeyStore::new(key_storage);
        let key_manager =
            create_key_manager_from_config(&config.key_manager, keystore, store.clone())?;

        let key_manager = Rc::new(key_manager);

        //TODO: move to key manager and use PEM key pair for communications_key
        // It uses pkcs8 format for the private key
        // get private key from file at p2p_key path
        let path = config.p2p_key();
        let pem_file = std::fs::read_to_string(path).unwrap();
        let keypair = KeyPair::from_pem_and_sign_algo(&pem_file, &PKCS_RSA_SHA256).unwrap();

        // TODO: hardcoded communications key to be on allowed list
        let communications_key = keypair.public_key_der();

        // Generate certificate
        let mut params = CertificateParams::default();
        params.key_pair = Some(keypair);
        params.alg = &PKCS_RSA_SHA256;
        let cert = Certificate::from_params(params).unwrap();

        Ok(Self {
            key_manager,
            communications_key,
            store,
            cert,
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

    pub fn derive_keypair(&mut self) -> Result<PublicKey, BitVMXError> {
        let index = self.get_new_ecdsa_index()?;

        Ok(self.key_manager.derive_keypair(index)?)
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

    // pub fn generate_pub_nonce(&self, program_id: uuid::Uuid, message_id: &str, message: Message) -> Result<(), BitVMXError> {
    //     self.key_manager
    //         .generate_pub_nonce(&program_id.to_string(), message_id, message.as_ref().to_vec(), &self.key_manager)
    //         .map_err(BitVMXError::MuSig2SignerError)?;
    //     Ok(())
    // }

    pub fn encrypt_messages(&self, message: Vec<u8>, public_key: Vec<u8>) -> Result<Vec<u8>, BitVMXError> {
        // 2. Parse the pkcs8public key with rsa crate
        let rsa_pub = RsaPublicKey::from_public_key_der(&public_key).unwrap();

        // 3. Encrypt data with public key
        let mut rng = thread_rng();
        let enc_data = rsa_pub.encrypt(&mut rng, Pkcs1v15Encrypt, &message).unwrap();

        Ok(enc_data)
    }

    pub fn decrypt_messages(&self, message: Vec<u8>) -> Result<Vec<u8>, BitVMXError> {
          // 1. Extract pkcs8 private key PEMs
          let privkey_der = self.cert.get_key_pair().serialize_der();
  
          // 2. Parse keys with rsa crate
          let rsa_priv = RsaPrivateKey::from_pkcs8_der(&privkey_der).unwrap();

          // 3. Decrypt data with private key
          let decrypted = rsa_priv.decrypt(Pkcs1v15Encrypt, &message).unwrap();

          Ok(decrypted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::rc::Rc;

    // TODO: when unhardcoded communications key in allowed list, remove this test
    #[test]
    fn test_communications_key() -> Result<(), BitVMXError> {
        // Create config and storage for testing
        let config_1 = Config::new(Some("config/op_1.yaml".to_string()))?;
        let store_1 = Rc::new(Storage::new(&config_1.storage)?);
        let keychain_1 = KeyChain::new(&config_1, store_1)?;
        let public_key_der_1 = keychain_1.cert.get_key_pair().public_key_der();
        assert_eq!(hex::encode(&public_key_der_1), "30820122300d06092a864886f70d01010105000382010f003082010a0282010100b0595a239c455f955ac2617061fadc0f3c532056da4a4ab4111b6581a62143e6c00b3041a00c290232fa65794ea0a55ca5f2ed3310ecbcab06a721d66e99a27e0d1b8a6afd8e395b741fbcf6cb73294eaeff43118f828f0118a4b5fdc95d472bcadaf2bc4d665e535ccd70b8ee5b82624794351a82c9f819d9a53638122228d1800d7d6561ae98183ae53c6cf23964c7eceeae95807db49a164cfbbc1ddc87a975fbe3d43545e8ce1bad2043cfe6a9aa3a7538ebdab8e6b900c94a691c1321d7c2d7f1a1beb3c3ef03686f7805ce938c92c8d5057cb5101cd51c1d97d7d3d4b9f13b7cb28bc5c4c5c9983a3062efc606b9c440021e1d5257d88d9c3ced0ac38f0203010001", "Op_1 public key should be correct");

        // Create config and storage for testing
        let config_2 = Config::new(Some("config/op_2.yaml".to_string()))?;
        let store_2 = Rc::new(Storage::new(&config_2.storage)?);
        let keychain_2 = KeyChain::new(&config_2, store_2)?;
        let public_key_der_2 = keychain_2.cert.get_key_pair().public_key_der();
        assert_eq!(hex::encode(&public_key_der_2), "30820122300d06092a864886f70d01010105000382010f003082010a0282010100c96872f74e913fbcf2e068d7f508e52dad5a278123ad6546d9735e3f35163e836427ef6ea14ff28d4ca30e7f0d4e251ddf4724668675052d6adb8581550b0adb11f0dcb78a4e9d6ad00f68bf21851d590d88d9fff1d8d7678454f9df4a1daad2f8ebfe69b4ea99160a9e2d43a98cdaaaf380bc4de9f9dec6bedc9351c89c43e4d5d89abbef98664f5d57cdf5c68d93e928203c84fd038fedddac5bbe2b243378141edec442e83c57f0bab437336586f6d6bc01bee222ee8f67dfacb2d94d7a4e406d05446c9f84de055d6175217de19d1005203674b1693f1df2d3dacd11839a782c343c33e86b952740812da624f2ddfd71edf9eb5e9ddf7944b9afc3a08b2f0203010001", "Op_2 public key should be correct");

        // Create config and storage for testing
        let config_3 = Config::new(Some("config/op_3.yaml".to_string()))?;
        let store_3 = Rc::new(Storage::new(&config_3.storage)?);
        let keychain_3 = KeyChain::new(&config_3, store_3)?;
        let public_key_der_3 = keychain_3.cert.get_key_pair().public_key_der();
        assert_eq!(hex::encode(&public_key_der_3), "30820122300d06092a864886f70d01010105000382010f003082010a0282010100e602dadfc9a2b10e6c042e10ba19628e49132fba6197f817457bd8728e881b35dc107838437b562cb9c611c2666fe3492db881630cd917178d17d21d48e664f685d9cd2ea2658501b3eb51ac7d9832e4ec580a5822616b0b663a3fb05a5aae15881baddeb7d8d329f064b460637a28ed569b93074446cb4946720474950456c950b5ae00b5f8b5a490eb1fc9af0206178ab81d3ca81b74fca1d84da9db510c10be2df4624be64fed6a6e59dc90880dc6ed61d4908ddcaf9eb0b08b0d58c5741085da051c4a537d33a8602fc22c6bef5853208698752561afa02ce763fb2bc0b88db51c90735d72dbd0ef6895c77aead64d5fe43e4d7521ed5f8da50c96636e4b0203010001", "Op_3 public key should be correct");

        // Create config and storage for testing
        let config_4 = Config::new(Some("config/op_4.yaml".to_string()))?;
        let store_4 = Rc::new(Storage::new(&config_4.storage)?);
        let keychain_4 = KeyChain::new(&config_4, store_4)?;
        let public_key_der_4 = keychain_4.cert.get_key_pair().public_key_der();
        assert_eq!(hex::encode(&public_key_der_4), "30820122300d06092a864886f70d01010105000382010f003082010a0282010100d1f76c66923556eaa6e9db0acf025fa96049e150cccd910ed6a36d6b32e1eb531620182c34b9ec04a00ba9e2f02f6f6f1493cf0dd42ffcafe60d81c7102f7b64f22a76ebe749dd285435a4d551ed03271062318e08efafbb1e9341aabe685a56cf81abf4af7437e60e9435a0a9682f8720b3ad017c29c517c3b25cc467f5f1ccd9ab791a206cef513141938491e5527df1e615088061a7bdc19622fd43323a74020870042ce33287f730fa5d17eb7f21b1dc6bb028d2a01850b9fb3c0ae40d5023dcdd2c888691a2c50d956f8e6d3d92c3cf893388f954781d1ee118b5840ef88a0d1cc8d218e535d706b044bf6c881ceafec982fd7ed516daaab60c4ea7d15b0203010001", "Op_4 public key should be correct");

        Ok(())
    }

    #[test]
    fn test_encrypt_and_decrypt_messages() -> Result<(), BitVMXError> {
        // Create config and storage for testing
        let config = Config::new(Some("config/development.yaml".to_string()))?;
        let store = Rc::new(Storage::new(&config.storage)?);

        // Create KeyChain using the existing constructor
        let keychain = KeyChain::new(&config, store)?;

        // Test message
        let original_message = b"Hello, this is a test message for encryption!".to_vec();
        
        // Get the public key from the certificate for encryption
        let public_key_der = keychain.cert.get_key_pair().public_key_der();

        // Encrypt the message
        let encrypted_message = keychain.encrypt_messages(original_message.clone(), public_key_der)?;
        
        // Verify encryption changed the data
        assert_ne!(original_message, encrypted_message);
        assert!(!encrypted_message.is_empty());
        
        // Decrypt the message
        let decrypted_message = keychain.decrypt_messages(encrypted_message)?;
        
        // Verify decryption restored the original message
        assert_eq!(original_message, decrypted_message);
        
        Ok(())
    }
}
