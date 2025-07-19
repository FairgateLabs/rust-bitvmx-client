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
use p2p_handler::Keypair;
use rcgen::{CertificateParams, Certificate, KeyPair as RcgenKeyPair, PKCS_RSA_SHA256};
use rsa::{pkcs8::{DecodePrivateKey, DecodePublicKey}, Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};

use protocol_builder::unspendable::unspendable_key;
use storage_backend::storage::{KeyValueStore, Storage};

use crate::{config::Config, errors::BitVMXError};

pub struct KeyChain {
    pub key_manager: Rc<KeyManager>,
    pub communications_key: Keypair,
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
    pub fn new(config: &Config, store: Rc<Storage>) -> Result<KeyChain, BitVMXError> {
        let key_storage = Rc::new(Storage::new(&config.key_storage)?);
        let keystore = KeyStore::new(key_storage);
        let key_manager =
            create_key_manager_from_config(&config.key_manager, keystore, store.clone())?;

        // TODO: hardcoded communications key to be on allowed list
        let privk = config.p2p_key();
        let communications_key =
            Keypair::from_protobuf_encoding(&hex::decode(privk.as_bytes()).unwrap()).unwrap();
        //TODO: move to key manager and use PEM key pair for communications_key
        // It uses pkcs8 format for the private key
        let keypair = RcgenKeyPair::from_pem_and_sign_algo(privk, &PKCS_RSA_SHA256).unwrap();
        let mut params = CertificateParams::default();
        params.key_pair = Some(keypair);
        params.alg = &PKCS_RSA_SHA256;
        let cert = Certificate::from_params(params).unwrap();

        let key_manager = Rc::new(key_manager);

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
