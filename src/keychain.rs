use std::{collections::HashMap, rc::Rc};

use bitcoin::{
    secp256k1::{self}, PublicKey, TapNodeHash, XOnlyPublicKey
};
use key_manager::{
    create_database_key_store_from_config, create_key_manager_from_config,
    key_manager::KeyManager,
    keystorage::database::DatabaseKeyStore,
    musig2::{types::MessageId, PartialSignature, PubNonce},
    winternitz::{WinternitzPublicKey, WinternitzType},
};
use p2p_handler::Keypair;
use protocol_builder::{
    graph::input::{SighashType, Signature},
    unspendable::unspendable_key,
};
use storage_backend::storage::{KeyValueStore, Storage};

use crate::{config::Config, errors::BitVMXError, program::program::Program};

pub struct KeyChain {
    pub key_manager: Rc<KeyManager<DatabaseKeyStore>>,
    pub communications_key: Keypair,
    // pub musig2_signer: MuSig2Signer,
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
        let keystore = create_database_key_store_from_config(
            &config.key_storage,
            &config.key_manager.network,
        )?;

        let key_manager =
            create_key_manager_from_config(&config.key_manager, keystore, store.clone())?;

        // TODO: hardcoded communications key to be on allowed list
        let privk = config.p2p_key();
        let communications_key =
            Keypair::from_protobuf_encoding(&hex::decode(privk.as_bytes()).unwrap()).unwrap();

        let key_manager = Rc::new(key_manager);
        // let musig2_signer = MuSig2Signer::new(store.clone(), key_manager.clone());

        Ok(Self {
            key_manager,
            communications_key,
            // musig2_signer,
            store,
        })
    }

    pub fn get_new_ecdsa_index(&self) -> Result<Index, BitVMXError> {
        let key = KeyChainStorageKeys::EcdsaIndex.get_key();
        let index: Option<Index> = self.store.get(&key).map_err(BitVMXError::from)?;

        let next_index = match index {
            Some(current_index) => current_index + 1,
            None => 0,
        };

        self.store
            .set(&key, next_index, None)
            .map_err(BitVMXError::from)?;

        Ok(next_index)
    }

    pub fn get_new_winternitz_index(&self) -> Result<Index, BitVMXError> {
        let key = KeyChainStorageKeys::WinternitzIndex.get_key();
        let index: Option<Index> = self.store.get(&key).map_err(BitVMXError::from)?;

        let next_index = match index {
            Some(current_index) => current_index + 1,
            None => 0,
        };

        self.store
            .set(&key, next_index, None)
            .map_err(BitVMXError::from)?;

        Ok(next_index)
    }

    pub fn derive_keypair(&mut self) -> Result<PublicKey, BitVMXError> {
        let index = self.get_new_ecdsa_index()?;

        self.key_manager
            .derive_keypair(index)
            .map_err(BitVMXError::from)
    }

    /* //CHECK: Is this function necessary ?
    pub fn derive_keypair_with_index(&mut self, index: u32) -> Result<PublicKey, BitVMXError> {
        self.key_manager
            .derive_keypair(index)
            .map_err(BitVMXError::from)
    }*/

    pub fn derive_winternitz_hash160(
        &mut self,
        message_bytes: usize,
    ) -> Result<WinternitzPublicKey, BitVMXError> {
        let index = self.get_new_winternitz_index()?;

        self.key_manager
            .derive_winternitz(message_bytes, WinternitzType::HASH160, index)
            .map_err(BitVMXError::from)
    }

    pub fn derive_winternitz_sha256(
        &mut self,
        message_bytes: usize,
    ) -> Result<WinternitzPublicKey, BitVMXError> {
        let index = self.get_new_winternitz_index()?;

        self.key_manager
            .derive_winternitz(message_bytes, WinternitzType::SHA256, index)
            .map_err(BitVMXError::from)
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

    pub fn unspendable_key(&mut self) -> Result<XOnlyPublicKey, BitVMXError> {
        let mut rng = secp256k1::rand::thread_rng();
        Ok(XOnlyPublicKey::from(unspendable_key(&mut rng)?))
    }

    pub fn sign_program(&self, program: &Program) -> Result<(), BitVMXError> {
        for (txname, infos) in program.drp.spending_infos()?.iter() {
            for (input_index, spending_info) in infos.iter().enumerate() {
                let mut signatures = vec![];
                for (message, input_key) in spending_info
                    .hashed_messages()
                    .iter()
                    .zip(spending_info.input_keys().iter())
                {
                    let signature = match spending_info.sighash_type() {
                        SighashType::Ecdsa(sighash_type) => {
                            let signature =
                                self.key_manager.sign_ecdsa_message(message, input_key)?;
                            Signature::Ecdsa(bitcoin::ecdsa::Signature {
                                signature,
                                sighash_type: *sighash_type,
                            })
                        }
                        SighashType::Taproot(sighash_type) => {
                            let signature =
                                self.key_manager.sign_schnorr_message(message, input_key)?;
                            Signature::Taproot(bitcoin::taproot::Signature {
                                signature,
                                sighash_type: *sighash_type,
                            })
                        }
                    };
                    signatures.push(signature);
                }

                program
                    .drp
                    .update_input_signatures(txname, input_index as u32, signatures)?;
            }
        }

        Ok(())
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
        program_id: uuid::Uuid,
        nonces: Vec<(MessageId, PubNonce)>,
        participant_pubkey: PublicKey,
    ) -> Result<(), BitVMXError> {
        let mut pubkey_nonce_map = HashMap::new();
        pubkey_nonce_map.insert(participant_pubkey, nonces);

        self.key_manager
            .aggregate_nonces(&program_id.to_string(), pubkey_nonce_map)
            .map_err(BitVMXError::MuSig2SignerError)?;

        Ok(())
    }

    pub fn new_musig2_session(
        &self,
        program_id: uuid::Uuid,
        participant_pubkeys: Vec<PublicKey>,
        my_pubkey: PublicKey,
        tweak: Option<TapNodeHash>,
    ) -> Result<PublicKey, BitVMXError> {
        self.key_manager
            .new_musig2_session(&program_id.to_string(), participant_pubkeys, my_pubkey, tweak)
            .map_err(BitVMXError::MuSig2SignerError)
    }

    pub fn get_aggregated_pubkey(&self, program_id: uuid::Uuid, tweak: Option<TapNodeHash>,) -> Result<PublicKey, BitVMXError> {
        self.key_manager
            .get_aggregated_pubkey(&program_id.to_string(), tweak)
            .map_err(BitVMXError::MuSig2SignerError)
    }

    pub fn add_signatures(
        &self,
        program_id: uuid::Uuid,
        participant_partial_signatures: Vec<(MessageId, PartialSignature)>,
        participant_pub_key: PublicKey,
    ) -> Result<(), BitVMXError> {
        self.key_manager
            .save_partial_signatures(
                &program_id.to_string(),
                participant_pub_key,
                participant_partial_signatures,
            )
            .map_err(BitVMXError::MuSig2SignerError)?;

        Ok(())
    }

    pub fn get_nonces(
        &self,
        program_id: uuid::Uuid,
    ) -> Result<Vec<(MessageId, PubNonce)>, BitVMXError> {
        let nonces = self
            .key_manager
            .get_my_pub_nonces(&program_id.to_string())
            .map_err(BitVMXError::MuSig2SignerError)?;

        Ok(nonces)
    }

    pub fn get_aggregated_signature(
        &self,
        program_id: uuid::Uuid,
        message_id: &str,
    ) -> Result<bitcoin::secp256k1::schnorr::Signature, BitVMXError> {
        let signature = self
            .key_manager
            .get_aggregated_signature(&program_id.to_string(), message_id)
            .map_err(BitVMXError::MuSig2SignerError)?;

        Ok(signature)
    }

    pub fn generate_nonces(&self, program_id: uuid::Uuid) -> Result<(), BitVMXError> {
        self.key_manager
            .get_my_pub_nonces(&program_id.to_string())
            .map_err(BitVMXError::MuSig2SignerError)?;
        Ok(())
    }

    pub fn get_signatures(
        &self,
        program_id: uuid::Uuid,
    ) -> Result<Vec<(MessageId, PartialSignature)>, BitVMXError> {
        let signatures = self
            .key_manager
            .get_my_partial_signatures(&program_id.to_string())
            .map_err(BitVMXError::MuSig2SignerError)?;

        Ok(signatures)
    }

    // pub fn generate_pub_nonce(&self, program_id: uuid::Uuid, message_id: &str, message: Message) -> Result<(), BitVMXError> {
    //     self.key_manager
    //         .generate_pub_nonce(&program_id.to_string(), message_id, message.as_ref().to_vec(), &self.key_manager)
    //         .map_err(BitVMXError::MuSig2SignerError)?;
    //     Ok(())
    // }
}
