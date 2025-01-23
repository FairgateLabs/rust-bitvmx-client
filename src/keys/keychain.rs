use std::rc::Rc;

use bitcoin::{secp256k1, PublicKey, XOnlyPublicKey};
use key_manager::{
    create_database_key_store_from_config, create_key_manager_from_config,
    key_manager::KeyManager,
    keystorage::database::DatabaseKeyStore,
    winternitz::{WinternitzPublicKey, WinternitzType},
};
use p2p_handler::Keypair;
use protocol_builder::{
    graph::input::{SighashType, Signature},
    unspendable::unspendable_key,
};

use crate::{config::Config, errors::BitVMXError, program::program::Program};

pub struct KeyChain {
    key_manager: Rc<KeyManager<DatabaseKeyStore>>,
    communications_key: Keypair,
    ecdsa_index: KeyIndex,
    winternitz_index: KeyIndex,
}

impl KeyChain {
    pub fn new(config: &Config) -> Result<KeyChain, BitVMXError> {
        let keystore = create_database_key_store_from_config(
            &config.key_storage,
            &config.key_manager.network,
        )?;
        let key_manager = create_key_manager_from_config(&config.key_manager, keystore)?;

        // TODO: hardcoded communications key to be on allowed list
        let privk = config.p2p_key();
        let communications_key =
            Keypair::from_protobuf_encoding(&hex::decode(privk.as_bytes()).unwrap()).unwrap();
        //let communications_key = Keypair::generate_ed25519();

        Ok(Self {
            key_manager: Rc::new(key_manager),
            ecdsa_index: KeyIndex::new(),
            winternitz_index: KeyIndex::new(),
            communications_key,
        })
    }

    pub fn get_key_manager(&self) -> Rc<KeyManager<DatabaseKeyStore>> {
        self.key_manager.clone()
    }

    pub fn derive_keypair(&mut self) -> Result<PublicKey, BitVMXError> {
        self.key_manager
            .derive_keypair(self.ecdsa_index.next())
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
        self.key_manager
            .derive_winternitz(
                message_bytes,
                WinternitzType::HASH160,
                self.winternitz_index.next(),
            )
            .map_err(BitVMXError::from)
    }

    pub fn derive_winternitz_sha256(
        &mut self,
        message_bytes: usize,
    ) -> Result<WinternitzPublicKey, BitVMXError> {
        self.key_manager
            .derive_winternitz(
                message_bytes,
                WinternitzType::SHA256,
                self.winternitz_index.next(),
            )
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

    pub(crate) fn communications_key(&self) -> Keypair {
        self.communications_key.clone()
    }

    pub fn sign_program(&self, program: &mut Program) -> Result<(), BitVMXError> {
        let protocol = program.dispute_resolution_protocol_mut();

        for (txname, infos) in protocol.spending_infos()?.iter() {
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

                protocol.update_input_signatures(txname, input_index as u32, signatures)?;
            }
        }

        Ok(())
    }

    //CHECK: Commenting to avoid miss use of internal state
    /*pub fn ecdsa_index(&self) -> u32 {
        self.ecdsa_index.index
    }

    pub fn winternitz_index(&self) -> u32 {
        self.winternitz_index.index
    }*/

    fn derive_winternitz_keys(
        &mut self,
        size_in_bytes: usize,
        key_type: WinternitzType,
        quantity: u32,
    ) -> Result<Vec<WinternitzPublicKey>, BitVMXError> {
        let mut keys = Vec::new();
        for _ in 0..quantity {
            let index = self.winternitz_index.next();
            let pk = self
                .key_manager
                .derive_winternitz(size_in_bytes, key_type, index)?;
            keys.push(pk);
        }

        Ok(keys)
    }
}

pub struct KeyIndex {
    index: u32,
}

impl Default for KeyIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyIndex {
    pub fn new() -> Self {
        Self { index: 0 }
    }

    pub fn next(&mut self) -> u32 {
        let next = self.index;
        self.index += 1;
        next
    }
}
