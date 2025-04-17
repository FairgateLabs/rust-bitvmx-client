use std::{collections::HashMap, rc::Rc};

use bitcoin::{
    key::UntweakedPublicKey, secp256k1, Amount, PublicKey, ScriptBuf, TxOut, XOnlyPublicKey,
};
use protocol_builder::{
    builder::Protocol,
    scripts,
    types::{input::SighashType, OutputType, Utxo},
};
use serde::{Deserialize, Serialize};
use storage_backend::storage::Storage;
use tracing::info;
use uuid::Uuid;

use crate::{errors::BitVMXError, keychain::KeyChain};

use super::{
    participant::ParticipantKeys,
    protocol_handler::{ProtocolContext, ProtocolHandler},
};

#[derive(Clone, Serialize, Deserialize)]
pub struct SlotProtocol {
    ctx: ProtocolContext,
}

impl ProtocolHandler for SlotProtocol {
    fn context(&self) -> &ProtocolContext {
        &self.ctx
    }

    fn context_mut(&mut self) -> &mut ProtocolContext {
        &mut self.ctx
    }
}

impl SlotProtocol {
    pub fn new(program_id: Uuid, storage: Rc<Storage>) -> Self {
        let protocol_name = format!("slot_{}", program_id);
        Self {
            ctx: ProtocolContext::new(protocol_name, storage),
        }
    }

    pub fn generate_keys(key_chain: &mut KeyChain) -> Result<ParticipantKeys, BitVMXError> {
        let aggregated_1 = key_chain.derive_keypair()?;

        let keys = vec![("aggregated_1".to_string(), aggregated_1.into())];

        Ok(ParticipantKeys::new(keys, vec!["aggregated_1".to_string()]))
    }

    pub fn build(
        &self,
        utxo: Utxo,
        _prover_keys: &ParticipantKeys,
        _verifier_keys: &ParticipantKeys,
        _computed_aggregated: HashMap<String, PublicKey>,
        _key_chain: &KeyChain,
    ) -> Result<(), BitVMXError> {
        // TODO get this from config, all values expressed in satoshis
        let _p2pkh_dust_threshold: u64 = 546;
        let _p2sh_p2wpkh_dust_threshold: u64 = 540;
        let mut _p2wpkh_dust_threshold: u64 = 99_999_000; // 294;
        let _taproot_dust_threshold: u64 = 330;
        let _fee = 1000;

        let tr_sighash_type = SighashType::taproot_all();

        let secp = secp256k1::Secp256k1::new();
        let internal_key = &utxo.pub_key;
        let untweaked_key: UntweakedPublicKey = XOnlyPublicKey::from(*internal_key);

        let spending_scripts = vec![scripts::timelock_renew(&internal_key)];
        let spend_info =
            scripts::build_taproot_spend_info(&secp, &untweaked_key, &spending_scripts)?;

        let script_pubkey = ScriptBuf::new_p2tr(&secp, untweaked_key, spend_info.merkle_root());

        //Description of the output that the START_CH consumes
        let prevout = TxOut {
            value: Amount::from_sat(utxo.amount),
            script_pubkey,
        };

        // let output_type = OutputType::TaprootScript {
        //     value: Amount::from_sat(utxo.amount),
        //     internal_key: *internal_key,
        //     script_pubkey,
        //     spending_scripts,
        //     with_key_path: true,
        //     prevouts: vec![prevout],
        // };

        let output_type = OutputType::tr_script(
            utxo.amount,
            internal_key,
            &spending_scripts,
            true,
            vec![prevout],
        )?;

        // let output_type = OutputSpendingType::TaprootUntweakedKey { key: *internal_key, prevouts: vec![prevout] };

        //let mut builder = ProtocolBuilder::new(&self.protocol_name, self.storage.clone().unwrap())?;
        let mut protocol = Protocol::load(
            &self.context().protocol_name,
            self.context().storage.clone().unwrap(),
        )?
        .unwrap_or(Protocol::new(&self.context().protocol_name));

        protocol.add_external_connection(
            utxo.txid,
            utxo.vout,
            output_type,
            "accept_tx",
            &tr_sighash_type,
        )?;

        info!("{}", protocol.visualize()?);
        self.save_protocol(protocol)?;

        Ok(())
    }
}
