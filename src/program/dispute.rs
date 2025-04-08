use std::{collections::HashMap, rc::Rc};

use bitcoin::{
    key::UntweakedPublicKey, secp256k1, Amount, PublicKey, ScriptBuf, Transaction, TxOut, Txid,
    XOnlyPublicKey,
};
use protocol_builder::{
    builder::{Protocol, ProtocolBuilder, SpendingArgs, Utxo},
    errors::ProtocolBuilderError,
    graph::{
        input::{InputSpendingInfo, SighashType},
        output::OutputSpendingType,
    },
    scripts,
};
use serde::{Deserialize, Serialize};
use storage_backend::storage::Storage;
use uuid::Uuid;

use crate::keychain::KeyChain;

use super::participant::ParticipantKeys;
pub struct SearchParams {
    _search_intervals: u8,
    _max_steps: u32,
}

impl SearchParams {
    pub fn new(search_intervals: u8, max_steps: u32) -> Self {
        Self {
            _search_intervals: search_intervals,
            _max_steps: max_steps,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct DisputeResolutionProtocol {
    pub protocol_name: String,
    #[serde(skip)]
    storage: Option<Rc<Storage>>,
}

const PREKICKOFF: &str = "pre_kickoff";
const KICKOFF: &str = "kickoff";
const _PROTOCOL: &str = "protocol";

impl DisputeResolutionProtocol {
    pub fn new(
        program_id: Uuid,
        storage: Rc<Storage>,
    ) -> Result<DisputeResolutionProtocol, ProtocolBuilderError> {
        let protocol_name = format!("drp_{}", program_id);

        Ok(Self {
            protocol_name,
            storage: Some(storage),
        })
    }

    pub fn set_storage(&mut self, storage: Rc<Storage>) {
        self.storage = Some(storage);
    }

    pub fn build(
        &self,
        id: &str,
        utxo: Utxo,
        internal_key: &PublicKey,
        prover_keys: &ParticipantKeys,
        _verifier_keys: &ParticipantKeys,
        _search: SearchParams,
        key_chain: &KeyChain,
    ) -> Result<(), ProtocolBuilderError> {
        // TODO get this from config, all values expressed in satoshis
        let _p2pkh_dust_threshold: u64 = 546;
        let _p2sh_p2wpkh_dust_threshold: u64 = 540;
        let p2wpkh_dust_threshold: u64 = 99_999_000; // 294;
        let taproot_dust_threshold: u64 = 330;

        let tr_sighash_type = SighashType::taproot_all();
        let mut builder = ProtocolBuilder::new(&self.protocol_name, self.storage.clone().unwrap())?;

        let secp = secp256k1::Secp256k1::new();
        let untweaked_key: UntweakedPublicKey = XOnlyPublicKey::from(*internal_key);

        let spending_scripts = vec![scripts::timelock_renew(&internal_key)];
        let spend_info =
            scripts::build_taproot_spend_info(&secp, &untweaked_key, &spending_scripts)?;

        let script_pubkey = ScriptBuf::new_p2tr(&secp, untweaked_key, spend_info.merkle_root());

        let prevout = TxOut {
            value: Amount::from_sat(utxo.amount),
            script_pubkey,
        };

        let output_type = OutputSpendingType::TaprootScript {
            spending_scripts,
            spend_info,
            internal_key: untweaked_key,
            prevouts: vec![prevout],
        };

        // let output_type = OutputSpendingType::TaprootUntweakedKey { key: *internal_key, prevouts: vec![prevout] };

        builder.connect_with_external_transaction(
            utxo.txid,
            utxo.vout,
            output_type,
            PREKICKOFF,
            &tr_sighash_type,
        )?;

        // let kickoff_spending = scripts::kickoff(
        //     internal_key,
        //     &prover_keys.program_input_key,
        //     &prover_keys.program_ending_state,
        //     &prover_keys.program_ending_step_number,
        // )?;

        // builder.add_taproot_script_spend_connection(
        //     PROTOCOL,
        //     PREKICKOFF,
        //     taproot_dust_threshold,
        //     &XOnlyPublicKey::from(*internal_key),
        //     &[kickoff_spending],
        //     KICKOFF,
        //     &tr_sighash_type,
        // )?;
        builder.add_speedup_output(PREKICKOFF, p2wpkh_dust_threshold, &prover_keys.speedup)?;

        let protocol = builder.build(id, &key_chain.key_manager)?;

        self.save_protocol(protocol)?;

        Ok(())
    }

    pub fn sign(&mut self, id: &str, key_chain: &KeyChain) -> Result<(), ProtocolBuilderError> {
        let mut protocol = self.load_protocol()?;
        protocol.sign(id, &key_chain.key_manager)?;
        self.save_protocol(protocol)?;
        Ok(())
    }

    pub fn prekickoff_transaction(&self) -> Result<Transaction, ProtocolBuilderError> {
        let signature = self
            .load_protocol()?
            .input_taproot_key_spend_signature(PREKICKOFF, 0)?;
        let mut taproot_arg = SpendingArgs::new_args();
        taproot_arg.push_taproot_signature(signature);

        self.load_protocol()?
            .transaction_to_send(PREKICKOFF, &[taproot_arg])
    }

    pub fn kickoff_transaction(&self) -> Result<Transaction, ProtocolBuilderError> {
        self.load_protocol()?.transaction_to_send(KICKOFF, &[])
    }

    pub fn get_transaction_by_id(&self, txid: Txid) -> Result<Transaction, ProtocolBuilderError> {
        let protocol = self.load_protocol()?;
        protocol.transaction_with_id(txid).cloned()
    }

    pub fn get_transaction_ids(&self) -> Result<Vec<Txid>, ProtocolBuilderError> {
        let protocol = self.load_protocol()?;
        Ok(protocol.get_transaction_ids())
    }

    fn load_protocol(&self) -> Result<Protocol, ProtocolBuilderError> {
        match Protocol::load(&self.protocol_name, self.storage.clone().unwrap())? {
            Some(protocol) => Ok(protocol),
            None => Err(ProtocolBuilderError::MissingProtocol),
        }
    }

    fn save_protocol(&self, protocol: Protocol) -> Result<(), ProtocolBuilderError> {
        protocol.save(self.storage.clone().unwrap())?;
        Ok(())
    }
}
