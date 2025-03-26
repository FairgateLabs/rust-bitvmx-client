use std::{collections::HashMap, rc::Rc};

use bitcoin::{key::UntweakedPublicKey, secp256k1::{self, Message}, Amount, PublicKey, ScriptBuf, Transaction, TxOut, Txid, XOnlyPublicKey};
use protocol_builder::{
    builder::{Protocol, ProtocolBuilder, SpendingArgs},
    errors::ProtocolBuilderError,
    graph::{
        graph::MessageId, input::{InputSpendingInfo, SighashType, Signature}, output::OutputSpendingType
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

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Funding {
    pub txid: Txid,
    pub vout: u32,
    pub pubkey: PublicKey,
    pub amount: Amount,
    pub protocol: u64,
    pub timelock: u64,
    pub speedup: u64,
}

impl Funding {
    pub fn new(
        txid: Txid,
        vout: u32,
        pubkey: PublicKey,
        amount: u64,
        protocol: u64,
        timelock: u64,
        speedup: u64,
    ) -> Self {
        Self {
            txid,
            vout,
            pubkey,
            amount: Amount::from_sat(amount),
            protocol,
            timelock,
            speedup,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct DisputeResolutionProtocol {
    pub protocol_name: String,
    pub funding: Funding,
    #[serde(skip)]
    storage: Option<Rc<Storage>>,
}

const PREKICKOFF: &str = "pre_kickoff";
const KICKOFF: &str = "kickoff";
const PROTOCOL: &str = "protocol";

impl DisputeResolutionProtocol {
    pub fn new(
        funding: Funding,
        program_id: Uuid,
        storage: Rc<Storage>,
    ) -> Result<DisputeResolutionProtocol, ProtocolBuilderError> {
        let protocol_name = format!("drp_{}", program_id);

        Ok(Self {
            protocol_name,
            funding,
            storage: Some(storage),
        })
    }

    pub fn set_storage(&mut self, storage: Rc<Storage>) {
        self.storage = Some(storage);
    }

    pub fn build(
        &self,
        id: &str,
        internal_key: &PublicKey,
        prover_keys: &ParticipantKeys,
        _verifier_keys: &ParticipantKeys,
        _search: SearchParams,
        key_chain: &KeyChain,
    ) -> Result<(), ProtocolBuilderError> {
        // let ecdsa_sighash_type = SighashType::ecdsa_all();
        let tr_sighash_type = SighashType::taproot_all();

        let mut builder = ProtocolBuilder::new(&self.protocol_name, self.storage.clone().unwrap())?;
        // let output_type =
        //     OutputSpendingType::new_segwit_key_spend(&internal_key, self.funding.amount);

        let secp = secp256k1::Secp256k1::new();
        let untweaked_key: UntweakedPublicKey = XOnlyPublicKey::from(*internal_key);
        let script_pubkey = ScriptBuf::new_p2tr(&secp, untweaked_key, None);

        let prevout = TxOut{
            value: self.funding.amount,
            script_pubkey,
        };

        let output_type = OutputSpendingType::TaprootUntweakedKey { key: internal_key.clone(), prevouts: vec![prevout] };
            
        builder.connect_with_external_transaction(
            self.funding.txid,
            self.funding.vout,
            output_type,
            PREKICKOFF,
            &tr_sighash_type,
        )?;

        let kickoff_spending = scripts::kickoff(
            internal_key,
            &prover_keys.program_input_key,
            &prover_keys.program_ending_state,
            &prover_keys.program_ending_step_number,
        )?;

        builder.add_taproot_script_spend_connection(
            PROTOCOL,
            PREKICKOFF,
            self.funding.protocol + self.funding.timelock,
            &prover_keys.internal,
            &[kickoff_spending],
            KICKOFF,
            &tr_sighash_type,
        )?;
        builder.add_speedup_output(PREKICKOFF, self.funding.speedup, &prover_keys.speedup)?;

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
        let signature = self.load_protocol()?.input_ecdsa_signature(PREKICKOFF, 0)?;
        let mut ecdsa_arg = SpendingArgs::new_args();
        ecdsa_arg.push_ecdsa_signature(signature);

        self.load_protocol()?
            .transaction_to_send(PREKICKOFF, &[ecdsa_arg])
    }

    pub fn kickoff_transaction(&self) -> Result<Transaction, ProtocolBuilderError> {
        self.load_protocol()?.transaction_to_send(KICKOFF, &[])
    }

    pub fn spending_infos(
        &self,
    ) -> Result<HashMap<String, Vec<InputSpendingInfo>>, ProtocolBuilderError> {
        self.load_protocol()?.spending_infos()
    }

    pub fn update_input_signatures(
        &self,
        transaction_name: &str,
        input_index: u32,
        signatures: Vec<Signature>,
    ) -> Result<(), ProtocolBuilderError> {
        let mut protocol = self.load_protocol()?;
        protocol.update_input_signatures(transaction_name, input_index, signatures)?;
        self.save_protocol(protocol)?;
        Ok(())
    }

    pub fn protocol_sighashes(&self) -> Result<Vec<(MessageId, Message)>, ProtocolBuilderError> {
        let sighashes = self.load_protocol()?.get_all_sighashes()?;

        // let mut sighashes = Vec::new();

        // for (_, infos) in spending_infos {
        //     for info in infos {
        //         for message in info.hashed_messages() {
        //             sighashes.push(message.to_owned());
        //         }  
        //     }
        // }

        Ok(sighashes)
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
