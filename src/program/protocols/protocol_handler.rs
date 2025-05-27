use bitcoin::key::UntweakedPublicKey;
use bitcoin::script::read_scriptint;
use bitcoin::{secp256k1, Amount, PublicKey, ScriptBuf, Transaction, TxOut, Txid, XOnlyPublicKey};
use bitcoin_coordinator::TransactionStatus;
use bitcoin_scriptexec::scriptint_vec;
use enum_dispatch::enum_dispatch;
use key_manager::winternitz::{message_bytes_length, WinternitzType};
use protocol_builder::scripts::{self, ProtocolScript};
use protocol_builder::types::{InputArgs, OutputType};
use protocol_builder::{builder::Protocol, errors::ProtocolBuilderError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::rc::Rc;
use storage_backend::storage::Storage;
use tracing::info;
use uuid::Uuid;

use crate::errors::BitVMXError;
use crate::keychain::KeyChain;

use crate::program::variables::WitnessTypes;
use crate::program::witness;
use crate::types::{
    ProgramContext, PROGRAM_TYPE_DRP, PROGRAM_TYPE_LOCK, PROGRAM_TYPE_SLOT, PROGRAM_TYPE_TRANSFER,
};

use super::super::participant::ParticipantKeys;
use super::dispute::DisputeResolutionProtocol;
use super::lock::LockProtocol;
use super::slot::SlotProtocol;
use super::transfer::TransferProtocol;

#[enum_dispatch]
pub trait ProtocolHandler {
    fn context(&self) -> &ProtocolContext;
    fn context_mut(&mut self) -> &mut ProtocolContext;
    fn get_pregenerated_aggregated_keys(
        &self,
        context: &ProgramContext,
    ) -> Result<Vec<(String, PublicKey)>, BitVMXError>;

    fn generate_keys(
        &self,
        program_context: &mut ProgramContext,
    ) -> Result<ParticipantKeys, BitVMXError>;

    fn set_storage(&mut self, storage: Rc<Storage>) {
        self.context_mut().storage = Some(storage);
    }

    fn build(
        &self,
        _keys: Vec<ParticipantKeys>,
        _computed_aggregated: HashMap<String, PublicKey>,
        _context: &ProgramContext,
    ) -> Result<(), BitVMXError>;

    fn sign(&mut self, key_chain: &KeyChain) -> Result<(), ProtocolBuilderError> {
        let mut protocol = self.load_protocol()?;
        protocol.sign(&key_chain.key_manager, &self.context().protocol_name)?;
        self.save_protocol(protocol)?;
        Ok(())
    }

    fn get_hashed_message(
        &mut self,
        transaction_name: &str,
        input_index: u32,
        message_index: u32,
    ) -> Result<String, BitVMXError> {
        let ret = self.load_protocol()?.get_hashed_message(
            transaction_name,
            input_index,
            message_index,
        )?;
        if ret.is_none() {
            return Err(BitVMXError::InvalidTransactionName(
                transaction_name.to_string(),
            ));
        }
        Ok(format!("{}", ret.unwrap()))
    }

    fn get_transaction_by_id(&self, txid: &Txid) -> Result<Transaction, ProtocolBuilderError> {
        self.load_protocol()?.transaction_by_id(txid).cloned()
    }

    fn get_transaction_ids(&self) -> Result<Vec<Txid>, ProtocolBuilderError> {
        Ok(self.load_protocol()?.get_transaction_ids())
    }

    fn get_transaction_name_by_id(&self, txid: Txid) -> Result<String, ProtocolBuilderError> {
        self.load_protocol()?.transaction_name_by_id(txid).cloned()
    }

    fn load_protocol(&self) -> Result<Protocol, ProtocolBuilderError> {
        match Protocol::load(
            &self.context().protocol_name,
            self.context().storage.clone().unwrap(),
        )? {
            Some(protocol) => Ok(protocol),
            None => Err(ProtocolBuilderError::MissingProtocol),
        }
    }

    fn load_or_create_protocol(&self) -> Protocol {
        let protocol = self.load_protocol();
        match protocol {
            Ok(protocol) => protocol,
            Err(_) => Protocol::new(&self.context().protocol_name),
        }
    }

    fn save_protocol(&self, protocol: Protocol) -> Result<(), ProtocolBuilderError> {
        protocol.save(self.context().storage.clone().unwrap())?;
        Ok(())
    }

    fn get_transaction_name(
        &self,
        name: &str,
        context: &ProgramContext,
    ) -> Result<Transaction, BitVMXError>;

    fn notify_news(
        &self,
        tx_id: Txid,
        vout: Option<u32>,
        tx_status: TransactionStatus,
        context: String,
        program_context: &ProgramContext,
        participant_keys: Vec<&ParticipantKeys>,
    ) -> Result<(), BitVMXError>;

    fn get_signed_tx(
        &self,
        context: &ProgramContext,
        name: &str,
        input_index: u32,
        leaf_index: u32,
        leaf_identification: bool,
        second_leaf_index: usize,
    ) -> Result<Transaction, BitVMXError> {
        let protocol = self.load_protocol()?;
        info!("Getting signed tx for {}", name);

        //TODO: Control that the variables sizes correspond with the keys
        //avoid invalid sig checks

        let signature = protocol
            .input_taproot_script_spend_signature(name, input_index as usize, leaf_index as usize)?
            .unwrap();
        let spend = protocol.get_script_to_spend(name, input_index, leaf_index)?;
        let mut spending_args = InputArgs::new_taproot_script_args(leaf_index as usize);

        for k in spend.get_keys().iter().rev() {
            let message = context
                .globals
                .get_var(&self.context().id, k.name())?
                .input()?;

            info!("Signigng message: {}", hex::encode(message.clone()));
            info!("With key: {:?}", k);

            let winternitz_signature = context.key_chain.key_manager.sign_winternitz_message(
                &message,
                WinternitzType::HASH160,
                spend.get_key(k.name()).unwrap().derivation_index(),
            )?;

            spending_args.push_winternitz_signature(winternitz_signature);
        }

        spending_args.push_taproot_signature(signature)?;
        if leaf_identification {
            spending_args.push_slice(scriptint_vec(leaf_index as i64).as_slice());
        }

        let mut args = vec![];
        args.push(spending_args);

        //TODO: try to generelaize to all inputs. This is a workaround to sign the claim-gate
        let tx = protocol.transaction_by_name(name)?;
        let total_inputs = tx.input.len();
        if total_inputs > 1 {
            let signature = protocol
                .input_taproot_script_spend_signature(name, 1, second_leaf_index)?
                .unwrap();
            let mut spending_args = InputArgs::new_taproot_script_args(second_leaf_index);
            spending_args.push_taproot_signature(signature)?;
            args.push(spending_args);
        }

        Ok(protocol.transaction_to_send(name, &args.as_slice())?)
    }

    fn decode_witness_for_tx(
        &self,
        name: &str,
        input_index: u32,
        program_context: &ProgramContext,
        participant_keys: &ParticipantKeys,
        transaction: &Transaction,
        leaf: Option<u32>,
    ) -> Result<Vec<String>, BitVMXError> {
        info!(
            "Program {}: Decoding witness for {} with input index {}",
            self.context().id,
            name,
            input_index
        );
        let protocol = self.load_protocol()?;

        let witness = transaction.input[0].witness.clone();
        let leaf = match leaf {
            Some(idx) => idx,
            None => {
                let leaf = read_scriptint(witness.third_to_last().unwrap()).unwrap() as u32;
                leaf
            }
        };

        let script = protocol.get_script_to_spend(&name, input_index, leaf)?;

        let mut names = vec![];
        let mut sizes = vec![];
        script.get_keys().iter().rev().for_each(|k| {
            names.push(k.name().to_string());
            sizes.push(message_bytes_length(
                participant_keys
                    .get_winternitz(k.name())
                    .unwrap()
                    .message_size()
                    .unwrap(),
            ));
        });
        info!("Decoding data for {}", name);
        info!("Names: {:?}", names);
        info!("Sizes: {:?}", sizes);

        let data = witness::decode_witness(sizes, WinternitzType::HASH160, witness)?;
        for i in 0..data.len() {
            info!(
                "Program {}:{} Witness data decoded: {}",
                self.context().id,
                names[i],
                hex::encode(&data[i].message_bytes())
            );
            program_context.witness.set_witness(
                &self.context().id,
                &names[i],
                WitnessTypes::Winternitz(data[i].clone()),
            )?;
        }
        Ok(names)
    }

    fn checked_sub(&self, amount: u64, value_to_subtract: u64) -> Result<u64, BitVMXError> {
         match amount.checked_sub(value_to_subtract){
            Some(amount) => Ok(amount),
            None => Err(BitVMXError::InsufficientAmount)
         }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ProtocolContext {
    pub protocol_name: String,
    pub id: Uuid,
    pub my_idx: usize,
    #[serde(skip)]
    pub storage: Option<Rc<Storage>>,
}

impl ProtocolContext {
    pub fn new(id: Uuid, name: &str, my_idx: usize, storage: Rc<Storage>) -> Self {
        Self {
            id,
            protocol_name: name.to_string(),
            my_idx,
            storage: Some(storage),
        }
    }
}

#[enum_dispatch(ProtocolHandler)]
#[derive(Clone, Serialize, Deserialize)]
pub enum ProtocolType {
    DisputeResolutionProtocol,
    LockProtocol,
    SlotProtocol,
    TransferProtocol,
}

pub fn new_protocol_type(
    id: Uuid,
    name: &str,
    my_idx: usize,
    storage: Rc<Storage>,
) -> Result<ProtocolType, BitVMXError> {
    let protocol_name = format!("{}_{}", name, id);
    let ctx = ProtocolContext::new(id, &protocol_name, my_idx, storage);

    match name {
        PROGRAM_TYPE_DRP => Ok(ProtocolType::DisputeResolutionProtocol(
            DisputeResolutionProtocol::new(ctx),
        )),
        PROGRAM_TYPE_LOCK => Ok(ProtocolType::LockProtocol(LockProtocol::new(ctx))),
        PROGRAM_TYPE_SLOT => Ok(ProtocolType::SlotProtocol(SlotProtocol::new(ctx))),
        PROGRAM_TYPE_TRANSFER => Ok(ProtocolType::TransferProtocol(TransferProtocol::new(ctx))),
        _ => Err(BitVMXError::NotImplemented(name.to_string())),
    }
}

impl ProtocolType {
    pub fn dispute(self) -> Result<DisputeResolutionProtocol, BitVMXError> {
        match self {
            ProtocolType::DisputeResolutionProtocol(protocol) => Ok(protocol),
            _ => Err(BitVMXError::InvalidMessageType),
        }
    }
}

pub fn external_fund_tx(
    internal_key: &PublicKey,
    //aggregated_list: &Vec<&PublicKey>,
    spending_scripts: Vec<ProtocolScript>,
    amount: u64,
) -> Result<OutputType, BitVMXError> {
    let secp = secp256k1::Secp256k1::new();
    let untweaked_key: UntweakedPublicKey = XOnlyPublicKey::from(*internal_key);

    /*let spending_scripts = aggregated_list
    .iter()
    .map(|k| scripts::check_aggregated_signature(k, SignMode::Aggregate))
    .collect::<Vec<_>>();*/

    let spend_info = scripts::build_taproot_spend_info(&secp, &untweaked_key, &spending_scripts)?;

    let script_pubkey = ScriptBuf::new_p2tr(&secp, untweaked_key, spend_info.merkle_root());

    //Description of the output that the SETUP_TX consumes
    let prevout = TxOut {
        value: Amount::from_sat(amount),
        script_pubkey,
    };

    Ok(OutputType::taproot(
        amount,
        internal_key,
        &spending_scripts,
        &vec![prevout],
    )?)
}
