use bitcoin::script::read_scriptint;
use bitcoin::{PublicKey, Transaction, Txid};
use bitcoin_coordinator::TransactionStatus;
use bitcoin_scriptexec::scriptint_vec;
use console::style;
use enum_dispatch::enum_dispatch;
use key_manager::winternitz::{message_bytes_length, WinternitzSignature, WinternitzType};
use protocol_builder::scripts::ProtocolScript;
use protocol_builder::types::output::SpeedupData;
use protocol_builder::types::{InputArgs, OutputType, Utxo};
use protocol_builder::{builder::Protocol, errors::ProtocolBuilderError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::rc::Rc;
use storage_backend::error::StorageError;
use storage_backend::storage::Storage;
use tracing::{error, info};
use uuid::Uuid;

use super::super::participant::ParticipantKeys;
use crate::errors::BitVMXError;
use crate::keychain::KeyChain;
#[cfg(feature = "union")]
use crate::program::protocols::union::full_penalization::FullPenalizationProtocol;

use super::aggregated_key::AggregatedKeyProtocol;
#[cfg(feature = "cardinal")]
use super::cardinal::{lock::LockProtocol, slot::SlotProtocol, transfer::TransferProtocol};
use super::cooperative_signature::CooperativeSignatureProtocol;
use super::dispute::DisputeResolutionProtocol;

#[cfg(feature = "union")]
use crate::program::protocols::union::{
    accept_pegin::AcceptPegInProtocol, advance_funds::AdvanceFundsProtocol,
    dispute_core::DisputeCoreProtocol, pairwise_penalization::PairwisePenalizationProtocol,
    reject_pegin::RejectPegInProtocol, user_take::UserTakeProtocol,
};

#[cfg(feature = "union")]
use crate::types::{
    PROGRAM_TYPE_ACCEPT_PEGIN, PROGRAM_TYPE_ADVANCE_FUNDS, PROGRAM_TYPE_DISPUTE_CORE,
    PROGRAM_TYPE_FULL_PENALIZATION, PROGRAM_TYPE_PAIRWISE_PENALIZATION, PROGRAM_TYPE_REJECT_PEGIN,
    PROGRAM_TYPE_USER_TAKE,
};

#[cfg(feature = "cardinal")]
use crate::types::{PROGRAM_TYPE_LOCK, PROGRAM_TYPE_SLOT, PROGRAM_TYPE_TRANSFER};

use crate::types::{
    ProgramContext, PROGRAM_TYPE_AGGREGATED_KEY, PROGRAM_TYPE_COOPERATIVE_SIGNATURE,
    PROGRAM_TYPE_DRP,
};

use crate::program::setup::steps::SetupStepName;
use crate::program::variables::WitnessTypes;
use crate::program::{variables::VariableTypes, witness};

#[enum_dispatch]
pub trait ProtocolHandler {
    fn context(&self) -> &ProtocolContext;
    fn context_mut(&mut self) -> &mut ProtocolContext;
    fn get_pregenerated_aggregated_keys(
        &self,
        _context: &ProgramContext,
    ) -> Result<Vec<(String, PublicKey)>, BitVMXError> {
        // Default implementation: no pregenerated keys
        Ok(vec![])
    }

    fn generate_keys(
        &self,
        program_context: &mut ProgramContext,
    ) -> Result<ParticipantKeys, BitVMXError>;

    fn set_storage(&mut self, storage: Rc<Storage>) {
        self.context_mut().storage = Some(storage);
    }

    // Default to 1 confirmation for Bitcoin transactions
    // Each protocol should override if different
    fn requested_confirmations(&self, program_context: &ProgramContext) -> Option<u32> {
        Some(
            program_context
                .globals
                .get_var(&self.context().id, "requested_confirmations")
                .unwrap_or(None)
                .unwrap_or(VariableTypes::Number(1))
                .number()
                .unwrap_or(1) as u32,
        )
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
        let ret = self
            .load_protocol()?
            .get_hashed_message(transaction_name, input_index, message_index)?
            .ok_or_else(|| {
                error!(
                    "Invalid transaction name when getting hashed message: {}. Protocol ID: {}",
                    transaction_name,
                    self.context().id
                );
                BitVMXError::InvalidTransactionName(transaction_name.to_string())
            })?;

        Ok(format!("{}", ret))
    }

    fn get_transaction_by_id(&self, txid: &Txid) -> Result<Transaction, ProtocolBuilderError> {
        self.load_protocol()?.transaction_by_id(txid).cloned()
    }

    fn add_vout_to_monitor(
        &self,
        program_context: &ProgramContext,
        name: &str,
        vout: u32,
    ) -> Result<(), BitVMXError> {
        let mut tx_names_and_vout = program_context
            .globals
            .get_var(&self.context().id, "tx_vouts_to_monitor")?
            .unwrap_or(VariableTypes::VecStr(vec![]))
            .vec_string()?;
        tx_names_and_vout.push(format!("{}:{}", name, vout));
        program_context.globals.set_var(
            &self.context().id,
            "tx_vouts_to_monitor",
            VariableTypes::VecStr(tx_names_and_vout),
        )?;

        Ok(())
    }

    fn get_transactions_to_monitor(
        &self,
        program_context: &ProgramContext,
    ) -> Result<(Vec<Txid>, Vec<(Txid, u32)>), BitVMXError> {
        // Try to load protocol, but if it doesn't exist (e.g., protocols without transactions),
        // return empty vectors
        let protocol = match self.load_protocol() {
            Ok(p) => p,
            Err(_) => {
                // Protocol doesn't exist or has no transactions - return empty
                return Ok((vec![], vec![]));
            }
        };
        let txs = protocol.get_transaction_ids();
        let tx_names_and_vout = program_context
            .globals
            .get_var(&self.context().id, "tx_vouts_to_monitor")?
            .unwrap_or(VariableTypes::VecStr(vec![]))
            .vec_string()?;
        let mut parsed: Vec<(Txid, u32)> = vec![];
        for name in &tx_names_and_vout {
            let parts: Vec<&str> = name.split(':').collect();
            if parts.len() == 2 {
                parsed.push((
                    protocol.transaction_by_name(parts[0])?.compute_txid(),
                    parts[1].parse::<u32>().unwrap_or(0),
                ));
            } else {
                error!("Invalid tx_vouts_to_monitor format: {}", name);
                return Err(BitVMXError::InvalidVariableType(
                    "tx_vouts_to_monitor".to_string(),
                ));
            }
        }

        Ok((txs, parsed))
    }

    fn get_transaction_name_by_id(&self, txid: Txid) -> Result<String, ProtocolBuilderError> {
        self.load_protocol()?.transaction_name_by_id(txid).cloned()
    }

    fn get_transaction_id_by_name(&self, name: &str) -> Result<Txid, ProtocolBuilderError> {
        Ok(self
            .load_protocol()?
            .transaction_by_name(name)?
            .compute_txid())
    }

    fn load_protocol(&self) -> Result<Protocol, ProtocolBuilderError> {
        match Protocol::load(
            &self.context().protocol_name,
            self.context()
                .storage
                .clone()
                .ok_or_else(|| StorageError::NotFound(self.context().protocol_name.clone()))?,
        )? {
            Some(protocol) => Ok(protocol),
            None => Err(ProtocolBuilderError::MissingProtocol(
                self.context().protocol_name.clone(),
            )),
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
        protocol.save(
            self.context()
                .storage
                .clone()
                .ok_or_else(|| StorageError::NotFound(self.context().protocol_name.clone()))?,
        )?;
        Ok(())
    }

    fn get_transaction_by_name(
        &self,
        name: &str,
        _context: &ProgramContext,
    ) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
        // Default implementation: protocol has no transactions
        Err(BitVMXError::InvalidTransactionName(format!(
            "Transaction '{}' not found - protocol has no transactions",
            name
        )))
    }

    fn notify_news(
        &self,
        _tx_id: Txid,
        _vout: Option<u32>,
        _tx_status: TransactionStatus,
        _context: String,
        _program_context: &ProgramContext,
        _participant_keys: Vec<&ParticipantKeys>,
    ) -> Result<(), BitVMXError> {
        // Default implementation: no-op for protocols that don't need to handle news
        Ok(())
    }

    fn notify_external_news(
        &self,
        _tx_id: Txid,
        _vout: Option<u32>,
        _tx_status: TransactionStatus,
        _context: String,
        _program_context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        Ok(())
    }

    fn get_winternitz_signature_for_script(
        &self,
        protocol_script: &ProtocolScript,
        program_context: &ProgramContext,
    ) -> Result<Vec<WinternitzSignature>, BitVMXError> {
        let mut wots_sigs = vec![];

        for k in protocol_script.get_keys().iter().rev() {
            //info!("Getting winternitz signature for key: {}", k.name());
            if let Some(var) = program_context
                .globals
                .get_var(&self.context().id, k.name())?
            {
                let message = var.input()?;

                info!(
                    "Signing message: {}",
                    style(hex::encode(message.clone())).yellow()
                );
                info!("With key: {:?}", k);

                let winternitz_signature = program_context
                    .key_chain
                    .key_manager
                    .sign_winternitz_message_by_index(
                        &message,
                        WinternitzType::HASH160,
                        protocol_script
                            .get_key(k.name())
                            .ok_or_else(|| BitVMXError::KeysNotFound(self.context().id))?
                            .derivation_index(),
                    )?;

                wots_sigs.push(winternitz_signature);
            } else {
                if let Some(witness) = program_context
                    .witness
                    .get_witness(&self.context().id, k.name())?
                {
                    let sigs = witness.winternitz()?;
                    info!(
                        "Winternitz signature found in witness for key: {}, with msg: {}",
                        k.name(),
                        hex::encode(sigs.message_bytes())
                    );
                    wots_sigs.push(sigs);
                } else {
                    error!("No winternitz signature found for key: {}", k.name());
                    return Err(BitVMXError::KeysNotFound(self.context().id));
                }
            }
        }
        Ok(wots_sigs)
    }

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
        info!("Getting signed tx for {}", style(name).green());

        //TODO: Control that the variables sizes correspond with the keys
        //avoid invalid sig checks

        let mut spending_args = InputArgs::new_taproot_script_args(leaf_index as usize);

        let spend = protocol.get_script_to_spend(name, input_index, leaf_index)?;
        for sig in self.get_winternitz_signature_for_script(&spend, context)? {
            spending_args.push_winternitz_signature(sig);
        }

        let signature = protocol
            .input_taproot_script_spend_signature(name, input_index as usize, leaf_index as usize)?
            .ok_or_else(|| BitVMXError::MissingInputSignature {
                tx_name: name.to_string(),
                input_index: input_index as usize,
                script_index: None,
            })?;
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
                .ok_or_else(|| BitVMXError::MissingInputSignature {
                    tx_name: name.to_string(),
                    input_index: 1,
                    script_index: None,
                })?;
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
        transaction: &Transaction,
        leaf: Option<u32>,
        protocol: Option<Protocol>,
        scripts: Option<Vec<ProtocolScript>>,
    ) -> Result<(Vec<String>, u32), BitVMXError> {
        info!(
            "Program {}: Decoding witness for {} with input index {}",
            style(self.context().protocol_name.clone()).blue(),
            style(name).green(),
            style(input_index).yellow()
        );
        let protocol = protocol.unwrap_or(self.load_protocol()?);

        let witness = transaction.input[input_index as usize].witness.clone();
        let leaf = match leaf {
            Some(idx) => idx,
            None => {
                let leaf = read_scriptint(
                    witness
                        .third_to_last()
                        .ok_or_else(|| BitVMXError::InvalidWitness(witness.clone()))?,
                )? as u32;
                program_context.globals.set_var(
                    &self.context().id,
                    &format!("{}_{}_leaf_index", name, input_index),
                    VariableTypes::Number(leaf),
                )?;
                info!(
                    "Leaf index for {}: {}",
                    style(name).green(),
                    style(leaf).yellow()
                );
                leaf
            }
        };

        let script = if let Some(scripts) = scripts {
            scripts[leaf as usize].clone()
        } else {
            protocol.get_script_to_spend(&name, input_index, leaf)?
        };

        let mut names = vec![];
        let mut sizes = vec![];
        //TODO: make the script save the size so we don't need to get it from participant keys or variables
        for k in script.get_keys().iter().rev() {
            names.push(k.name().to_string());

            let size = k.key_type().winternitz_message_size().map_err(|e| {
                error!("Failed to get key size for {}: {}", k.name(), e);
                e
            })?;
            sizes.push(message_bytes_length(size));
        }

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
        Ok((names, leaf))
    }

    fn decode_witness_from_speedup(
        &self,
        prev_tx_id: Txid,
        prev_vout: u32,
        prev_name: &str,
        program_context: &ProgramContext,
        transaction: &Transaction,
        leaf: Option<u32>,
    ) -> Result<(Vec<String>, u32), BitVMXError> {
        let idx = self.find_prevout(prev_tx_id, prev_vout, transaction)?;
        let protocol = self.load_protocol()?;
        let scripts = protocol
            .get_script_from_output(prev_name, prev_vout)?
            .1
            .clone();

        self.decode_witness_for_tx(
            prev_name,
            idx,
            program_context,
            transaction,
            leaf,
            Some(protocol),
            Some(scripts),
        )
    }

    fn find_prevout(&self, tx_id: Txid, vout: u32, tx: &Transaction) -> Result<u32, BitVMXError> {
        for (i, txin) in tx.input.iter().enumerate() {
            if txin.previous_output.txid == tx_id && txin.previous_output.vout == vout {
                return Ok(i as u32);
            }
        }
        return Err(BitVMXError::InvalidTransactionName(
            "The tx did not consume the expected output".to_string(),
        ));
    }

    fn checked_sub(&self, amount: u64, value_to_subtract: u64) -> Result<u64, BitVMXError> {
        match amount.checked_sub(value_to_subtract) {
            Some(amount) => Ok(amount),
            None => {
                error!("Insufficient amount: {} - {}", amount, value_to_subtract);
                Err(BitVMXError::InsufficientAmount)
            }
        }
    }

    fn get_speedup_key(&self, program_context: &ProgramContext) -> Result<PublicKey, BitVMXError> {
        program_context
            .globals
            .get_var_or_err(&self.context().id, "speedup")?
            .pubkey()
    }

    fn get_speedup_data_from_tx(
        &self,
        tx: &Transaction,
        program_context: &ProgramContext,
        vout: Option<u32>,
    ) -> Result<SpeedupData, BitVMXError> {
        let txid = tx.compute_txid();
        let speedup = self.get_speedup_key(program_context)?;
        let vout = vout.unwrap_or(tx.output.len() as u32 - 1);
        let speedup_utxo = Utxo::new(
            txid,
            vout,
            tx.output[vout as usize].value.to_sat(),
            &speedup,
        );
        Ok(speedup_utxo.into())
    }

    fn load_protocol_by_name(
        &self,
        name: &str,
        protocol_id: Uuid,
    ) -> Result<ProtocolType, BitVMXError> {
        new_protocol_type(
            protocol_id,
            name,
            self.context().my_idx,
            self.context()
                .storage
                .as_ref()
                .ok_or_else(|| {
                    BitVMXError::StorageUnavailable(self.context().protocol_name.clone())
                })?
                .clone(),
        )
    }

    fn setup_complete(&self, _program_context: &ProgramContext) -> Result<(), BitVMXError> {
        // Default implementation: no additional setup needed
        Ok(())
    }

    /// Whether ProgramV2 should send a SetupCompleted message when this protocol finishes setup.
    ///
    /// Defaults to `true`. Protocols that are used internally (e.g., AggregatedKeyProtocol
    /// created by SetupKey) should return `false` to maintain backward compatibility,
    /// since the caller only expects the protocol-specific response (e.g., AggregatedPubkey).
    fn send_setup_completed(&self) -> bool {
        true
    }

    /// Returns the list of setup step names for this protocol.
    ///
    /// By default, returns the standard steps: keys, nonces, signatures.
    /// Protocols can override this method to customize their setup flow.
    ///
    /// Returns None if the protocol doesn't use the SetupEngine system.
    /// Protocols using ProgramV2 MUST override this to return their required steps.
    ///
    /// The steps will be created by the factory when needed.
    fn setup_steps(&self) -> Option<Vec<SetupStepName>> {
        Some(vec![
            SetupStepName::Keys,
            SetupStepName::Nonces,
            SetupStepName::Signatures,
        ])
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
    AggregatedKeyProtocol,
    CooperativeSignatureProtocol,
    DisputeResolutionProtocol,
    #[cfg(feature = "cardinal")]
    LockProtocol,
    #[cfg(feature = "cardinal")]
    SlotProtocol,
    #[cfg(feature = "cardinal")]
    TransferProtocol,
    #[cfg(feature = "union")]
    AcceptPegInProtocol,
    #[cfg(feature = "union")]
    UserTakeProtocol,
    #[cfg(feature = "union")]
    AdvanceFundsProtocol,
    #[cfg(feature = "union")]
    DisputeCoreProtocol,
    #[cfg(feature = "union")]
    PairwisePenalizationProtocol,
    #[cfg(feature = "union")]
    FullPenalizationProtocol,
    #[cfg(feature = "union")]
    RejectPegInProtocol,
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
        PROGRAM_TYPE_AGGREGATED_KEY => Ok(ProtocolType::AggregatedKeyProtocol(
            AggregatedKeyProtocol::new(ctx),
        )),
        PROGRAM_TYPE_COOPERATIVE_SIGNATURE => Ok(ProtocolType::CooperativeSignatureProtocol(
            CooperativeSignatureProtocol::new(ctx),
        )),
        PROGRAM_TYPE_DRP => Ok(ProtocolType::DisputeResolutionProtocol(
            DisputeResolutionProtocol::new(ctx),
        )),
        #[cfg(feature = "cardinal")]
        PROGRAM_TYPE_LOCK => Ok(ProtocolType::LockProtocol(LockProtocol::new(ctx))),
        #[cfg(feature = "cardinal")]
        PROGRAM_TYPE_SLOT => Ok(ProtocolType::SlotProtocol(SlotProtocol::new(ctx))),
        #[cfg(feature = "cardinal")]
        PROGRAM_TYPE_TRANSFER => Ok(ProtocolType::TransferProtocol(TransferProtocol::new(ctx))),
        #[cfg(feature = "union")]
        PROGRAM_TYPE_ACCEPT_PEGIN => Ok(ProtocolType::AcceptPegInProtocol(
            AcceptPegInProtocol::new(ctx),
        )),
        #[cfg(feature = "union")]
        PROGRAM_TYPE_USER_TAKE => Ok(ProtocolType::UserTakeProtocol(UserTakeProtocol::new(ctx))),
        #[cfg(feature = "union")]
        PROGRAM_TYPE_ADVANCE_FUNDS => Ok(ProtocolType::AdvanceFundsProtocol(
            AdvanceFundsProtocol::new(ctx),
        )),
        #[cfg(feature = "union")]
        PROGRAM_TYPE_PAIRWISE_PENALIZATION => Ok(ProtocolType::PairwisePenalizationProtocol(
            PairwisePenalizationProtocol::new(ctx),
        )),
        #[cfg(feature = "union")]
        PROGRAM_TYPE_REJECT_PEGIN => Ok(ProtocolType::RejectPegInProtocol(
            RejectPegInProtocol::new(ctx),
        )),
        #[cfg(feature = "union")]
        PROGRAM_TYPE_DISPUTE_CORE => Ok(ProtocolType::DisputeCoreProtocol(
            DisputeCoreProtocol::new(ctx),
        )),
        #[cfg(feature = "union")]
        PROGRAM_TYPE_FULL_PENALIZATION => Ok(ProtocolType::FullPenalizationProtocol(
            FullPenalizationProtocol::new(ctx),
        )),
        _ => Err(BitVMXError::NotImplemented(name.to_string())),
    }
}

pub fn external_fund_tx(
    internal_key: &PublicKey,
    spending_scripts: Vec<ProtocolScript>,
    amount: u64,
) -> Result<OutputType, BitVMXError> {
    Ok(OutputType::taproot(
        amount,
        internal_key,
        &spending_scripts,
    )?)
}
