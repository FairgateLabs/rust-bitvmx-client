use bitcoin::script::read_scriptint;
use bitcoin::{PublicKey, Transaction, Txid};
use bitcoin_coordinator::TransactionStatus;
use bitcoin_scriptexec::scriptint_vec;
use console::style;
use enum_dispatch::enum_dispatch;
use key_manager::key_manager::KeyManager;
use key_manager::lamport::{HashFunction, LamportSignature};
use key_manager::winternitz::{message_bytes_length, WinternitzSignature, WinternitzType};
use protocol_builder::builder::ProtocolBuilder;
use protocol_builder::scripts::{self, ProtocolScript, SignMode};
use protocol_builder::types::connection::{InputSpec, OutputSpec};
use protocol_builder::types::input::{SighashType, SpendMode};
use protocol_builder::types::output::{AmountType, SpeedupData};
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
use crate::program::participant::ParticipantRole;
use crate::program::protocols::claim::ClaimGate;
#[cfg(feature = "union")]
use crate::program::protocols::union::full_penalization::FullPenalizationProtocol;
use crate::program::protocols::{dispute, light_drp};

use super::aggregated_key::AggregatedKeyProtocol;
#[cfg(feature = "cardinal")]
use super::cardinal::{lock::LockProtocol, slot::SlotProtocol, transfer::TransferProtocol};
use super::dispute::DisputeResolutionProtocol;
use super::light_drp::LightDisputeResolutionProtocol;

#[cfg(feature = "union")]
use crate::program::protocols::union::{
    accept_pegin::AcceptPegInProtocol, advance_funds::AdvanceFundsProtocol,
    dispute_core::DisputeCoreProtocol, pairwise_penalization::PairwisePenalizationProtocol,
    reject_pegin::RejectPegInProtocol, user_take::UserTakeProtocol,
};

#[cfg(feature = "union")]
use crate::types::{
    PROGRAM_TYPE_ACCEPT_PEGIN, PROGRAM_TYPE_ADVANCE_FUNDS, PROGRAM_TYPE_DISPUTE_CORE,
    PROGRAM_TYPE_FULL_PENALIZATION, PROGRAM_TYPE_LIGHT_DRP, PROGRAM_TYPE_PAIRWISE_PENALIZATION,
    PROGRAM_TYPE_REJECT_PEGIN, PROGRAM_TYPE_USER_TAKE,
};

#[cfg(feature = "cardinal")]
use crate::types::{PROGRAM_TYPE_LOCK, PROGRAM_TYPE_SLOT, PROGRAM_TYPE_TRANSFER};

use crate::types::{ProgramContext, PROGRAM_TYPE_AGGREGATED_KEY, PROGRAM_TYPE_DRP};

use crate::program::setup::steps::SetupStepName;
use crate::program::variables::{Globals, PartialUtxo, WitnessTypes};
use crate::program::{variables::VariableTypes, witness};

const REQUESTED_CONFIRMATIONS_VAR: &str = "requested_confirmations";

#[derive(Clone, Debug)]
pub struct LeafToSign {
    pub leaf_index: u32,
    pub leaf_identification: bool,
}

impl LeafToSign {
    pub fn new(leaf_index: u32, leaf_identification: bool) -> Self {
        Self {
            leaf_index,
            leaf_identification,
        }
    }
}

impl From<u32> for LeafToSign {
    fn from(leaf_index: u32) -> Self {
        Self {
            leaf_index,
            leaf_identification: false,
        }
    }
}

impl From<(u32, bool)> for LeafToSign {
    fn from(tuple: (u32, bool)) -> Self {
        Self {
            leaf_index: tuple.0,
            leaf_identification: tuple.1,
        }
    }
}

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
                .get_var(&self.context().id, REQUESTED_CONFIRMATIONS_VAR)
                .unwrap_or(None)
                .unwrap_or(VariableTypes::Number(1))
                .number()
                .unwrap_or(1) as u32,
        )
    }

    fn set_requested_confirmations(
        &self,
        program_context: &ProgramContext,
        confirmations: u32,
    ) -> Result<(), BitVMXError> {
        program_context.globals.set_var(
            &self.context().id,
            REQUESTED_CONFIRMATIONS_VAR,
            VariableTypes::Number(confirmations),
        )?;
        Ok(())
    }

    fn build(
        &self,
        _keys: Vec<ParticipantKeys>,
        _computed_aggregated: HashMap<String, PublicKey>,
        _context: &ProgramContext,
    ) -> Result<(), BitVMXError>;

    fn sign(&mut self, key_manager: &Rc<KeyManager>) -> Result<(), ProtocolBuilderError> {
        let mut protocol = match self.load_protocol() {
            Ok(p) => p,
            Err(ProtocolBuilderError::MissingProtocol(_)) => return Ok(()),
            Err(e) => return Err(e),
        };
        protocol.sign(key_manager, &self.context().protocol_name)?;
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
        )
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

    fn get_lamport_signature_for_script(
        &self,
        protocol_script: &ProtocolScript,
        program_context: &ProgramContext,
    ) -> Result<Vec<LamportSignature>, BitVMXError> {
        let keys = protocol_script.get_keys();
        let mut lamp_sigs = Vec::with_capacity(keys.len());

        for key in keys.iter().rev() {
            if let Some(var) = program_context
                .globals
                .get_var(&self.context().id, key.name())?
            {
                let message = var.input()?;

                info!(
                    "Signing message: {}",
                    style(hex::encode(message.clone())).yellow()
                );
                info!("With lamport key: {:?}", key);

                let lamport_signature =
                    program_context.key_manager.sign_lamport_message_by_pubkey(
                        &message,
                        key.key_type().lamport_public_key()?,
                    )?;

                lamp_sigs.push(lamport_signature);
            } else {
                error!("No Lamport signature found for key: {}", key.name());
                return Err(BitVMXError::KeysNotFound(self.context().id));
            }
        }

        Ok(lamp_sigs)
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

    fn get_signed(
        &self,
        context: &ProgramContext,
        name: &str,
        inputs: Vec<LeafToSign>,
    ) -> Result<Transaction, BitVMXError> {
        let mut all_input_args = vec![];

        let protocol = self.load_protocol()?;
        info!("Getting signed tx: {}", style(name).green());

        for (input_index, input) in inputs.iter().enumerate() {
            let mut spending_args = InputArgs::new_taproot_script_args(input.leaf_index as usize);

            let spend = protocol.get_script_to_spend(name, input_index as u32, input.leaf_index)?;
            for sig in self.get_winternitz_signature_for_script(&spend, context)? {
                spending_args.push_winternitz_signature(sig);
            }

            let signature = protocol
                .input_taproot_script_spend_signature(
                    name,
                    input_index as usize,
                    input.leaf_index as usize,
                )?
                .ok_or_else(|| BitVMXError::MissingInputSignature {
                    tx_name: name.to_string(),
                    input_index: input_index as usize,
                    script_index: Some(input.leaf_index as usize),
                })?;
            spending_args.push_taproot_signature(signature)?;

            if input.leaf_identification {
                spending_args.push_slice(scriptint_vec(input.leaf_index as i64).as_slice());
            }

            all_input_args.push(spending_args);
        }

        // Add signatures for extra inputs, defaulting to leaf 0
        let tx = protocol.transaction_by_name(name)?;
        let total_inputs = tx.input.len();
        if total_inputs > inputs.len() {
            for input_index in inputs.len()..total_inputs {
                let signature = protocol
                    .input_taproot_script_spend_signature(name, input_index, 0)?
                    .ok_or_else(|| BitVMXError::MissingInputSignature {
                        tx_name: name.to_string(),
                        input_index: input_index,
                        script_index: None,
                    })?;
                let mut spending_args = InputArgs::new_taproot_script_args(0);
                spending_args.push_taproot_signature(signature)?;
                all_input_args.push(spending_args);
            }
        }

        Ok(protocol.transaction_to_send(name, &all_input_args.as_slice())?)
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

    fn decode_lamport_for_speedup(
        &self,
        prev_tx_id: Txid,
        prev_vout: u32,
        prev_name: &str,
        transaction: &Transaction,
    ) -> Result<Vec<(Vec<u8>, u8)>, BitVMXError> {
        let idx = self.find_prevout(prev_tx_id, prev_vout, transaction)?;
        let protocol = self.load_protocol()?;
        let script = &protocol.get_script_from_output(prev_name, prev_vout)?.1[0];

        let witness = transaction.input[idx as usize].witness.clone();
        let mut iter = witness.iter();

        let mut hashes = vec![];

        for key in script.get_keys().iter() {
            let key_type = key.key_type();
            let public_key = key_type.lamport_public_key()?;
            let (hashes_0, hashes_1) = public_key.to_hashes();

            for (hash_0, hash_1) in hashes_0.iter().zip(hashes_1.iter()) {
                let signature = iter
                    .next()
                    .ok_or(BitVMXError::ScriptSignatureMissing(key.name().to_string()))?;
                let hash = public_key.hash_type().hash(signature).to_bytes();

                if &hash == hash_0 {
                    hashes.push((hash, 0));
                } else if &hash == hash_1 {
                    hashes.push((hash, 1));
                } else {
                    error!("Found invalid lamport signature");
                }
            }
        }

        Ok(hashes)
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

    /// Whether Program should send a SetupCompleted message when this protocol finishes setup.
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
    /// Protocols using Program MUST override this to return their required steps.
    ///
    /// The steps will be created by the factory when needed.
    fn setup_steps(&self) -> Option<Vec<SetupStepName>> {
        Some(vec![
            SetupStepName::Keys,
            SetupStepName::Nonces,
            SetupStepName::Signatures,
        ])
    }

    fn add_connection_with_scripts<V: Into<AmountType> + std::fmt::Debug + std::clone::Clone>(
        &self,
        context: &ProgramContext,
        aggregated: &PublicKey,
        protocol: &mut Protocol,
        timelock_blocks: u16,
        amount: V,
        amount_speedup: u64,
        from: &str,
        to: &str,
        claim_gate: &ClaimGate,
        mut leaves: Vec<ProtocolScript>,
        speedup_keys: (&PublicKey, &PublicKey),
    ) -> Result<(), BitVMXError> {
        //TODO:
        // - Support multiple inputs
        // - check if input is prover of verifier and use proper keys[n]
        // - the prover needs to re-sign any verifier provided input (so the equivocation is possible on reads)

        info!(
            "Adding winternitz check for {} to {}. Amount: {:?}. Leaves {}",
            style(from).green(),
            style(to).green(),
            style(amount.clone()).green(),
            style(leaves.len()).yellow()
        );

        let (_mine_speedup, other_speedup) = speedup_keys;

        //add a tiemouet leaf to the possible leaves
        let timeout_input = scripts::timelock(timelock_blocks, &aggregated, SignMode::Aggregate);
        leaves.push(timeout_input);
        for (pos, leave) in leaves.iter_mut().enumerate() {
            leave.set_assert_leaf_id(pos as u32);
        }

        //creates the connector output with the connection and timeout leaves
        //the connector needs two times the timelock, because it needs to give time to the input in speedup timeout
        let mut connection_leaf = scripts::check_signature(aggregated, SignMode::Aggregate);
        connection_leaf.set_assert_leaf_id(0);
        let mut timeout_leaf =
            scripts::timelock(2 * timelock_blocks, &aggregated, SignMode::Aggregate);
        timeout_leaf.set_assert_leaf_id(1);
        let connector_leaves = vec![connection_leaf, timeout_leaf];

        let output_type = OutputType::taproot(amount, aggregated, &connector_leaves)?;

        // connector from -> to
        protocol.add_connection(
            &format!("{}__{}", from, to),
            from,
            output_type.clone().into(),
            to,
            InputSpec::Auto(SighashType::taproot_all(), SpendMode::Script { leaf: 0 }),
            None,
            None,
        )?;

        // creates the speedup output where the input will be commited
        let output_type = OutputType::taproot(amount_speedup, &aggregated, &leaves)?;
        protocol.add_transaction_output(to, &output_type)?;
        let last = protocol.get_output_count(to)? - 1;
        self.add_vout_to_monitor(context, to, last)?;

        // store the input and leaf for the timeout tx
        context.globals.set_var(
            &self.context().id,
            &timeout_tx(to),
            VariableTypes::VecNumber(vec![1, timelock_blocks as u32 * 2]),
        )?;

        // add the timeout tx to penalize the non-acting party
        protocol.add_connection(
            &format!("{}_TL_{}_{}_TO", from, 2 * timelock_blocks, to),
            from,
            OutputSpec::Last,
            &timeout_tx(to),
            InputSpec::Auto(SighashType::taproot_all(), SpendMode::Script { leaf: 1 }),
            Some(2 * timelock_blocks),
            None,
        )?;

        // if the previous party does not present the input in time, the other party can also consume the connector output of the connection
        // so is not forced to reply (as the reply will have a timelock that would allow the dihonest party to start a claim)
        if from != dispute::START_CH && from != light_drp::START_CH {
            protocol.add_connection(
                &format!("{}__CONNECTOR__INPUT_TO", from),
                from,
                OutputSpec::Last,
                &timeout_input_tx(from),
                InputSpec::Auto(SighashType::taproot_all(), SpendMode::Script { leaf: 0 }),
                None, //There is no timelock here as the timelock is already enforced by the other input of the timeout_input_tx
                None,
            )?;
        }

        //connect the opositte party claim gate to the timeout tx
        claim_gate.add_claimer_win_connection(protocol, &timeout_tx(to))?;
        let pb = ProtocolBuilder {};
        pb.add_speedup_output(protocol, &timeout_tx(to), amount_speedup, other_speedup)?;

        // store the input and leaf for the timeout tx
        context.globals.set_var(
            &self.context().id,
            &timeout_input_tx(to),
            VariableTypes::VecNumber(vec![leaves.len() as u32 - 1, timelock_blocks as u32]),
        )?;

        // add the timeout tx to penalize the party for not commiting the input
        protocol.add_connection(
            &format!("{}_TL_{}_INPUT_TO", to, timelock_blocks),
            to,
            OutputSpec::Last,
            &timeout_input_tx(to),
            InputSpec::Auto(
                SighashType::taproot_all(),
                SpendMode::Script {
                    leaf: leaves.len() - 1,
                },
            ),
            Some(timelock_blocks),
            None,
        )?;

        //connect the opositte party claim gate to the timeout tx
        claim_gate.add_claimer_win_connection(protocol, &timeout_input_tx(to))?;
        let pb = ProtocolBuilder {};
        pb.add_speedup_output(
            protocol,
            &timeout_input_tx(to),
            amount_speedup,
            other_speedup,
        )?;

        Ok(())
    }

    fn add_action(
        &self,
        protocol: &mut Protocol,
        utxo_action: &PartialUtxo,
        leaves: &Vec<usize>,
        speedup_pub: &PublicKey,
        role: &ParticipantRole,
        claim: &str,
        action_number: u32,
    ) -> Result<(), BitVMXError> {
        let speedup_dust = OutputType::generic_dust_limit(None).to_sat();
        protocol.add_transaction(&action_wins(role, action_number))?;
        protocol.add_connection(
            &format!("{:?}_ACTION_{action_number}", role),
            &ClaimGate::tx_success(claim),
            0.into(),
            &action_wins(role, action_number),
            InputSpec::Auto(
                SighashType::taproot_all(),
                SpendMode::All {
                    key_path_sign: SignMode::Aggregate,
                },
            ),
            None,
            None,
        )?;

        let output_type = utxo_action.3.as_ref().ok_or_else(|| {
            BitVMXError::MissingParameter("UTXO output type is required".to_string())
        })?;
        protocol.add_external_transaction(&external_action(role, action_number))?;
        protocol.add_unknown_outputs(&external_action(role, action_number), utxo_action.1)?;
        protocol.add_transaction_output(&external_action(role, action_number), &output_type)?;
        protocol.add_connection(
            &format!("EXTERNAL_ACTION__{:?}_WINS", role),
            &external_action(role, action_number),
            (utxo_action.1 as usize).into(),
            &action_wins(role, action_number),
            InputSpec::Auto(
                SighashType::taproot_all(),
                SpendMode::Scripts {
                    leaves: leaves.clone(),
                },
            ),
            None,
            Some(utxo_action.0),
        )?;

        let pb = ProtocolBuilder {};
        pb.add_speedup_output(
            protocol,
            &action_wins(role, action_number),
            speedup_dust,
            &speedup_pub,
        )?;

        Ok(())
    }

    fn partial_utxo_from(&self, tx: &Transaction, vout: u32) -> (Txid, u32, u64) {
        let txid = tx.compute_txid();
        let amount = tx.output[vout as usize].value.to_sat();
        (txid, vout, amount)
    }
}

pub trait WithClaimGateConfig {
    type Config: ClaimGateConfig;
    const PROGRAM_TYPE: &'static str;

    fn role(&self) -> ParticipantRole;
}

pub trait ClaimGateConfig: Sized {
    fn load(id: &Uuid, globals: &Globals) -> Result<Self, BitVMXError>;
    fn get_notify_protocol(&self) -> &Vec<(String, Uuid)>;
    fn get_prover_actions(&self) -> &Vec<(PartialUtxo, Vec<usize>)>;
    fn get_verifier_actions(&self) -> &Vec<(PartialUtxo, Vec<usize>)>;
}

pub fn timeout_tx(name: &str) -> String {
    format!("{}_TO", name)
}

pub fn timeout_input_tx(name: &str) -> String {
    format!("{}_INPUT_TO", name)
}

pub fn get_tx_name_from_timeout(name: &str) -> Option<String> {
    if name.ends_with("_INPUT_TO") {
        Some(name.strip_suffix("_INPUT_TO")?.to_string())
    } else if name.ends_with("_TO") {
        Some(name.strip_suffix("_TO")?.to_string())
    } else {
        None
    }
}

pub fn action_wins_prefix(role: &ParticipantRole) -> String {
    match role {
        ParticipantRole::Prover => "ACTION_PROVER_WINS_".to_string(),
        ParticipantRole::Verifier => "ACTION_VERIFIER_WINS_".to_string(),
    }
}

pub fn action_wins(role: &ParticipantRole, n: u32) -> String {
    format!("{}{}", action_wins_prefix(role), n)
}

pub fn external_action(role: &ParticipantRole, n: u32) -> String {
    match role {
        ParticipantRole::Prover => format!("EXTERNAL_ACTION_PROVER_{n}"),
        ParticipantRole::Verifier => format!("EXTERNAL_ACTION_VERIFIER_{n}"),
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
    DisputeResolutionProtocol,
    LightDisputeResolutionProtocol,
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
        PROGRAM_TYPE_DRP => Ok(ProtocolType::DisputeResolutionProtocol(
            DisputeResolutionProtocol::new(ctx),
        )),
        PROGRAM_TYPE_LIGHT_DRP => Ok(ProtocolType::LightDisputeResolutionProtocol(
            LightDisputeResolutionProtocol::new(ctx),
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
