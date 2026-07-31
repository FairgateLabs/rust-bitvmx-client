use crate::ports::bitcoin_coordinator::BitcoinCoordinatorApi;
/// Program — orchestrates protocol setup and lifecycle.
///
/// - Uses SetupEngine for multi-step setup (keys, nonces, signatures)
/// - Delegates aggregation responsibility to protocols
/// - Protocols define their setup steps via ProtocolHandler::setup_steps()
use crate::{
    bitvmx::Context,
    comms_helper::CommsMessageType,
    config::ClientConfig,
    errors::{BitVMXError, ProgramError},
    ping_helper::JobDispatcherType,
    program::{
        participant::{get_comms_address_by_pubkey_hash, validate_participants},
        protocols::protocol_handler::{new_protocol_type, ProtocolHandler, ProtocolType},
        setup::{SetupEngine, SetupEngineState, StepState},
        state::ProgramState,
    },
    signature_verifier::OperatorVerificationStore,
    types::{MessageDisposition, OutgoingBitVMXApiMessages, ProgramContext},
};
use bitcoin::{Transaction, Txid};
use bitcoin_coordinator::{TransactionStatus, TypesToMonitor};
use bitvmx_broker::identification::identifier::PubkHash as PubKeyHash;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::rc::Rc;
use storage_backend::storage::{KeyValueStore, Storage};
use tracing::{debug, info};
use uuid::Uuid;

use super::participant::CommsAddress;

#[derive(Serialize, Deserialize)]
pub struct Program {
    pub program_id: Uuid,
    pub my_idx: usize,
    pub participants: Vec<CommsAddress>,
    pub leader: usize,
    pub protocol: ProtocolType,
    #[serde(skip)]
    state: ProgramState,
    /// Serializable state of the SetupEngine (saved separately since SetupEngine contains trait objects)
    setup_engine_state: Option<SetupEngineState>,
    /// All participant keys collected during setup (populated by build_protocol)
    #[serde(skip)]
    pub setup_engine: Option<SetupEngine>,
    #[serde(skip)]
    storage: Option<Rc<Storage>>,
    config: ClientConfig,
}

impl Program {
    /// Returns the storage key for this program
    fn storage_key(&self) -> String {
        format!("program/{}", self.program_id)
    }

    /// Sends SetupCompleted to the L2 channel.
    /// Some protocols (e.g., AggregatedKeyProtocol) suppress this message.
    fn send_setup_completed<BC: BitcoinCoordinatorApi>(
        &mut self,
        program_context: &mut ProgramContext<BC>,
    ) -> Result<(), BitVMXError> {
        if !self.protocol.send_setup_completed() {
            return Ok(());
        }

        let msg = OutgoingBitVMXApiMessages::SetupCompleted(self.program_id).to_string()?;
        program_context
            .broker_channel
            .send(&program_context.components_config.l2, msg)?;

        info!(
            "Program: Sent SetupCompleted for program {}",
            self.program_id
        );
        Ok(())
    }

    /// Creates a SetupEngine for the protocol using its setup_steps() method.
    fn try_create_setup_engine(
        protocol: &ProtocolType,
        total_participants: usize,
    ) -> Result<Option<SetupEngine>, BitVMXError> {
        if let Some(step_names) = protocol.setup_steps() {
            debug!(
                "Protocol supports SetupEngine with {} steps",
                step_names.len()
            );
            Ok(Some(SetupEngine::new(step_names, total_participants)?))
        } else {
            debug!("Protocol does not use SetupEngine");
            Ok(None)
        }
    }

    /// Creates and initializes a new Program instance
    pub fn new<BC: BitcoinCoordinatorApi>(
        program_id: Uuid,
        program_type: &str,
        peers: Vec<CommsAddress>,
        leader: usize,
        context: &mut ProgramContext<BC>,
        storage: Rc<Storage>,
        config: &ClientConfig,
    ) -> Result<(), BitVMXError> {
        info!(
            "Program: Setting up program {} with type {}",
            program_id, program_type
        );

        // Participant public-key hashes define protocol indices and must be unique.
        validate_participants(&peers)?;

        // Validate leader index
        if leader >= peers.len() {
            return Err(BitVMXError::InvalidMessageFormat);
        }

        let my_pubkey_hash = context.comms.get_pubk_hash()?;

        let my_idx = peers
            .iter()
            .position(|peer| peer.pubkey_hash == my_pubkey_hash)
            .ok_or_else(|| BitVMXError::InvalidMessage("Peer not found in the list".to_string()))?;

        info!("Program: my_pos: {}", my_idx);
        info!("Program: Leader pos: {}", leader);

        // Request verification keys from other participants for message authentication
        // This is critical for security - allows us to verify message authenticity
        OperatorVerificationStore::request_missing_verification_keys(
            &context.globals,
            &context.comms,
            &context.key_manager,
            &context.rsa_public_key,
            &program_id,
            &peers,
        )?;

        // Create protocol
        let mut protocol = new_protocol_type(program_id, program_type, my_idx, storage.clone())?;
        protocol.set_storage(storage.clone());

        // Try to create SetupEngine if protocol supports it
        let setup_engine = Self::try_create_setup_engine(&protocol, peers.len())?;

        let mut program = Program {
            program_id,
            my_idx,
            participants: peers,
            leader,
            protocol,
            state: ProgramState::SettingUp,
            setup_engine_state: None, // Will be set when saving
            setup_engine,
            storage: Some(storage.clone()),
            config: config.clone(),
        };

        // Save initial program (includes state)
        program.save()?;

        info!("Program: Setup complete for program {}", program_id);
        Ok(())
    }

    /// Loads a Program from storage
    pub fn load(storage: Rc<Storage>, program_id: &Uuid) -> Result<Self, BitVMXError> {
        let key = format!("program/{}", program_id);
        let mut program: Program = storage
            .get(&key, None)?
            .ok_or(BitVMXError::ProgramNotFound(*program_id))?;

        debug!(
            "Program::load() - Loaded program {} with state: {:?}",
            program_id, program.state
        );

        program.storage = Some(storage.clone());
        program.protocol.set_storage(storage.clone());

        // Recreate SetupEngine if protocol supports it
        program.setup_engine =
            Self::try_create_setup_engine(&program.protocol, program.participants.len())?;

        program.state = storage
            .get(&format!("program/{}/state", program_id), None)?
            .unwrap_or_default();

        // Restore SetupEngine state if it was saved
        if let (Some(engine), Some(saved_state)) =
            (&mut program.setup_engine, &program.setup_engine_state)
        {
            debug!(
                "Program::load() - Restoring SetupEngine state for program {}",
                program_id
            );
            engine.restore_state(saved_state.clone())?;
        }

        Ok(program)
    }

    /// Saves the program to storage
    ///
    /// This method:
    /// 1. Extracts the SetupEngine state (which cannot be serialized) into `setup_engine_state`
    /// 2. Saves the entire program struct (including state as a field) in a single storage key
    ///
    /// Note: Fields marked with `#[serde(skip)]` (setup_engine, storage) are excluded from serialization
    pub fn save(&mut self) -> Result<(), ProgramError> {
        let storage = self
            .storage
            .clone()
            .ok_or(ProgramError::StorageUnavailable)?;

        // Save SetupEngine state before serializing (since SetupEngine itself can't be serialized)
        if let Some(engine) = &self.setup_engine {
            self.setup_engine_state = Some(engine.state().clone());
        }

        info!(
            "Program::save() - Saving program {} with state: {:?}",
            self.program_id, self.state
        );

        let state_key = format!("program/{}/state", self.program_id);
        storage.set(&state_key, &self.state, None)?;

        storage.set(&self.storage_key(), self, None)?;

        Ok(())
    }

    /// Main tick function - drives the program forward
    pub fn tick<BC: BitcoinCoordinatorApi>(
        &mut self,
        program_context: &mut ProgramContext<BC>,
    ) -> Result<(), BitVMXError> {
        let mut state_changed = false;

        match &self.state {
            ProgramState::SettingUp => {
                // Run the engine tick (uses block scope to avoid borrow conflict
                // between setup_engine and other self fields)
                let (tick_result, is_complete, engine_state) = {
                    let engine = self.setup_engine.as_mut().ok_or_else(|| {
                        BitVMXError::InvalidMessage(
                            "Protocol must return setup steps for Program".to_string(),
                        )
                    })?;

                    let tick_result = engine.tick(
                        &mut self.protocol,
                        &self.participants,
                        self.my_idx,
                        &self.program_id,
                        self.leader,
                        program_context,
                    )?;

                    let is_complete = engine.is_complete();

                    debug!(
                        "Program: SetupEngine tick - is_complete: {}, step: {}/{}",
                        is_complete,
                        engine.state().current_step_index,
                        engine.total_steps()
                    );

                    (tick_result, is_complete, engine.state().clone())
                };

                if tick_result.state_changed {
                    state_changed = true;
                    if engine_state.current_step_state == StepState::WaitingForParticipants {
                        self.state = ProgramState::WaitingData;
                    } else {
                        self.state = ProgramState::SettingUp;
                    }
                }

                // After all setup steps complete, sign and finalize
                if is_complete {
                    self.protocol.sign(&program_context.key_manager)?;
                    self.protocol.setup_complete(&program_context)?;
                    self.start_monitoring(program_context)?;
                    self.state = ProgramState::Ready;
                    state_changed = true;
                    info!("Program: Setup finalized, transitioning to Ready state");
                }
            }
            ProgramState::WaitingData | ProgramState::Ready => {
                // Protocol is ready and monitoring is active
                // Just waiting for blockchain events via notify_news()
                debug!("Program: waiting for events");
            }
        }

        // Only save if there were actual changes to avoid infinite load-save loops
        if state_changed {
            self.save()?;
        }
        Ok(())
    }

    fn start_monitoring<BC: BitcoinCoordinatorApi>(
        &mut self,
        program_context: &mut ProgramContext<BC>,
    ) -> Result<(), BitVMXError> {
        // After the protocol is ready, we need to monitor the transactions on blockchain
        // Only register monitoring if not already done (idempotent)
        info!("Program: Setting up blockchain monitoring");

        // Get transactions and UTXOs to monitor from the protocol
        let (txns_to_monitor, vouts_to_monitor) =
            self.protocol.get_transactions_to_monitor(program_context)?;

        let confirmations = self.protocol.requested_confirmations(program_context);

        // Create context for monitoring
        let context = Context::ProgramId(self.program_id);
        let context_str = context.to_string()?;

        // Register transactions to monitor
        if !txns_to_monitor.is_empty() {
            info!(
                "Program: Monitoring {} transactions for program {}",
                txns_to_monitor.len(),
                self.program_id
            );
            let txs_to_monitor =
                TypesToMonitor::Transactions(txns_to_monitor, context_str.clone(), confirmations);
            program_context
                .bitcoin_coordinator
                .monitor(txs_to_monitor)?;
        }

        // Register specific UTXOs (vouts) to monitor for spending
        for (txid, vout) in vouts_to_monitor {
            info!(
                "Program: Monitoring vout {} of txid {} for program {}",
                vout, txid, self.program_id
            );
            let vout_to_monitor = TypesToMonitor::SpendingUTXOTransaction(
                txid,
                vout,
                context_str.clone(),
                confirmations,
            );
            program_context
                .bitcoin_coordinator
                .monitor(vout_to_monitor)?;
        }

        self.send_setup_completed(program_context)?;
        Ok(())
    }

    /// Receives results from job dispatchers (Garbler, Emulator)
    pub fn receive_dispatcher_result<BC: BitcoinCoordinatorApi>(
        &mut self,
        result: Value,
        context: Context,
        dispatcher: JobDispatcherType,
        program_context: &mut ProgramContext<BC>,
    ) -> Result<(), BitVMXError> {
        // Setup dispatcher results may be delivered more than once or arrive after
        // setup has completed. They are no longer actionable once the program is
        // ready and must not turn an otherwise harmless replay into a fatal tick
        // error. ProgramStep results remain valid after setup.
        if matches!(&context, Context::SetupStep(_, _, _, _))
            && matches!(self.state, ProgramState::Ready)
        {
            debug!(
                "Program::receive_dispatcher_result() - Ignoring setup result for ready program"
            );
            return Ok(());
        }

        match dispatcher {
            JobDispatcherType::Garbler => {
                info!("Program::receive_dispatcher_result() - Received result from Garbler");
                match &context {
                    Context::SetupStep(_, _, _, _) => {
                        if let Some(engine) = &mut self.setup_engine {
                            if engine.receive_dispatcher_result(
                                result,
                                &context,
                                self.my_idx,
                                &self.program_id,
                                self.leader,
                                &self.participants,
                                program_context,
                            )? {
                                if engine.state().current_step_state.clone()
                                    == StepState::WaitingForParticipants
                                {
                                    self.state = ProgramState::WaitingData;
                                } else {
                                    self.state = ProgramState::SettingUp;
                                }
                                self.save()?;
                                info!("Program::receive_dispatcher_result() - SetupEngine state changed, saved program with state {:?}", self.state);
                            }
                        }
                    }
                    Context::ProgramStep(_, _) => {
                        //TODO: Connect with GC DRP
                        return self.protocol.gc_drp()?.execution_result(
                            result,
                            &context,
                            program_context,
                        );
                    }
                    _ => {
                        return Err(BitVMXError::InvalidMessage(format!(
                            "Invalid context for Garbler result: {:?}. Expected SetupStep.",
                            context
                        )));
                    }
                }
            }
            JobDispatcherType::Emulator => {
                debug!("Program::receive_dispatcher_result() - Received result from Emulator");
                return self.protocol.dispute()?.execution_result(
                    result,
                    &context,
                    program_context,
                );
            }
            _ => {
                return Err(BitVMXError::InvalidMessage(format!(
                    "Unknown dispatcher type: {:?}",
                    dispatcher
                )));
            }
        };

        Ok(())
    }

    /// Receives setup data from another participant
    ///
    /// This is a public wrapper that delegates to SetupEngine when the program
    /// is in SettingUp state. The SetupEngine handles all the logic internally.
    fn receive_setup_data<BC: BitcoinCoordinatorApi>(
        &mut self,
        data: Value,
        msg_type: CommsMessageType,
        from: &PubKeyHash,
        program_context: &mut ProgramContext<BC>,
    ) -> Result<MessageDisposition, BitVMXError> {
        // Only handle setup data if we're in setup state
        if matches!(self.state, ProgramState::Ready) {
            debug!("Program::receive_setup_data() - Not in SettingUp state, ignoring");
            return Ok(MessageDisposition::RetryLater);
        }

        // Track state changes and completion status for save/log after borrow ends
        let (disposition, engine_state) = if let Some(engine) = &mut self.setup_engine {
            let disposition = engine.receive_setup_data(
                data,
                msg_type,
                from,
                &self.program_id,
                self.my_idx,
                self.leader,
                &self.participants,
                &self.protocol,
                program_context,
            )?;
            (disposition, engine.state().current_step_state.clone())
        } else {
            (MessageDisposition::RetryLater, StepState::Completed) // Preserve the previous Ok(false) behavior.
        };

        // Preserve the previous behavior: save messages reported as processed.
        if disposition == MessageDisposition::Processed {
            if engine_state == StepState::WaitingForParticipants {
                self.state = ProgramState::WaitingData;
            } else {
                self.state = ProgramState::SettingUp;
            }
            self.save()?;
            info!(
                "Program::receive_setup_data() - Saved program state {:?}",
                self.state
            );
        }

        Ok(disposition)
    }

    /// Returns the protocol ID
    pub fn protocol_id(&self) -> Uuid {
        self.protocol.context().id
    }

    /// Finds a participant's address by their pubkey hash
    pub fn get_address_from_pubkey_hash(
        &self,
        pubkey_hash: &PubKeyHash,
    ) -> Result<CommsAddress, BitVMXError> {
        get_comms_address_by_pubkey_hash(&self.participants, pubkey_hash)
    }

    /// Main entry point for processing incoming communication messages
    ///
    /// Routes SetupStepData messages to receive_setup_data()
    pub fn process_comms_message<BC: BitcoinCoordinatorApi>(
        &mut self,
        comms_address: &PubKeyHash,
        msg_type: &CommsMessageType,
        data: Value,
        program_context: &mut ProgramContext<BC>,
    ) -> Result<MessageDisposition, BitVMXError> {
        debug!(
            "Program::process_comms_message() - Received {:?}  from {}",
            msg_type, comms_address
        );

        match msg_type {
            CommsMessageType::VerificationKey | CommsMessageType::VerificationKeyRequest => {
                debug!("Program: Verification key message handled upstream, ignoring");
            }
            CommsMessageType::Broadcasted => {
                debug!("Program: Broadcasted message should be handled upstream");
            }
            _ => {
                debug!(
                    "Program::process_comms_message() - Routing {:?} to receive_setup_data()",
                    msg_type
                );
                return self.receive_setup_data(
                    data,
                    msg_type.clone(),
                    comms_address,
                    program_context,
                );
            }
        }

        Ok(MessageDisposition::Processed)
    }

    /// Gets a transaction by name from the protocol
    pub fn get_transaction_by_name<BC: BitcoinCoordinatorApi>(
        &self,
        name: &str,
        context: &ProgramContext<BC>,
    ) -> Result<Transaction, BitVMXError> {
        let (tx, _speedup) = self.protocol.get_transaction_by_name(name, context)?;
        Ok(tx)
    }

    /// Gets a transaction by ID
    pub fn get_tx_by_id(&self, txid: Txid) -> Result<Transaction, BitVMXError> {
        self.protocol
            .get_transaction_by_id(&txid)
            .map_err(|e| BitVMXError::InvalidMessage(format!("Transaction not found: {}", e)))
    }

    /// Dispatches (broadcasts) a transaction by name
    pub fn dispatch_transaction_name<BC: BitcoinCoordinatorApi>(
        &mut self,
        name: &str,
        program_context: &mut ProgramContext<BC>,
    ) -> Result<(), BitVMXError> {
        let (tx, speedup) = self
            .protocol
            .get_transaction_by_name(name, program_context)?;
        let context = Context::ProgramId(self.program_id);

        info!(
            "Program: Dispatching transaction: {} with speedup: {:?}",
            tx.compute_txid(),
            speedup.is_some()
        );

        program_context.bitcoin_coordinator.dispatch(
            tx,
            speedup,
            context.to_string()?,
            None,
            self.protocol.requested_confirmations(program_context),
        )?;

        Ok(())
    }

    /// Notifies the protocol about blockchain events (transaction confirmations, etc.)
    pub fn notify_news<BC: BitcoinCoordinatorApi>(
        &self,
        tx_id: Txid,
        vout: Option<u32>,
        tx_status: TransactionStatus,
        context: String,
        program_context: &ProgramContext<BC>,
    ) -> Result<(), BitVMXError> {
        self.protocol
            .notify_news(tx_id, vout, tx_status.clone(), context, program_context)?;

        // Send transaction notification to L2 channel
        if vout.is_none() {
            let name = self.protocol.get_transaction_name_by_id(tx_id)?;
            program_context.broker_channel.send(
                &program_context.components_config.l2,
                OutgoingBitVMXApiMessages::Transaction(self.program_id, tx_status, Some(name))
                    .to_string()?,
            )?;
        }

        Ok(())
    }
}

pub fn is_active_program(storage: &Rc<Storage>, uuid: &Uuid) -> Result<bool, BitVMXError> {
    let key = format!("program/{}/state", uuid);
    let state: ProgramState = storage.get(&key, None)?.unwrap_or_default();
    Ok(state.is_active())
}
