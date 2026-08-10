use crate::ports::bitcoin_coordinator::BitcoinCoordinatorApi;
/// Program — orchestrates protocol setup and lifecycle.
///
/// - Uses SetupEngine for multi-step setup (keys, nonces, signatures)
/// - Delegates aggregation responsibility to protocols
/// - Protocols define their setup steps via ProtocolHandler::setup_steps()
use crate::{
    bitvmx::Context,
    comms_helper::CommsMessageType,
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
    /// Stored separately so program states can be queried without loading whole programs.
    #[serde(skip)]
    state: ProgramState,
    /// Serializable snapshot embedded in the program since SetupEngine contains trait objects.
    setup_engine_state: Option<SetupEngineState>,
    /// All participant keys collected during setup (populated by build_protocol)
    #[serde(skip)]
    pub setup_engine: Option<SetupEngine>,
    #[serde(skip)]
    storage: Option<Rc<Storage>>,
}

impl Program {
    /// Returns the storage key for a program.
    fn key_program(program_id: &Uuid) -> String {
        format!("program/{program_id}")
    }

    /// Returns the storage key for a program's separately serialized state.
    fn key_program_state(program_id: &Uuid) -> String {
        format!("program/{program_id}/state")
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

    /// Reports an unrecoverable setup failure to the L2 channel and marks the program dead.
    /// Once the program is `Failed`, later calls do nothing.
    pub(crate) fn fail_setup<BC: BitcoinCoordinatorApi>(
        &mut self,
        peer: Option<PubKeyHash>,
        reason: &str,
        program_context: &mut ProgramContext<BC>,
    ) -> Result<(), BitVMXError> {
        if !matches!(
            self.state,
            ProgramState::SettingUp | ProgramState::WaitingData
        ) {
            debug!(
                "Program::fail_setup() - Program {} is {:?}, not reporting a setup failure",
                self.program_id, self.state
            );
            return Ok(());
        }

        let step = self
            .setup_engine
            .as_ref()
            .map(|engine| engine.current_step_name().to_string())
            .unwrap_or_default();

        let msg = OutgoingBitVMXApiMessages::SetupFailed(
            self.program_id,
            step.clone(),
            peer.clone(),
            reason.to_string(),
        )
        .to_string()?;
        program_context
            .broker_channel
            .send(&program_context.components_config.l2, msg)?;

        self.state = ProgramState::Failed;
        self.save()?;

        info!(
            "Program: Sent SetupFailed for program {} at step '{}' (peer: {:?}): {}",
            self.program_id, step, peer, reason
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
        };

        // Save the initial program and its separately serialized state.
        program.save()?;

        info!("Program: Setup complete for program {}", program_id);
        Ok(())
    }

    /// Loads a Program from storage
    pub fn load(storage: Rc<Storage>, program_id: &Uuid) -> Result<Self, BitVMXError> {
        let mut program: Program = storage
            .get(&Self::key_program(program_id), None)?
            .ok_or(BitVMXError::ProgramNotFound(*program_id))?;

        program.storage = Some(storage.clone());
        program.protocol.set_storage(storage.clone());

        // Recreate SetupEngine if protocol supports it
        program.setup_engine =
            Self::try_create_setup_engine(&program.protocol, program.participants.len())?;

        program.state = storage
            .get(&Self::key_program_state(program_id), None)?
            .unwrap_or_default();

        debug!(
            "Program::load() - Loaded program {} with state: {:?}",
            program_id, program.state
        );

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
    /// 1. Snapshots the non-serializable SetupEngine into `setup_engine_state`.
    /// 2. Saves the program without its runtime-only fields or state.
    /// 3. Saves the state separately so it can be queried without loading the whole program.
    ///
    /// Fields marked with `#[serde(skip)]` are excluded from program serialization.
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

        storage.set(
            &Self::key_program_state(&self.program_id),
            &self.state,
            None,
        )?;

        storage.set(&Self::key_program(&self.program_id), self, None)?;

        Ok(())
    }

    /// Main tick function - drives the program forward.
    ///
    /// A setup-phase error is reported as `SetupFailed` and swallowed rather than returned:
    /// `main.rs` treats a `tick` error as fatal. Errors past `Ready` propagate unchanged.
    pub fn tick<BC: BitcoinCoordinatorApi>(
        &mut self,
        program_context: &mut ProgramContext<BC>,
    ) -> Result<(), BitVMXError> {
        match self.tick_inner(program_context) {
            Err(e) if self.state != ProgramState::Ready => {
                self.fail_setup(None, &e.to_string(), program_context)?;
                Ok(())
            }
            other => other,
        }
    }

    fn tick_inner<BC: BitcoinCoordinatorApi>(
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
            ProgramState::Failed => {
                // Terminal; `is_active` keeps process_programs from reaching this.
                debug!("Program: setup failed, nothing to drive");
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

    /// Receives results from job dispatchers (Garbler, Emulator).
    ///
    /// Errors during setup are reported to L2 rather than propagated; see `tick`.
    pub fn receive_dispatcher_result<BC: BitcoinCoordinatorApi>(
        &mut self,
        result: Value,
        context: Context,
        dispatcher: JobDispatcherType,
        program_context: &mut ProgramContext<BC>,
    ) -> Result<(), BitVMXError> {
        match self.receive_dispatcher_result_inner(result, context, dispatcher, program_context) {
            Err(e) if self.state != ProgramState::Ready => {
                self.fail_setup(None, &e.to_string(), program_context)?;
                Ok(())
            }
            other => other,
        }
    }

    fn receive_dispatcher_result_inner<BC: BitcoinCoordinatorApi>(
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
        // Terminal: discard rather than requeue, since a retry can only exhaust and re-report.
        if matches!(self.state, ProgramState::Failed) {
            debug!("Program::receive_setup_data() - Program setup failed, discarding message");
            return Ok(MessageDisposition::Processed);
        }

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
    /// Routes SetupStepData messages to receive_setup_data().
    ///
    /// A peer's message that fails verification fails the setup: L2 is told which peer sent it,
    /// and the message is `Processed` rather than queued for a retry that cannot succeed.
    pub fn process_comms_message<BC: BitcoinCoordinatorApi>(
        &mut self,
        comms_address: &PubKeyHash,
        msg_type: &CommsMessageType,
        data: Value,
        program_context: &mut ProgramContext<BC>,
    ) -> Result<MessageDisposition, BitVMXError> {
        match self.process_comms_message_inner(comms_address, msg_type, data, program_context) {
            Err(e) if self.state != ProgramState::Ready => {
                self.fail_setup(Some(comms_address.clone()), &e.to_string(), program_context)?;
                Ok(MessageDisposition::Processed)
            }
            other => other,
        }
    }

    fn process_comms_message_inner<BC: BitcoinCoordinatorApi>(
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
    let state: ProgramState = storage
        .get(&Program::key_program_state(uuid), None)?
        .unwrap_or_default();
    Ok(state.is_active())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        program::variables::VariableTypes,
        test_utils::{TestProgramContextEnv, TestStorageDir},
        types::PROGRAM_TYPE_AGGREGATED_KEY,
    };
    use bitcoin::{absolute::LockTime, transaction::Version};

    fn test_program(storage: Rc<Storage>, program_id: Uuid) -> Program {
        let participants = vec![CommsAddress::new(
            "127.0.0.1:10000".parse().unwrap(),
            "7005e4a0325b644baa2b66c3fa2ed2a795cae584b6d3a57ca45ebf5d0eb0011f".to_string(),
        )];
        let protocol =
            new_protocol_type(program_id, PROGRAM_TYPE_AGGREGATED_KEY, 0, storage.clone()).unwrap();
        let setup_engine = Program::try_create_setup_engine(&protocol, participants.len()).unwrap();

        Program {
            program_id,
            my_idx: 0,
            participants,
            leader: 0,
            protocol,
            state: ProgramState::SettingUp,
            setup_engine_state: None,
            setup_engine,
            storage: Some(storage),
        }
    }

    #[test]
    fn test_save_serializes_program_and_state_separately() {
        let dir = TestStorageDir::new("program-save");
        let storage = dir.storage();
        let program_id = Uuid::new_v4();
        let mut program = test_program(storage.clone(), program_id);
        program.state = ProgramState::WaitingData;

        program.save().unwrap();

        let serialized_program: Program = storage
            .get(&Program::key_program(&program_id), None)
            .unwrap()
            .unwrap();
        let serialized_state: ProgramState = storage
            .get(&Program::key_program_state(&program_id), None)
            .unwrap()
            .unwrap();

        // A directly deserialized Program has the default state because state is
        // deliberately excluded from the whole-program value.
        assert_eq!(serialized_program.state, ProgramState::SettingUp);
        assert_eq!(serialized_state, ProgramState::WaitingData);
        assert_eq!(serialized_program.program_id, program_id);
        assert!(serialized_program.setup_engine_state.is_some());
    }

    #[test]
    fn test_load_restores_program_state_and_runtime_fields() {
        let dir = TestStorageDir::new("program-load");
        let storage = dir.storage();
        let program_id = Uuid::new_v4();
        let mut program = test_program(storage.clone(), program_id);
        program.state = ProgramState::Ready;
        program.save().unwrap();

        let loaded = Program::load(storage, &program_id).unwrap();

        assert_eq!(loaded.program_id, program_id);
        assert_eq!(loaded.state, ProgramState::Ready);
        assert!(loaded.storage.is_some());
        assert!(loaded.protocol.context().storage.is_some());
        assert_eq!(
            loaded.setup_engine.as_ref().unwrap().state(),
            loaded.setup_engine_state.as_ref().unwrap()
        );
    }

    #[test]
    fn test_is_active_program_reads_separately_saved_state() {
        let dir = TestStorageDir::new("program-active-state");
        let storage = dir.storage();
        let program_id = Uuid::new_v4();
        let mut program = test_program(storage.clone(), program_id);

        program.save().unwrap();
        assert!(is_active_program(&storage, &program_id).unwrap());

        program.state = ProgramState::WaitingData;
        program.save().unwrap();
        assert!(!is_active_program(&storage, &program_id).unwrap());

        program.state = ProgramState::Ready;
        program.save().unwrap();
        assert!(!is_active_program(&storage, &program_id).unwrap());
    }

    #[test]
    fn test_missing_program_and_storage_are_reported_explicitly() {
        let dir = TestStorageDir::new("program-missing");
        let missing_id = Uuid::new_v4();
        assert!(matches!(
            Program::load(dir.storage(), &missing_id),
            Err(BitVMXError::ProgramNotFound(id)) if id == missing_id
        ));

        let storage = dir.storage();
        let mut program = test_program(storage, Uuid::new_v4());
        program.storage = None;
        assert!(matches!(
            program.save(),
            Err(ProgramError::StorageUnavailable)
        ));
    }

    #[test]
    fn test_new_validates_participants_leader_and_local_membership() {
        let mut env = TestProgramContextEnv::new("program-new-validation").unwrap();
        let dir = TestStorageDir::new("program-new-validation-storage");
        let self_address = env.self_address().unwrap();

        let empty_result = Program::new(
            Uuid::new_v4(),
            PROGRAM_TYPE_AGGREGATED_KEY,
            vec![],
            0,
            &mut env.context,
            dir.storage(),
        );
        assert!(matches!(empty_result, Err(BitVMXError::InvalidMessage(_))));

        let bad_leader_result = Program::new(
            Uuid::new_v4(),
            PROGRAM_TYPE_AGGREGATED_KEY,
            vec![self_address.clone()],
            1,
            &mut env.context,
            dir.storage(),
        );
        assert!(matches!(
            bad_leader_result,
            Err(BitVMXError::InvalidMessageFormat)
        ));

        let stranger = CommsAddress::try_new(
            "127.0.0.1:29999".parse().unwrap(),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        )
        .unwrap();
        let missing_local_result = Program::new(
            Uuid::new_v4(),
            PROGRAM_TYPE_AGGREGATED_KEY,
            vec![stranger],
            0,
            &mut env.context,
            dir.storage(),
        );
        assert!(matches!(
            missing_local_result,
            Err(BitVMXError::InvalidMessage(message)) if message.contains("Peer not found")
        ));
    }

    #[test]
    fn test_new_persists_a_loadable_program_for_the_local_participant() {
        let mut env = TestProgramContextEnv::new("program-new-success").unwrap();
        let dir = TestStorageDir::new("program-new-success-storage");
        let storage = dir.storage();
        let program_id = Uuid::new_v4();
        let self_address = env.self_address().unwrap();

        Program::new(
            program_id,
            PROGRAM_TYPE_AGGREGATED_KEY,
            vec![self_address.clone()],
            0,
            &mut env.context,
            storage.clone(),
        )
        .unwrap();

        let loaded = Program::load(storage, &program_id).unwrap();
        assert_eq!(loaded.program_id, program_id);
        assert_eq!(loaded.protocol_id(), program_id);
        assert_eq!(loaded.my_idx, 0);
        assert_eq!(loaded.leader, 0);
        assert_eq!(loaded.participants, vec![self_address]);
        assert_eq!(loaded.state, ProgramState::SettingUp);
        assert!(loaded.setup_engine.is_some());
    }

    #[test]
    fn test_tick_completes_single_participant_setup_and_persists_progress() {
        let mut env = TestProgramContextEnv::new("program-tick-lifecycle").unwrap();
        let dir = TestStorageDir::new("program-tick-lifecycle-storage");
        let storage = dir.storage();
        let program_id = Uuid::new_v4();
        let mut program = test_program(storage.clone(), program_id);
        env.context
            .globals
            .set_var(
                &program_id,
                "optional_keys",
                VariableTypes::String("null".to_string()),
            )
            .unwrap();

        program.tick(&mut env.context).unwrap();
        assert_eq!(program.state, ProgramState::SettingUp);
        assert_eq!(
            program
                .setup_engine
                .as_ref()
                .unwrap()
                .state()
                .current_step_state,
            StepState::AllParticipantsCompleted
        );
        let after_generation = Program::load(storage.clone(), &program_id).unwrap();
        assert_eq!(after_generation.state, ProgramState::SettingUp);
        assert_eq!(
            after_generation
                .setup_engine
                .as_ref()
                .unwrap()
                .state()
                .current_step_state,
            StepState::AllParticipantsCompleted
        );

        program.tick(&mut env.context).unwrap();
        assert_eq!(program.state, ProgramState::Ready);
        assert!(program.setup_engine.as_ref().unwrap().is_complete());
        assert!(env
            .context
            .globals
            .get_var_or_err(&program_id, "final_aggregated_key")
            .unwrap()
            .pubkey()
            .is_ok());
        assert!(env.coordinator_mock().monitored().is_empty());

        let completed = Program::load(storage, &program_id).unwrap();
        assert_eq!(completed.state, ProgramState::Ready);
        assert!(completed.setup_engine.as_ref().unwrap().is_complete());

        program.tick(&mut env.context).unwrap();
        assert_eq!(program.state, ProgramState::Ready);
    }

    #[test]
    fn test_tick_reports_setup_failure_instead_of_propagating() {
        let mut env = TestProgramContextEnv::new("program-tick-no-engine").unwrap();
        let dir = TestStorageDir::new("program-tick-no-engine-storage");
        let mut program = test_program(dir.storage(), Uuid::new_v4());
        let program_id = program.program_id;
        program.setup_engine = None;

        // This error used to propagate, and main.rs treats a tick error as fatal.
        program.tick(&mut env.context).unwrap();
        assert_eq!(program.state, ProgramState::Failed);

        let messages = env.l2_messages().unwrap();
        assert_eq!(messages.len(), 1);
        match &messages[0] {
            OutgoingBitVMXApiMessages::SetupFailed(id, _, peer, reason) => {
                assert_eq!(*id, program_id);
                assert!(peer.is_none());
                assert!(reason.contains("Protocol must return setup steps"));
            }
            other => panic!("expected SetupFailed, got {other:?}"),
        }
    }

    #[test]
    fn test_unverifiable_peer_data_reports_setup_failed_to_l2() {
        let mut env = TestProgramContextEnv::new("program-setup-failed").unwrap();
        let dir = TestStorageDir::new("program-setup-failed-storage");
        let storage = dir.storage();
        let program_id = Uuid::new_v4();
        let mut program = test_program(storage.clone(), program_id);
        let sender = program.participants[0].pubkey_hash.clone();

        let disposition = program
            .process_comms_message(
                &sender,
                &CommsMessageType::Keys,
                serde_json::json!({}),
                &mut env.context,
            )
            .unwrap();

        // The message that killed the setup is not queued for a retry.
        assert_eq!(disposition, MessageDisposition::Processed);
        assert_eq!(program.state, ProgramState::Failed);
        assert_eq!(
            Program::load(storage.clone(), &program_id).unwrap().state,
            ProgramState::Failed
        );
        assert!(!is_active_program(&storage, &program_id).unwrap());

        let messages = env.l2_messages().unwrap();
        assert_eq!(messages.len(), 1);
        match &messages[0] {
            OutgoingBitVMXApiMessages::SetupFailed(id, step, peer, reason) => {
                assert_eq!(*id, program_id);
                assert_eq!(step, "keys");
                assert_eq!(peer.as_ref(), Some(&sender));
                assert!(reason.contains("Failed to deserialize key declaration"));
            }
            other => panic!("expected SetupFailed, got {other:?}"),
        }
    }

    #[test]
    fn test_ready_program_is_never_reported_as_a_setup_failure() {
        let mut env = TestProgramContextEnv::new("program-ready-not-failed").unwrap();
        let dir = TestStorageDir::new("program-ready-not-failed-storage");
        let mut program = test_program(dir.storage(), Uuid::new_v4());
        program.state = ProgramState::Ready;

        // Reached from bitvmx.rs when a late message for a finished setup exhausts its retries.
        program
            .fail_setup(None, "message dropped after max retries", &mut env.context)
            .unwrap();

        assert_eq!(program.state, ProgramState::Ready);
        assert!(env.l2_messages().unwrap().is_empty());
    }

    #[test]
    fn test_failed_setup_is_reported_once_and_stops_being_driven() {
        let mut env = TestProgramContextEnv::new("program-setup-failed-once").unwrap();
        let dir = TestStorageDir::new("program-setup-failed-once-storage");
        let mut program = test_program(dir.storage(), Uuid::new_v4());
        let sender = program.participants[0].pubkey_hash.clone();

        program
            .process_comms_message(
                &sender,
                &CommsMessageType::Keys,
                serde_json::json!({}),
                &mut env.context,
            )
            .unwrap();
        assert_eq!(env.l2_messages().unwrap().len(), 1);

        // Later messages for a dead program are discarded, not queued for retry.
        let disposition = program
            .process_comms_message(
                &sender,
                &CommsMessageType::Keys,
                serde_json::json!({}),
                &mut env.context,
            )
            .unwrap();
        assert_eq!(disposition, MessageDisposition::Processed);

        // And ticking it again reports nothing further.
        program.tick(&mut env.context).unwrap();

        assert_eq!(program.state, ProgramState::Failed);
        assert_eq!(env.l2_messages().unwrap().len(), 1);
    }

    #[test]
    fn test_control_messages_are_processed_without_mutating_setup() {
        let mut env = TestProgramContextEnv::new("program-control-messages").unwrap();
        let dir = TestStorageDir::new("program-control-storage");
        let mut program = test_program(dir.storage(), Uuid::new_v4());
        let sender = program.participants[0].pubkey_hash.clone();
        let initial_engine_state = program.setup_engine.as_ref().unwrap().state().clone();

        for message_type in [
            CommsMessageType::VerificationKey,
            CommsMessageType::VerificationKeyRequest,
            CommsMessageType::Broadcasted,
        ] {
            let disposition = program
                .process_comms_message(
                    &sender,
                    &message_type,
                    serde_json::json!({"ignored": true}),
                    &mut env.context,
                )
                .unwrap();
            assert_eq!(disposition, MessageDisposition::Processed);
        }
        assert_eq!(
            program.setup_engine.as_ref().unwrap().state(),
            &initial_engine_state
        );
        assert_eq!(program.state, ProgramState::SettingUp);
    }

    #[test]
    fn test_ready_program_defers_setup_data_and_ignores_replayed_setup_job() {
        let mut env = TestProgramContextEnv::new("program-ready-replays").unwrap();
        let dir = TestStorageDir::new("program-ready-replays-storage");
        let mut program = test_program(dir.storage(), Uuid::new_v4());
        program.state = ProgramState::Ready;
        let sender = program.participants[0].pubkey_hash.clone();

        let disposition = program
            .process_comms_message(
                &sender,
                &CommsMessageType::Keys,
                serde_json::json!({}),
                &mut env.context,
            )
            .unwrap();
        assert_eq!(disposition, MessageDisposition::RetryLater);

        let context = Context::SetupStep(
            program.program_id,
            "keys".to_string(),
            "".to_string(),
            CommsMessageType::Keys,
        );
        program
            .receive_dispatcher_result(
                serde_json::json!({"stale": true}),
                context,
                JobDispatcherType::Garbler,
                &mut env.context,
            )
            .unwrap();
        assert_eq!(program.state, ProgramState::Ready);
    }

    #[test]
    fn test_invalid_dispatcher_routes_report_setup_failure() {
        let mut env = TestProgramContextEnv::new("program-dispatcher-routes").unwrap();
        let dir = TestStorageDir::new("program-dispatcher-routes-storage");
        let storage = dir.storage();
        let program_id = Uuid::new_v4();
        let mut program = test_program(storage.clone(), program_id);

        // A Garbler result carrying a non-SetupStep context cannot be routed.
        program
            .receive_dispatcher_result(
                serde_json::json!({}),
                Context::ProgramId(program_id),
                JobDispatcherType::Garbler,
                &mut env.context,
            )
            .unwrap();
        assert_eq!(program.state, ProgramState::Failed);

        let messages = env.l2_messages().unwrap();
        assert_eq!(messages.len(), 1);
        match &messages[0] {
            OutgoingBitVMXApiMessages::SetupFailed(id, _, peer, reason) => {
                assert_eq!(*id, program_id);
                assert!(peer.is_none());
                assert!(reason.contains("Invalid context for Garbler result"));
            }
            other => panic!("expected SetupFailed, got {other:?}"),
        }

        // Same for the emulator route, which this protocol does not support. Uses a second
        // program because the first one is already terminal.
        let other_id = Uuid::new_v4();
        let mut other_program = test_program(storage, other_id);
        other_program
            .receive_dispatcher_result(
                serde_json::json!({}),
                Context::ProgramId(other_id),
                JobDispatcherType::Emulator,
                &mut env.context,
            )
            .unwrap();
        assert_eq!(other_program.state, ProgramState::Failed);
        assert_eq!(env.l2_messages().unwrap().len(), 2);
    }

    #[test]
    fn test_transaction_api_reports_unsupported_aggregated_key_operations() {
        let mut env = TestProgramContextEnv::new("program-transaction-api").unwrap();
        let dir = TestStorageDir::new("program-transaction-api-storage");
        let program_id = Uuid::new_v4();
        let mut program = test_program(dir.storage(), program_id);
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![],
        };
        let txid = tx.compute_txid();

        assert!(matches!(
            program.get_transaction_by_name("missing", &env.context),
            Err(BitVMXError::InvalidTransactionName(message)) if message.contains("missing")
        ));
        assert!(matches!(
            program.get_tx_by_id(txid),
            Err(BitVMXError::InvalidMessage(message))
                if message.contains("Transaction not found")
        ));
        assert!(program
            .dispatch_transaction_name("missing", &mut env.context)
            .is_err());
        assert!(env.coordinator_mock().dispatched().is_empty());

        let status: TransactionStatus = serde_json::from_value(serde_json::json!({
            "tx": null,
            "block_info": null,
            "confirmations": 0,
            "status": "NotFound"
        }))
        .unwrap();
        program
            .notify_news(
                txid,
                Some(0),
                status,
                Context::ProgramId(program_id).to_string().unwrap(),
                &env.context,
            )
            .unwrap();
    }

    #[test]
    fn test_program_queries_and_unknown_dispatcher_errors_are_precise() {
        let mut env = TestProgramContextEnv::new("program-query-errors").unwrap();
        let dir = TestStorageDir::new("program-query-errors-storage");
        let program_id = Uuid::new_v4();
        let mut program = test_program(dir.storage(), program_id);
        let participant = program.participants[0].clone();

        assert_eq!(program.protocol_id(), program_id);
        assert_eq!(
            program
                .get_address_from_pubkey_hash(&participant.pubkey_hash)
                .unwrap(),
            participant
        );
        assert!(program
            .get_address_from_pubkey_hash(
                &"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string()
            )
            .is_err());

        // An unroutable dispatcher result is reported to L2 rather than propagated.
        program
            .receive_dispatcher_result(
                serde_json::json!({}),
                Context::ProgramId(program_id),
                JobDispatcherType::ZKP,
                &mut env.context,
            )
            .unwrap();
        assert_eq!(program.state, ProgramState::Failed);

        let messages = env.l2_messages().unwrap();
        assert_eq!(messages.len(), 1);
        assert!(matches!(
            &messages[0],
            OutgoingBitVMXApiMessages::SetupFailed(_, _, _, reason)
                if reason.contains("Unknown dispatcher type: ZKP")
        ));
    }

    #[test]
    fn test_aggregated_key_monitoring_registers_nothing_and_suppresses_completion() {
        let mut env = TestProgramContextEnv::new("program-monitoring").unwrap();
        let dir = TestStorageDir::new("program-monitoring-storage");
        let mut program = test_program(dir.storage(), Uuid::new_v4());

        program.start_monitoring(&mut env.context).unwrap();

        assert!(env.coordinator_mock().monitored().is_empty());
        assert!(!program.protocol.send_setup_completed());
    }
}
