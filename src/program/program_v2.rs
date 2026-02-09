/// ProgramV2 - New Program implementation using SetupEngine
///
/// This is the next generation Program implementation that:
/// - Uses SetupEngine for orchestrating setup steps
/// - Delegates aggregation responsibility to protocols
/// - Provides cleaner separation of concerns
/// - Protocols define their setup steps via ProtocolHandler::setup_steps()
///
/// Key differences from Program:
/// - No prepare_aggregated_keys() - protocols do their own aggregation
/// - Uses SetupEngine to orchestrate setup steps
/// - Cleaner state machine
/// - Protocol-specific setup logic in the protocol itself

use crate::{
    bitvmx::Context,
    comms_helper::CommsMessageType,
    config::ClientConfig,
    errors::{BitVMXError, ProgramError},
    program::{
        participant::ParticipantData,
        protocols::protocol_handler::{new_protocol_type, ProtocolHandler, ProtocolType},
        setup::{SetupEngine, SetupEngineState, StepState},
        state::ProgramState,
    },
    signature_verifier::OperatorVerificationStore,
    types::{OutgoingBitVMXApiMessages, ProgramContext},
};
use bitcoin::{Transaction, Txid};
use bitcoin_coordinator::{coordinator::BitcoinCoordinatorApi, TransactionStatus, TypesToMonitor};
use bitvmx_broker::identification::identifier::PubkHash as PubKeyHash;
use serde::{Deserialize, Serialize};
use std::rc::Rc;
use storage_backend::storage::{KeyValueStore, Storage};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use super::participant::{CommsAddress, ParticipantKeys};

#[derive(Debug, Clone)]
pub enum StoreKeyV2 {
    Program(Uuid),
}

#[derive(Serialize, Deserialize)]
pub struct ProgramV2 {
    pub program_id: Uuid,
    pub my_idx: usize,
    pub participants: Vec<ParticipantData>,
    pub leader: usize,
    pub protocol: ProtocolType,
    pub state: ProgramState,
    /// Serializable state of the SetupEngine (saved separately since SetupEngine contains trait objects)
    setup_engine_state: Option<SetupEngineState>,
    /// Flag to track if SetupCompleted message has been sent to avoid sending it multiple times
    setup_completed_sent: bool,
    /// Flag to track if build_protocol() was already called (prevents duplicate builds on crash recovery)
    protocol_built: bool,
    /// All participant keys collected during setup (populated by build_protocol)
    all_participant_keys: Option<Vec<ParticipantKeys>>,
    /// Flag to track if monitoring has been registered with bitcoin coordinator
    monitoring_registered: bool,
    #[serde(skip)]
    pub setup_engine: Option<SetupEngine>,
    #[serde(skip)]
    storage: Option<Rc<Storage>>,
    config: ClientConfig,
}

impl ProgramV2 {
    /// Returns the storage key for this program
    fn storage_key(&self) -> String {
        format!("program_v2_{}", self.program_id)
    }

    /// Creates a SetupEngine for the protocol using its setup_steps() method
    fn try_create_setup_engine(protocol: &ProtocolType) -> Option<SetupEngine> {
        if let Some(step_names) = protocol.setup_steps() {
            debug!("Protocol supports SetupEngine with {} steps", step_names.len());
            Some(SetupEngine::new(step_names))
        } else {
            debug!("Protocol does not use SetupEngine");
            None
        }
    }

    /// Creates and initializes a new ProgramV2 instance
    pub fn setup(
        program_id: Uuid,
        program_type: &str,
        peers: Vec<CommsAddress>,
        leader: usize,
        context: &mut ProgramContext,
        storage: Rc<Storage>,
        config: &ClientConfig,
    ) -> Result<(), BitVMXError> {
        info!(
            "ProgramV2: Setting up program {} with type {}",
            program_id, program_type
        );

        // Validate leader index
        if leader >= peers.len() {
            return Err(BitVMXError::InvalidMessageFormat);
        }

        let my_pubkey_hash = context.comms.get_pubk_hash()?;

        let my_idx = peers
            .iter()
            .position(|peer| peer.pubkey_hash == my_pubkey_hash)
            .ok_or_else(|| BitVMXError::InvalidMessage("Peer not found in the list".to_string()))?;

        info!("ProgramV2: my_pos: {}", my_idx);
        info!("ProgramV2: Leader pos: {}", leader);

        // Request verification keys from other participants for message authentication
        // This is critical for security - allows us to verify message authenticity
        OperatorVerificationStore::request_missing_verification_keys(
            &context.globals,
            &context.comms,
            &context.key_chain,
            &program_id,
            &peers,
        )?;

        let participants: Vec<ParticipantData> = peers
            .into_iter()
            .map(|addr| ParticipantData {
                comms_address: addr,
                keys: None,
                nonces: None,
                partial: None,
            })
            .collect();

        // Create protocol
        let mut protocol = new_protocol_type(program_id, program_type, my_idx, storage.clone())?;
        protocol.set_storage(storage.clone());

        // Try to create SetupEngine if protocol supports it
        let setup_engine = Self::try_create_setup_engine(&protocol);

        let mut program = ProgramV2 {
            program_id,
            my_idx,
            participants,
            leader,
            protocol,
            state: ProgramState::New,
            setup_engine_state: None,  // Will be set when saving
            setup_completed_sent: false,
            protocol_built: false,
            all_participant_keys: None,
            monitoring_registered: false,
            setup_engine,
            storage: Some(storage.clone()),
            config: config.clone(),
        };

        // Save initial program (includes state)
        program.save()?;

        info!("ProgramV2: Setup complete for program {}", program_id);
        Ok(())
    }

    /// Loads a ProgramV2 from storage
    pub fn load(storage: Rc<Storage>, program_id: &Uuid) -> Result<Self, ProgramError> {
        let key = format!("program_v2_{}", program_id);
        let mut program: ProgramV2 = storage
            .get(&key)?
            .ok_or(ProgramError::ProgramNotFound(*program_id))?;

        // Only log at info level if state changed or if not in waiting state
        // This reduces log spam when program is waiting for data
        let is_waiting = matches!(program.state, ProgramState::SettingUpV2) 
            && program.setup_engine_state.as_ref()
                .map(|s| s.current_step_state == StepState::WaitingForParticipants)
                .unwrap_or(false);

        if is_waiting {
            debug!("ProgramV2::load() - Loaded program {} with state: {:?} (waiting for participants)", program_id, program.state);
        } else {
            info!("ProgramV2::load() - Loaded program {} with state: {:?}", program_id, program.state);
        }

        program.storage = Some(storage.clone());
        program.protocol.set_storage(storage.clone());

        // State is already loaded as part of the program struct
        // Recreate SetupEngine if protocol supports it
        program.setup_engine = Self::try_create_setup_engine(&program.protocol);

        // Restore SetupEngine state if it was saved
        if let (Some(engine), Some(saved_state)) = (&mut program.setup_engine, &program.setup_engine_state) {
            if !is_waiting {
                info!("ProgramV2::load() - Restoring SetupEngine state for program {}", program_id);
            } else {
                debug!("ProgramV2::load() - Restoring SetupEngine state for program {} (waiting)", program_id);
            }
            engine.restore_state(saved_state.clone()).map_err(|e| {
                ProgramError::InvalidProgramStoragePath(format!("Failed to restore engine state: {}", e))
            })?;
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

        info!("ProgramV2::save() - Saving program {} with state: {:?}", self.program_id, self.state);

        // Write state to the legacy key so is_active_program() works for ProgramV2
        // This allows process_programs() to skip V2 programs that have reached Ready state
        let legacy_state_key = format!("program/{}/state", self.program_id);
        storage.set(&legacy_state_key, &self.state, None)?;

        storage.set(&self.storage_key(), self, None)?;

        Ok(())
    }

    /// Main tick function - drives the program forward
    pub fn tick(&mut self, program_context: &mut ProgramContext) -> Result<(), BitVMXError> {
        let mut state_changed = false;
        
        match &self.state {
            ProgramState::New => {
                info!("ProgramV2: State is New, transitioning to SettingUpV2");
                // Use SettingUpV2 - SetupEngine manages the actual setup flow
                // No SettingUpState needed - SetupEngine tracks its own state
                self.state = ProgramState::SettingUpV2;
                state_changed = true;
            }
            ProgramState::SettingUpV2 => {
                // SetupEngine drives the entire setup flow.
                //
                // build_protocol() must run AFTER keys step but BEFORE nonces
                // step generates data (matching the legacy Program flow).
                // We check twice:
                //   (a) BEFORE the engine tick — covers programs loaded from
                //       disk where the keys step already completed previously.
                //   (b) AFTER the engine tick  — covers the tick where the keys
                //       step completes (engine advances to nonces/Pending but
                //       does not generate data in the same tick).

                // (a) Pre-tick: build protocol if keys already done (loaded state)
                {
                    let engine = self.setup_engine.as_ref().ok_or_else(|| {
                        BitVMXError::InvalidMessage(
                            "Protocol must return setup steps for ProgramV2".to_string(),
                        )
                    })?;
                    let keys_done = engine.state().current_step_index > 0
                        || engine.is_complete();
                    if keys_done && !self.protocol_built {
                        info!("ProgramV2: Keys step complete (pre-tick), building protocol graph");
                        self.build_protocol(&program_context)?;
                        self.protocol_built = true;
                        info!("ProgramV2: Protocol graph built successfully");
                    }
                }

                // Run the engine tick
                let (tick_state_changed, is_complete) = {
                    let engine = self.setup_engine.as_mut().ok_or_else(|| {
                        BitVMXError::InvalidMessage(
                            "Protocol must return setup steps for ProgramV2".to_string(),
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

                    info!(
                        "ProgramV2: SetupEngine check - is_complete: {}, current_step: {}/{}",
                        is_complete,
                        engine.state().current_step_index,
                        engine.total_steps()
                    );

                    (tick_result.state_changed, is_complete)
                };

                if tick_state_changed {
                    state_changed = true;
                }

                // (b) Post-tick: build protocol if keys just completed in this tick
                {
                    let engine = self.setup_engine.as_ref().ok_or_else(|| {
                        BitVMXError::InvalidMessage(
                            "Protocol must return setup steps for ProgramV2".to_string(),
                        )
                    })?;
                    let keys_done = engine.state().current_step_index > 0
                        || engine.is_complete();
                    if keys_done && !self.protocol_built {
                        info!("ProgramV2: Keys step complete (post-tick), building protocol graph");
                        self.build_protocol(&program_context)?;
                        self.protocol_built = true;
                        info!("ProgramV2: Protocol graph built successfully");
                    }
                }

                // After all setup steps complete, sign and finalize
                if is_complete {
                    self.protocol.sign(&program_context.key_chain)?;
                    self.protocol.setup_complete(&program_context)?;
                    self.state = ProgramState::Monitoring;
                    state_changed = true;
                    info!("ProgramV2: Setup finalized, transitioning to Monitoring state");
                }
            }
            ProgramState::Monitoring => {
                // After the protocol is ready, we need to monitor the transactions on blockchain
                // Only register monitoring if not already done (idempotent)
                if !self.monitoring_registered {
                    info!("ProgramV2: Setting up blockchain monitoring");

                    // Get transactions and UTXOs to monitor from the protocol
                    let (txns_to_monitor, vouts_to_monitor) =
                        self.protocol.get_transactions_to_monitor(program_context)?;

                    // Create context for monitoring
                    let context = Context::ProgramId(self.program_id);
                    let context_str = context.to_string()?;

                    // Register transactions to monitor
                    if !txns_to_monitor.is_empty() {
                        info!(
                            "ProgramV2: Monitoring {} transactions for program {}",
                            txns_to_monitor.len(),
                            self.program_id
                        );
                        let txs_to_monitor = TypesToMonitor::Transactions(txns_to_monitor, context_str.clone(), None);
                        program_context.bitcoin_coordinator.monitor(txs_to_monitor)?;
                    }

                    // Register specific UTXOs (vouts) to monitor for spending
                    for (txid, vout) in vouts_to_monitor {
                        info!(
                            "ProgramV2: Monitoring vout {} of txid {} for program {}",
                            vout, txid, self.program_id
                        );
                        let vout_to_monitor = TypesToMonitor::SpendingUTXOTransaction(txid, vout, context_str.clone(), None);
                        program_context.bitcoin_coordinator.monitor(vout_to_monitor)?;
                    }

                    // Mark monitoring as registered - won't re-register on retry
                    self.monitoring_registered = true;
                }

                // Transition to Ready state - monitoring is now active
                self.state = ProgramState::Ready;
                state_changed = true;
                info!("ProgramV2: Monitoring setup complete, transitioning to Ready state");

                // Send SetupCompleted message to API channel (only once)
                // Some protocols (e.g., AggregatedKeyProtocol) suppress this to maintain
                // backward compatibility with callers that don't expect it.
                if !self.setup_completed_sent && self.protocol.send_setup_completed() {
                    match OutgoingBitVMXApiMessages::SetupCompleted(self.program_id).to_string() {
                        Ok(msg) => {
                            let result = program_context.broker_channel.send(
                                &program_context.components_config.l2,
                                msg,
                            );
                            if let Err(e) = result {
                                warn!("ProgramV2: Error sending setup completed message: {:?}", e);
                            } else {
                                info!("ProgramV2: Sent SetupCompleted message for program {}", self.program_id);
                                self.setup_completed_sent = true;
                                state_changed = true;  // Save the flag
                            }
                        }
                        Err(e) => {
                            warn!("ProgramV2: Error serializing SetupCompleted message: {:?}", e);
                        }
                    }
                }
            }
            ProgramState::Ready => {
                // Protocol is ready and monitoring is active
                // Just waiting for blockchain events via notify_news()
                debug!("ProgramV2: In Ready state - monitoring active, waiting for events");

                // Retry sending SetupCompleted if previous attempts failed
                if !self.setup_completed_sent && self.protocol.send_setup_completed() {
                    match OutgoingBitVMXApiMessages::SetupCompleted(self.program_id).to_string() {
                        Ok(msg) => {
                            let result = program_context.broker_channel.send(
                                &program_context.components_config.l2,
                                msg,
                            );
                            if let Err(e) = result {
                                warn!("ProgramV2: Retry sending SetupCompleted failed: {:?}", e);
                            } else {
                                info!("ProgramV2: SetupCompleted message sent on retry for program {}", self.program_id);
                                self.setup_completed_sent = true;
                                state_changed = true;
                            }
                        }
                        Err(e) => {
                            warn!("ProgramV2: Error serializing SetupCompleted message: {:?}", e);
                        }
                    }
                }
            }
            ProgramState::SettingUp(_) => {
                // This should never happen for ProgramV2 - we use SettingUpV2
                // But handle it gracefully for forward compatibility
                error!("ProgramV2: Unexpected SettingUp state - should be SettingUpV2");
                return Err(BitVMXError::InvalidMessage(
                    "ProgramV2 should use SettingUpV2, not SettingUp".to_string(),
                ));
            }
        }

        // Only save if there were actual changes to avoid infinite load-save loops
        if state_changed {
            self.save()?;
        }
        Ok(())
    }


    /// Receives setup data from another participant
    ///
    /// This is a public wrapper that delegates to SetupEngine when the program
    /// is in SettingUpV2 state. The SetupEngine handles all the logic internally.
    pub fn receive_setup_data(
        &mut self,
        data: &[u8],
        from: &PubKeyHash,
        program_context: &mut ProgramContext,
    ) -> Result<(), BitVMXError> {
        // Only handle setup data if we're in setup state
        if !matches!(self.state, ProgramState::SettingUpV2) {
            debug!("ProgramV2::receive_setup_data() - Not in SettingUpV2 state, ignoring");
            return Ok(());
        }

        // Track state changes and completion status for save/log after borrow ends
        let (state_changed, is_complete) = if let Some(engine) = &mut self.setup_engine {
            let state_changed = engine.receive_setup_data(
                data,
                from,
                &self.program_id,
                self.my_idx,
                self.leader,
                &self.participants,
                &self.protocol,
                program_context,
            )?;
            let is_complete = engine.is_complete();
            (state_changed, is_complete)
        } else {
            (false, false)
        };

        // Always save when state changes to avoid data loss on crash
        // The protocol_built flag prevents duplicate builds in tick() during crash recovery
        if state_changed {
            self.save()?;
            if is_complete {
                info!("ProgramV2::receive_setup_data() - Saved program state (setup complete, waiting for tick to build)");
            } else {
                info!("ProgramV2::receive_setup_data() - Saved program state (setup not yet complete)");
            }
        }

        Ok(())
    }

    /// Builds the protocol after all setup steps are complete
    ///
    /// This method:
    /// 1. Collects all participant keys from globals
    /// 2. Retrieves the pre-computed aggregated keys from KeysStep
    /// 3. Passes both to protocol.build()
    fn build_protocol(&mut self, program_context: &ProgramContext) -> Result<(), BitVMXError> {
        info!("ProgramV2: Building protocol {}", self.program_id);

        let protocol_id = self.protocol.context().id;

        // Collect all participant keys from globals
        // These were stored by KeysStep during setup
        let all_keys_var = program_context
            .globals
            .get_var(&protocol_id, "all_participant_keys")?
            .ok_or_else(|| BitVMXError::InvalidMessage("all_participant_keys not found in globals".to_string()))?;

        let all_keys_json = all_keys_var.string()?;

        let all_keys: Vec<ParticipantKeys> = serde_json::from_str(&all_keys_json)
            .map_err(|e| BitVMXError::InvalidMessage(format!("Failed to parse keys: {}", e)))?;

        // Retrieve my_keys to get pre-computed aggregated keys from KeysStep
        let my_keys_var = program_context
            .globals
            .get_var(&protocol_id, "my_keys")?
            .ok_or_else(|| BitVMXError::InvalidMessage("my_keys not found in globals".into()))?;
        let my_keys: ParticipantKeys = serde_json::from_str(&my_keys_var.string()?)?;

        info!(
            "ProgramV2: Collected {} participant keys and {} pre-computed aggregated keys for protocol build",
            all_keys.len(),
            my_keys.computed_aggregated.len()
        );

        // Store keys for later use in notify_news()
        self.all_participant_keys = Some(all_keys.clone());

        self.protocol.build(all_keys, my_keys.computed_aggregated, program_context)?;

        info!("ProgramV2: Protocol build complete");
        Ok(())
    }

    /// Returns the protocol ID
    pub fn protocol_id(&self) -> Uuid {
        self.protocol.context().id
    }

    /// Returns the program state
    pub fn state(&self) -> &ProgramState {
        &self.state
    }

    /// Returns whether the program is complete
    pub fn is_complete(&self) -> bool {
        matches!(
            self.state,
            ProgramState::Monitoring | ProgramState::Ready
        )
    }

    /// Finds a participant's address by their pubkey hash
    pub fn get_address_from_pubkey_hash(
        &self,
        pubkey_hash: &PubKeyHash,
    ) -> Result<CommsAddress, BitVMXError> {
        for p in &self.participants {
            if &p.comms_address.pubkey_hash == pubkey_hash {
                return Ok(p.comms_address.clone());
            }
        }
        Err(BitVMXError::CommsCommunicationError)
    }

    /// Main entry point for processing incoming communication messages
    ///
    /// Routes SetupStepData messages to receive_setup_data()
    pub fn process_comms_message(
        &mut self,
        comms_address: &PubKeyHash,
        msg_type: &CommsMessageType,
        data: Vec<u8>,
        program_context: &mut ProgramContext,
    ) -> Result<(), BitVMXError> {
        info!(
            "ProgramV2::process_comms_message() - Received {:?} message ({} bytes) from {}",
            msg_type,
            data.len(),
            comms_address
        );

        match msg_type {
            CommsMessageType::SetupStepData => {
                info!("ProgramV2::process_comms_message() - Routing SetupStepData to receive_setup_data()");
                self.receive_setup_data(&data, comms_address, program_context)?;
            }
            CommsMessageType::VerificationKey | CommsMessageType::VerificationKeyRequest => {
                debug!("ProgramV2: Verification key message handled upstream, ignoring");
            }
            CommsMessageType::Broadcasted => {
                debug!("ProgramV2: Broadcasted message should be handled upstream");
            }
            _ => {
                // Other message types are for Program legacy
                debug!(
                    "ProgramV2: Ignoring message type {:?} - not supported by ProgramV2",
                    msg_type
                );
            }
        }

        Ok(())
    }

    /// Gets a transaction by name from the protocol
    pub fn get_transaction_by_name(
        &self,
        name: &str,
        context: &ProgramContext,
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
    pub fn dispatch_transaction_name(
        &mut self,
        name: &str,
        program_context: &mut ProgramContext,
    ) -> Result<(), BitVMXError> {
        let (tx, speedup) = self.protocol.get_transaction_by_name(name, program_context)?;
        let context = Context::ProgramId(self.program_id);

        info!(
            "ProgramV2: Dispatching transaction: {} with speedup: {:?}",
            tx.compute_txid(),
            speedup.is_some()
        );

        program_context.bitcoin_coordinator.dispatch(
            tx,
            speedup,
            context.to_string()?,
            None,
            None,
        )?;

        Ok(())
    }

    /// Notifies the protocol about blockchain events (transaction confirmations, etc.)
    pub fn notify_news(
        &self,
        tx_id: Txid,
        vout: Option<u32>,
        tx_status: TransactionStatus,
        context: String,
        program_context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        // Use keys from all_participant_keys (populated during build_protocol)
        // Falls back to empty vec if keys not yet available
        let participant_keys: Vec<&ParticipantKeys> = self
            .all_participant_keys
            .as_ref()
            .map(|keys| keys.iter().collect())
            .unwrap_or_default();

        self.protocol.notify_news(
            tx_id,
            vout,
            tx_status.clone(),
            context,
            program_context,
            participant_keys,
        )?;

        // Send transaction notification to L2 channel (matching legacy Program behavior)
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
