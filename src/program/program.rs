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
    program::{
        participant::ParticipantData,
        protocols::protocol_handler::{new_protocol_type, ProtocolHandler, ProtocolType},
        setup::{SetupEngine, SetupEngineState},
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
use tracing::{debug, info, warn};
use uuid::Uuid;

use super::participant::{CommsAddress, ParticipantKeys};

#[derive(Serialize, Deserialize)]
pub struct Program {
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

impl Program {
    /// Returns the storage key for this program
    fn storage_key(&self) -> String {
        format!("program/{}", self.program_id)
    }

    /// Returns a reference to the SetupEngine, or an error if it doesn't exist
    fn engine(&self) -> Result<&SetupEngine, BitVMXError> {
        self.setup_engine.as_ref().ok_or_else(|| {
            BitVMXError::InvalidMessage("Protocol must return setup steps for Program".to_string())
        })
    }

    /// Attempts to send SetupCompleted message to the L2 channel.
    /// Returns true if the message was sent (meaning state changed and should be saved).
    /// Some protocols (e.g., AggregatedKeyProtocol) suppress this message.
    fn try_send_setup_completed(&mut self, program_context: &mut ProgramContext) -> bool {
        if self.setup_completed_sent || !self.protocol.send_setup_completed() {
            return false;
        }

        match OutgoingBitVMXApiMessages::SetupCompleted(self.program_id).to_string() {
            Ok(msg) => {
                if let Err(e) = program_context
                    .broker_channel
                    .send(&program_context.components_config.l2, msg)
                {
                    warn!("Program: Error sending SetupCompleted message: {:?}", e);
                    false
                } else {
                    info!(
                        "Program: Sent SetupCompleted for program {}",
                        self.program_id
                    );
                    self.setup_completed_sent = true;
                    true
                }
            }
            Err(e) => {
                warn!("Program: Error serializing SetupCompleted message: {:?}", e);
                false
            }
        }
    }

    /// Creates a SetupEngine for the protocol using its setup_steps() method
    fn try_create_setup_engine(protocol: &ProtocolType) -> Option<SetupEngine> {
        if let Some(step_names) = protocol.setup_steps() {
            debug!(
                "Protocol supports SetupEngine with {} steps",
                step_names.len()
            );
            Some(SetupEngine::new(step_names))
        } else {
            debug!("Protocol does not use SetupEngine");
            None
        }
    }

    /// Creates and initializes a new Program instance
    pub fn new(
        program_id: Uuid,
        program_type: &str,
        peers: Vec<CommsAddress>,
        leader: usize,
        context: &mut ProgramContext,
        storage: Rc<Storage>,
        config: &ClientConfig,
    ) -> Result<(), BitVMXError> {
        info!(
            "Program: Setting up program {} with type {}",
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

        info!("Program: my_pos: {}", my_idx);
        info!("Program: Leader pos: {}", leader);

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

        let mut program = Program {
            program_id,
            my_idx,
            participants,
            leader,
            protocol,
            state: ProgramState::New,
            setup_engine_state: None, // Will be set when saving
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

        info!("Program: Setup complete for program {}", program_id);
        Ok(())
    }

    /// Loads a Program from storage
    pub fn load(storage: Rc<Storage>, program_id: &Uuid) -> Result<Self, ProgramError> {
        let key = format!("program/{}", program_id);
        let mut program: Program = storage
            .get(&key)?
            .ok_or(ProgramError::ProgramNotFound(*program_id))?;

        debug!(
            "Program::load() - Loaded program {} with state: {:?}",
            program_id, program.state
        );

        program.storage = Some(storage.clone());
        program.protocol.set_storage(storage.clone());

        // Recreate SetupEngine if protocol supports it
        program.setup_engine = Self::try_create_setup_engine(&program.protocol);

        // Restore SetupEngine state if it was saved
        if let (Some(engine), Some(saved_state)) =
            (&mut program.setup_engine, &program.setup_engine_state)
        {
            debug!(
                "Program::load() - Restoring SetupEngine state for program {}",
                program_id
            );
            engine.restore_state(saved_state.clone()).map_err(|e| {
                ProgramError::InvalidProgramStoragePath(format!(
                    "Failed to restore engine state: {}",
                    e
                ))
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
    pub fn tick(&mut self, program_context: &mut ProgramContext) -> Result<(), BitVMXError> {
        let mut state_changed = false;

        match &self.state {
            ProgramState::New => {
                info!("Program: State is New, transitioning to SettingUp");
                // Use SettingUp - SetupEngine manages the actual setup flow
                // No SettingUpState needed - SetupEngine tracks its own state
                self.state = ProgramState::SettingUp;
                state_changed = true;
            }
            ProgramState::SettingUp => {
                // Pre-tick: build protocol if keys step already completed (e.g., crash recovery)
                let keys_done =
                    self.engine()?.state().current_step_index > 0 || self.engine()?.is_complete();
                if keys_done && !self.protocol_built {
                    info!("Program: Keys step complete (pre-tick), building protocol graph");
                    self.build_protocol(&program_context)?;
                    self.protocol_built = true;
                }

                // Run the engine tick (uses block scope to avoid borrow conflict
                // between setup_engine and other self fields)
                let (tick_state_changed, is_complete) = {
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

                    (tick_result.state_changed, is_complete)
                };

                if tick_state_changed {
                    state_changed = true;
                }

                // Post-tick: build protocol if keys just completed in this tick
                let keys_done =
                    self.engine()?.state().current_step_index > 0 || self.engine()?.is_complete();
                if keys_done && !self.protocol_built {
                    info!("Program: Keys step complete (post-tick), building protocol graph");
                    self.build_protocol(&program_context)?;
                    self.protocol_built = true;
                }

                // After all setup steps complete, sign and finalize
                if is_complete {
                    self.protocol.sign(&program_context.key_chain)?;
                    self.protocol.setup_complete(&program_context)?;
                    self.state = ProgramState::Monitoring;
                    state_changed = true;
                    info!("Program: Setup finalized, transitioning to Monitoring state");
                }
            }
            ProgramState::Monitoring => {
                // After the protocol is ready, we need to monitor the transactions on blockchain
                // Only register monitoring if not already done (idempotent)
                if !self.monitoring_registered {
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
                        let txs_to_monitor = TypesToMonitor::Transactions(
                            txns_to_monitor,
                            context_str.clone(),
                            confirmations,
                        );
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

                    // Mark monitoring as registered - won't re-register on retry
                    self.monitoring_registered = true;
                }

                // Transition to Ready state - monitoring is now active
                self.state = ProgramState::Ready;
                state_changed = true;
                info!("Program: Monitoring setup complete, transitioning to Ready state");

                if self.try_send_setup_completed(program_context) {
                    state_changed = true;
                }
            }
            ProgramState::Ready => {
                // Protocol is ready and monitoring is active
                // Just waiting for blockchain events via notify_news()
                debug!("Program: In Ready state - monitoring active, waiting for events");

                // Retry sending SetupCompleted if previous attempts failed
                if self.try_send_setup_completed(program_context) {
                    state_changed = true;
                }
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
    /// is in SettingUp state. The SetupEngine handles all the logic internally.
    pub fn receive_setup_data(
        &mut self,
        data: &[u8],
        from: &PubKeyHash,
        program_context: &mut ProgramContext,
    ) -> Result<(), BitVMXError> {
        // Only handle setup data if we're in setup state
        if !matches!(self.state, ProgramState::SettingUp) {
            debug!("Program::receive_setup_data() - Not in SettingUp state, ignoring");
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
                info!("Program::receive_setup_data() - Saved program state (setup complete, waiting for tick to build)");
            } else {
                info!(
                    "Program::receive_setup_data() - Saved program state (setup not yet complete)"
                );
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
        info!("Program: Building protocol {}", self.program_id);

        let protocol_id = self.protocol.context().id;

        // Collect all participant keys from globals
        // These were stored by KeysStep during setup
        let all_keys_var = program_context
            .globals
            .get_var(&protocol_id, "all_participant_keys")?
            .ok_or_else(|| {
                BitVMXError::InvalidMessage("all_participant_keys not found in globals".to_string())
            })?;

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
            "Program: Collected {} participant keys and {} pre-computed aggregated keys for protocol build",
            all_keys.len(),
            my_keys.computed_aggregated.len()
        );

        // Store keys for later use in notify_news()
        self.all_participant_keys = Some(all_keys.clone());

        self.protocol
            .build(all_keys, my_keys.computed_aggregated, program_context)?;

        info!("Program: Protocol build complete");
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
        matches!(self.state, ProgramState::Monitoring | ProgramState::Ready)
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
        debug!(
            "Program::process_comms_message() - Received {:?} ({} bytes) from {}",
            msg_type,
            data.len(),
            comms_address
        );

        match msg_type {
            CommsMessageType::SetupStepData => {
                debug!("Program::process_comms_message() - Routing SetupStepData to receive_setup_data()");
                self.receive_setup_data(&data, comms_address, program_context)?;
            }
            CommsMessageType::VerificationKey | CommsMessageType::VerificationKeyRequest => {
                debug!("Program: Verification key message handled upstream, ignoring");
            }
            CommsMessageType::Broadcasted => {
                debug!("Program: Broadcasted message should be handled upstream");
            }
            _ => {
                // Other message types
                debug!(
                    "Program: Ignoring message type {:?} - not supported by Program",
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
    pub fn notify_news(
        &self,
        tx_id: Txid,
        vout: Option<u32>,
        tx_status: TransactionStatus,
        context: String,
        program_context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        // Use keys from all_participant_keys (populated during build_protocol)
        if self.all_participant_keys.is_none() {
            warn!(
                "Program: notify_news() called with no participant keys for program {}",
                self.program_id
            );
        }
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
    let state: ProgramState = storage.get(&key)?.unwrap_or_default();
    Ok(state.is_active())
}
