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
    comms_helper::{prepare_message, request, CommsMessageType},
    config::ClientConfig,
    errors::{BitVMXError, ProgramError},
    leader_broadcast::OriginalMessage,
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
use bitvmx_operator_comms::operator_comms::PubKeyHash;
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
            setup_engine,
            storage: Some(storage.clone()),
            config: config.clone(),
        };

        // Handle single-participant protocols
        // For protocols with only one participant, we can skip setup and go straight to building
        if program.participants.len() == 1 {
            info!("ProgramV2: Single participant protocol - building immediately");

            // Generate keys for the protocol (normally done by SetupEngine's KeysStep)
            let my_keys = program.protocol.generate_keys(context)?;

            // Store keys in the format expected by build_protocol
            let all_keys = vec![my_keys];
            let all_keys_json = serde_json::to_string(&all_keys)
                .map_err(|e| BitVMXError::InvalidMessage(format!("Failed to serialize keys: {}", e)))?;

            context.globals.set_var(
                &program.protocol.context().id,
                "all_participant_keys",
                crate::program::variables::VariableTypes::String(all_keys_json),
            )?;

            // Now build and sign
            program.build_protocol(context)?;
            program.protocol.sign(&context.key_chain)?;
            program.state = ProgramState::Monitoring;
        }

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
            debug!("🔄 ProgramV2::load() - Loaded program {} with state: {:?} (waiting for participants)", program_id, program.state);
        } else {
            info!("🔄 ProgramV2::load() - Loaded program {} with state: {:?}", program_id, program.state);
        }

        program.storage = Some(storage.clone());
        program.protocol.set_storage(storage.clone());

        // State is already loaded as part of the program struct
        // Recreate SetupEngine if protocol supports it
        program.setup_engine = Self::try_create_setup_engine(&program.protocol);

        // Restore SetupEngine state if it was saved
        if let (Some(engine), Some(saved_state)) = (&mut program.setup_engine, &program.setup_engine_state) {
            if !is_waiting {
                info!("🔄 ProgramV2::load() - Restoring SetupEngine state for program {}", program_id);
            } else {
                debug!("🔄 ProgramV2::load() - Restoring SetupEngine state for program {} (waiting)", program_id);
            }
            *engine.state_mut() = saved_state.clone();
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
            .ok_or_else(|| {
                ProgramError::ProgramNotFound(self.program_id)
            })?;

        // Save SetupEngine state before serializing (since SetupEngine itself can't be serialized)
        if let Some(engine) = &self.setup_engine {
            self.setup_engine_state = Some(engine.state().clone());
        }

        info!("💾 ProgramV2::save() - Saving program {} with state: {:?}", self.program_id, self.state);

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
                // SetupEngine drives the entire setup flow
                if let Some(engine) = &mut self.setup_engine {
                    // Clone step name to owned String before any mutable borrows
                    let current_step_name = engine.current_step_name().unwrap_or("unknown").to_string();
                    let current_state = engine.state().current_step_state.clone();
                    let participants_completed = engine.state().participants_completed.len();
                    let total_participants = self.participants.len();
                    
                    // If we're waiting for participants and haven't received all data yet,
                    // there's nothing to do - early return to avoid unnecessary processing
                    if engine.state().current_step_state == StepState::WaitingForParticipants {
                        // Check if we can advance (this will return false if not all participants have sent data)
                        let can_advance = engine.current_step()
                            .map(|step| {
                                step.can_advance(&self.protocol, &self.participants, program_context)
                                    .unwrap_or(false)
                            })
                            .unwrap_or(false);
                        
                        if !can_advance {
                            // Still waiting for data from other participants - no changes, no need to save
                            debug!(
                                "ProgramV2::tick() - Step '{}' ({}/{}), state: {:?}, completed: {}/{} - Waiting for participants, early return",
                                current_step_name,
                                engine.state().current_step_index + 1,
                                engine.total_steps(),
                                current_state,
                                participants_completed,
                                total_participants
                            );
                            return Ok(());
                        } else {
                            info!(
                                "ProgramV2::tick() - Step '{}' ({}/{}), state: {:?}, completed: {}/{} - Can advance!",
                                current_step_name,
                                engine.state().current_step_index + 1,
                                engine.total_steps(),
                                current_state,
                                participants_completed,
                                total_participants
                            );
                        }
                    } else {
                        info!(
                            "ProgramV2::tick() - Step '{}' ({}/{}), state: {:?}, completed: {}/{}",
                            current_step_name,
                            engine.state().current_step_index + 1,
                            engine.total_steps(),
                            current_state,
                            participants_completed,
                            total_participants
                        );
                    }
                    
                    // Save engine state before tick to detect changes
                    let engine_state_before = engine.state().clone();
                    
                    // Use SetupEngine to drive setup
                    let data_to_send = engine.tick(&mut self.protocol, &self.participants, program_context)?;
                    let is_complete = engine.is_complete();

                    // Check if engine state changed
                    let engine_state_after = engine.state().clone();
                    if engine_state_before != engine_state_after {
                        info!(
                            "ProgramV2: SetupEngine state changed - before: {:?}, after: {:?}",
                            engine_state_before.current_step_state,
                            engine_state_after.current_step_state
                        );
                        state_changed = true;
                    }

                    // Send data if generated
                    if let Some(data) = data_to_send {
                        info!(
                            "ProgramV2: Generated {} bytes of data for step '{}', broadcasting to {} participants",
                            data.len(),
                            current_step_name,
                            self.participants.len() - 1
                        );

                        // IMPORTANT: Store our own data in globals BEFORE sending to others
                        // The step's can_advance() method checks that ALL participants' data exists in globals
                        if let Some(engine) = &mut self.setup_engine {
                            if let Some(step) = engine.current_step() {
                                let my_participant = &self.participants[self.my_idx];
                                step.verify_received(&data, my_participant, &self.protocol, &self.participants, program_context)?;
                                info!(
                                    "ProgramV2: Stored our own data (participant {}) in globals for step '{}'",
                                    self.my_idx,
                                    current_step_name
                                );
                            }
                        }

                        // Send the data to other participants
                        self.broadcast_setup_data(data, program_context)?;

                        // Mark as sent and mark ourselves as completed
                        if let Some(engine) = &mut self.setup_engine {
                            engine.mark_current_step_sent()?;
                            // Mark ourselves as completed since we've sent our data
                            engine.state_mut().mark_participant_completed(self.my_idx);
                            info!(
                                "ProgramV2: Marked ourselves (participant {}) as completed for step '{}'",
                                self.my_idx,
                                current_step_name
                            );
                            state_changed = true;
                        }
                    }

                    // Check if setup is complete
                    if is_complete {
                        info!("ProgramV2: SetupEngine completed all steps, building protocol");
                        self.build_protocol(&program_context)?;
                        self.state = ProgramState::Monitoring;
                        state_changed = true;
                        info!("ProgramV2: Protocol built, transitioning to Monitoring state");
                    }
                } else {
                    error!("ProgramV2: Protocol doesn't use SetupEngine - this shouldn't happen");
                    return Err(BitVMXError::InvalidMessage(
                        "Protocol must return setup steps for ProgramV2".to_string(),
                    ));
                }
            }
            ProgramState::Monitoring => {
                // After the protocol is ready, we need to monitor the transactions on blockchain
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
                    let txs_to_monitor = TypesToMonitor::Transactions(txns_to_monitor, context_str.clone());
                    program_context.bitcoin_coordinator.monitor(txs_to_monitor)?;
                }

                // Register specific UTXOs (vouts) to monitor for spending
                for (txid, vout) in vouts_to_monitor {
                    info!(
                        "ProgramV2: Monitoring vout {} of txid {} for program {}",
                        vout, txid, self.program_id
                    );
                    let vout_to_monitor = TypesToMonitor::SpendingUTXOTransaction(txid, vout, context_str.clone());
                    program_context.bitcoin_coordinator.monitor(vout_to_monitor)?;
                }

                // Transition to Ready state - monitoring is now active
                self.state = ProgramState::Ready;
                state_changed = true;
                info!("ProgramV2: Monitoring setup complete, transitioning to Ready state");

                // Send SetupCompleted message to API channel (only once)
                if !self.setup_completed_sent {
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
                // No changes in Ready state - don't save
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

    /// Broadcasts setup data using leader broadcast pattern
    ///
    /// Uses `CommsMessageType::SetupStepData` which is a generic message type for
    /// any SetupEngine step data. The actual step type (keys, nonces, signatures, etc.)
    /// is determined by the SetupEngine's current step, not by the message type.
    ///
    /// Leader broadcast pattern:
    /// - Non-leaders send their data only to the leader
    /// - Leader stores its own data + collects data from non-leaders
    /// - When all data is received, leader broadcasts to all non-leaders
    ///
    /// This is different from Program (legacy) which uses specific message types
    /// (Keys, PublicNonces, PartialSignatures) for each step.
    fn broadcast_setup_data(
        &self,
        data: Vec<u8>,
        program_context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        let my_idx = self.my_idx;
        let is_leader = my_idx == self.leader;

        if is_leader {
            // Leader: Store own message for later broadcast
            info!(
                "ProgramV2::broadcast_setup_data() - Leader storing own {} bytes",
                data.len()
            );

            // Prepare the message (serialize + sign)
            let (version, data_value, timestamp, signature) = prepare_message(
                &program_context.key_chain,
                &self.program_id,
                CommsMessageType::SetupStepData,
                data,
            )?;

            // Create OriginalMessage
            let original_msg = OriginalMessage {
                sender_pubkey_hash: program_context.comms.get_pubk_hash()?,
                msg_type: CommsMessageType::SetupStepData,
                data: data_value,
                original_timestamp: timestamp,
                original_signature: signature,
                version,
            };

            // Store leader's own message
            program_context
                .leader_broadcast_helper
                .store_original_message(&self.program_id, CommsMessageType::SetupStepData, original_msg)?;
        } else {
            // Non-leader: Send only to leader
            let leader_address = &self.participants[self.leader].comms_address;

            info!(
                "ProgramV2::broadcast_setup_data() - Non-leader sending {} bytes to leader {}",
                data.len(),
                leader_address.pubkey_hash
            );

            request(
                &program_context.comms,
                &program_context.key_chain,
                &self.program_id,
                leader_address.clone(),
                CommsMessageType::SetupStepData,
                data,
            )?;
        }

        Ok(())
    }

    /// Receives setup data from another participant
    ///
    /// This handles messages with type `CommsMessageType::SetupStepData`.
    /// The data is passed to the current SetupStep for verification and processing.
    pub fn receive_setup_data(
        &mut self,
        data: &[u8],
        from: &PubKeyHash,
        program_context: &mut ProgramContext,
    ) -> Result<(), BitVMXError> {
        let mut state_changed = false;

        info!(
            "ProgramV2::receive_setup_data() - Received {} bytes from participant {}",
            data.len(),
            from
        );

        // Check if setup is already complete - if so, ignore the message
        // This can happen when a non-leader receives the broadcast containing their own message
        if let Some(engine) = &self.setup_engine {
            if engine.is_complete() {
                info!(
                    "ProgramV2::receive_setup_data() - Setup already complete, ignoring message from {}",
                    from
                );
                return Ok(());
            }
        }

        // Find the participant
        let from_participant = self
            .participants
            .iter()
            .find(|p| &p.comms_address.pubkey_hash == from)
            .ok_or_else(|| {
                BitVMXError::InvalidMessage(format!("Unknown participant: {}", from))
            })?
            .clone();

        if let Some(engine) = &mut self.setup_engine {
            // Clone step name to owned String before any mutable borrows
            let step_name = engine.current_step_name().unwrap_or("unknown").to_string();
            let participants_completed_before = engine.state().participants_completed.len();
            
            info!(
                "ProgramV2::receive_setup_data() - Processing data for step '{}' (completed before: {}/{})",
                step_name,
                participants_completed_before,
                self.participants.len()
            );
            
            engine.receive_current_step_data(
                data,
                &from_participant,
                &self.protocol,
                &self.participants,
                program_context,
            )?;
            state_changed = true; // Receiving data changes the engine state

            let participants_completed_after = engine.state().participants_completed.len();
            info!(
                "ProgramV2::receive_setup_data() - After processing: {}/{} participants completed",
                participants_completed_after,
                self.participants.len()
            );

            // Leader broadcast: If I'm the leader and have all messages, broadcast to non-leaders
            if self.my_idx == self.leader {
                use crate::comms_helper::CommsMessageType;
                use crate::leader_broadcast::get_non_leader_participants;

                // Get list of all participant pubkey hashes (including leader)
                let all_participant_hashes: Vec<_> = self
                    .participants
                    .iter()
                    .map(|p| p.comms_address.pubkey_hash.clone())
                    .collect();

                // Check if we have all messages
                let has_all = program_context
                    .leader_broadcast_helper
                    .has_all_expected_messages(
                        &self.program_id,
                        CommsMessageType::SetupStepData,
                        &all_participant_hashes,
                    )?;

                if has_all {
                    info!(
                        "ProgramV2::receive_setup_data() - Leader has all messages, broadcasting to non-leaders"
                    );

                    // Get non-leader participants
                    let my_pubkey_hash = program_context.comms.get_pubk_hash()?;
                    let non_leaders = get_non_leader_participants(&self.participants.iter().map(|p| p.comms_address.clone()).collect::<Vec<_>>(), &my_pubkey_hash);

                    // Broadcast to all non-leaders
                    program_context
                        .leader_broadcast_helper
                        .broadcast_to_non_leaders(
                            program_context,
                            &self.program_id,
                            CommsMessageType::SetupStepData,
                            &non_leaders,
                        )?;

                    info!(
                        "ProgramV2::receive_setup_data() - Leader successfully broadcasted messages to {} non-leaders",
                        non_leaders.len()
                    );
                }
            }

            // Try to advance after receiving data
            let engine_state_before_advance = engine.state().current_step_state.clone();
            let participants_completed_count = engine.state().participants_completed.len();
            let total_participants = self.participants.len();
            
            info!(
                "ProgramV2::receive_setup_data() - Attempting to advance step '{}' (state: {:?}, completed: {}/{})",
                step_name,
                engine_state_before_advance,
                participants_completed_count,
                total_participants
            );
            
            let advanced = engine.try_advance_current_step(&self.protocol, &self.participants, program_context)?;
            if advanced {
                info!(
                    "ProgramV2::receive_setup_data() - Step '{}' advanced after receiving data",
                    step_name
                );
                state_changed = true;
            } else {
                info!(
                    "ProgramV2::receive_setup_data() - Step '{}' could not advance (state: {:?}, completed: {}/{})",
                    step_name,
                    engine_state_before_advance,
                    engine.state().participants_completed.len(),
                    self.participants.len()
                );
            }
        }

        // Only save if we haven't completed all steps yet
        // If all steps are complete, let tick() handle the transition to Monitoring/Ready
        // to avoid race conditions where we save in SettingUpV2 while tick() is transitioning to Ready
        if state_changed {
            if let Some(engine) = &self.setup_engine {
                if !engine.is_complete() {
                    self.save()?;
                    info!("ProgramV2::receive_setup_data() - Saved program state (setup not yet complete)");
                } else {
                    info!("ProgramV2::receive_setup_data() - Setup complete, skipping save to avoid race with tick()");
                }
            }
        }
        Ok(())
    }

    /// Builds the protocol after all setup steps are complete
    ///
    /// This method:
    /// 1. Collects all participant keys from globals
    /// 2. Passes them to protocol.build()
    /// 3. The protocol is responsible for its own MuSig2 aggregation
    ///
    /// NOTE: Unlike Program::build_protocol(), this does NOT compute aggregated keys.
    /// Each protocol must handle its own aggregation in its build() method.
    fn build_protocol(&mut self, program_context: &ProgramContext) -> Result<(), BitVMXError> {
        use std::collections::HashMap;

        info!("ProgramV2: Building protocol {}", self.program_id);

        // Collect all participant keys from globals
        // These were stored by KeysStep during setup
        let all_keys_var = program_context
            .globals
            .get_var(&self.protocol.context().id, "all_participant_keys")?
            .ok_or_else(|| BitVMXError::InvalidMessage("all_participant_keys not found in globals".to_string()))?;

        let all_keys_json = all_keys_var.string()?;

        let all_keys: Vec<ParticipantKeys> = serde_json::from_str(&all_keys_json)
            .map_err(|e| BitVMXError::InvalidMessage(format!("Failed to parse keys: {}", e)))?;

        info!(
            "ProgramV2: Collected {} participant keys for protocol build",
            all_keys.len()
        );

        // Call protocol.build() with empty computed_aggregated
        // Protocols using ProgramV2 should ignore this parameter and do their own aggregation
        let empty_aggregated = HashMap::new();
        self.protocol.build(all_keys, empty_aggregated, program_context)?;

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
        let participant_keys: Vec<&ParticipantKeys> = self
            .participants
            .iter()
            .filter_map(|p| p.keys.as_ref())
            .collect();

        self.protocol.notify_news(
            tx_id,
            vout,
            tx_status,
            context,
            program_context,
            participant_keys,
        )?;
        Ok(())
    }
}
