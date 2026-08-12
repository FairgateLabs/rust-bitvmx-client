use crate::ports::bitcoin_coordinator::BitcoinCoordinatorApi;
use crate::{
    bitvmx::Context,
    comms_helper::{prepare_message, request, CommsMessageType},
    errors::BitVMXError,
    leader_broadcast::{get_non_leader_participants, OriginalMessage},
    program::{
        participant::{get_comms_address_by_pubkey_hash, get_index_by_pubkey_hash, CommsAddress},
        protocols::protocol_handler::ProtocolType,
    },
    types::{MessageDisposition, ProgramContext},
};
use bitvmx_broker::identification::identifier::PubkHash as PubKeyHash;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use super::{
    steps::{create_setup_step, SetupStepEnum, SetupStepName},
    SetupStep,
};

/// Current state of a setup step in the engine.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum StepState {
    /// Step is generating data
    Generating,
    /// Step has sent data and is waiting for other participants
    WaitingForParticipants,
    /// All participants have sent data and step is ready to advance to the next step
    AllParticipantsCompleted,
    /// Step has received all data and can advance
    Completed,
}

/// Tracks the state of the setup engine.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SetupEngineState {
    /// Index of the current active step (0-based)
    pub current_step_index: usize,
    /// State of the current step
    pub current_step_state: StepState,
    /// Set of participant indices that have sent data for the current step
    pub participants_completed: Vec<usize>,
    /// Whether all steps have been completed
    pub all_steps_completed: bool,
}

impl SetupEngineState {
    pub fn new() -> Self {
        Self {
            current_step_index: 0,
            current_step_state: StepState::Generating,
            participants_completed: Vec::new(),
            all_steps_completed: false,
        }
    }

    /// Check if a participant has completed the current step
    pub fn has_participant_completed(&self, participant_idx: usize) -> bool {
        self.participants_completed.contains(&participant_idx)
    }

    /// Mark a participant as completed for the current step
    pub fn mark_participant_completed(&mut self, participant_idx: usize) {
        if !self.has_participant_completed(participant_idx) {
            self.participants_completed.push(participant_idx);
        }
    }
}

/// Result of a SetupEngine tick operation.
#[derive(Debug)]
pub struct SetupTickResult {
    /// Whether the engine state changed during this tick
    pub state_changed: bool,
}

/// Engine that orchestrates the setup process using SetupSteps.
///
/// The SetupEngine manages the lifecycle of protocol setup by:
/// 1. Executing steps in sequence
/// 2. Managing step state transitions
/// 3. Coordinating data exchange between participants
/// 4. Verifying completion conditions
///
/// ## State Machine
///
/// For each step:
/// ```text
/// Generating ──→ WaitingForParticipants ──→ AllParticipantsCompleted ──→ Completed
/// Generating ─────────────────────────────────→ AllParticipantsCompleted
/// ```
///
/// Synchronous generation can move directly to `AllParticipantsCompleted` when
/// no other participant data is needed. `Completed` is transient: the engine
/// immediately advances to the next step or marks the whole setup complete.
pub struct SetupEngine {
    /// The steps to execute in order
    steps: Vec<SetupStepEnum>,
    /// Number of participants fixed when the owning Program is created
    total_participants: usize,
    /// Current state of the engine
    state: SetupEngineState,
}

impl SetupEngine {
    /// Creates a new SetupEngine with the given step names and participant count.
    ///
    /// The owning Program fixes its participant list at creation, so runtime
    /// operations can rely on both values being non-empty.
    pub fn new(
        step_names: Vec<SetupStepName>,
        total_participants: usize,
    ) -> Result<Self, BitVMXError> {
        if step_names.is_empty() {
            return Err(BitVMXError::InvalidParameter(
                "SetupEngine requires at least one step".to_string(),
            ));
        }
        if total_participants == 0 {
            return Err(BitVMXError::InvalidParameter(
                "SetupEngine requires at least one participant".to_string(),
            ));
        }

        let steps: Vec<SetupStepEnum> = step_names
            .iter()
            .map(|name| create_setup_step(name))
            .collect();

        Ok(Self {
            steps,
            total_participants,
            state: SetupEngineState::new(),
        })
    }

    /// Returns the current state of the engine.
    pub fn state(&self) -> &SetupEngineState {
        &self.state
    }

    /// Restores engine state from a saved state (used during load).
    ///
    /// Validates invariants maintained by the engine's public operations. The
    /// final step remains at its index when setup completes; the index is never
    /// advanced one past the end.
    pub fn restore_state(&mut self, saved_state: SetupEngineState) -> Result<(), BitVMXError> {
        let total_steps = self.total_steps();
        if saved_state.current_step_index >= total_steps {
            return Err(BitVMXError::InvalidMessage(format!(
                "Invalid step index {} for engine with {} steps",
                saved_state.current_step_index, total_steps
            )));
        }

        let is_final_step = saved_state.current_step_index == total_steps - 1;
        match (
            saved_state.all_steps_completed,
            &saved_state.current_step_state,
        ) {
            // advance_to_next_step leaves the final step in Completed state.
            (true, StepState::Completed) if is_final_step => {}
            (true, _) => {
                return Err(BitVMXError::InvalidMessage(format!(
                    "Completed setup has inconsistent state at step {}: {:?}",
                    saved_state.current_step_index, saved_state.current_step_state
                )));
            }
            (false, StepState::Completed) => {
                return Err(BitVMXError::InvalidMessage(format!(
                    "Incomplete setup cannot have a Completed current step at index {}",
                    saved_state.current_step_index
                )));
            }
            (false, _) => {}
        }

        self.state = saved_state;
        Ok(())
    }

    /// Returns a mutable reference to the state (for tests only).
    #[cfg(test)]
    pub fn state_mut(&mut self) -> &mut SetupEngineState {
        &mut self.state
    }

    /// Returns the current step, if any.
    fn current_step(&self) -> &SetupStepEnum {
        self.steps
            .get(self.state.current_step_index)
            .expect("index should be always in range")
    }

    /// Returns the name of the current step.
    pub fn current_step_name(&self) -> &str {
        self.current_step().step_name()
    }

    /// Returns true if all steps have been completed.
    pub fn is_complete(&self) -> bool {
        self.state.all_steps_completed
    }

    /// Returns the total number of steps.
    pub fn total_steps(&self) -> usize {
        self.steps.len()
    }

    /// Resets state for the next step or marks the final step complete.
    fn advance_to_next_step(&mut self) {
        if self.state.current_step_index < self.total_steps() - 1 {
            self.state.current_step_index += 1;
            self.state.current_step_state = StepState::Generating;
            self.state.participants_completed.clear();
        } else {
            self.state.all_steps_completed = true;
        }
    }

    fn if_not_completed(&self) -> Result<(), BitVMXError> {
        if self.is_complete() {
            Err(BitVMXError::InvalidMessage(
                "Setup is already complete".to_string(),
            ))
        } else {
            Ok(())
        }
    }

    /// Generates data for the current step.
    ///
    /// This transitions the step from Generating → WaitingForParticipants.
    ///
    /// Returns the serialized data to send to other participants, or None if
    /// the step doesn't generate data.
    fn generate_current_step_data<BC: BitcoinCoordinatorApi>(
        &mut self,
        protocol: &mut ProtocolType,
        context: &mut ProgramContext<BC>,
    ) -> Result<Option<(serde_json::Value, CommsMessageType)>, BitVMXError> {
        self.if_not_completed()?;

        let step_name = self.current_step_name().to_string();

        if self.state.current_step_state != StepState::Generating {
            return Err(BitVMXError::InvalidState(format!(
                "Step '{}' is not in Generating state (current: {:?})",
                step_name, self.state.current_step_state
            )));
        }

        info!(
            "SetupEngine: Generating data for step '{}' ({}/{}). Participants completed: {}/{}",
            step_name,
            self.state.current_step_index + 1,
            self.total_steps(),
            self.state.participants_completed.len(),
            self.total_participants
        );

        // Now get the step and generate data
        let step = &self.steps[self.state.current_step_index];
        let data_and_type = step.generate_data(protocol, context)?;

        if (self.total_participants == 1
            || self.state.participants_completed.len() == self.total_participants - 1)
            && !step.generate_async()
        {
            self.state.current_step_state = StepState::AllParticipantsCompleted;
        } else {
            self.state.current_step_state = StepState::WaitingForParticipants;
        }

        debug!("SetupEngine: Step '{}' generated ", step_name);

        Ok(data_and_type)
    }

    pub fn receive_dispatcher_result<BC: BitcoinCoordinatorApi>(
        &mut self,
        result: Value,
        context: &Context,
        my_idx: usize,
        program_id: &Uuid,
        leader: usize,
        participants: &[CommsAddress],
        program_context: &mut ProgramContext<BC>,
    ) -> Result<bool, BitVMXError> {
        // Dispatcher delivery is at-least-once. A result received after all
        // setup steps completed is a harmless replay, not a protocol error.
        if self.is_complete() {
            info!(
                "SetupEngine::receive_dispatcher_result() - Ignoring result because setup is complete"
            );
            return Ok(false);
        }

        let current_step_name = self.current_step_name().to_string();

        let (sub_step, msg_type) = match context {
            Context::SetupStep(_, step_name, sub_step, msg_type) => {
                // A result from an earlier step may arrive after the engine has
                // advanced. It cannot be useful for the current step, so discard
                // it without making the client fail its tick.
                if step_name != &current_step_name {
                    info!(
                        "SetupEngine::receive_dispatcher_result() - Ignoring result for step '{}'; current step is '{}'",
                        step_name, current_step_name
                    );
                    return Ok(false);
                }
                info!(
                    "SetupEngine::receive_dispatcher_result() - Received dispatcher result for step '{}', sub_step '{}'",
                    step_name, sub_step
                );
                (sub_step, msg_type)
            }
            _ => {
                return Err(BitVMXError::InvalidMessage(format!(
                    "Invalid context for dispatcher result: {:?}. Expected SetupStep.",
                    context
                )));
            }
        };

        // Check for a replay before validating the state: the original result
        // may already have moved the step to AllParticipantsCompleted.
        if self.state.has_participant_completed(my_idx) {
            info!(
                "SetupEngine::receive_dispatcher_result() - Ignoring duplicate result for participant {} in step '{}'",
                my_idx, current_step_name
            );
            return Ok(false);
        }

        if self.state.current_step_state != StepState::WaitingForParticipants {
            return Err(BitVMXError::InvalidState(format!(
                "Dispatcher result for step '{}' received while in {:?} state",
                current_step_name, self.state.current_step_state
            )));
        }

        let step = &self.steps[self.state.current_step_index];

        let data = step.receive_dispatcher_result(
            result,
            msg_type.clone(),
            sub_step,
            program_context,
            program_id,
        )?;

        self.process_produced_data(
            data,
            msg_type.clone(),
            my_idx,
            leader,
            participants,
            program_id,
            program_context,
        )?;

        if self.state.participants_completed.len() == self.total_participants {
            self.state.current_step_state = StepState::AllParticipantsCompleted;
        }

        Ok(true)
    }

    /// Receives and verifies data from a participant for the current step.
    ///
    /// This marks the participant as completed for this step.
    fn receive_current_step_data<BC: BitcoinCoordinatorApi>(
        &mut self,
        data: Value,
        msg_type: CommsMessageType,
        my_idx: usize,
        from_participant: &CommsAddress,
        protocol: &ProtocolType,
        participants: &[CommsAddress],
        context: &mut ProgramContext<BC>,
    ) -> Result<MessageDisposition, BitVMXError> {
        self.if_not_completed()?;

        let step_name = self.current_step_name().to_string();

        // Find participant index
        let participant_idx =
            get_index_by_pubkey_hash(participants, &from_participant.pubkey_hash)?;

        // Check if already received
        if self.state.has_participant_completed(participant_idx) {
            if participant_idx == my_idx {
                warn!("Getting data from ourselves again for step '{}', ignoring since we already processed it.", step_name);
                return Ok(MessageDisposition::Processed);
            }

            info!(
                "SetupEngine: Already received data from participant {} for step '{}'",
                participant_idx, step_name
            );
            return Ok(MessageDisposition::RetryLater);
        }

        debug!(
            "SetupEngine: Receiving data from participant {} for step '{}'",
            participant_idx, step_name
        );

        // Verify and store the data
        let step = &self.steps[self.state.current_step_index];
        let verified = step.verify_received(
            data,
            msg_type,
            from_participant,
            protocol,
            participants,
            context,
            false,
        )?;

        /*if step.verify_async() && !verified {
            info!(
                "SetupEngine: Step '{}' is async and data from participant {} is not verified yet, waiting for async verification to complete",
                step_name, participant_idx
             );
            return Ok(MessageDisposition::Processed);
        }*/

        if !verified {
            warn!(
                "SetupEngine: Data from participant {} for step '{}' did not verify, ignoring",
                participant_idx, step_name
            );
            return Ok(MessageDisposition::RetryLater);
        }

        // Mark participant as completed
        self.state.mark_participant_completed(participant_idx);

        if self.state.participants_completed.len() == self.total_participants {
            self.state.current_step_state = StepState::AllParticipantsCompleted;
        }

        info!(
            "SetupEngine::receive_current_step_data() - Step '{}': {}/{} participants completed (participant {} just completed) {:?}",
            step_name,
            self.state.participants_completed.len(),
            self.total_participants,
            participant_idx,
            self.state.current_step_state
        );

        Ok(MessageDisposition::Processed)
    }

    /// Checks if the current step can advance to the next step.
    ///
    /// If the step can advance, it transitions to Completed and prepares for
    /// the next step.
    ///
    /// Returns true if the step advanced, false if still waiting.
    fn try_advance_current_step<BC: BitcoinCoordinatorApi>(
        &mut self,
        protocol: &ProtocolType,
        participants: &[CommsAddress],
        context: &mut ProgramContext<BC>,
    ) -> Result<bool, BitVMXError> {
        self.if_not_completed()?;

        if self.state.current_step_state != StepState::AllParticipantsCompleted {
            return Ok(false);
        }

        let step_name = self.current_step_name().to_string();

        // Check if we can advance
        let step = &self.steps[self.state.current_step_index];
        let can_advance = step.can_advance(protocol, participants, context)?;

        if !can_advance {
            debug!(
                "SetupEngine::try_advance_current_step() - Step '{}' cannot advance yet ({}/{} participants completed)",
                step_name,
                self.state.participants_completed.len(),
                self.total_participants
            );
            return Ok(false);
        }

        info!(
            "SetupEngine::try_advance_current_step() - Step '{}' can advance! ({}/{} participants completed)",
            step_name,
            self.state.participants_completed.len(),
            self.total_participants
        );

        info!(
            "SetupEngine: Step '{}' completed, advancing to next step",
            step_name
        );

        // Call the completion hook
        step.on_step_complete(protocol, participants, context)?;

        // Transition to completed
        self.state.current_step_state = StepState::Completed;

        // Advance to next step
        self.advance_to_next_step();

        if self.is_complete() {
            info!("SetupEngine: All steps completed!");
        } else {
            let next_step_name = self.current_step_name();
            info!(
                "SetupEngine: Advanced to step '{}' ({}/{})",
                next_step_name,
                self.state.current_step_index + 1,
                self.total_steps()
            );
        }

        Ok(true)
    }

    /// Broadcasts setup data using leader broadcast pattern.
    ///
    /// Each setup step uses its concrete `CommsMessageType` (`Keys`,
    /// `PublicNonces`, `PartialSignatures`, or `GarbledCircuit`).
    ///
    /// Leader broadcast pattern:
    /// - Non-leaders send their data only to the leader
    /// - Leader stores its own data + collects data from non-leaders
    /// - When all data is received, leader broadcasts to all non-leaders
    fn broadcast_setup_data<BC: BitcoinCoordinatorApi>(
        &self,
        data: serde_json::Value,
        msg_type: CommsMessageType,
        program_id: &Uuid,
        my_idx: usize,
        leader: usize,
        participants: &[CommsAddress],
        context: &ProgramContext<BC>,
    ) -> Result<(), BitVMXError> {
        let is_leader = my_idx == leader;

        if is_leader {
            // Leader: Store own message for later broadcast
            info!("SetupEngine::broadcast_setup_data() - Leader storing own msg for type {:?} in step '{}'", msg_type, self.current_step_name());

            // Prepare the message (serialize + sign)
            let (version, data_value, timestamp, signature) = prepare_message(
                &context.key_manager,
                &context.rsa_public_key,
                program_id,
                msg_type,
                data,
            )?;

            // Create OriginalMessage
            let original_msg = OriginalMessage {
                sender_pubkey_hash: context.comms.get_pubk_hash()?,
                msg_type,
                data: data_value,
                original_timestamp: timestamp,
                original_signature: signature,
                version,
            };

            // Store leader's own message
            context.leader_broadcast_helper.store_original_message(
                program_id,
                msg_type,
                original_msg,
            )?;
        } else {
            // Non-leader: Send only to leader
            let leader_address = &participants[leader];

            info!(
                "SetupEngine::broadcast_setup_data() - type: {:?} - Non-leader sending to leader {}",
                msg_type, leader_address.pubkey_hash
            );

            request(
                &context.comms,
                &context.key_manager,
                &context.rsa_public_key,
                program_id,
                leader_address.clone(),
                msg_type,
                data,
            )?;
        }

        Ok(())
    }

    /// Receives setup data from another participant.
    ///
    /// This handles the complete flow of receiving data:
    /// 1. Verifies and stores the data
    /// 2. Handles leader broadcast pattern (if leader has all messages, broadcasts)
    /// 3. Tries to advance the current step
    ///
    /// Returns whether the message was processed or should be retried later.
    pub fn receive_setup_data<BC: BitcoinCoordinatorApi>(
        &mut self,
        data: Value,
        msg_type: CommsMessageType,
        from: &PubKeyHash,
        program_id: &Uuid,
        my_idx: usize,
        leader: usize,
        participants: &[CommsAddress],
        protocol: &ProtocolType,
        context: &mut ProgramContext<BC>,
    ) -> Result<MessageDisposition, BitVMXError> {
        info!(
            "SetupEngine::receive_setup_data() - Received data of type {:?} from participant {}",
            msg_type, from
        );

        // Check if setup is already complete. Preserve the existing retry
        // behavior represented previously by Ok(false).
        if self.is_complete() {
            warn!(
                "SetupEngine::receive_setup_data() - Setup already complete, ignoring message from {}",
                from
            );
            return Ok(MessageDisposition::RetryLater);
        }

        // Find the participant
        let from_participant = get_comms_address_by_pubkey_hash(participants, from)?;

        let step_name = self.current_step_name().to_string();
        let participants_completed_before = self.state.participants_completed.len();

        info!(
            "SetupEngine::receive_setup_data() - Processing data for step '{}' (completed before: {}/{})",
            step_name,
            participants_completed_before,
            self.total_participants
        );

        // Receive and verify the data
        let disposition = self.receive_current_step_data(
            data,
            msg_type,
            my_idx,
            &from_participant,
            protocol,
            participants,
            context,
        )?;
        if disposition == MessageDisposition::RetryLater {
            debug!(
                "SetupEngine::receive_setup_data() - Data from participant {} could not be processed for step '{}'",
                from, step_name
            );
            return Ok(MessageDisposition::RetryLater);
        }

        let participants_completed_after = self.state.participants_completed.len();
        info!(
            "SetupEngine::receive_setup_data() - After processing: {}/{} participants completed",
            participants_completed_after, self.total_participants
        );

        // Leader broadcast: If I'm the leader and have all messages, broadcast to non-leaders
        if my_idx == leader {
            self.send_broadcast_data_to_non_leaders(context, program_id, participants, msg_type)?;
        }

        Ok(MessageDisposition::Processed)
    }

    fn send_broadcast_data_to_non_leaders<BC: BitcoinCoordinatorApi>(
        &self,
        context: &ProgramContext<BC>,
        program_id: &Uuid,
        participants: &[CommsAddress],
        msg_type: CommsMessageType,
    ) -> Result<(), BitVMXError> {
        // Get list of all participant pubkey hashes (including leader)
        let all_participant_hashes: Vec<_> =
            participants.iter().map(|p| p.pubkey_hash.clone()).collect();

        // Check if we have all messages
        let has_all = context.leader_broadcast_helper.has_all_expected_messages(
            program_id,
            msg_type,
            &all_participant_hashes,
        )?;

        if has_all {
            info!(
                    "SetupEngine::receive_setup_data() - type: {:?} - Leader has all messages, broadcasting to non-leaders", msg_type
                );

            // Get non-leader participants
            let my_pubkey_hash = context.comms.get_pubk_hash()?;
            let non_leaders = get_non_leader_participants(participants, &my_pubkey_hash);

            // Broadcast to all non-leaders
            context.leader_broadcast_helper.broadcast_to_non_leaders(
                context,
                program_id,
                msg_type,
                &non_leaders,
            )?;

            info!(
                "SetupEngine::receive_setup_data() - type: {:?} - Leader successfully broadcasted messages to {} non-leaders", msg_type, non_leaders.len()
            );
        }

        Ok(())
    }

    /// Processes the setup tick.
    ///
    /// This is the main entry point for driving the setup forward. It should
    /// be called periodically to:
    /// 1. Generate data for pending steps
    /// 2. Check if steps can advance
    ///
    /// This method handles all the logic internally, including:
    /// - Early return when waiting for participants
    /// - Verifying and storing own data before sending
    /// - Broadcasting data
    /// - Marking participants as completed
    ///
    /// Returns the data to send (if any) and whether state changed.
    pub fn tick<BC: BitcoinCoordinatorApi>(
        &mut self,
        protocol: &mut ProtocolType,
        participants: &[CommsAddress],
        my_idx: usize,
        program_id: &Uuid,
        leader: usize,
        context: &mut ProgramContext<BC>,
    ) -> Result<SetupTickResult, BitVMXError> {
        if self.is_complete() {
            debug!("SetupEngine::tick() - Setup already complete");
            return Ok(SetupTickResult {
                state_changed: false,
            });
        }

        let step_name = self.current_step_name().to_string();

        // Save engine state before tick to detect changes
        let engine_state_before = self.state.clone();

        // Process the tick based on current state
        let mut data_and_type_to_send = None;
        let mut state_changed = false;

        match self.state.current_step_state {
            StepState::Generating => {
                info!(
                    "SetupEngine::tick() - Step '{}' is Generating, generating data",
                    step_name
                );
                // Generate data for this step
                let data_and_type = self.generate_current_step_data(protocol, context)?;
                if let Some((ref d, ref msg_type)) = data_and_type {
                    info!(
                        "SetupEngine::tick() - Generated {} - type {:?}",
                        step_name, msg_type
                    );

                    // IMPORTANT: Store our own data in globals BEFORE sending to others
                    // The step's can_advance() method checks that ALL participants' data exists in globals
                    let my_participant = &participants[my_idx];
                    self.current_step().verify_received(
                        d.clone(),
                        *msg_type,
                        my_participant,
                        protocol,
                        participants,
                        context,
                        true,
                    )?;
                    info!(
                            "SetupEngine::tick() - Stored our own data (participant {}) in globals for step '{}' type: {:?}",
                            my_idx,
                            step_name,
                            msg_type
                        );

                    data_and_type_to_send = data_and_type;
                } else {
                    info!(
                        "SetupEngine::tick() - Step '{}' generated no data",
                        step_name
                    );
                }
                state_changed = true;
            }
            StepState::WaitingForParticipants => {
                info!("Wasted");
            }
            StepState::AllParticipantsCompleted => {
                debug!(
                    "SetupEngine::tick() - Step '{}' is AllParticipantsCompleted (completed: {}/{}), trying to advance",
                    step_name,
                    self.state.participants_completed.len(),
                    self.total_participants
                );
                // Try to advance if possible
                let advanced = self.try_advance_current_step(protocol, participants, context)?;
                if advanced {
                    info!(
                        "SetupEngine::tick() - Step '{}' advanced successfully",
                        step_name
                    );
                    state_changed = true;
                }
            }
            StepState::Completed => {
                error!("We should never be in Completed state during tick - the engine should have already advanced to the next step. Step '{}'", step_name);
            }
        }

        // Check if engine state changed
        let engine_state_after = self.state.clone();
        if engine_state_before != engine_state_after {
            info!(
                "SetupEngine::tick() - State changed - before: {:?}, after: {:?}",
                engine_state_before.current_step_state, engine_state_after.current_step_state
            );
            state_changed = true;
        }

        // If we have data to send, broadcast it and mark as sent
        if let Some((data, msg_type)) = data_and_type_to_send {
            self.process_produced_data(
                data,
                msg_type,
                my_idx,
                leader,
                participants,
                program_id,
                context,
            )?;
            state_changed = true;
        }

        Ok(SetupTickResult { state_changed })
    }

    fn process_produced_data<BC: BitcoinCoordinatorApi>(
        &mut self,
        data: Value,
        msg_type: CommsMessageType,
        my_idx: usize,
        leader: usize,
        participants: &[CommsAddress],
        program_id: &Uuid,
        context: &mut ProgramContext<BC>,
    ) -> Result<(), BitVMXError> {
        let step_name = self.current_step_name().to_string();
        info!(
            "SetupEngine::tick() - type: {:?} - Broadcasting for step '{}' to {} participants",
            msg_type,
            &step_name,
            self.total_participants - 1
        );

        // Broadcast the data if it's not leader
        // if leader stores its own message
        self.broadcast_setup_data(
            data.clone(),
            msg_type,
            program_id,
            my_idx,
            leader,
            participants,
            context,
        )?;

        self.state.mark_participant_completed(my_idx);
        info!(
            "SetupEngine::tick() - type: {:?} - Marked ourselves (participant {}) as completed for step '{}'",
            msg_type, my_idx, step_name
        );

        if my_idx == leader {
            // If we're the leader and have all messages, broadcast to non-leaders
            self.send_broadcast_data_to_non_leaders(context, program_id, participants, msg_type)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::participant::ParticipantKeyDeclaration;
    use crate::program::protocols::protocol_handler::new_protocol_type;
    use crate::program::variables::VariableTypes;
    use crate::test_utils::{TestProgramContextEnv, TestStorageDir};
    use crate::types::PROGRAM_TYPE_AGGREGATED_KEY;

    fn aggregated_key_protocol(id: Uuid, dir: &TestStorageDir) -> ProtocolType {
        new_protocol_type(id, PROGRAM_TYPE_AGGREGATED_KEY, 0, dir.storage()).unwrap()
    }

    fn set_optional_keys<BC: BitcoinCoordinatorApi>(id: &Uuid, context: &ProgramContext<BC>) {
        context
            .globals
            .set_var(
                id,
                "optional_keys",
                VariableTypes::String("null".to_string()),
            )
            .unwrap();
    }

    #[test]
    fn test_setup_engine_creation() {
        let step_names = vec![
            SetupStepName::Keys,
            SetupStepName::Nonces,
            SetupStepName::Signatures,
        ];

        let engine = SetupEngine::new(step_names, 2).unwrap();

        assert_eq!(engine.total_steps(), 3);
        assert_eq!(engine.state().current_step_index, 0);
        assert_eq!(engine.state().current_step_state, StepState::Generating);
        assert!(!engine.is_complete());
        assert_eq!(engine.current_step_name(), "keys");
    }

    #[test]
    fn setup_engine_creation_rejects_empty_steps_or_participants() {
        assert!(SetupEngine::new(Vec::new(), 1).is_err());
        assert!(SetupEngine::new(vec![SetupStepName::Keys], 0).is_err());
    }

    #[test]
    fn test_step_state_transitions() {
        let mut engine =
            SetupEngine::new(vec![SetupStepName::Keys, SetupStepName::Nonces], 2).unwrap();

        assert_eq!(engine.state().current_step_state, StepState::Generating);
        assert_eq!(engine.state().current_step_index, 0);
        assert!(engine.state().participants_completed.is_empty());

        engine.state_mut().mark_participant_completed(0);
        assert!(engine.state().has_participant_completed(0));
        assert!(!engine.state().has_participant_completed(1));

        engine.state_mut().mark_participant_completed(1);
        assert!(engine.state().has_participant_completed(1));
        assert_eq!(engine.state().participants_completed.len(), 2);

        engine.advance_to_next_step();
        assert_eq!(engine.state().current_step_index, 1);
        assert_eq!(engine.state().current_step_state, StepState::Generating);
        assert!(engine.state().participants_completed.is_empty());
    }

    #[test]
    fn test_engine_completion() {
        let step_names = vec![SetupStepName::Keys];

        let mut engine = SetupEngine::new(step_names, 1).unwrap();
        assert!(!engine.is_complete());

        // Simulate completing and advancing past the final step
        engine.state_mut().current_step_state = StepState::Completed;
        engine.advance_to_next_step();
        assert!(engine.is_complete());
    }

    #[test]
    fn single_participant_tick_runs_keys_step_to_completion() {
        let mut env = TestProgramContextEnv::new("setup-engine-keys-lifecycle").unwrap();
        let dir = TestStorageDir::new("setup-engine-keys-protocol");
        let id = Uuid::new_v4();
        let mut protocol = aggregated_key_protocol(id, &dir);
        let participants = vec![env.self_address().unwrap()];
        let mut engine = SetupEngine::new(vec![SetupStepName::Keys], 1).unwrap();
        set_optional_keys(&id, &env.context);

        assert!(
            engine
                .tick(&mut protocol, &participants, 0, &id, 0, &mut env.context)
                .unwrap()
                .state_changed
        );
        assert_eq!(
            engine.state().current_step_state,
            StepState::AllParticipantsCompleted
        );
        assert_eq!(engine.state().participants_completed, vec![0]);

        assert!(
            engine
                .tick(&mut protocol, &participants, 0, &id, 0, &mut env.context)
                .unwrap()
                .state_changed
        );
        assert!(engine.is_complete());
        assert!(
            !engine
                .tick(&mut protocol, &participants, 0, &id, 0, &mut env.context)
                .unwrap()
                .state_changed
        );
        assert!(engine.if_not_completed().is_err());
    }

    #[test]
    fn receive_data_handles_unverified_and_duplicate_messages() {
        let mut env = TestProgramContextEnv::new_with_peers("setup-engine-receive", 1).unwrap();
        let dir = TestStorageDir::new("setup-engine-receive-protocol");
        let id = Uuid::new_v4();
        let protocol = aggregated_key_protocol(id, &dir);
        let own = env.self_address().unwrap();
        let peer = env.peer_address(0).unwrap();
        let participants = vec![own.clone(), peer.clone()];
        let mut engine = SetupEngine::new(vec![SetupStepName::Keys], 2).unwrap();
        let data = serde_json::to_value(ParticipantKeyDeclaration::empty()).unwrap();

        assert_eq!(
            engine
                .receive_current_step_data(
                    data.clone(),
                    CommsMessageType::PublicNonces,
                    0,
                    &peer,
                    &protocol,
                    &participants,
                    &mut env.context,
                )
                .unwrap(),
            MessageDisposition::RetryLater
        );
        assert_eq!(
            engine
                .receive_current_step_data(
                    data.clone(),
                    CommsMessageType::Keys,
                    0,
                    &peer,
                    &protocol,
                    &participants,
                    &mut env.context,
                )
                .unwrap(),
            MessageDisposition::Processed
        );
        assert_eq!(
            engine
                .receive_current_step_data(
                    data.clone(),
                    CommsMessageType::Keys,
                    0,
                    &peer,
                    &protocol,
                    &participants,
                    &mut env.context,
                )
                .unwrap(),
            MessageDisposition::RetryLater
        );

        engine.state_mut().mark_participant_completed(0);
        assert_eq!(
            engine
                .receive_current_step_data(
                    data,
                    CommsMessageType::Keys,
                    0,
                    &own,
                    &protocol,
                    &participants,
                    &mut env.context,
                )
                .unwrap(),
            MessageDisposition::Processed
        );
    }

    #[test]
    fn generation_and_advance_require_the_expected_states() {
        let mut env = TestProgramContextEnv::new("setup-engine-state-validation").unwrap();
        let dir = TestStorageDir::new("setup-engine-state-protocol");
        let id = Uuid::new_v4();
        let mut protocol = aggregated_key_protocol(id, &dir);
        let participants = vec![env.self_address().unwrap()];
        let mut engine = SetupEngine::new(vec![SetupStepName::Keys], 1).unwrap();
        set_optional_keys(&id, &env.context);

        assert!(!engine
            .try_advance_current_step(&protocol, &participants, &mut env.context)
            .unwrap());
        engine.state_mut().current_step_state = StepState::WaitingForParticipants;
        assert!(matches!(
            engine.generate_current_step_data(&mut protocol, &mut env.context),
            Err(BitVMXError::InvalidState(_))
        ));

        let waiting = engine
            .tick(&mut protocol, &participants, 0, &id, 0, &mut env.context)
            .unwrap();
        assert!(!waiting.state_changed);
        engine.state_mut().current_step_state = StepState::Completed;
        let completed = engine
            .tick(&mut protocol, &participants, 0, &id, 0, &mut env.context)
            .unwrap();
        assert!(!completed.state_changed);
    }

    #[test]
    fn dispatcher_result_requires_waiting_state_and_ignores_replays() {
        let mut env = TestProgramContextEnv::new("setup-engine-dispatcher-validation").unwrap();
        let participant = env.self_address().unwrap();
        let participants = vec![participant];
        let program_id = Uuid::new_v4();
        let context = Context::SetupStep(
            program_id,
            "garbler".to_string(),
            "generate".to_string(),
            CommsMessageType::GarbledCircuit,
        );
        let mut engine = SetupEngine::new(vec![SetupStepName::Garbler], 1).unwrap();

        let result = engine.receive_dispatcher_result(
            Value::Null,
            &context,
            0,
            &program_id,
            0,
            &participants,
            &mut env.context,
        );
        assert!(matches!(result, Err(BitVMXError::InvalidState(_))));

        engine.state_mut().current_step_state = StepState::WaitingForParticipants;
        engine.state_mut().mark_participant_completed(0);
        let result = engine.receive_dispatcher_result(
            Value::Null,
            &context,
            0,
            &program_id,
            0,
            &participants,
            &mut env.context,
        );
        assert_eq!(result.unwrap(), false);

        engine.state_mut().all_steps_completed = true;
        let result = engine.receive_dispatcher_result(
            Value::Null,
            &context,
            0,
            &program_id,
            0,
            &participants,
            &mut env.context,
        );
        assert_eq!(result.unwrap(), false);
    }

    #[test]
    fn restore_rejects_index_at_or_past_end() {
        let mut engine = SetupEngine::new(vec![SetupStepName::Keys], 1).unwrap();

        for index in [1, 2] {
            let mut saved_state = SetupEngineState::new();
            saved_state.current_step_index = index;

            assert!(engine.restore_state(saved_state).is_err());
            assert_eq!(engine.state(), &SetupEngineState::new());
        }
    }

    #[test]
    fn restore_rejects_completion_before_final_step() {
        let mut engine =
            SetupEngine::new(vec![SetupStepName::Keys, SetupStepName::Nonces], 1).unwrap();
        let mut saved_state = SetupEngineState::new();
        saved_state.all_steps_completed = true;
        saved_state.current_step_state = StepState::Completed;

        assert!(engine.restore_state(saved_state).is_err());
        assert_eq!(engine.state(), &SetupEngineState::new());
    }

    #[test]
    fn restore_rejects_completed_runtime_state_for_incomplete_setup() {
        let mut engine = SetupEngine::new(vec![SetupStepName::Keys], 1).unwrap();
        let mut saved_state = SetupEngineState::new();
        saved_state.current_step_state = StepState::Completed;

        assert!(engine.restore_state(saved_state).is_err());
        assert_eq!(engine.state(), &SetupEngineState::new());
    }

    #[test]
    fn restore_accepts_active_final_step_and_completed_setup() {
        let mut engine =
            SetupEngine::new(vec![SetupStepName::Keys, SetupStepName::Nonces], 1).unwrap();
        let mut active_final_step = SetupEngineState::new();
        active_final_step.current_step_index = 1;
        active_final_step.current_step_state = StepState::AllParticipantsCompleted;
        engine.restore_state(active_final_step.clone()).unwrap();
        assert_eq!(engine.state(), &active_final_step);

        let mut completed = active_final_step;
        completed.current_step_state = StepState::Completed;
        completed.all_steps_completed = true;
        engine.restore_state(completed.clone()).unwrap();
        assert_eq!(engine.state(), &completed);
    }
}
