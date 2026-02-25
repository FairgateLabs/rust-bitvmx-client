use crate::{
    comms_helper::{prepare_message, request, CommsMessageType},
    errors::BitVMXError,
    leader_broadcast::{get_non_leader_participants, OriginalMessage},
    program::{
        participant::{get_comms_address_by_pubkey_hash, get_index_by_pubkey_hash, CommsAddress},
        protocols::protocol_handler::ProtocolType,
    },
    types::ProgramContext,
};
use bitvmx_broker::identification::identifier::PubkHash as PubKeyHash;
use serde::{Deserialize, Serialize};
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
    /// Total number of steps (for validation during restore)
    pub total_steps: usize,
}

impl SetupEngineState {
    pub fn new(total_steps: usize) -> Self {
        Self {
            current_step_index: 0,
            current_step_state: StepState::Generating,
            participants_completed: Vec::new(),
            all_steps_completed: false,
            total_steps,
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

    /// Reset state for next step
    pub fn advance_to_next_step(&mut self) {
        if self.current_step_index < self.total_steps - 1 {
            self.current_step_index += 1;
            self.current_step_state = StepState::Generating;
            self.participants_completed.clear();
        } else {
            self.all_steps_completed = true;
        }
    }
}

/// Result of a SetupEngine tick operation.
#[derive(Debug)]
pub struct SetupTickResult {
    /// Data to send to other participants (if any)
    pub data_to_send: Option<Vec<u8>>,
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
/// Generating → WaitingForParticipants → Completed
/// ```
///
/// Once a step is Completed, the engine advances to the next step.
pub struct SetupEngine {
    /// The steps to execute in order
    steps: Vec<SetupStepEnum>,
    /// Current state of the engine
    state: SetupEngineState,
}

impl SetupEngine {
    /// Creates a new SetupEngine with the given step names.
    ///
    /// Steps will be created from the names using the factory and executed in the order provided.
    pub fn new(step_names: Vec<SetupStepName>) -> Self {
        let steps: Vec<SetupStepEnum> = step_names
            .iter()
            .map(|name| create_setup_step(name))
            .collect();

        Self {
            steps,
            state: SetupEngineState::new(step_names.len()),
        }
    }

    /// Returns the current state of the engine.
    pub fn state(&self) -> &SetupEngineState {
        &self.state
    }

    /// Restores engine state from a saved state (used during load).
    /// Validates that step index is within bounds.
    pub fn restore_state(&mut self, saved_state: SetupEngineState) -> Result<(), BitVMXError> {
        // Validate step index is within bounds (or equal to len for completed state)
        if saved_state.current_step_index > self.steps.len() {
            return Err(BitVMXError::InvalidMessage(format!(
                "Invalid step index {} for engine with {} steps",
                saved_state.current_step_index,
                self.steps.len()
            )));
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
    fn current_step_name(&self) -> &str {
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
    fn generate_current_step_data(
        &mut self,
        protocol: &mut ProtocolType,
        context: &mut ProgramContext,
        total_participants: usize,
    ) -> Result<Option<Vec<u8>>, BitVMXError> {
        self.if_not_completed()?;

        // Get step name first before any mutable borrows (copy to owned String)
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
            self.state.total_steps,
            self.state.participants_completed.len(),
            total_participants
        );

        // Now get the step and generate data
        let step = &self.steps[self.state.current_step_index];
        let data = step.generate_data(protocol, context)?;
        //TODO: for steps that generate data asyn, instead of moving to waiting, move to a new state "WaitingGeneration"
        //that will be handled with another external call and would allow the transition

        if total_participants == 1
            || self.state.participants_completed.len() == total_participants - 1
        {
            self.state.current_step_state = StepState::AllParticipantsCompleted;
        } else {
            self.state.current_step_state = StepState::WaitingForParticipants;
        }

        debug!(
            "SetupEngine: Step '{}' generated {} bytes",
            step_name,
            data.as_ref().map(|d| d.len()).unwrap_or(0)
        );

        Ok(data)
    }

    /// Receives and verifies data from a participant for the current step.
    ///
    /// This marks the participant as completed for this step.
    fn receive_current_step_data(
        &mut self,
        data: &[u8],
        my_idx: usize,
        from_participant: &CommsAddress,
        protocol: &ProtocolType,
        participants: &[CommsAddress],
        context: &mut ProgramContext,
    ) -> Result<bool, BitVMXError> {
        self.if_not_completed()?;

        let step_name = self.current_step_name().to_string(); // Copy to owned String to avoid borrow issues

        // Find participant index
        let participant_idx =
            get_index_by_pubkey_hash(participants, &from_participant.pubkey_hash)?;

        // Check if already received
        if self.state.has_participant_completed(participant_idx) {
            if participant_idx == my_idx {
                warn!("Getting data from ourselves again for step '{}', ignoring since we already processed it.", step_name);
                return Ok(true);
            }

            info!(
                "SetupEngine: Already received data from participant {} for step '{}'",
                participant_idx, step_name
            );
            return Ok(false);
        }

        debug!(
            "SetupEngine: Receiving data from participant {} for step '{}'",
            participant_idx, step_name
        );

        // Verify and store the data
        let step = &self.steps[self.state.current_step_index];
        step.verify_received(data, from_participant, protocol, participants, context)?;

        // Mark participant as completed
        self.state.mark_participant_completed(participant_idx);

        if self.state.participants_completed.len() == participants.len() {
            self.state.current_step_state = StepState::AllParticipantsCompleted;
        }

        info!(
            "SetupEngine::receive_current_step_data() - Step '{}': {}/{} participants completed (participant {} just completed) {:?}",
            step_name,
            self.state.participants_completed.len(),
            participants.len(),
            participant_idx,
            self.state.current_step_state
        );

        Ok(true)
    }

    /// Checks if the current step can advance to the next step.
    ///
    /// If the step can advance, it transitions to Completed and prepares for
    /// the next step.
    ///
    /// Returns true if the step advanced, false if still waiting.
    fn try_advance_current_step(
        &mut self,
        protocol: &ProtocolType,
        participants: &[CommsAddress],
        context: &mut ProgramContext,
    ) -> Result<bool, BitVMXError> {
        self.if_not_completed()?;

        if self.state.current_step_state != StepState::AllParticipantsCompleted {
            return Ok(false);
        }

        let step_name = self.current_step_name().to_string(); // Copy to owned String

        // Check if we can advance
        let step = &self.steps[self.state.current_step_index];
        let can_advance = step.can_advance(protocol, participants, context)?;

        if !can_advance {
            debug!(
                "SetupEngine::try_advance_current_step() - Step '{}' cannot advance yet ({}/{} participants completed)",
                step_name,
                self.state.participants_completed.len(),
                participants.len()
            );
            return Ok(false);
        }

        info!(
            "SetupEngine::try_advance_current_step() - Step '{}' can advance! ({}/{} participants completed)",
            step_name,
            self.state.participants_completed.len(),
            participants.len()
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
        self.state.advance_to_next_step();

        if self.is_complete() {
            info!("SetupEngine: All steps completed!");
        } else {
            let next_step_name = self.current_step_name();
            info!(
                "SetupEngine: Advanced to step '{}' ({}/{})",
                next_step_name,
                self.state.current_step_index + 1,
                self.state.total_steps
            );
        }

        Ok(true)
    }

    /// Broadcasts setup data using leader broadcast pattern.
    ///
    /// Uses `CommsMessageType::SetupStepData` which is a generic message type for
    /// any SetupEngine step data. The actual step type (keys, nonces, signatures, etc.)
    /// is determined by the SetupEngine's current step, not by the message type.
    ///
    /// Leader broadcast pattern:
    /// - Non-leaders send their data only to the leader
    /// - Leader stores its own data + collects data from non-leaders
    /// - When all data is received, leader broadcasts to all non-leaders
    fn broadcast_setup_data(
        &self,
        data: Vec<u8>,
        program_id: &Uuid,
        my_idx: usize,
        leader: usize,
        participants: &[CommsAddress],
        context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        let is_leader = my_idx == leader;

        if is_leader {
            // Leader: Store own message for later broadcast
            info!(
                "SetupEngine::broadcast_setup_data() - Leader storing own {} bytes",
                data.len()
            );

            // Prepare the message (serialize + sign)
            let (version, data_value, timestamp, signature) = prepare_message(
                &context.key_chain,
                program_id,
                CommsMessageType::SetupStepData,
                data,
            )?;

            // Create OriginalMessage
            let original_msg = OriginalMessage {
                sender_pubkey_hash: context.comms.get_pubk_hash()?,
                msg_type: CommsMessageType::SetupStepData,
                data: data_value,
                original_timestamp: timestamp,
                original_signature: signature,
                version,
            };

            // Store leader's own message
            context.leader_broadcast_helper.store_original_message(
                program_id,
                CommsMessageType::SetupStepData,
                original_msg,
            )?;
        } else {
            // Non-leader: Send only to leader
            let leader_address = &participants[leader];

            info!(
                "SetupEngine::broadcast_setup_data() - Non-leader sending {} bytes to leader {}",
                data.len(),
                leader_address.pubkey_hash
            );

            request(
                &context.comms,
                &context.key_chain,
                program_id,
                leader_address.clone(),
                CommsMessageType::SetupStepData,
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
    /// Returns whether the engine state changed.
    pub fn receive_setup_data(
        &mut self,
        data: &[u8],
        from: &PubKeyHash,
        program_id: &Uuid,
        my_idx: usize,
        leader: usize,
        participants: &[CommsAddress],
        protocol: &ProtocolType,
        context: &mut ProgramContext,
    ) -> Result<bool, BitVMXError> {
        info!(
            "SetupEngine::receive_setup_data() - Received {} bytes from participant {}",
            data.len(),
            from
        );

        // Check if setup is already complete - if so, ignore the message
        // This can happen when a non-leader receives the broadcast containing their own message
        if self.is_complete() {
            warn!(
                "SetupEngine::receive_setup_data() - Setup already complete, ignoring message from {}",
                from
            );
            return Ok(false);
        }

        // Find the participant
        let from_participant = get_comms_address_by_pubkey_hash(participants, from)?;

        let step_name = self.current_step_name().to_string();
        let participants_completed_before = self.state.participants_completed.len();

        info!(
            "SetupEngine::receive_setup_data() - Processing data for step '{}' (completed before: {}/{})",
            step_name,
            participants_completed_before,
            participants.len()
        );

        // Receive and verify the data
        if !self.receive_current_step_data(
            data,
            my_idx,
            &from_participant,
            protocol,
            participants,
            context,
        )? {
            debug!(
                "SetupEngine::receive_setup_data() - Data from participant {} did not change state for step '{}'",
                from, step_name
            );
            return Ok(false);
        }

        let participants_completed_after = self.state.participants_completed.len();
        info!(
            "SetupEngine::receive_setup_data() - After processing: {}/{} participants completed",
            participants_completed_after,
            participants.len()
        );

        // Leader broadcast: If I'm the leader and have all messages, broadcast to non-leaders
        if my_idx == leader {
            // Get list of all participant pubkey hashes (including leader)
            let all_participant_hashes: Vec<_> =
                participants.iter().map(|p| p.pubkey_hash.clone()).collect();

            // Check if we have all messages
            let has_all = context.leader_broadcast_helper.has_all_expected_messages(
                program_id,
                CommsMessageType::SetupStepData,
                &all_participant_hashes,
            )?;

            if has_all {
                info!(
                    "SetupEngine::receive_setup_data() - Leader has all messages, broadcasting to non-leaders"
                );

                // Get non-leader participants
                let my_pubkey_hash = context.comms.get_pubk_hash()?;
                let non_leaders = get_non_leader_participants(participants, &my_pubkey_hash);

                // Broadcast to all non-leaders
                context.leader_broadcast_helper.broadcast_to_non_leaders(
                    context,
                    program_id,
                    CommsMessageType::SetupStepData,
                    &non_leaders,
                )?;

                info!(
                    "SetupEngine::receive_setup_data() - Leader successfully broadcasted messages to {} non-leaders",
                    non_leaders.len()
                );
            }
        }

        // Receiving data always changes the engine state
        Ok(true)
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
    pub fn tick(
        &mut self,
        protocol: &mut ProtocolType,
        participants: &[CommsAddress],
        my_idx: usize,
        program_id: &Uuid,
        leader: usize,
        context: &mut ProgramContext,
    ) -> Result<SetupTickResult, BitVMXError> {
        if self.is_complete() {
            debug!("SetupEngine::tick() - Setup already complete");
            return Ok(SetupTickResult {
                data_to_send: None,
                state_changed: false,
            });
        }

        // Clone step name to owned String before any mutable borrows
        let step_name = self.current_step_name().to_string();

        // Save engine state before tick to detect changes
        let engine_state_before = self.state.clone();

        // Process the tick based on current state
        let mut data_to_send = None;
        let mut state_changed = false;

        match self.state.current_step_state {
            StepState::Generating => {
                info!(
                    "SetupEngine::tick() - Step '{}' is Generating, generating data",
                    step_name
                );
                // Generate data for this step
                let data =
                    self.generate_current_step_data(protocol, context, participants.len())?;
                if let Some(ref d) = data {
                    info!(
                        "SetupEngine::tick() - Generated {} bytes for step '{}'",
                        d.len(),
                        step_name
                    );

                    // IMPORTANT: Store our own data in globals BEFORE sending to others
                    // The step's can_advance() method checks that ALL participants' data exists in globals
                    let my_participant = &participants[my_idx];
                    self.current_step().verify_received(
                        d,
                        my_participant,
                        protocol,
                        participants,
                        context,
                    )?;
                    info!(
                            "SetupEngine::tick() - Stored our own data (participant {}) in globals for step '{}'",
                            my_idx,
                            step_name
                        );

                    data_to_send = Some(d.clone());
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
                    participants.len()
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
        if let Some(data) = &data_to_send {
            info!(
                "SetupEngine::tick() - Broadcasting {} bytes for step '{}' to {} participants",
                data.len(),
                step_name,
                participants.len() - 1
            );

            // Broadcast the data
            self.broadcast_setup_data(
                data.clone(),
                program_id,
                my_idx,
                leader,
                participants,
                context,
            )?;

            self.state.mark_participant_completed(my_idx);
            info!(
                "SetupEngine::tick() - Marked ourselves (participant {}) as completed for step '{}'",
                my_idx,
                step_name
            );
            state_changed = true;
        }

        Ok(SetupTickResult {
            data_to_send,
            state_changed,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_setup_engine_creation() {
        let step_names = vec![
            SetupStepName::Keys,
            SetupStepName::Nonces,
            SetupStepName::Signatures,
        ];

        let engine = SetupEngine::new(step_names);

        assert_eq!(engine.total_steps(), 3);
        assert_eq!(engine.state().current_step_index, 0);
        assert_eq!(engine.state().current_step_state, StepState::Generating);
        assert!(!engine.is_complete());
        assert_eq!(engine.current_step_name(), "keys");
    }

    #[test]
    fn test_step_state_transitions() {
        let mut state = SetupEngineState::new(2);

        assert_eq!(state.current_step_state, StepState::Generating);
        assert_eq!(state.current_step_index, 0);
        assert!(state.participants_completed.is_empty());

        state.mark_participant_completed(0);
        assert!(state.has_participant_completed(0));
        assert!(!state.has_participant_completed(1));

        state.mark_participant_completed(1);
        assert!(state.has_participant_completed(1));
        assert_eq!(state.participants_completed.len(), 2);

        state.advance_to_next_step();
        assert_eq!(state.current_step_index, 1);
        assert_eq!(state.current_step_state, StepState::Generating);
        assert!(state.participants_completed.is_empty());
    }

    #[test]
    fn test_engine_completion() {
        let step_names = vec![SetupStepName::Keys];

        let mut engine = SetupEngine::new(step_names);
        assert!(!engine.is_complete());

        // Simulate advancing past all steps
        engine.state_mut().advance_to_next_step();
        assert!(engine.is_complete());
    }
}
