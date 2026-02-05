use crate::{
    comms_helper::{prepare_message, request, CommsMessageType},
    errors::BitVMXError,
    leader_broadcast::{get_non_leader_participants, OriginalMessage},
    program::{participant::ParticipantData, protocols::protocol_handler::ProtocolType},
    types::ProgramContext,
};
use bitvmx_broker::identification::identifier::PubkHash as PubKeyHash;
use serde::{Deserialize, Serialize};
use tracing::{debug, info};
use uuid::Uuid;

use super::{SetupStep, steps::{SetupStepName, create_setup_step}};

/// Current state of a setup step in the engine.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum StepState {
    /// Step has not started yet
    Pending,
    /// Step is generating data
    Generating,
    /// Step has generated data and is waiting to send
    ReadyToSend,
    /// Step has sent data and is waiting for other participants
    WaitingForParticipants,
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
}

impl SetupEngineState {
    pub fn new() -> Self {
        Self {
            current_step_index: 0,
            current_step_state: StepState::Pending,
            participants_completed: Vec::new(),
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
        self.current_step_index += 1;
        self.current_step_state = StepState::Pending;
        self.participants_completed.clear();
    }
}

impl Default for SetupEngineState {
    fn default() -> Self {
        Self::new()
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
/// Pending → Generating → ReadyToSend → WaitingForParticipants → Completed
/// ```
///
/// Once a step is Completed, the engine advances to the next step.
pub struct SetupEngine {
    /// The steps to execute in order
    steps: Vec<Box<dyn SetupStep>>,
    /// Current state of the engine
    state: SetupEngineState,
}

impl SetupEngine {
    /// Creates a new SetupEngine with the given step names.
    ///
    /// Steps will be created from the names using the factory and executed in the order provided.
    pub fn new(step_names: Vec<SetupStepName>) -> Self {
        let steps: Vec<Box<dyn SetupStep>> = step_names
            .iter()
            .map(|name| create_setup_step(name))
            .collect();
        
        Self {
            steps,
            state: SetupEngineState::new(),
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
    pub fn current_step(&self) -> Option<&Box<dyn SetupStep>> {
        self.steps.get(self.state.current_step_index)
    }

    /// Returns the name of the current step.
    pub fn current_step_name(&self) -> Option<&str> {
        self.current_step().map(|step| step.step_name())
    }

    /// Returns true if all steps have been completed.
    pub fn is_complete(&self) -> bool {
        self.state.current_step_index >= self.steps.len()
    }

    /// Returns the total number of steps.
    pub fn total_steps(&self) -> usize {
        self.steps.len()
    }

    /// Generates data for the current step.
    ///
    /// This transitions the step from Pending → Generating → ReadyToSend.
    ///
    /// Returns the serialized data to send to other participants, or None if
    /// the step doesn't generate data.
    pub fn generate_current_step_data(
        &mut self,
        protocol: &mut ProtocolType,
        context: &mut ProgramContext,
    ) -> Result<Option<Vec<u8>>, BitVMXError> {
        if self.is_complete() {
            return Err(BitVMXError::InvalidMessage(
                "Setup is already complete".to_string(),
            ));
        }

        // Get step name first before any mutable borrows (copy to owned String)
        let step_name = self
            .current_step_name()
            .ok_or_else(|| BitVMXError::InvalidMessage("No current step available".to_string()))?
            .to_string();

        if self.state.current_step_state != StepState::Pending {
            return Err(BitVMXError::InvalidMessage(format!(
                "Step '{}' is not in Pending state (current: {:?})",
                step_name, self.state.current_step_state
            )));
        }

        info!(
            "SetupEngine: Generating data for step '{}' ({}/{})",
            step_name,
            self.state.current_step_index + 1,
            self.total_steps()
        );

        self.state.current_step_state = StepState::Generating;

        // Now get the step and generate data
        let step = &self.steps[self.state.current_step_index];
        let data = step.generate_data(protocol, context)?;

        self.state.current_step_state = StepState::ReadyToSend;

        debug!(
            "SetupEngine: Step '{}' generated {} bytes",
            step_name,
            data.as_ref().map(|d| d.len()).unwrap_or(0)
        );

        Ok(data)
    }

    /// Marks the current step as sent and transitions to WaitingForParticipants.
    pub fn mark_current_step_sent(&mut self) -> Result<(), BitVMXError> {
        if self.state.current_step_state != StepState::ReadyToSend {
            return Err(BitVMXError::InvalidMessage(format!(
                "Cannot mark as sent: step is not in ReadyToSend state (current: {:?})",
                self.state.current_step_state
            )));
        }

        let step_name = self.current_step_name().unwrap_or("unknown");
        debug!("SetupEngine: Step '{}' data sent", step_name);

        self.state.current_step_state = StepState::WaitingForParticipants;

        Ok(())
    }

    /// Receives and verifies data from a participant for the current step.
    ///
    /// This marks the participant as completed for this step.
    pub fn receive_current_step_data(
        &mut self,
        data: &[u8],
        from_participant: &ParticipantData,
        protocol: &ProtocolType,
        participants: &[ParticipantData],
        context: &mut ProgramContext,
    ) -> Result<(), BitVMXError> {
        if self.is_complete() {
            return Err(BitVMXError::InvalidMessage(
                "Setup is already complete".to_string(),
            ));
        }

        // Allow receiving data if we're in ReadyToSend (we've generated our data but haven't sent yet)
        // or WaitingForParticipants (we've sent our data and are waiting for others)
        // This handles the case where messages arrive in any order
        if self.state.current_step_state != StepState::WaitingForParticipants 
            && self.state.current_step_state != StepState::ReadyToSend {
            return Err(BitVMXError::InvalidMessage(format!(
                "Cannot receive data: step is not ready to receive (current: {:?}). Must be ReadyToSend or WaitingForParticipants",
                self.state.current_step_state
            )));
        }
        
        // If we're in ReadyToSend, transition to WaitingForParticipants when we receive the first message
        // This handles the case where we receive a message before sending our own
        if self.state.current_step_state == StepState::ReadyToSend {
            info!(
                "SetupEngine::receive_current_step_data() - Received message while in ReadyToSend, transitioning to WaitingForParticipants"
            );
            self.state.current_step_state = StepState::WaitingForParticipants;
        }

        let step_name = self
            .current_step_name()
            .ok_or_else(|| BitVMXError::InvalidMessage("No current step available".to_string()))?
            .to_string(); // Copy to owned String to avoid borrow issues

        // Find participant index
        let participant_idx = participants
            .iter()
            .position(|p| p.comms_address.pubkey_hash == from_participant.comms_address.pubkey_hash)
            .ok_or_else(|| {
                BitVMXError::InvalidMessage(format!(
                    "Unknown participant: {}",
                    from_participant.comms_address.pubkey_hash
                ))
            })?;

        // Check if already received
        if self.state.has_participant_completed(participant_idx) {
            debug!(
                "SetupEngine: Already received data from participant {} for step '{}'",
                participant_idx, step_name
            );
            return Ok(());
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

        info!(
            "SetupEngine::receive_current_step_data() - Step '{}': {}/{} participants completed (participant {} just completed)",
            step_name,
            self.state.participants_completed.len(),
            participants.len(),
            participant_idx
        );

        Ok(())
    }

    /// Checks if the current step can advance to the next step.
    ///
    /// If the step can advance, it transitions to Completed and prepares for
    /// the next step.
    ///
    /// Returns true if the step advanced, false if still waiting.
    pub fn try_advance_current_step(
        &mut self,
        protocol: &ProtocolType,
        participants: &[ParticipantData],
        context: &mut ProgramContext,
    ) -> Result<bool, BitVMXError> {
        if self.is_complete() {
            return Ok(false);
        }

        if self.state.current_step_state != StepState::WaitingForParticipants {
            return Ok(false);
        }

        let step_name = self
            .current_step_name()
            .ok_or_else(|| BitVMXError::InvalidMessage("No current step available".to_string()))?
            .to_string(); // Copy to owned String

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
            let next_step_name = self.current_step_name().unwrap_or("unknown");
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
    /// Uses `CommsMessageType::SetupStepData` which is a generic message type for
    /// any SetupEngine step data. The actual step type (keys, nonces, signatures, etc.)
    /// is determined by the SetupEngine's current step, not by the message type.
    ///
    /// Leader broadcast pattern:
    /// - Non-leaders send their data only to the leader
    /// - Leader stores its own data + collects data from non-leaders
    /// - When all data is received, leader broadcasts to all non-leaders
    pub fn broadcast_setup_data(
        &self,
        data: Vec<u8>,
        program_id: &Uuid,
        my_idx: usize,
        leader: usize,
        participants: &[ParticipantData],
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
            context
                .leader_broadcast_helper
                .store_original_message(program_id, CommsMessageType::SetupStepData, original_msg)?;
        } else {
            // Non-leader: Send only to leader
            let leader_address = &participants[leader].comms_address;

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
        participants: &[ParticipantData],
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
            info!(
                "SetupEngine::receive_setup_data() - Setup already complete, ignoring message from {}",
                from
            );
            return Ok(false);
        }

        // Find the participant
        let from_participant = participants
            .iter()
            .find(|p| &p.comms_address.pubkey_hash == from)
            .ok_or_else(|| {
                BitVMXError::InvalidMessage(format!("Unknown participant: {}", from))
            })?
            .clone();

        let step_name = self.current_step_name().unwrap_or("unknown").to_string();
        let participants_completed_before = self.state.participants_completed.len();
        
        info!(
            "SetupEngine::receive_setup_data() - Processing data for step '{}' (completed before: {}/{})",
            step_name,
            participants_completed_before,
            participants.len()
        );
        
        // Receive and verify the data
        self.receive_current_step_data(
            data,
            &from_participant,
            protocol,
            participants,
            context,
        )?;

        let participants_completed_after = self.state.participants_completed.len();
        info!(
            "SetupEngine::receive_setup_data() - After processing: {}/{} participants completed",
            participants_completed_after,
            participants.len()
        );

        // Leader broadcast: If I'm the leader and have all messages, broadcast to non-leaders
        if my_idx == leader {
            // Get list of all participant pubkey hashes (including leader)
            let all_participant_hashes: Vec<_> = participants
                .iter()
                .map(|p| p.comms_address.pubkey_hash.clone())
                .collect();

            // Check if we have all messages
            let has_all = context
                .leader_broadcast_helper
                .has_all_expected_messages(
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
                let non_leaders = get_non_leader_participants(
                    &participants.iter().map(|p| p.comms_address.clone()).collect::<Vec<_>>(),
                    &my_pubkey_hash,
                );

                // Broadcast to all non-leaders
                context
                    .leader_broadcast_helper
                    .broadcast_to_non_leaders(
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

        // Try to advance after receiving data
        let engine_state_before_advance = self.state.current_step_state.clone();
        let participants_completed_count = self.state.participants_completed.len();
        let total_participants = participants.len();
        
        info!(
            "SetupEngine::receive_setup_data() - Attempting to advance step '{}' (state: {:?}, completed: {}/{})",
            step_name,
            engine_state_before_advance,
            participants_completed_count,
            total_participants
        );
        
        let advanced = self.try_advance_current_step(protocol, participants, context)?;
        if advanced {
            info!(
                "SetupEngine::receive_setup_data() - Step '{}' advanced after receiving data",
                step_name
            );
        } else {
            info!(
                "SetupEngine::receive_setup_data() - Step '{}' could not advance (state: {:?}, completed: {}/{})",
                step_name,
                engine_state_before_advance,
                self.state.participants_completed.len(),
                participants.len()
            );
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
        participants: &[ParticipantData],
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
        let step_name = self.current_step_name().unwrap_or("unknown").to_string();
        let current_state = self.state.current_step_state.clone();
        let participants_completed = self.state.participants_completed.len();
        let total_participants = participants.len();
        
        // If we're waiting for participants and haven't received all data yet,
        // there's nothing to do - early return to avoid unnecessary processing
        if self.state.current_step_state == StepState::WaitingForParticipants {
            // Check if we can advance (this will return false if not all participants have sent data)
            let can_advance = self.current_step()
                .map(|step| {
                    step.can_advance(protocol, participants, context)
                        .unwrap_or(false)
                })
                .unwrap_or(false);
            
            if !can_advance {
                // Still waiting for data from other participants - no changes, no need to save
                debug!(
                    "SetupEngine::tick() - Step '{}' ({}/{}), state: {:?}, completed: {}/{} - Waiting for participants, early return",
                    step_name,
                    self.state.current_step_index + 1,
                    self.total_steps(),
                    current_state,
                    participants_completed,
                    total_participants
                );
                return Ok(SetupTickResult {
                    data_to_send: None,
                    state_changed: false,
                });
            } else {
                info!(
                    "SetupEngine::tick() - Step '{}' ({}/{}), state: {:?}, completed: {}/{} - Can advance!",
                    step_name,
                    self.state.current_step_index + 1,
                    self.total_steps(),
                    current_state,
                    participants_completed,
                    total_participants
                );
            }
        } else {
            info!(
                "SetupEngine::tick() - Step '{}' ({}/{}), state: {:?}, completed: {}/{}",
                step_name,
                self.state.current_step_index + 1,
                self.total_steps(),
                current_state,
                participants_completed,
                total_participants
            );
        }
        
        // Save engine state before tick to detect changes
        let engine_state_before = self.state.clone();
        
        // Process the tick based on current state
        let mut data_to_send = None;
        let mut state_changed = false;

        match self.state.current_step_state {
            StepState::Pending => {
                info!("SetupEngine::tick() - Step '{}' is Pending, generating data", step_name);
                // Generate data for this step
                let data = self.generate_current_step_data(protocol, context)?;
                if let Some(ref d) = data {
                    info!("SetupEngine::tick() - Generated {} bytes for step '{}'", d.len(), step_name);

                    // IMPORTANT: Store our own data in globals BEFORE sending to others
                    // The step's can_advance() method checks that ALL participants' data exists in globals
                    if let Some(step) = self.current_step() {
                        let my_participant = &participants[my_idx];
                        step.verify_received(d, my_participant, protocol, participants, context)?;
                        info!(
                            "SetupEngine::tick() - Stored our own data (participant {}) in globals for step '{}'",
                            my_idx,
                            step_name
                        );
                    }

                    data_to_send = Some(d.clone());
                } else {
                    info!("SetupEngine::tick() - Step '{}' generated no data", step_name);
                }
                state_changed = true;
            }
            StepState::Generating => {
                // Recovery: If we crashed while generating, reset to Pending and re-generate
                info!(
                    "SetupEngine::tick() - Step '{}' stuck in Generating state, resetting to Pending for recovery",
                    step_name
                );
                self.state.current_step_state = StepState::Pending;
                state_changed = true;
                // Next tick will generate the data
            }
            StepState::ReadyToSend => {
                // Recovery: Data was generated but not sent. Since we may have lost the generated
                // data after a crash, reset to Pending to re-generate and re-send.
                info!(
                    "SetupEngine::tick() - Step '{}' stuck in ReadyToSend state, resetting to Pending for recovery",
                    step_name
                );
                self.state.current_step_state = StepState::Pending;
                state_changed = true;
                // Next tick will re-generate the data
            }
            StepState::WaitingForParticipants => {
                debug!(
                    "SetupEngine::tick() - Step '{}' is WaitingForParticipants (completed: {}/{}), trying to advance",
                    step_name,
                    self.state.participants_completed.len(),
                    participants.len()
                );
                // Try to advance if possible
                let advanced = self.try_advance_current_step(protocol, participants, context)?;
                if advanced {
                    info!("SetupEngine::tick() - Step '{}' advanced successfully", step_name);
                    state_changed = true;
                }
            }
            StepState::Completed => {
                // Recovery: Step completed but didn't advance (crash between completing and advancing)
                // Advance to the next step now
                info!(
                    "SetupEngine::tick() - Step '{}' stuck in Completed state, advancing to next step for recovery",
                    step_name
                );
                self.state.advance_to_next_step();
                state_changed = true;

                if self.is_complete() {
                    info!("SetupEngine::tick() - All steps completed after recovery!");
                } else {
                    let next_step_name = self.current_step_name().unwrap_or("unknown");
                    info!(
                        "SetupEngine::tick() - Advanced to step '{}' ({}/{}) after recovery",
                        next_step_name,
                        self.state.current_step_index + 1,
                        self.total_steps()
                    );
                }
            }
        }

        // Check if engine state changed
        let engine_state_after = self.state.clone();
        if engine_state_before != engine_state_after {
            info!(
                "SetupEngine::tick() - State changed - before: {:?}, after: {:?}",
                engine_state_before.current_step_state,
                engine_state_after.current_step_state
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

            // Mark as sent and mark ourselves as completed
            self.mark_current_step_sent()?;
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
        assert_eq!(engine.state().current_step_state, StepState::Pending);
        assert!(!engine.is_complete());
        assert_eq!(engine.current_step_name(), Some("keys"));
    }

    #[test]
    fn test_step_state_transitions() {
        let mut state = SetupEngineState::new();

        assert_eq!(state.current_step_state, StepState::Pending);
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
        assert_eq!(state.current_step_state, StepState::Pending);
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
        assert_eq!(engine.current_step_name(), None);
    }

    #[test]
    fn test_mark_current_step_sent() {
        let step_names = vec![SetupStepName::Keys];
        let mut engine = SetupEngine::new(step_names);

        // Cannot mark as sent when in Pending state
        let result = engine.mark_current_step_sent();
        assert!(result.is_err());

        // Change to ReadyToSend
        engine.state_mut().current_step_state = StepState::ReadyToSend;
        let result = engine.mark_current_step_sent();
        assert!(result.is_ok());
        assert_eq!(
            engine.state().current_step_state,
            StepState::WaitingForParticipants
        );
    }
}
