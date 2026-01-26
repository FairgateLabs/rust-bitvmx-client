use crate::{
    errors::BitVMXError,
    program::{participant::ParticipantData, protocols::protocol_handler::ProtocolType},
    types::ProgramContext,
};
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

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

    /// Returns a mutable reference to the state.
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

    /// Processes the setup tick.
    ///
    /// This is the main entry point for driving the setup forward. It should
    /// be called periodically to:
    /// 1. Generate data for pending steps
    /// 2. Check if steps can advance
    ///
    /// Returns the data to send (if any) for the current step.
    pub fn tick(
        &mut self,
        protocol: &mut ProtocolType,
        participants: &[ParticipantData],
        context: &mut ProgramContext,
    ) -> Result<Option<Vec<u8>>, BitVMXError> {
        if self.is_complete() {
            debug!("SetupEngine::tick() - Setup already complete");
            return Ok(None);
        }

        // Clone step name to owned String before any mutable borrows
        let step_name = self.current_step_name().unwrap_or("unknown").to_string();
        let current_state = self.state.current_step_state.clone();
        
        debug!(
            "SetupEngine::tick() - Step '{}' ({}/{}), state: {:?}, completed: {}/{}",
            step_name,
            self.state.current_step_index + 1,
            self.total_steps(),
            current_state,
            self.state.participants_completed.len(),
            participants.len()
        );

        match self.state.current_step_state {
            StepState::Pending => {
                info!("SetupEngine::tick() - Step '{}' is Pending, generating data", step_name);
                // Generate data for this step
                let data = self.generate_current_step_data(protocol, context)?;
                if let Some(ref d) = data {
                    info!("SetupEngine::tick() - Generated {} bytes for step '{}'", d.len(), step_name);
                } else {
                    info!("SetupEngine::tick() - Step '{}' generated no data", step_name);
                }
                Ok(data)
            }
            StepState::ReadyToSend => {
                debug!("SetupEngine::tick() - Step '{}' is ReadyToSend, waiting for send", step_name);
                // Data is ready but hasn't been sent yet
                // The caller should send it and call mark_current_step_sent()
                Ok(None)
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
                }
                Ok(None)
            }
            _ => {
                debug!("SetupEngine::tick() - Step '{}' in state {:?}, no action", step_name, current_state);
                Ok(None)
            }
        }
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
