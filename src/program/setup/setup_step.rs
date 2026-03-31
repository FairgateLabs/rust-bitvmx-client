use enum_dispatch::enum_dispatch;

use crate::{
    errors::BitVMXError,
    program::{participant::CommsAddress, protocols::protocol_handler::ProtocolType},
    types::ProgramContext,
};

/// Trait that defines a generic step of a protocol setup.
///
/// Each step manages its own lifecycle in 4 phases:
/// 1. **Generate**: Generate own data (stores in `context.globals`)
/// 2. **Exchange**: Exchange with participants (handled by `Program`)
/// 3. **Verify**: Verify received data (validates and stores in `context.globals`)
/// 4. **Advance**: Verify if it can advance to the next step
///
/// ## Storage conventions in globals:
///
/// - My data: `"my_{step_name}"`
/// - Participant i data: `"participant_{i}_{step_name}"`
/// - Aggregates: `"all_{step_name}"`
#[enum_dispatch]
pub trait SetupStep {
    /// Identifying name of the step (e.g.: "keys", "nonces", "signatures", "proof")
    fn step_name(&self) -> &str;

    /// **GENERATE** data to send.
    ///
    /// Returns serialized bytes or `None` if this step does not generate data.
    ///
    /// **IMPORTANT**: Must store the generated data in `context.globals`
    /// using the convention `"my_{step_name}"` for later use.
    fn generate_data(
        &self,
        protocol: &mut ProtocolType,
        context: &mut ProgramContext,
    ) -> Result<Option<Vec<u8>>, BitVMXError>;

    /// **VERIFY** and store data received from a participant.
    ///
    /// **IMPORTANT**: Must store the verified data in `context.globals`
    /// using the convention `"participant_{idx}_{step_name}"`.
    fn verify_received(
        &self,
        data: &[u8],
        from_participant: &CommsAddress,
        protocol: &ProtocolType,
        participants: &[CommsAddress],
        context: &mut ProgramContext,
    ) -> Result<(), BitVMXError>;

    /// **VERIFY ADVANCE** - Verifies if all participants have completed this step.
    ///
    /// Typically, verifies that variables exist in `context.globals` for all participants.
    fn can_advance(
        &self,
        protocol: &ProtocolType,
        participants: &[CommsAddress],
        context: &ProgramContext,
    ) -> Result<bool, BitVMXError>;

    /// **Optional hook**: Called when the step completes successfully.
    ///
    /// Can be used for:
    /// - Computing aggregates (e.g.: sum all keys in MuSig2)
    /// - Storing final data in `"all_{step_name}"`
    /// - Completion logging
    ///
    /// Default: does nothing.
    fn on_step_complete(
        &self,
        _protocol: &ProtocolType,
        _participants: &[CommsAddress],
        _context: &mut ProgramContext,
    ) -> Result<(), BitVMXError> {
        Ok(())
    }

    /// Returns true if this step generates data asynchronously.
    ///
    /// Async steps work differently from sync steps:
    /// - `generate_data()` initiates the async operation (e.g., sends a job to a dispatcher)
    ///   and returns `None`
    /// - The engine transitions to `WaitingGeneration` instead of `WaitingForParticipants`
    /// - When the async result arrives, `receive_generation_result()` is called
    /// - The engine then transitions to `WaitingForParticipants` and broadcasts the data
    ///
    /// Default: false (synchronous step).
    fn is_async(&self) -> bool {
        false
    }

    /// Called when an async generation result arrives from an external source.
    ///
    /// Only relevant for async steps (`is_async() == true`).
    /// Should process the result and return the data to broadcast to other participants.
    ///
    /// Default: returns error (not an async step).
    fn receive_generation_result(
        &self,
        _result: &[u8],
        _protocol: &mut ProtocolType,
        _context: &mut ProgramContext,
    ) -> Result<Option<Vec<u8>>, BitVMXError> {
        Err(BitVMXError::InvalidMessage(
            "receive_generation_result called on a non-async step".to_string(),
        ))
    }

    /// Send a verification job to the dispatcher with all participants' data.
    ///
    /// Only relevant for async steps (`is_async() == true`).
    /// Called after all participants' data has been received (`AllParticipantsCompleted`).
    /// The engine transitions to `WaitingVerification` after this call.
    ///
    /// Default: returns error (not an async step).
    fn send_verification_job(
        &self,
        _protocol: &ProtocolType,
        _participants: &[CommsAddress],
        _context: &mut ProgramContext,
    ) -> Result<(), BitVMXError> {
        Err(BitVMXError::InvalidMessage(
            "send_verification_job called on a non-async step".to_string(),
        ))
    }

    /// Called when an async verification result arrives from the dispatcher.
    ///
    /// Only relevant for async steps (`is_async() == true`).
    /// Should return `Ok(())` if verification passed, or an error if it failed.
    ///
    /// Default: returns error (not an async step).
    fn receive_verification_result(
        &self,
        _result: &[u8],
        _protocol: &ProtocolType,
        _context: &mut ProgramContext,
    ) -> Result<(), BitVMXError> {
        Err(BitVMXError::InvalidMessage(
            "receive_verification_result called on a non-async step".to_string(),
        ))
    }
}
