use crate::{
    errors::BitVMXError,
    program::{participant::ParticipantData, protocols::protocol_handler::ProtocolType},
    types::ProgramContext,
};

use super::ExchangeConfig;

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
pub trait SetupStep: Send + Sync {
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
        from_participant: &ParticipantData,
        protocol: &ProtocolType,
        participants: &[ParticipantData],
        context: &mut ProgramContext,
    ) -> Result<(), BitVMXError>;

    /// **VERIFY ADVANCE** - Verifies if all participants have completed this step.
    ///
    /// Typically, verifies that variables exist in `context.globals` for all participants.
    fn can_advance(
        &self,
        protocol: &ProtocolType,
        participants: &[ParticipantData],
        context: &mut ProgramContext,
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
        _participants: &[ParticipantData],
        _context: &mut ProgramContext,
    ) -> Result<(), BitVMXError> {
        Ok(())
    }

    /// Exchange configuration (broadcasting, timeouts, etc.)
    ///
    /// Default: broadcasting enabled, signature verification enabled, 3 retries.
    fn exchange_config(&self) -> ExchangeConfig {
        ExchangeConfig::default()
    }
}
