use crate::{
    ports::bitcoin_coordinator::BitcoinCoordinatorApi,
    program::variables::{Globals, VariableTypes},
};
use enum_dispatch::enum_dispatch;
use serde_json::Value;
use uuid::Uuid;

use crate::{
    comms_helper::CommsMessageType,
    errors::BitVMXError,
    program::{participant::CommsAddress, protocols::protocol_handler::ProtocolType},
    types::ProgramContext,
};

/// Trait that defines a generic step of a protocol setup.
///
/// Each step manages its own lifecycle in 4 phases:
/// 1. **Generate**: Generate own data
/// 2. **Exchange**: Exchange with participants (handled by `Program`)
/// 3. **Verify**: Verify received data (validates and stores in `context.globals`)
/// 4. **Advance**: Verify if it can advance to the next step
///
/// ## Storage conventions in globals:
///
/// - Participant i data: `"participant_{i}_{step_name}"`
/// - Step-specific data may use additional keys such as `"my_keys"`
#[enum_dispatch]
pub trait SetupStep {
    /// Identifying name of the step (e.g.: "keys", "nonces", "signatures", "proof")
    fn step_name(&self) -> &str;

    /// **GENERATE** data to send.
    ///
    /// Returns serialized bytes or `None` if this step does not generate data.
    fn generate_data<BC: BitcoinCoordinatorApi>(
        &self,
        protocol: &mut ProtocolType,
        context: &mut ProgramContext<BC>,
    ) -> Result<Option<(Value, CommsMessageType)>, BitVMXError>;

    /// **VERIFY** and store data received from a participant.
    ///
    /// **IMPORTANT**: Must store the verified data in `context.globals`
    /// using the convention `"participant_{idx}_{step_name}"`.
    fn verify_received<BC: BitcoinCoordinatorApi>(
        &self,
        data: Value,
        msg_type: CommsMessageType,
        from_participant: &CommsAddress,
        protocol: &ProtocolType,
        participants: &[CommsAddress],
        context: &mut ProgramContext<BC>,
        your_data: bool,
    ) -> Result<bool, BitVMXError>;

    /// **VERIFY ADVANCE** - Verifies if all participants have completed this step.
    ///
    /// Typically, verifies that variables exist in `context.globals` for all participants.
    fn can_advance<BC: BitcoinCoordinatorApi>(
        &self,
        protocol: &ProtocolType,
        participants: &[CommsAddress],
        context: &ProgramContext<BC>,
    ) -> Result<bool, BitVMXError>;

    /// **Optional hook**: Called when the step completes successfully.
    ///
    /// Can be used for:
    /// - Computing aggregates (e.g.: sum all keys in MuSig2)
    /// - Storing final data in `"all_{step_name}"`
    /// - Completion logging
    ///
    /// Default: does nothing.
    fn on_step_complete<BC: BitcoinCoordinatorApi>(
        &self,
        _protocol: &ProtocolType,
        _participants: &[CommsAddress],
        _context: &mut ProgramContext<BC>,
    ) -> Result<(), BitVMXError> {
        Ok(())
    }

    fn receive_dispatcher_result<BC: BitcoinCoordinatorApi>(
        &self,
        _result: serde_json::Value,
        _msg_type: CommsMessageType,
        _sub_step: &str,
        _program_context: &mut ProgramContext<BC>,
        _protocol_id: &Uuid,
    ) -> Result<Option<Value>, BitVMXError> {
        Ok(Some(Value::Null))
    }

    fn generate_async(&self) -> bool {
        false
    }

    fn verify_async(&self) -> bool {
        false
    }

    fn store_participant_data(
        &self,
        globals: &Globals,
        uuid: &Uuid,
        idx: usize,
        data: &str,
    ) -> Result<(), BitVMXError> {
        let key = format!("participant_{}_{}", idx, self.step_name());
        globals.set_var(uuid, &key, VariableTypes::String(data.to_string()))
    }

    fn get_participant_data(
        &self,
        globals: &Globals,
        uuid: &Uuid,
        idx: usize,
    ) -> Result<String, BitVMXError> {
        let step_name = self.step_name();
        let key = format!("participant_{}_{}", idx, step_name);
        globals
            .get_var(uuid, &key)?
            .ok_or_else(|| {
                BitVMXError::InvalidMessage(format!(
                    "Missing {} for participant {}",
                    step_name, idx
                ))
            })?
            .string()
    }

    fn has_participant_data(
        &self,
        globals: &Globals,
        uuid: &Uuid,
        idx: usize,
    ) -> Result<bool, BitVMXError> {
        let key = format!("participant_{}_{}", idx, self.step_name());
        globals.contains_var(uuid, &key)
    }
}
