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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        program::protocols::protocol_handler::new_protocol_type,
        test_utils::{TestProgramContextEnv, TestStorageDir},
        types::PROGRAM_TYPE_AGGREGATED_KEY,
    };

    struct TestStep;

    impl SetupStep for TestStep {
        fn step_name(&self) -> &str {
            "test"
        }

        fn generate_data<BC: BitcoinCoordinatorApi>(
            &self,
            _protocol: &mut ProtocolType,
            _context: &mut ProgramContext<BC>,
        ) -> Result<Option<(Value, CommsMessageType)>, BitVMXError> {
            Ok(None)
        }

        fn verify_received<BC: BitcoinCoordinatorApi>(
            &self,
            _data: Value,
            _msg_type: CommsMessageType,
            _from_participant: &CommsAddress,
            _protocol: &ProtocolType,
            _participants: &[CommsAddress],
            _context: &mut ProgramContext<BC>,
            _your_data: bool,
        ) -> Result<bool, BitVMXError> {
            Ok(false)
        }

        fn can_advance<BC: BitcoinCoordinatorApi>(
            &self,
            _protocol: &ProtocolType,
            _participants: &[CommsAddress],
            _context: &ProgramContext<BC>,
        ) -> Result<bool, BitVMXError> {
            Ok(false)
        }
    }

    #[test]
    fn async_defaults_are_disabled() {
        let step = TestStep;

        assert!(!step.generate_async());
        assert!(!step.verify_async());
    }

    #[test]
    fn participant_data_defaults_store_and_load_strings() {
        let dir = TestStorageDir::new("setup-step-participant-data");
        let globals = Globals::new(dir.storage());
        let id = Uuid::new_v4();
        let step = TestStep;

        assert!(!step.has_participant_data(&globals, &id, 2).unwrap());
        step.store_participant_data(&globals, &id, 2, "payload")
            .unwrap();
        assert!(step.has_participant_data(&globals, &id, 2).unwrap());
        assert_eq!(
            step.get_participant_data(&globals, &id, 2).unwrap(),
            "payload"
        );
    }

    #[test]
    fn participant_data_default_reports_missing_and_invalid_values() {
        let dir = TestStorageDir::new("setup-step-participant-errors");
        let globals = Globals::new(dir.storage());
        let id = Uuid::new_v4();
        let step = TestStep;

        let missing = step.get_participant_data(&globals, &id, 1).unwrap_err();
        assert!(matches!(
            missing,
            BitVMXError::InvalidMessage(message)
                if message == "Missing test for participant 1"
        ));

        globals
            .set_var(&id, "participant_1_test", VariableTypes::Number(1))
            .unwrap();
        assert!(matches!(
            step.get_participant_data(&globals, &id, 1),
            Err(BitVMXError::InvalidVariableType(_))
        ));
    }

    #[test]
    fn test_step_methods_and_default_hooks_return_expected_values() {
        let mut env = TestProgramContextEnv::new("setup-step-default-hooks").unwrap();
        let dir = TestStorageDir::new("setup-step-default-hooks-protocol");
        let id = Uuid::new_v4();
        let mut protocol =
            new_protocol_type(id, PROGRAM_TYPE_AGGREGATED_KEY, 0, dir.storage()).unwrap();
        let participant = env.self_address().unwrap();
        let participants = vec![participant.clone()];
        let step = TestStep;

        assert_eq!(
            step.generate_data(&mut protocol, &mut env.context).unwrap(),
            None
        );
        assert!(!step
            .verify_received(
                Value::Null,
                CommsMessageType::Keys,
                &participant,
                &protocol,
                &participants,
                &mut env.context,
                false,
            )
            .unwrap());
        assert!(!step
            .can_advance(&protocol, &participants, &env.context)
            .unwrap());
        step.on_step_complete(&protocol, &participants, &mut env.context)
            .unwrap();
        let result = step
            .receive_dispatcher_result(
                serde_json::json!({"ignored": true}),
                CommsMessageType::Keys,
                "ignored",
                &mut env.context,
                &id,
            )
            .unwrap();

        assert_eq!(result, Some(Value::Null));
    }
}
