use crate::{
    ports::bitcoin_coordinator::BitcoinCoordinatorApi,
    program::variables::{Globals, VariableTypes},
};
use enum_dispatch::enum_dispatch;
use serde::de::DeserializeOwned;
use serde_json::Value;
use tracing::info;
use uuid::Uuid;

use crate::{
    comms_helper::CommsMessageType,
    errors::BitVMXError,
    program::{
        participant::{get_index_by_pubkey_hash, CommsAddress},
        protocols::protocol_handler::ProtocolType,
    },
    types::{NoOpReason, PeerSetupFaultReason, ProgramContext, RetryReason},
};

/// Result of validating a contribution for the active setup step.
///
/// Peer-controlled validation failures are values rather than errors so the
/// caller can consume the message and fail setup. `Err` is reserved for local
/// state, storage, and infrastructure failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupMessageOutcome {
    Accepted,
    NotReady(SetupRetryReason),
    NoOp(SetupNoOpReason),
    Rejected(SetupRejectReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupRetryReason {
    UnexpectedMessageType,
    MissingPrerequisite,
}

impl SetupRetryReason {
    pub fn into_retry_reason(self) -> RetryReason {
        match self {
            Self::UnexpectedMessageType | Self::MissingPrerequisite => RetryReason::SetupNotReady,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupNoOpReason {
    ContributionAlreadyAccepted,
    UnauthorizedSender,
}

impl SetupNoOpReason {
    pub fn into_no_op_reason(self) -> NoOpReason {
        match self {
            Self::ContributionAlreadyAccepted => NoOpReason::ContributionAlreadyAccepted,
            Self::UnauthorizedSender => NoOpReason::UnauthorizedSender,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupRejectReason {
    MalformedContribution,
    InvalidContribution,
}

impl SetupRejectReason {
    pub fn into_peer_fault_reason(self) -> PeerSetupFaultReason {
        match self {
            Self::MalformedContribution => PeerSetupFaultReason::MalformedMessage,
            Self::InvalidContribution => PeerSetupFaultReason::InvalidSetupContribution,
        }
    }
}

/// Decodes a JSON setup contribution and classifies malformed peer data.
pub(crate) fn decode_contribution<T>(data: Value) -> Result<T, SetupMessageOutcome>
where
    T: DeserializeOwned,
{
    serde_json::from_value(data).map_err(|error| {
        info!("Rejecting malformed setup contribution: {}", error);
        SetupMessageOutcome::Rejected(SetupRejectReason::MalformedContribution)
    })
}

/// Decodes an encoded JSON value nested inside a setup contribution.
pub(crate) fn decode_contribution_slice<T>(data: &[u8]) -> Result<T, SetupMessageOutcome>
where
    T: DeserializeOwned,
{
    serde_json::from_slice(data).map_err(|error| {
        info!("Rejecting malformed encoded setup contribution: {}", error);
        SetupMessageOutcome::Rejected(SetupRejectReason::MalformedContribution)
    })
}

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

    /// Peer message type accepted while this step is active.
    fn accepted_message_type(&self) -> CommsMessageType;

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
    /// Applies the checks shared by every step before delegating the payload to
    /// [`SetupStep::verify_received_impl`]:
    ///
    /// - a sender outside the participant list cannot contribute to this
    ///   program and is consumed as a no-op;
    /// - a message for another step's `accepted_message_type` stays retryable,
    ///   because the engine may still advance to the step that consumes it.
    ///
    /// Steps implement `verify_received_impl` and must not repeat these checks.
    fn verify_received<BC: BitcoinCoordinatorApi>(
        &self,
        data: Value,
        msg_type: CommsMessageType,
        from_participant: &CommsAddress,
        protocol: &ProtocolType,
        participants: &[CommsAddress],
        context: &mut ProgramContext<BC>,
        your_data: bool,
    ) -> Result<SetupMessageOutcome, BitVMXError> {
        let Some(from_idx) = get_index_by_pubkey_hash(participants, &from_participant.pubkey_hash)
        else {
            info!(
                "Discarding '{}' step data from non-participant {}",
                self.step_name(),
                from_participant.pubkey_hash
            );
            return Ok(SetupMessageOutcome::NoOp(
                SetupNoOpReason::UnauthorizedSender,
            ));
        };

        let accepted = self.accepted_message_type();
        if msg_type != accepted {
            info!(
                "Received message with type {:?} in '{}' step, deferring. Expected type: {:?}",
                msg_type,
                self.step_name(),
                accepted
            );
            return Ok(SetupMessageOutcome::NotReady(
                SetupRetryReason::UnexpectedMessageType,
            ));
        }

        self.verify_received_impl(
            data,
            from_participant,
            from_idx,
            protocol,
            context,
            your_data,
        )
    }

    /// **VERIFY** the step-specific payload of an accepted participant message.
    ///
    /// `from_idx` is the sender's index in the program participant list, already
    /// resolved by [`SetupStep::verify_received`].
    ///
    /// **IMPORTANT**: Must store the verified data in `context.globals`
    /// using the convention `"participant_{idx}_{step_name}"`.
    fn verify_received_impl<BC: BitcoinCoordinatorApi>(
        &self,
        data: Value,
        from_participant: &CommsAddress,
        from_idx: usize,
        protocol: &ProtocolType,
        context: &mut ProgramContext<BC>,
        your_data: bool,
    ) -> Result<SetupMessageOutcome, BitVMXError>;

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
        msg_type: CommsMessageType,
        sub_step: &str,
        _program_context: &mut ProgramContext<BC>,
        _protocol_id: &Uuid,
    ) -> Result<Value, BitVMXError> {
        Err(BitVMXError::NotImplemented(format!(
            "{} step received msg_type: {:?} sub_type: {} but does not implement a handler",
            self.step_name(),
            msg_type,
            sub_step
        )))
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

        fn accepted_message_type(&self) -> CommsMessageType {
            CommsMessageType::Keys
        }

        fn generate_data<BC: BitcoinCoordinatorApi>(
            &self,
            _protocol: &mut ProtocolType,
            _context: &mut ProgramContext<BC>,
        ) -> Result<Option<(Value, CommsMessageType)>, BitVMXError> {
            Ok(None)
        }

        fn verify_received_impl<BC: BitcoinCoordinatorApi>(
            &self,
            _data: Value,
            _from_participant: &CommsAddress,
            _from_idx: usize,
            _protocol: &ProtocolType,
            _context: &mut ProgramContext<BC>,
            _your_data: bool,
        ) -> Result<SetupMessageOutcome, BitVMXError> {
            Ok(SetupMessageOutcome::NotReady(
                SetupRetryReason::MissingPrerequisite,
            ))
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
        // The accepted message type from a known participant reaches the
        // step-specific implementation.
        assert_eq!(
            step.verify_received(
                Value::Null,
                CommsMessageType::Keys,
                &participant,
                &protocol,
                &participants,
                &mut env.context,
                false,
            )
            .unwrap(),
            SetupMessageOutcome::NotReady(SetupRetryReason::MissingPrerequisite)
        );
        assert!(!step
            .can_advance(&protocol, &participants, &env.context)
            .unwrap());
        step.on_step_complete(&protocol, &participants, &mut env.context)
            .unwrap();
        let result = step.receive_dispatcher_result(
            serde_json::json!({"ignored": true}),
            CommsMessageType::Keys,
            "ignored",
            &mut env.context,
            &id,
        );

        assert!(matches!(result, Err(BitVMXError::NotImplemented(_))));
    }

    #[test]
    fn verify_received_applies_shared_checks_before_the_step_implementation() {
        let mut env = TestProgramContextEnv::new("setup-step-shared-checks").unwrap();
        let dir = TestStorageDir::new("setup-step-shared-checks-protocol");
        let id = Uuid::new_v4();
        let protocol =
            new_protocol_type(id, PROGRAM_TYPE_AGGREGATED_KEY, 0, dir.storage()).unwrap();
        let participant = env.self_address().unwrap();
        let participants = vec![participant.clone()];
        let step = TestStep;

        // A message belonging to another step never reaches the implementation.
        assert_eq!(
            step.verify_received(
                Value::Null,
                CommsMessageType::PublicNonces,
                &participant,
                &protocol,
                &participants,
                &mut env.context,
                false,
            )
            .unwrap(),
            SetupMessageOutcome::NotReady(SetupRetryReason::UnexpectedMessageType)
        );

        let mut outsider = participant;
        outsider.pubkey_hash = "unknown-participant".to_string();
        assert_eq!(
            step.verify_received(
                Value::Null,
                CommsMessageType::PublicNonces,
                &outsider,
                &protocol,
                &participants,
                &mut env.context,
                false,
            )
            .unwrap(),
            SetupMessageOutcome::NoOp(SetupNoOpReason::UnauthorizedSender)
        );
    }
}
