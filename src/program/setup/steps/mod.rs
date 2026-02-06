pub mod keys_step;
pub mod nonces_step;
pub mod signatures_step;

pub use keys_step::KeysStep;
pub use nonces_step::NoncesStep;
pub use signatures_step::SignaturesStep;

use crate::errors::BitVMXError;
use super::SetupStep;
use std::fmt;
use std::str::FromStr;

/// Enum representing the available setup step types.
///
/// This provides type-safe step names and avoids magic strings throughout the codebase.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SetupStepName {
    Keys,
    Nonces,
    Signatures,
}

impl SetupStepName {
    /// Returns the string representation of the step name.
    pub fn as_str(&self) -> &'static str {
        match self {
            SetupStepName::Keys => "keys",
            SetupStepName::Nonces => "nonces",
            SetupStepName::Signatures => "signatures",
        }
    }

    /// Returns all available step names.
    pub fn all() -> Vec<SetupStepName> {
        vec![
            SetupStepName::Keys,
            SetupStepName::Nonces,
            SetupStepName::Signatures,
        ]
    }
}

impl fmt::Display for SetupStepName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for SetupStepName {
    type Err = BitVMXError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "keys" => Ok(SetupStepName::Keys),
            "nonces" => Ok(SetupStepName::Nonces),
            "signatures" => Ok(SetupStepName::Signatures),
            _ => Err(BitVMXError::InvalidMessage(format!(
                "Unknown setup step name: '{}'. Valid names are: 'keys', 'nonces', 'signatures'",
                s
            ))),
        }
    }
}

impl From<SetupStepName> for String {
    fn from(name: SetupStepName) -> Self {
        name.as_str().to_string()
    }
}

/// Concrete enum that groups all `SetupStep` implementations.
///
/// This allows us to avoid heap allocations (`Box<dyn SetupStep>`) while
/// still using a unified type that implements the `SetupStep` trait.
#[derive(Debug, Clone)]
pub enum SetupStepEnum {
    Keys(KeysStep),
    Nonces(NoncesStep),
    Signatures(SignaturesStep),
}

impl SetupStep for SetupStepEnum {
    fn step_name(&self) -> &str {
        match self {
            SetupStepEnum::Keys(step) => step.step_name(),
            SetupStepEnum::Nonces(step) => step.step_name(),
            SetupStepEnum::Signatures(step) => step.step_name(),
        }
    }

    fn generate_data(
        &self,
        protocol: &mut crate::program::protocols::protocol_handler::ProtocolType,
        context: &mut crate::types::ProgramContext,
    ) -> Result<Option<Vec<u8>>, BitVMXError> {
        match self {
            SetupStepEnum::Keys(step) => step.generate_data(protocol, context),
            SetupStepEnum::Nonces(step) => step.generate_data(protocol, context),
            SetupStepEnum::Signatures(step) => step.generate_data(protocol, context),
        }
    }

    fn verify_received(
        &self,
        data: &[u8],
        from_participant: &crate::program::participant::ParticipantData,
        protocol: &crate::program::protocols::protocol_handler::ProtocolType,
        participants: &[crate::program::participant::ParticipantData],
        context: &mut crate::types::ProgramContext,
    ) -> Result<(), BitVMXError> {
        match self {
            SetupStepEnum::Keys(step) => {
                step.verify_received(data, from_participant, protocol, participants, context)
            }
            SetupStepEnum::Nonces(step) => {
                step.verify_received(data, from_participant, protocol, participants, context)
            }
            SetupStepEnum::Signatures(step) => {
                step.verify_received(data, from_participant, protocol, participants, context)
            }
        }
    }

    fn can_advance(
        &self,
        protocol: &crate::program::protocols::protocol_handler::ProtocolType,
        participants: &[crate::program::participant::ParticipantData],
        context: &crate::types::ProgramContext,
    ) -> Result<bool, BitVMXError> {
        match self {
            SetupStepEnum::Keys(step) => step.can_advance(protocol, participants, context),
            SetupStepEnum::Nonces(step) => step.can_advance(protocol, participants, context),
            SetupStepEnum::Signatures(step) => step.can_advance(protocol, participants, context),
        }
    }

    fn on_step_complete(
        &self,
        protocol: &crate::program::protocols::protocol_handler::ProtocolType,
        participants: &[crate::program::participant::ParticipantData],
        context: &mut crate::types::ProgramContext,
    ) -> Result<(), BitVMXError> {
        match self {
            SetupStepEnum::Keys(step) => step.on_step_complete(protocol, participants, context),
            SetupStepEnum::Nonces(step) => step.on_step_complete(protocol, participants, context),
            SetupStepEnum::Signatures(step) => {
                step.on_step_complete(protocol, participants, context)
            }
        }
    }
}

/// Factory function to create a concrete `SetupStepEnum` from its name.
pub fn create_setup_step(name: &SetupStepName) -> SetupStepEnum {
    match name {
        SetupStepName::Keys => SetupStepEnum::Keys(KeysStep::new()),
        SetupStepName::Nonces => SetupStepEnum::Nonces(NoncesStep::new()),
        SetupStepName::Signatures => SetupStepEnum::Signatures(SignaturesStep::new()),
    }
}

