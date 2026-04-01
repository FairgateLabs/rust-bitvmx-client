pub mod keys_step;
pub mod nonces_step;
pub mod signatures_step;

pub use keys_step::KeysStep;
pub use nonces_step::NoncesStep;
pub use signatures_step::SignaturesStep;

use enum_dispatch::enum_dispatch;

use super::SetupStep;
use crate::errors::BitVMXError;
use crate::program::participant::CommsAddress;
use crate::program::protocols::protocol_handler::ProtocolType;
use crate::types::ProgramContext;

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
}

/// Concrete enum that groups all `SetupStep` implementations.
///
/// This allows us to avoid heap allocations (`Box<dyn SetupStep>`) while
/// still using a unified type that implements the `SetupStep` trait.
#[enum_dispatch(SetupStep)]
#[derive(Debug, Clone)]
pub enum SetupStepEnum {
    Keys(KeysStep),
    Nonces(NoncesStep),
    Signatures(SignaturesStep),
}

/// Factory function to create a concrete `SetupStepEnum` from its name.
pub fn create_setup_step(name: &SetupStepName) -> SetupStepEnum {
    match name {
        SetupStepName::Keys => SetupStepEnum::Keys(KeysStep::new()),
        SetupStepName::Nonces => SetupStepEnum::Nonces(NoncesStep::new()),
        SetupStepName::Signatures => SetupStepEnum::Signatures(SignaturesStep::new()),
    }
}
