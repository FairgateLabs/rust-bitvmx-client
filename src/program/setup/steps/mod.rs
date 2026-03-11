pub mod async_dispatcher_step;
pub mod keys_step;
pub mod garbled_handler;
pub mod nonces_step;
pub mod signatures_step;

pub use async_dispatcher_step::{AsyncDispatcherStep, AsyncStepHandler};
pub use keys_step::KeysStep;
pub use garbled_handler::GarbledHandler;
pub use nonces_step::NoncesStep;
pub use signatures_step::SignaturesStep;

use enum_dispatch::enum_dispatch;

use super::SetupStep;
use crate::config::ComponentsConfig;
use crate::errors::BitVMXError;
use crate::program::participant::CommsAddress;
use crate::program::protocols::protocol_handler::ProtocolType;
use crate::types::ProgramContext;
use bitvmx_broker::identification::identifier::Identifier;
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;

/// Enum representing the available setup step types.
///
/// This provides type-safe step names and avoids magic strings throughout the codebase.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SetupStepName {
    Keys,
    Nonces,
    Signatures,
    GarbledCircuits,
}

impl SetupStepName {
    /// Returns the string representation of the step name.
    pub fn as_str(&self) -> &'static str {
        match self {
            SetupStepName::Keys => "keys",
            SetupStepName::Nonces => "nonces",
            SetupStepName::Signatures => "signatures",
            SetupStepName::GarbledCircuits => "garbled_circuits",
        }
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
            "garbled_circuits" => Ok(SetupStepName::GarbledCircuits),
            _ => Err(BitVMXError::InvalidMessage(format!(
                "Unknown setup step name: '{}'. Valid names are: 'keys', 'nonces', 'signatures', 'garbled_circuits'",
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
#[enum_dispatch(SetupStep)]
#[derive(Debug, Clone)]
pub enum SetupStepEnum {
    Keys(KeysStep),
    Nonces(NoncesStep),
    Signatures(SignaturesStep),
    AsyncDispatcher(AsyncDispatcherStep),
}

/// Concrete enum grouping all [`AsyncStepHandler`] implementations.
///
/// When adding a new async dispatcher type, add a variant here.
#[enum_dispatch(AsyncStepHandler)]
#[derive(Debug, Clone)]
pub enum AsyncStepHandlerEnum {
    Garbled(GarbledHandler),
}

/// Factory function to create a concrete `SetupStepEnum` from its name.
pub fn create_setup_step(name: &SetupStepName) -> SetupStepEnum {
    match name {
        SetupStepName::Keys => SetupStepEnum::Keys(KeysStep::new()),
        SetupStepName::Nonces => SetupStepEnum::Nonces(NoncesStep::new()),
        SetupStepName::Signatures => SetupStepEnum::Signatures(SignaturesStep::new()),
        SetupStepName::GarbledCircuits => {
            SetupStepEnum::AsyncDispatcher(AsyncDispatcherStep::new("garbled_circuits"))
        }
    }
}
