pub mod garbler_step;
pub mod keys_step;
pub mod nonces_step;
pub mod signatures_step;

pub use garbler_step::GarblerStep;
pub use keys_step::KeysStep;
pub use nonces_step::NoncesStep;
pub use signatures_step::SignaturesStep;

use enum_dispatch::enum_dispatch;
use serde_json::Value;
use uuid::Uuid;

use super::SetupStep;
use crate::comms_helper::CommsMessageType;
use crate::errors::BitVMXError;
use crate::ports::bitcoin_coordinator::BitcoinCoordinatorApi;
use crate::program::participant::{CommsAddress, ParticipantKeys};
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
    Garbler,
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
    Garbler(GarblerStep),
}

/// Factory function to create a concrete `SetupStepEnum` from its name.
pub fn create_setup_step(name: &SetupStepName) -> SetupStepEnum {
    match name {
        SetupStepName::Keys => SetupStepEnum::Keys(KeysStep::new()),
        SetupStepName::Nonces => SetupStepEnum::Nonces(NoncesStep::new()),
        SetupStepName::Signatures => SetupStepEnum::Signatures(SignaturesStep::new()),
        SetupStepName::Garbler => SetupStepEnum::Garbler(GarblerStep::new()),
    }
}

fn load_my_keys<BC: BitcoinCoordinatorApi>(
    protocol_id: &Uuid,
    context: &ProgramContext<BC>,
    missing_message: &str,
) -> Result<ParticipantKeys, BitVMXError> {
    let keys_json = context
        .globals
        .get_var(protocol_id, "my_keys")?
        .ok_or_else(|| BitVMXError::InvalidMessage(missing_message.to_string()))?
        .string()?;

    Ok(serde_json::from_str(&keys_json)?)
}
