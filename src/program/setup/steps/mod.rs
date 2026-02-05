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

/// Factory function to create a SetupStep from its name.
///
/// Returns an error if the step name is not recognized.
pub fn create_setup_step(name: &SetupStepName) -> Box<dyn SetupStep> {
    match name {
        SetupStepName::Keys => Box::new(KeysStep::new()),
        SetupStepName::Nonces => Box::new(NoncesStep::new()),
        SetupStepName::Signatures => Box::new(SignaturesStep::new()),
    }
}

