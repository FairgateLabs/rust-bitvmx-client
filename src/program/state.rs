use serde::{Deserialize, Serialize};

#[derive(PartialEq, Clone, Serialize, Deserialize, Debug)]
pub enum ProgramState {
    /// Program is in setup phase using SetupEngine.
    /// The actual setup flow is managed by SetupEngine.
    SettingUp,

    /// Ready state after setup is completed and the transactions are being monitored
    Ready,
}

impl Default for ProgramState {
    fn default() -> Self {
        ProgramState::SettingUp
    }
}

impl ProgramState {
    pub fn is_active(&self) -> bool {
        matches!(self, &ProgramState::SettingUp)
    }
}
