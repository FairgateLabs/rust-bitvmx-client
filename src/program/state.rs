use serde::{Deserialize, Serialize};

#[derive(PartialEq, Clone, Serialize, Deserialize, Debug)]
pub enum ProgramState {
    /// Program is in setup phase using SetupEngine.
    /// The actual setup flow is managed by SetupEngine.
    SettingUp,

    /// Waiting data
    WaitingData,

    /// Ready state after setup is completed and the transactions are being monitored
    Ready,

    /// Setup failed unrecoverably. Terminal: L2 has been told and the program is no longer driven.
    Failed,
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
