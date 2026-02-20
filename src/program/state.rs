use serde::{Deserialize, Serialize};

#[derive(PartialEq, Clone, Serialize, Deserialize, Debug)]
pub enum ProgramState {
    /// Initial state when a program is first created
    New,

    /// Program is in setup phase using SetupEngine.
    /// The actual setup flow is managed by SetupEngine.
    SettingUp,

    /// Program setup is complete and is ready to send transactions monitor
    Monitoring,

    /// Ready state after setup is completed and the transactions are being monitored
    Ready,
}

impl Default for ProgramState {
    fn default() -> Self {
        ProgramState::New
    }
}

impl ProgramState {
    pub fn is_active(&self) -> bool {
        self.is_setting_up() || self.is_monitoring()
    }

    pub fn is_setting_up(&self) -> bool {
        matches!(self, &ProgramState::New | &ProgramState::SettingUp)
    }

    pub fn is_monitoring(&self) -> bool {
        self == &ProgramState::Monitoring
    }
}
