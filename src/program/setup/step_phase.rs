use serde::{Deserialize, Serialize};

/// Current phase of a setup step
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StepPhase {
    /// Waiting to generate own data
    WaitingToGenerate,
    /// Waiting to exchange data with other participants
    WaitingToExchange,
    /// Exchanging data (sending/receiving)
    Exchanging,
    /// Verifying that all participants completed the step
    Verifying,
    /// Step completed
    Completed,
}

impl Default for StepPhase {
    fn default() -> Self {
        Self::WaitingToGenerate
    }
}

impl StepPhase {
    /// Advance to the next phase according to whether I am leader or not
    pub fn next_phase(&self, is_leader: bool) -> Self {
        match (self, is_leader) {
            // WaitingToGenerate -> Exchanging (all)
            (Self::WaitingToGenerate, _) => Self::Exchanging,

            // Exchanging:
            // - Leader: waits to receive from all -> WaitingToExchange
            // - Not leader: sent and waits for leader's broadcast -> Verifying
            (Self::Exchanging, true) => Self::WaitingToExchange,
            (Self::Exchanging, false) => Self::Verifying,

            // WaitingToExchange (leader only): received from all, broadcast -> Verifying
            (Self::WaitingToExchange, _) => Self::Verifying,

            // Verifying -> Completed (all)
            (Self::Verifying, _) => Self::Completed,

            // Completed -> Completed (idempotent)
            (Self::Completed, _) => Self::Completed,
        }
    }
}
