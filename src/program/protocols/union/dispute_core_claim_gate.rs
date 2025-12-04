use crate::program::protocols::claim::ClaimGate;

pub const CLAIM_GATE_START_SUCCESS_LEAF: usize = 1;
pub const CLAIM_GATE_START_STOP_LEAF: usize = 0;

pub const CLAIM_GATE_INIT_STOPPER_COMMITTEE_LEAF: usize = 0;
// const CLAIM_GATE_INIT_STOPPER_KEYPAIR_LEAF: usize = 0;
pub const CLAIM_GATE_INIT_EXCLUSIVE_WIN_LEAF: usize = 0;
pub const CLAIM_GATE_INIT_START_LEAF: usize = 0;

pub enum ClaimGateAction {
    Start,
    Stop { with_speedup: bool },
    Success { block_height: Option<u32> },
}

impl ClaimGateAction {
    pub fn tx_name(&self, base: &str) -> String {
        match self {
            ClaimGateAction::Start => ClaimGate::tx_start(base),
            ClaimGateAction::Stop { .. } => ClaimGate::tx_stop(base, 0),
            ClaimGateAction::Success { .. } => ClaimGate::tx_success(base),
        }
    }

    pub fn inputs(&self) -> Vec<(usize, usize)> {
        match self {
            ClaimGateAction::Start => vec![(0, CLAIM_GATE_INIT_START_LEAF)],
            ClaimGateAction::Stop { .. } => vec![
                (0, CLAIM_GATE_INIT_STOPPER_COMMITTEE_LEAF),
                (1, CLAIM_GATE_START_STOP_LEAF),
            ],
            ClaimGateAction::Success { .. } => vec![
                (0, CLAIM_GATE_START_SUCCESS_LEAF),
                (1, CLAIM_GATE_INIT_EXCLUSIVE_WIN_LEAF),
            ],
        }
    }

    pub fn with_speedup(&self) -> bool {
        match self {
            ClaimGateAction::Start => true,
            ClaimGateAction::Stop { with_speedup } => *with_speedup,
            ClaimGateAction::Success { .. } => true,
        }
    }

    pub fn block_height(&self) -> Option<u32> {
        match self {
            ClaimGateAction::Success {
                block_height: blocks,
            } => *blocks,
            _ => None,
        }
    }
}
