use bitcoin::PublicKey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::program::participant::{P2PAddress, ParticipantRole};

// Key names
pub const TAKE_AGGREGATED_KEY: &str = "take_aggregated_key";
pub const DISPUTE_AGGREGATED_KEY: &str = "dispute_aggregated_key";

// Transaction names
pub const ACCEPT_PEG_IN_TX: &str = "ACCEPT_PEG_IN_TX";
pub const OP_FUNDING_TX: &str = "OP_FUNDING_TX";
pub const WT_FUNDING_TX: &str = "WT_FUNDING_TX";
pub const OP_INITIAL_DEPOSIT_TX: &str = "OP_INITIAL_DEPOSIT_TX";
pub const WT_INITIAL_DEPOSIT_TX: &str = "WT_INITIAL_DEPOSIT_TX";
pub const REIMBURSEMENT_KICKOFF_TX: &str = "REIMBURSEMENT_KICKOFF_TX";
pub const NO_TAKE_TX: &str = "NO_TAKE_TX";
pub const CHALLENGE_TX: &str = "CHALLENGE_TX";
pub const YOU_CANT_TAKE_TX: &str = "YOU_CANT_TAKE_TX";
pub const TRY_MOVE_ON_TX: &str = "TRY_MOVE_ON_TX";
pub const TRY_TAKE_2_TX: &str = "TRY_TAKE_2_TX";
pub const NO_DISPUTE_OPENED_TX: &str = "NO_DISPUTE_OPENED_TX";

// Parameters
pub const TAKE_ENABLER_TIMELOCK: u16 = 144;
pub const DISPUTE_OPENER_VALUE: u64 = 1000;
pub const START_ENABLER_VALUE: u64 = 1000;
pub const DUST_VALUE: u64 = 546;

// Suffixes
pub const FUNDING_UTXO_SUFFIX: &str = "_FUNDING_UTXO";
pub const FUNDING_TX_SUFFIX: &str = "_FUNDING_TX";
pub const INITIAL_DEPOSIT_TX_SUFFIX: &str = "_INITIAL_DEPOSIT_TX";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitteeCreated {
    pub my_role: ParticipantRole,
    pub my_take_pubkey: PublicKey,
    pub my_dispute_pubkey: PublicKey,
    pub take_aggregated_key: PublicKey,
    pub dispute_aggregated_key: PublicKey,
    pub addresses: HashMap<PublicKey, P2PAddress>,
    pub operator_count: u32,
    pub watchtower_count: u32,
}

impl CommitteeCreated {
    pub fn name() -> String {
        "committee_created".to_string()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PegInRequest {
    pub my_role: ParticipantRole,
    pub take_aggregated_key: PublicKey,
    pub addresses: HashMap<PublicKey, P2PAddress>,
}

impl PegInRequest {
    pub fn name() -> String {
        "peg_in_request".to_string()
    }
}
