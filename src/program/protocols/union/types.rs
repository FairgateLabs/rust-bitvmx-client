use bitcoin::{PublicKey, Txid};
use musig2::{secp::MaybeScalar, PubNonce};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::program::{participant::ParticipantRole, variables::PartialUtxo};

// Key names
pub const TAKE_AGGREGATED_KEY: &str = "take_aggregated_key";
pub const DISPUTE_AGGREGATED_KEY: &str = "dispute_aggregated_key";
pub const SELECTED_OPERATOR_PUBKEY: &str = "selected_operator_pubkey";
pub const OP_INITIAL_DEPOSIT_FLAG: &str = "op_initial_deposit_flag";

// Transaction names
pub const REQUEST_PEGIN_TX: &str = "REQUEST_PEGIN_TX";
pub const ACCEPT_PEGIN_TX: &str = "ACCEPT_PEGIN_TX";
pub const USER_TAKE_TX: &str = "USER_TAKE_TX";
pub const ADVANCE_FUNDS_TX: &str = "ADVANCE_FUNDS_TX";
pub const OPERATOR_TAKE_TX: &str = "OPERATOR_TAKE_TX";
pub const OPERATOR_WON_TX: &str = "OPERATOR_WON_TX";
pub const OP_FUNDING_TX: &str = "OP_FUNDING_TX";
pub const WT_FUNDING_TX: &str = "WT_FUNDING_TX";
pub const OP_INITIAL_DEPOSIT_TX: &str = "OP_INITIAL_DEPOSIT_TX";
pub const WT_INITIAL_DEPOSIT_TX: &str = "WT_INITIAL_DEPOSIT_TX";
pub const REIMBURSEMENT_KICKOFF_TX: &str = "REIMBURSEMENT_KICKOFF_TX";
pub const NO_TAKE_TX: &str = "NO_TAKE_TX";
pub const CHALLENGE_TX: &str = "CHALLENGE_TX";
pub const REVEAL_INPUT_TX: &str = "REVEAL_INPUT_TX";
pub const INPUT_NOT_REVEALED_TX: &str = "INPUT_NOT_REVEALED_TX";
pub const YOU_CANT_TAKE_TX: &str = "YOU_CANT_TAKE_TX";
pub const OP_SELF_DISABLER_TX: &str = "OP_SELF_DISABLER_TX";
pub const TRY_TAKE_2_TX: &str = "TRY_TAKE_2_TX";
pub const NO_DISPUTE_OPENED_TX: &str = "NO_DISPUTE_OPENED_TX";
pub const NO_CHALLENGE_TX: &str = "NO_CHALLENGE_TX";

// Parameters
pub const DISPUTE_CORE_SHORT_TIMELOCK: u16 = 3;
pub const DISPUTE_CORE_LONG_TIMELOCK: u16 = 6;
pub const DUST_VALUE: u64 = 546;
pub const SPEED_UP_VALUE: u64 = 546;
pub const P2TR_FEE: u64 = 355; // This should match the value P2TR_FEE in Union Smart contracts

// Suffixes
pub const FUNDING_UTXO_SUFFIX: &str = "_FUNDING_UTXO";
pub const FUNDING_TX_SUFFIX: &str = "_FUNDING_TX";
pub const SETUP_TX_SUFFIX: &str = "_SETUP_TX";
pub const INITIAL_DEPOSIT_TX_SUFFIX: &str = "_INITIAL_DEPOSIT_TX";
pub const SELF_DISABLER_TX_SUFFIX: &str = "_SELF_DISABLER_TX";

// UTXOs
pub const OPERATOR_TAKE_ENABLER: &str = "operator_take_enabler";
pub const OPERATOR_WON_ENABLER: &str = "operator_won_enabler";
pub const ADVANCE_FUNDS_INPUT: &str = "advance_funds_input";

// Roles
pub const OPERATOR: &str = "OP";
pub const WATCHTOWER: &str = "WT";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberData {
    pub role: ParticipantRole,
    pub take_key: PublicKey,
    pub dispute_key: PublicKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Committee {
    pub members: Vec<MemberData>,
    pub take_aggregated_key: PublicKey,
    pub dispute_aggregated_key: PublicKey,
    pub operator_count: u32,
    pub packet_size: u32,
}

impl Committee {
    pub fn name() -> String {
        "committee".to_string()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisputeCoreData {
    pub committee_id: Uuid,
    pub operator_index: usize,
    pub operator_utxo: PartialUtxo,
}

impl DisputeCoreData {
    pub fn name() -> String {
        "dispute_core_data".to_string()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PegInRequest {
    pub txid: Txid,
    pub amount: u64,
    pub accept_pegin_sighash: Vec<u8>,
    pub take_aggregated_key: PublicKey,
    pub operators_take_key: Vec<PublicKey>,
    pub slot_index: u32,
    pub committee_id: uuid::Uuid,
    pub rootstock_address: String,
    pub reimbursement_pubkey: PublicKey,
}

impl PegInRequest {
    pub fn name() -> String {
        "pegin_request".to_string()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PegInAccepted {
    pub committee_id: Uuid,
    pub accept_pegin_txid: Txid,
    pub accept_pegin_nonce: PubNonce,
    pub accept_pegin_signature: MaybeScalar,
    pub operator_take_sighash: Vec<u8>,
    pub operator_won_sighash: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PegOutRequest {
    pub committee_id: Uuid,
    pub slot_id: u32,
    pub fee: u64,
    pub user_pubkey: PublicKey,
    pub take_aggregated_key: PublicKey,
}

impl PegOutRequest {
    pub fn name() -> String {
        "pegout_request".to_string()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PegOutAccepted {
    pub committee_id: Uuid,
    pub user_take_txid: Txid,
    pub user_take_sighash: Vec<u8>,
    pub user_take_nonce: PubNonce,
    pub user_take_signature: MaybeScalar,
}

impl PegOutAccepted {
    pub fn name() -> String {
        "pegout_accepted".to_string()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvanceFundsRequest {
    pub committee_id: Uuid,
    pub slot_index: usize,
    pub pegout_id: Vec<u8>,
    pub fee: u64,
    pub user_pubkey: PublicKey,
    pub my_take_pubkey: PublicKey,
}

impl AdvanceFundsRequest {
    pub fn name() -> String {
        "advance_funds_request".to_string()
    }
}
