use bitcoin::{PublicKey, Txid};
use key_manager::musig2::{secp::MaybeScalar, PubNonce};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::program::{participant::ParticipantRole, variables::PartialUtxo};

// Key names
pub const TAKE_AGGREGATED_KEY: &str = "take_aggregated_key";
pub const DISPUTE_AGGREGATED_KEY: &str = "dispute_aggregated_key";
pub const SELECTED_OPERATOR_PUBKEY: &str = "selected_operator_pubkey";
pub const REIMBURSEMENT_KICKOFF_IN_PROGRESS: &str = "reimbursement_kickoff_in_progress";
pub const MONITORED_OPERATOR_KEY: &str = "monitored_operator_key";
pub const MONITORED_WATCHTOWER_KEY: &str = "monitored_watchtower_key";
pub const OP_INITIAL_DEPOSIT_FLAG: &str = "op_initial_deposit_flag";
pub const OPERATOR_LEAF_INDEX: &str = "operator_leaf_index";
pub const SPEEDUP_KEY: &str = "speedup_key";
pub const OP_INITIAL_DEPOSIT_TXID: &str = "op_initial_deposit_txid";
pub const OP_INITIAL_DEPOSIT_AMOUNT: &str = "op_initial_deposit_amount";
pub const OP_INITIAL_DEPOSIT_OUT_SCRIPT: &str = "op_initial_deposit_out_script";

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
pub const TWO_DISPUTE_PENALIZATION_TX: &str = "TWO_DISPUTE_PENALIZATION_TX";
pub const NO_TAKE_TX: &str = "NO_TAKE_TX";
pub const CHALLENGE_TX: &str = "CHALLENGE_TX";
pub const REVEAL_INPUT_TX: &str = "REVEAL_INPUT_TX";
pub const INPUT_NOT_REVEALED_TX: &str = "INPUT_NOT_REVEALED_TX";
pub const YOU_CANT_TAKE_TX: &str = "YOU_CANT_TAKE_TX";
pub const OP_SELF_DISABLER_TX: &str = "OP_SELF_DISABLER_TX";
pub const TRY_TAKE_2_TX: &str = "TRY_TAKE_2_TX";
pub const NO_DISPUTE_OPENED_TX: &str = "NO_DISPUTE_OPENED_TX";
pub const NO_CHALLENGE_TX: &str = "NO_CHALLENGE_TX";
pub const OP_DISABLER_TX: &str = "OP_DISABLER_TX";
pub const OP_LAZY_DISABLER_TX: &str = "OP_LAZY_DISABLER_TX";
pub const OP_DISABLER_DIRECTORY_TX: &str = "OP_DISABLER_DIRECTORY_TX";

// Parameters
pub const DISPUTE_CORE_SHORT_TIMELOCK: u16 = 1;
pub const DISPUTE_CORE_LONG_TIMELOCK: u16 = 6;
pub const DUST_VALUE: u64 = 540;
pub const SPEEDUP_VALUE: u64 = 540;
pub const P2TR_FEE: u64 = 335; // This should match the value P2TR_FEE in Union Smart contracts
pub const USER_TAKE_FEE: u64 = 335; // This should match the value USER_TAKE_FEE in Union Smart contracts
pub const OP_DISABLER_FEE: u64 = 240;

// Suffixes
pub const FUNDING_TX: &str = "FUNDING_TX";
pub const WT_START_ENABLER_TX: &str = "WT_START_ENABLER_TX";
pub const SETUP_TX: &str = "SETUP_TX";
pub const SELF_DISABLER_TX_SUFFIX: &str = "_SELF_DISABLER_TX";

// UTXOs
pub const OPERATOR_TAKE_ENABLER: &str = "operator_take_enabler";
pub const OPERATOR_WON_ENABLER: &str = "operator_won_enabler";
pub const ADVANCE_FUNDS_INPUT: &str = "advance_funds_input";
pub const LAST_OPERATOR_TAKE_UTXO: &str = "last_operator_take_utxo";
pub const SETUP_DISABLER_OP_DIRECTORY_UTXO: &str = "setup_disabler_op_directory_utxo";
pub const SETUP_DISABLER_WT_DIRECTORY_UTXO: &str = "setup_disabler_wt_directory_utxo";

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
    pub member_index: usize,
    pub funding_utxo: PartialUtxo,
}

impl DisputeCoreData {
    pub fn name() -> String {
        "dispute_core_data".to_string()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitData {
    pub committee_id: Uuid,
    pub member_index: usize,
    pub watchtower_utxo: PartialUtxo,
}

impl InitData {
    pub fn name() -> String {
        "init_data".to_string()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PegInRequest {
    pub txid: Txid,
    pub amount: u64,
    pub accept_pegin_sighash: Vec<u8>,
    pub take_aggregated_key: PublicKey,
    pub operator_indexes: Vec<usize>,
    pub slot_index: usize,
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
    pub accept_pegin_sighash: Vec<u8>,
    pub accept_pegin_nonce: PubNonce,
    pub accept_pegin_signature: MaybeScalar,
    pub operator_take_sighash: Vec<u8>,
    pub operator_won_sighash: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PegOutRequest {
    pub committee_id: Uuid,
    pub stream_id: u64,
    pub packet_number: u64,
    pub slot_index: usize,
    pub amount: u64,
    pub pegout_id: Vec<u8>,
    pub pegout_signature_hash: Vec<u8>,
    pub pegout_signature_message: Vec<u8>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullPenalizationData {
    pub committee_id: Uuid,
}

impl FullPenalizationData {
    pub fn name() -> String {
        "full_penalization_data".to_string()
    }
}
