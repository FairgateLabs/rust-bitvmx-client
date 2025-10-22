use bitcoin::{PublicKey, Txid};
use key_manager::musig2::{secp::MaybeScalar, PubNonce};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::program::{participant::ParticipantRole, variables::PartialUtxo};

// Key names
pub const TAKE_AGGREGATED_KEY: &str = "TAKE_AGGREGATED_KEY";
pub const DISPUTE_AGGREGATED_KEY: &str = "DISPUTE_AGGREGATED_KEY";
pub const SELECTED_OPERATOR_PUBKEY: &str = "SELECTED_OPERATOR_PUBKEY";
pub const REIMBURSEMENT_KICKOFF_IN_PROGRESS: &str = "REIMBURSEMENT_KICKOFF_IN_PROGRESS";
pub const OP_INITIAL_DEPOSIT_FLAG: &str = "OP_INITIAL_DEPOSIT_FLAG";
pub const OPERATOR_LEAF_INDEX: &str = "OPERATOR_LEAF_INDEX";
pub const SPEEDUP_KEY: &str = "SPEEDUP_KEY";
pub const OP_INITIAL_DEPOSIT_TXID: &str = "OP_INITIAL_DEPOSIT_TXID";
pub const OP_INITIAL_DEPOSIT_AMOUNT: &str = "OP_INITIAL_DEPOSIT_AMOUNT";
pub const OP_INITIAL_DEPOSIT_OUT_SCRIPT: &str = "OP_INITIAL_DEPOSIT_OUT_SCRIPT";

// Transaction names
pub const REQUEST_PEGIN_TX: &str = "REQUEST_PEGIN_TX";
pub const ACCEPT_PEGIN_TX: &str = "ACCEPT_PEGIN_TX";
pub const USER_TAKE_TX: &str = "USER_TAKE_TX";
pub const ADVANCE_FUNDS_TX: &str = "ADVANCE_FUNDS_TX";
pub const OPERATOR_TAKE_TX: &str = "OPERATOR_TAKE_TX";
pub const OPERATOR_WON_TX: &str = "OPERATOR_WON_TX";
pub const OP_INITIAL_DEPOSIT_TX: &str = "OP_INITIAL_DEPOSIT_TX";
pub const REIMBURSEMENT_KICKOFF_TX: &str = "REIMBURSEMENT_KICKOFF_TX";
pub const TWO_DISPUTE_PENALIZATION_TX: &str = "TWO_DISPUTE_PENALIZATION_TX";
pub const CHALLENGE_TX: &str = "CHALLENGE_TX";
pub const REVEAL_INPUT_TX: &str = "REVEAL_INPUT_TX";
pub const INPUT_NOT_REVEALED_TX: &str = "INPUT_NOT_REVEALED_TX";
pub const OP_SELF_DISABLER_TX: &str = "OP_SELF_DISABLER_TX";
pub const OP_DISABLER_TX: &str = "OP_DISABLER_TX";
pub const OP_LAZY_DISABLER_TX: &str = "OP_LAZY_DISABLER_TX";
pub const OP_DISABLER_DIRECTORY_TX: &str = "OP_DISABLER_DIRECTORY_TX";
pub const FUNDING_TX: &str = "FUNDING_TX";
pub const WT_START_ENABLER_TX: &str = "WT_START_ENABLER_TX";
pub const PROTOCOL_FUNDING_TX: &str = "PROTOCOL_FUNDING_TX";

// Parameters
pub const DISPUTE_CORE_SHORT_TIMELOCK: u16 = 1;
pub const DISPUTE_CORE_LONG_TIMELOCK: u16 = 6;
pub const DUST_VALUE: u64 = 540;
pub const SPEEDUP_VALUE: u64 = 540;
pub const P2TR_FEE: u64 = 335; // This should match the value P2TR_FEE in Union Smart contracts
pub const USER_TAKE_FEE: u64 = 335; // This should match the value USER_TAKE_FEE in Union Smart contracts
pub const OP_DISABLER_FEE: u64 = 240;

// Suffixes
pub const SELF_DISABLER_TX_SUFFIX: &str = "_SELF_DISABLER_TX";

// UTXOs
pub const OPERATOR_TAKE_ENABLER: &str = "OPERATOR_TAKE_ENABLER";
pub const OPERATOR_WON_ENABLER: &str = "OPERATOR_WON_ENABLER";
pub const ADVANCE_FUNDS_INPUT: &str = "ADVANCE_FUNDS_INPUT";
pub const LAST_OPERATOR_TAKE_UTXO: &str = "LAST_OPERATOR_TAKE_UTXO";
pub const OP_DISABLER_DIRECTORY_UTXO: &str = "OP_DISABLER_DIRECTORY_UTXO";
pub const WT_DISABLER_DIRECTORY_UTXO: &str = "WT_DISABLER_DIRECTORY_UTXO";

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
