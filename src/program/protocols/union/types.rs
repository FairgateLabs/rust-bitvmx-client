use bitcoin::{PublicKey, Txid};
use key_manager::musig2::{secp::MaybeScalar, PubNonce};
use protocol_builder::types::OutputType;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use crate::{
    program::{participant::ParticipantRole, variables::PartialUtxo},
    spv_proof::BtcTxSPVProof,
};

// Key names
pub const TAKE_AGGREGATED_KEY: &str = "TAKE_AGGREGATED_KEY";
pub const DISPUTE_AGGREGATED_KEY: &str = "DISPUTE_AGGREGATED_KEY";
pub const SELECTED_OPERATOR_PUBKEY: &str = "SELECTED_OPERATOR_PUBKEY";
pub const REVEAL_IN_PROGRESS: &str = "REVEAL_IN_PROGRESS";
pub const OP_INITIAL_DEPOSIT_FLAG: &str = "OP_INITIAL_DEPOSIT_FLAG";
pub const SPEEDUP_KEY: &str = "SPEEDUP_KEY";
pub const OP_INITIAL_DEPOSIT_TXID: &str = "OP_INITIAL_DEPOSIT_TXID";
pub const OP_INITIAL_DEPOSIT_AMOUNT: &str = "OP_INITIAL_DEPOSIT_AMOUNT";
pub const OP_INITIAL_DEPOSIT_OUT_SCRIPT: &str = "OP_INITIAL_DEPOSIT_OUT_SCRIPT";
pub const WT_START_ENABLER_UTXOS: &str = "WT_START_ENABLER_UTXOS";
pub const WT_CLAIM_SUCCESS_DISABLER_DIRECTORY_UTXO: &str =
    "WT_CLAIM_SUCCESS_DISABLER_DIRECTORY_UTXO";
pub const OP_CLAIM_SUCCESS_DISABLER_DIRECTORY_UTXO: &str =
    "OP_CLAIM_SUCCESS_DISABLER_DIRECTORY_UTXO";
pub const WT_INIT_CHALLENGE_UTXOS: &str = "WT_INIT_CHALLENGE_UTXOS";
pub const OP_COSIGN_UTXOS: &str = "OP_COSIGN_UTXOS";
pub const PAIRWISE_DISPUTE_KEY: &str = "PAIRWISE_DISPUTE_KEY";

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
pub const WT_SELF_DISABLER_TX: &str = "WT_SELF_DISABLER_TX";
pub const OP_DISABLER_TX: &str = "OP_DISABLER_TX";
pub const WT_DISABLER_TX: &str = "WT_DISABLER_TX";
pub const WT_COSIGN_DISABLER_TX: &str = "WT_COSIGN_DISABLER_TX";
pub const OP_LAZY_DISABLER_TX: &str = "OP_LAZY_DISABLER_TX";
pub const OP_DISABLER_DIRECTORY_TX: &str = "OP_DISABLER_DIRECTORY_TX";
pub const WT_DISABLER_DIRECTORY_TX: &str = "WT_DISABLER_DIRECTORY_TX";
pub const FUNDING_TX: &str = "FUNDING_TX";
pub const WT_START_ENABLER_TX: &str = "WT_START_ENABLER_TX";
pub const WT_INIT_CHALLENGE_TX: &str = "WT_INIT_CHALLENGE_TX";
pub const PROTOCOL_FUNDING_TX: &str = "PROTOCOL_FUNDING_TX";
pub const WT_CLAIM_GATE: &str = "WT_CLAIM_GATE";
pub const WT_CLAIM_GATE_SUCCESS: &str = "WT_CLAIM_GATE_SUCCESS";
pub const OP_CLAIM_GATE: &str = "OP_CLAIM_GATE";
pub const OP_CLAIM_GATE_SUCCESS: &str = "OP_CLAIM_GATE_SUCCESS";
pub const OP_COSIGN_TX: &str = "OP_COSIGN_TX";
pub const OP_NO_COSIGN_TX: &str = "OP_NO_COSIGN_TX";
pub const WT_NO_CHALLENGE_TX: &str = "WT_NO_CHALLENGE_TX";
pub const STOP_OP_WON_TX: &str = "STOP_OP_WON_TX";

// Parameters
pub const DUST_VALUE: u64 = 540;
pub const SPEEDUP_VALUE: u64 = 540;
pub const P2TR_FEE: u64 = 335; // This should match the value P2TR_FEE in Union Smart contracts
pub const USER_TAKE_FEE: u64 = 335; // This should match the value USER_TAKE_FEE in Union Smart contracts
pub const OP_DISABLER_FEE: u64 = 240;

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

pub const GLOBAL_SETTINGS_UUID: Uuid = Uuid::from_bytes(*b"UNION_BRIDGE-000");

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
    pub stream_denomination: u64,
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
    pub operator_take_sighash: Option<Vec<u8>>,
    pub operator_won_sighash: Option<Vec<u8>>,
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
pub struct FundsAdvanced {
    pub txid: Txid,
    pub committee_id: Uuid,
    pub slot_index: usize,
    pub pegout_id: Vec<u8>,
}

impl FundsAdvanced {
    pub fn name() -> String {
        "funds_advanced".to_string()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FundsAdvanceSPV {
    pub txid: Txid,
    pub committee_id: Uuid,
    pub slot_index: usize,
    pub pegout_id: Vec<u8>,
    pub spv_proof: Option<BtcTxSPVProof>,
}

impl FundsAdvanceSPV {
    pub fn name() -> String {
        "funds_advance_spv".to_string()
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamSettings {
    pub short_timelock: u16,
    pub long_timelock: u16,
    pub op_won_timelock: u16,
    pub claim_gate_timelock: u16,
    pub input_not_revealed_timelock: u16,
    pub op_no_cosign_timelock: u16,
    pub wt_no_challenge_timelock: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnionSettings {
    pub settings: HashMap<u64, StreamSettings>,
}

impl UnionSettings {
    pub fn name() -> String {
        "union_settings".to_string()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WtInitChallengeOutputs {
    pub op_cosign: OutputType,
    pub wt_stopper: OutputType,
    pub op_stopper: OutputType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WtInitChallengeUtxos {
    pub op_cosign: PartialUtxo,
    pub wt_stopper: PartialUtxo,
    pub op_stopper: PartialUtxo,
}
