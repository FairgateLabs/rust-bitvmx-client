//! Shared with `rust-bitvmx-client-types` — this file is copied verbatim on release.
//! Node-only code does not belong here; put it in the sibling `mod.rs`.

use bitcoin::{PublicKey, Txid};
use key_manager::musig2::{secp::MaybeScalar, PubNonce};
use protocol_builder::types::OutputType;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use crate::{
    program::{
        participant::ParticipantRole, protocols::union::common::indexed_name,
        variables::PartialUtxo,
    },
    spv_proof::BtcTxSPVProof,
};

// Key names
pub const TAKE_AGGREGATED_KEY: &str = "TAKE_AGGREGATED_KEY";
pub const DISPUTE_AGGREGATED_KEY: &str = "DISPUTE_AGGREGATED_KEY";
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
pub const OPERATOR_PENALIZED: &str = "OPERATOR_PENALIZED";
pub const WATCHTOWER_PENALIZED: &str = "WATCHTOWER_PENALIZED";
pub const MY_IDX: &str = "MY_IDX";

// UnionMessage keys
pub const COMMITTEE: &str = "committee";
pub const DISPUTE_CORE_DATA: &str = "dispute_core_data";
pub const INIT_DATA: &str = "init_data";
pub const PEGIN_REQUEST: &str = "pegin_request";
pub const REJECT_PEGIN_DATA: &str = "reject_pegin_data";
pub const PEGOUT_REQUEST: &str = "pegout_request";
pub const PEGOUT_ACCEPTED: &str = "pegout_accepted";
pub const ADVANCE_FUNDS_REQUEST: &str = "advance_funds_request";
pub const FUNDS_ADVANCED: &str = "funds_advanced";
pub const FUNDS_ADVANCE_SPV: &str = "funds_advance_spv";
pub const UNION_SPV_NOTIFICATION: &str = "union_spv_notification";
pub const FULL_PENALIZATION_DATA: &str = "full_penalization_data";
pub const UNION_SETTINGS: &str = "union_settings";

// Transaction names
pub const REQUEST_PEGIN_TX: &str = "REQUEST_PEGIN_TX";
pub const REJECT_PEGIN_TX: &str = "REJECT_PEGIN_TX";
pub const ACCEPT_PEGIN_TX: &str = "ACCEPT_PEGIN_TX";
pub const CANCEL_TAKE0_TX: &str = "CANCEL_TAKE0_TX";
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
    pub pegin_confirmations: u32,
    pub pegout_confirmations: u32,
    pub reject_pegin_confirmations: u32,
}

impl Committee {
    pub fn name() -> String {
        COMMITTEE.to_string()
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
        DISPUTE_CORE_DATA.to_string()
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
        INIT_DATA.to_string()
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
        PEGIN_REQUEST.to_string()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RejectPeginData {
    pub txid: Txid,
    pub committee_id: Uuid,
    pub member_index: usize,
}

impl RejectPeginData {
    pub fn name() -> String {
        REJECT_PEGIN_DATA.to_string()
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
    pub slot_index: usize,
    pub amount: u64,
    pub pegout_id: Vec<u8>,
    pub user_pubkey: PublicKey,
    pub pegout_sighash: Vec<u8>,
    pub take_aggregated_key: PublicKey,
}

impl PegOutRequest {
    pub fn name() -> String {
        PEGOUT_REQUEST.to_string()
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
        PEGOUT_ACCEPTED.to_string()
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
        ADVANCE_FUNDS_REQUEST.to_string()
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
        FUNDS_ADVANCED.to_string()
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
        FUNDS_ADVANCE_SPV.to_string()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvanceFundsRegistered {
    pub committee_id: Uuid,
    pub slot_index: usize,
    pub txid: Txid,
    pub pegout_id: Vec<u8>,
    pub operator_pubkey: PublicKey,
}

impl AdvanceFundsRegistered {
    pub fn name(slot_id: usize) -> String {
        indexed_name("ADVANCED_FUNDS", slot_id)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UnionTxType {
    ReimbursementKickoff,
    OperatorTake,
    OperatorWon,
    Challenge,
    RevealInput,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnionSPVNotification {
    pub txid: Txid,
    pub committee_id: Uuid,
    pub slot_index: usize,
    pub spv_proof: Option<BtcTxSPVProof>,
    pub tx_type: UnionTxType,
}

impl UnionSPVNotification {
    pub fn name() -> String {
        UNION_SPV_NOTIFICATION.to_string()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullPenalizationData {
    pub committee_id: Uuid,
}

impl FullPenalizationData {
    pub fn name() -> String {
        FULL_PENALIZATION_DATA.to_string()
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
    pub request_pegin_timelock: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnionSettings {
    pub settings: HashMap<u64, StreamSettings>,
}

impl UnionSettings {
    pub fn name() -> String {
        UNION_SETTINGS.to_string()
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PenalizedMember {
    pub member_index: usize,
    pub role: ParticipantRole,
    pub challenger_index: usize,
}

impl PenalizedMember {
    pub fn storage_name(&self) -> String {
        PenalizedMember::name(self.member_index, &self.role)
    }

    pub fn name(index: usize, role: &ParticipantRole) -> String {
        match role {
            ParticipantRole::Verifier => indexed_name(WATCHTOWER_PENALIZED, index),
            ParticipantRole::Prover => indexed_name(OPERATOR_PENALIZED, index),
        }
    }
}
