//! Shared with `rust-bitvmx-client-types` — this file is copied verbatim on release.
//! Node-only code does not belong here; put it in the sibling `mod.rs`.

use bitcoin::PublicKey;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::program::protocols::union::types::PAIRWISE_DISPUTE_KEY;

pub fn get_dispute_core_pid(committee_id: Uuid, pubkey: &PublicKey) -> Uuid {
    let mut hasher = Sha256::new();
    hasher.update(committee_id.as_bytes());
    hasher.update(pubkey.to_bytes());
    hasher.update("dispute_core");

    // Get the result as a byte array
    let hash = hasher.finalize();
    return Uuid::from_bytes(hash[0..16].try_into().unwrap());
}

pub fn get_accept_pegin_pid(committee_id: Uuid, slot_index: usize) -> Uuid {
    let mut hasher = Sha256::new();
    hasher.update(committee_id.as_bytes());
    hasher.update(&slot_index.to_be_bytes());
    hasher.update("accept_pegin");

    // Get the result as a byte array
    let hash = hasher.finalize();
    return Uuid::from_bytes(hash[0..16].try_into().unwrap());
}

pub fn get_advance_funds_pid(committee_id: Uuid, slot_index: usize) -> Uuid {
    let mut hasher = Sha256::new();
    hasher.update(committee_id.as_bytes());
    hasher.update(&slot_index.to_be_bytes());
    hasher.update("advance_funds");

    // Get the result as a byte array
    let hash = hasher.finalize();
    return Uuid::from_bytes(hash[0..16].try_into().unwrap());
}

pub fn get_user_take_pid(committee_id: Uuid, slot_index: usize) -> Uuid {
    let mut hasher = Sha256::new();
    hasher.update(committee_id.as_bytes());
    hasher.update(&slot_index.to_be_bytes());
    hasher.update("user_take");

    // Get the result as a byte array
    let hash = hasher.finalize();
    return Uuid::from_bytes(hash[0..16].try_into().unwrap());
}

pub fn get_take_aggreated_key_pid(committee_id: Uuid) -> Uuid {
    let mut hasher = Sha256::new();
    hasher.update(committee_id.as_bytes());
    hasher.update("take_aggregated_key");

    // Get the result as a byte array
    let hash = hasher.finalize();
    return Uuid::from_bytes(hash[0..16].try_into().unwrap());
}

pub fn get_dispute_aggregated_key_pid(committee_id: Uuid) -> Uuid {
    let mut hasher = Sha256::new();
    hasher.update(committee_id.as_bytes());
    hasher.update("dispute_aggregated_key");

    // Get the result as a byte array
    let hash = hasher.finalize();
    return Uuid::from_bytes(hash[0..16].try_into().unwrap());
}

pub fn get_dispute_pair_aggregated_key_pid(committee_id: Uuid, idx_a: usize, idx_b: usize) -> Uuid {
    let mut hasher = Sha256::new();
    // Ensure canonical ordering (min, max) so both parties derive the same id.
    let (min_i, max_i) = if idx_a <= idx_b {
        (idx_a, idx_b)
    } else {
        (idx_b, idx_a)
    };

    hasher.update(committee_id.as_bytes());
    hasher.update(&min_i.to_be_bytes());
    hasher.update(&max_i.to_be_bytes());
    hasher.update("pairwise_aggregated_key");

    let hash = hasher.finalize();
    Uuid::from_bytes(hash[0..16].try_into().unwrap())
}

pub fn get_dispute_pair_key_name(idx_a: usize, idx_b: usize) -> String {
    // Ensure canonical ordering (min, max) so both parties derive the same name.
    let (min_i, max_i) = if idx_a <= idx_b {
        (idx_a, idx_b)
    } else {
        (idx_b, idx_a)
    };

    double_indexed_name(PAIRWISE_DISPUTE_KEY, min_i, max_i)
}

// Deterministic id for a dispute-channel instance (directional): from_idx -> to_idx
pub fn get_dispute_channel_pid(committee_id: Uuid, op_index: usize, wt_index: usize) -> Uuid {
    let mut hasher = Sha256::new();

    hasher.update(committee_id.as_bytes());
    hasher.update(&op_index.to_be_bytes());
    hasher.update(&wt_index.to_be_bytes());
    hasher.update("dispute_channel");

    let hash = hasher.finalize();
    Uuid::from_bytes(hash[0..16].try_into().unwrap())
}

pub fn get_full_penalization_pid(committee_id: Uuid) -> Uuid {
    let mut hasher = Sha256::new();
    hasher.update(committee_id.as_bytes());
    hasher.update("full_penalization");

    // Get the result as a byte array
    let hash = hasher.finalize();
    return Uuid::from_bytes(hash[0..16].try_into().unwrap());
}

pub fn indexed_name(prefix: &str, index: usize) -> String {
    format!("{}_{}", prefix, index)
}

pub fn double_indexed_name(prefix: &str, index_1: usize, index_2: usize) -> String {
    format!("{}_{}_{}", prefix, index_1, index_2)
}

pub fn triple_indexed_name(prefix: &str, index_1: usize, index_2: usize, index_3: usize) -> String {
    format!("{}_{}_{}_{}", prefix, index_1, index_2, index_3)
}
