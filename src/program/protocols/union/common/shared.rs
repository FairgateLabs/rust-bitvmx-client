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
    // FIXME: Make this derivation operator-aware and define protocol-id reuse so AdvanceFunds is
    // never triggered twice for the same operator and slot.
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

#[cfg(test)]
mod tests {
    //! Pins the nine derived program ids to literal UUIDs. Drift here (a changed salt string or
    //! hash input order) produces no runtime error anywhere in the protocol — the program is
    //! simply never found. These tests are the only alarm for that class of bug.
    //!
    //! The literal UUIDs below were captured from these tests' own failure output, never
    //! computed by hand and never copied from the union repo.
    use std::str::FromStr;

    use super::*;

    fn committee_id() -> Uuid {
        Uuid::from_str("00000000-0000-0000-0000-000000000042").unwrap()
    }

    fn pubkey() -> PublicKey {
        PublicKey::from_str("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
            .unwrap()
    }

    #[test]
    fn dispute_core_pid_is_pinned() {
        let actual = get_dispute_core_pid(committee_id(), &pubkey());
        assert_eq!(actual.to_string(), "56c7752e-956c-da39-58fb-b68e3a6ef484");
    }

    #[test]
    fn accept_pegin_pid_is_pinned() {
        let actual = get_accept_pegin_pid(committee_id(), 7);
        assert_eq!(actual.to_string(), "60a1d53c-0d8c-1832-e2ac-0b446cc22ef0");
    }

    #[test]
    fn advance_funds_pid_is_pinned() {
        let actual = get_advance_funds_pid(committee_id(), 7);
        assert_eq!(actual.to_string(), "29c4f6fa-a06f-bd4f-aae5-ed1e30a1da8e");
    }

    #[test]
    fn user_take_pid_is_pinned() {
        let actual = get_user_take_pid(committee_id(), 7);
        assert_eq!(actual.to_string(), "a5aa3764-3044-7e54-faf8-fefb23c223d0");
    }

    #[test]
    fn take_aggreated_key_pid_is_pinned() {
        let actual = get_take_aggreated_key_pid(committee_id());
        assert_eq!(actual.to_string(), "f203b47d-f062-1c1d-947f-47669a59b1bb");
    }

    #[test]
    fn dispute_aggregated_key_pid_is_pinned() {
        let actual = get_dispute_aggregated_key_pid(committee_id());
        assert_eq!(actual.to_string(), "2487b8b7-f77f-3a5e-b5e1-d0d28d945fe0");
    }

    #[test]
    fn dispute_pair_aggregated_key_pid_is_pinned() {
        let actual = get_dispute_pair_aggregated_key_pid(committee_id(), 3, 9);
        assert_eq!(actual.to_string(), "05a5559e-90f1-3ba0-a141-e6d8bdc8f1b1");
    }

    #[test]
    fn dispute_channel_pid_is_pinned() {
        let actual = get_dispute_channel_pid(committee_id(), 3, 9);
        assert_eq!(actual.to_string(), "eef6f9eb-bfed-cce5-d570-67fbaf5402ae");
    }

    #[test]
    fn full_penalization_pid_is_pinned() {
        let actual = get_full_penalization_pid(committee_id());
        assert_eq!(actual.to_string(), "c232abbd-92dc-91ab-703a-102d8b0b3b1d");
    }
}
