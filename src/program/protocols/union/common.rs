use bitcoin::PublicKey;
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub fn get_dispute_core_id(committee_id: Uuid, pubkey: &PublicKey) -> Uuid {
    let mut hasher = Sha256::new();
    hasher.update(committee_id.as_bytes());
    hasher.update(pubkey.to_bytes());

    // Get the result as a byte array
    let hash = hasher.finalize();
    return Uuid::from_bytes(hash[0..16].try_into().unwrap());
}
