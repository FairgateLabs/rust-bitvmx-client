use sha2::{Digest, Sha256};
use uuid::Uuid;

pub fn get_next_uuid(seed: Uuid) -> Uuid {
    let mut hasher = Sha256::new();
    hasher.update(seed.as_bytes());

    // Get the result as a byte array
    let hash = hasher.finalize();

    return Uuid::from_bytes(hash[0..16].try_into().unwrap());
}

pub fn get_covenant_id_by_index(covenant_seed: Uuid, member_index: usize) -> Uuid {
    let mut seed = get_next_uuid(covenant_seed);
    for _ in 0..member_index {
        seed = get_next_uuid(seed);
    }
    seed
}
