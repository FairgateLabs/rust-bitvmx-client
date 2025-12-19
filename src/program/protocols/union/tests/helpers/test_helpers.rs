use bitcoin::secp256k1::{PublicKey as Secp256k1PublicKey, Secp256k1, SecretKey};
use bitcoin::PublicKey;
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const DUST_THRESHOLD: u64 = 546;
pub const BASE_TX_WEIGHT: u64 = 46;
pub const INPUT_WEIGHT: u64 = 68;
pub const OUTPUT_WEIGHT: u64 = 34;
pub const SATOSHIS_PER_BITCOIN: u64 = 100_000_000;
pub const MAX_BITCOIN_SUPPLY: u64 = 21_000_000 * SATOSHIS_PER_BITCOIN;

pub fn test_pubkey(seed: &str) -> PublicKey {
    let secp = Secp256k1::new();
    let mut hasher = Sha256::new();
    hasher.update(b"test_key:");
    hasher.update(seed.as_bytes());
    let hash = hasher.finalize();
    let secret = SecretKey::from_slice(&hash).expect("valid key");
    PublicKey::new(Secp256k1PublicKey::from_secret_key(&secp, &secret))
}

pub fn test_committee(label: &str) -> Uuid {
    let mut hasher = Sha256::new();
    hasher.update(b"test_committee:");
    hasher.update(label.as_bytes());
    let hash = hasher.finalize();
    Uuid::from_bytes(hash[..16].try_into().unwrap())
}

pub fn test_key(name: &str, index: usize) -> String {
    format!("{}_{}", name, index)
}

pub fn dust_amount(multiplier: u64) -> u64 {
    DUST_THRESHOLD * multiplier
}


