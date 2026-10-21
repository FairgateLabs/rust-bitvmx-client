use bitvmx_broker::identification::identifier::PubkHash;

use crate::errors::BitVMXError;
use rsa::{
    pkcs1::DecodeRsaPublicKey,
    pkcs8::{DecodePublicKey, EncodePublicKey, LineEnding},
    RsaPublicKey,
};
use sha2::{Digest, Sha256};

fn invalid_rsa_public_key(verification_key: &str) -> BitVMXError {
    BitVMXError::InvalidMessage(format!("Invalid RSA public key: {}", verification_key))
}

/// Parses an RSA public key announced as SPKI (`PUBLIC KEY`) or PKCS#1 (`RSA PUBLIC KEY`) PEM.
fn parse_rsa_public_key(verification_key: &str) -> Result<RsaPublicKey, BitVMXError> {
    RsaPublicKey::from_public_key_pem(verification_key)
        .or_else(|_| RsaPublicKey::from_pkcs1_pem(verification_key))
        .map_err(|_| invalid_rsa_public_key(verification_key))
}

/// The fingerprint is computed over the SPKI DER, so both encodings of a key have the same one.
pub fn compute_pubkey_hash(verification_key: &str) -> Result<PubkHash, BitVMXError> {
    let rsa_pubkey = parse_rsa_public_key(verification_key)?;
    let der = rsa_pubkey
        .to_public_key_der()
        .map_err(|_| invalid_rsa_public_key(verification_key))?;
    let digest = Sha256::digest(der.as_bytes());
    Ok(hex::encode(digest))
}

/// Re-encodes an announced verification key as SPKI PEM, the only encoding signature verification parses.
pub fn canonical_verification_key(verification_key: &str) -> Result<String, BitVMXError> {
    parse_rsa_public_key(verification_key)?
        .to_public_key_pem(LineEnding::LF)
        .map_err(|_| invalid_rsa_public_key(verification_key))
}
