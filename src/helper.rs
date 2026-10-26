use bitvmx_broker::identification::identifier::PubkHash;

use crate::errors::BitVMXError;
use rsa::{
    pkcs1::DecodeRsaPublicKey,
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePublicKey, LineEnding},
    RsaPrivateKey, RsaPublicKey,
};
use sha2::{Digest, Sha256};

pub fn compute_pubkey_hash(verification_key: &str) -> Result<PubkHash, BitVMXError> {
    let rsa_pubkey = RsaPublicKey::from_public_key_pem(verification_key)
        .or_else(|_| RsaPublicKey::from_pkcs1_pem(verification_key))
        .map_err(|_| {
            BitVMXError::InvalidMessage(
                format!("Invalid RSA public key: {}", verification_key).to_string(),
            )
        })?;
    let der = rsa_pubkey.to_public_key_der().map_err(|_| {
        BitVMXError::InvalidMessage(
            format!("Invalid RSA public key: {}", verification_key).to_string(),
        )
    })?;
    let digest = Sha256::digest(der.as_bytes());
    Ok(hex::encode(digest))
}

/// PEM public key of a PKCS#8 PEM private key (e.g. a comms key file).
pub fn rsa_public_key_pem(private_key: &str) -> Result<String, BitVMXError> {
    let invalid = || BitVMXError::InvalidMessage("Invalid RSA private key".to_string());
    RsaPrivateKey::from_pkcs8_pem(private_key)
        .map_err(|_| invalid())?
        .to_public_key()
        .to_public_key_pem(LineEnding::LF)
        .map_err(|_| invalid())
}
