use bitvmx_broker::identification::identifier::PubkHash;

use crate::errors::BitVMXError;
use rsa::{
    pkcs1::DecodeRsaPublicKey,
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePublicKey, LineEnding},
    RsaPrivateKey, RsaPublicKey,
};
use sha2::{Digest, Sha256};

// The key is peer/L2 input of arbitrary size, so it is never echoed in errors.
fn invalid_rsa_public_key() -> BitVMXError {
    BitVMXError::InvalidMessage("Invalid RSA public key".to_string())
}

/// Parses an RSA public key given as SPKI (`PUBLIC KEY`) or PKCS#1 (`RSA PUBLIC KEY`) PEM.
fn parse_rsa_public_key(verification_key: &str) -> Result<RsaPublicKey, BitVMXError> {
    RsaPublicKey::from_public_key_pem(verification_key)
        .or_else(|_| RsaPublicKey::from_pkcs1_pem(verification_key))
        .map_err(|_| invalid_rsa_public_key())
}

/// The fingerprint is computed over the SPKI DER, so both encodings of a key have the same one.
pub fn compute_pubkey_hash(verification_key: &str) -> Result<PubkHash, BitVMXError> {
    let der = parse_rsa_public_key(verification_key)?
        .to_public_key_der()
        .map_err(|_| invalid_rsa_public_key())?;
    let digest = Sha256::digest(der.as_bytes());
    Ok(hex::encode(digest))
}

/// Re-encodes a verification key as SPKI PEM, the only encoding signature verification parses.
/// Uses the default line ending, like `RSAKeyPair::export_public_pem`.
pub fn canonical_verification_key(verification_key: &str) -> Result<String, BitVMXError> {
    parse_rsa_public_key(verification_key)?
        .to_public_key_pem(LineEnding::default())
        .map_err(|_| invalid_rsa_public_key())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TestProgramContextEnv;
    use bitvmx_settings::settings;

    // Program::new checks peers' `pubkey_pem` against their `pubkey_hash`, so
    // our hash must equal the broker's PubkHash for the same key.
    #[test]
    fn pubkey_hash_matches_broker_identity() {
        let env = TestProgramContextEnv::new_with_peers("helper-pubkey-hash", 1).unwrap();

        assert_eq!(
            compute_pubkey_hash(&env.context.rsa_public_key).unwrap(),
            env.context.comms.get_pubk_hash()
        );

        let private_key = settings::decrypt_or_read_file("config/keys/op_2.key").unwrap();
        let pem = rsa_public_key_pem(&private_key).unwrap();
        assert_eq!(
            compute_pubkey_hash(&pem).unwrap(),
            env.peers[0].get_pubk_hash()
        );
    }

    #[test]
    fn rsa_public_key_pem_rejects_invalid_private_key() {
        assert!(matches!(
            rsa_public_key_pem("not a key"),
            Err(BitVMXError::InvalidMessage(_))
        ));
    }
}
