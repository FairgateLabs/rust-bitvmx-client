use crate::{errors::ParseError, program::participant::ParticipantKeys};
#[cfg(test)]
use bitcoin::{key::Secp256k1, PublicKey};
#[cfg(test)]
use key_manager::winternitz::{WinternitzPublicKey, WinternitzType};

use crate::errors::BitVMXError;
use bitvmx_operator_comms::operator_comms::PubKeyHash;
use key_manager::musig2::{types::MessageId, PartialSignature, PubNonce};
use rsa::{
    pkcs1::DecodeRsaPublicKey,
    pkcs8::{DecodePublicKey, EncodePublicKey},
    RsaPublicKey,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub fn parse_keys(value: Value) -> Result<Vec<(PubKeyHash, ParticipantKeys)>, ParseError> {
    let keys: Vec<(PubKeyHash, ParticipantKeys)> =
        serde_json::from_value(value).map_err(|_| ParseError::InvalidParticipantKeys)?;
    if keys.is_empty() {
        return Err(ParseError::InvalidParticipantKeys);
    }
    Ok(keys)
}

pub type PubNonceMessage = Vec<(
    bitcoin::PublicKey,
    bitcoin::PublicKey,
    Vec<(MessageId, PubNonce)>,
)>;

pub fn parse_nonces(data: Value) -> Result<Vec<(PubKeyHash, PubNonceMessage)>, ParseError> {
    Ok(serde_json::from_value(data).map_err(|_| ParseError::InvalidNonces))?
}

pub type PartialSignatureMessage = Vec<(
    bitcoin::PublicKey,
    bitcoin::PublicKey,
    Vec<(MessageId, PartialSignature)>,
)>;

pub fn parse_signatures(
    data: Value,
) -> Result<Vec<(PubKeyHash, PartialSignatureMessage)>, ParseError> {
    Ok(serde_json::from_value(data).map_err(|_| ParseError::InvalidPartialSignatures))?
}

pub fn compute_pubkey_hash(verification_key: &str) -> Result<PubKeyHash, BitVMXError> {
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

#[test]
fn keys_encoding_test() -> Result<(), anyhow::Error> {
    let _secp = Secp256k1::new();

    let protocol = "026e14224899cf9c780fef5dd200f92a28cc67f71c0af6fe30b5657ffc943f08f4"
        .parse::<PublicKey>()
        .unwrap();

    let speedup_key = "026e14224899cf9c780fef5dd200f92a28cc67f71c0af6fe30b5657ffc943f08f4"
        .parse::<PublicKey>()
        .unwrap();

    let timelock_key = "026e14224899cf9c780fef5dd200f92a28cc67f71c0af6fe30b5657ffc943f08f4"
        .parse::<PublicKey>()
        .unwrap();

    let program_input =
        WinternitzPublicKey::from_bytes(&[0u8; 32], WinternitzType::SHA256).unwrap();

    let program_ending_state =
        WinternitzPublicKey::from_bytes(&[0u8; 32], WinternitzType::SHA256).unwrap();

    let program_ending_step_number =
        WinternitzPublicKey::from_bytes(&[0u8; 32], WinternitzType::SHA256).unwrap();

    let dp = WinternitzPublicKey::from_bytes(&[0u8; 32], WinternitzType::SHA256).unwrap();
    let dispute_resolution: Vec<WinternitzPublicKey> = vec![dp];

    let keys = vec![
        ("protocol".to_string(), protocol.into()),
        ("speedup".to_string(), speedup_key.into()),
        ("timelock".to_string(), timelock_key.into()),
        (
            "program_input_key".to_string(),
            program_input.clone().into(),
        ),
        (
            "program_ending_state".to_string(),
            program_ending_state.clone().into(),
        ),
        (
            "program_ending_step_number".to_string(),
            program_ending_step_number.clone().into(),
        ),
        (
            "dispute_resolution".to_string(),
            dispute_resolution[0].clone().into(),
        ),
    ];

    let participant = ParticipantKeys::new(keys, vec![]);

    let participant_value = serde_json::to_value(&participant)?;

    let parsed = serde_json::from_value(participant_value)
        .map_err(|_| ParseError::InvalidParticipantKeys)?;

    assert_eq!(participant, parsed);

    Ok(())
}
