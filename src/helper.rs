use crate::{errors::ParseError, program::participant::ParticipantKeys};
#[cfg(test)]
use bitcoin::{key::Secp256k1, PublicKey};
#[cfg(test)]
use key_manager::winternitz::{WinternitzPublicKey, WinternitzType};

use key_manager::musig2::{types::MessageId, PartialSignature, PubNonce};
use serde_json::Value;

pub fn parse_keys(value: Value) -> Result<ParticipantKeys, ParseError> {
    let participant_keys: ParticipantKeys =
        serde_json::from_value(value).map_err(|_| ParseError::InvalidParticipantKeys)?;

    Ok(participant_keys)
}

type PubNonceMessage = (bitcoin::PublicKey, Vec<(MessageId, PubNonce)>);

pub fn parse_nonces(data: Value) -> Result<PubNonceMessage, ParseError> {
    let nonces: PubNonceMessage =
        serde_json::from_value(data).map_err(|_| ParseError::InvalidNonces)?;

    Ok(nonces)
}

type PartialSignatureMessage = (bitcoin::PublicKey, Vec<(MessageId, PartialSignature)>);

pub fn parse_signatures(data: Value) -> Result<PartialSignatureMessage, ParseError> {
    let signatures: PartialSignatureMessage =
        serde_json::from_value(data).map_err(|_| ParseError::InvalidPartialSignatures)?;

    Ok(signatures)
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

    let participant = ParticipantKeys::new(keys);

    let participant_value = serde_json::to_value(&participant)?;
    let pub_key_final = parse_keys(participant_value)?;

    assert_eq!(participant, pub_key_final);

    Ok(())
}
