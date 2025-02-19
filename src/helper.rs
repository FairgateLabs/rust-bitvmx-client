use crate::{errors::ParseError, program::participant::ParticipantKeys};
use bitcoin::{
    key::{constants, rand, Keypair, Secp256k1},
    PublicKey, XOnlyPublicKey,
};
use bitvmx_musig2::{PartialSignature, PubNonce};
use key_manager::winternitz::{WinternitzPublicKey, WinternitzType};

pub fn bytes_to_nonce(value: Vec<u8>) -> Result<PubNonce, ParseError> {
    let nonce = PubNonce::from_bytes(&value).map_err(|_| ParseError::InvalidNonce)?;
    Ok(nonce)
}

pub fn bytes_to_nonces(value: Vec<u8>) -> Result<Vec<PubNonce>, ParseError> {
    let mut nonces = Vec::new();

    for i in 0..value.len() / constants::PUBLIC_KEY_SIZE {
        let nonce_bytes =
            value[i * constants::PUBLIC_KEY_SIZE..(i + 1) * constants::PUBLIC_KEY_SIZE].to_vec();
        let nonce = bytes_to_nonce(nonce_bytes)?;
        nonces.push(nonce);
    }

    Ok(nonces)
}

pub fn nonces_to_bytes(nonces: Vec<PubNonce>) -> Result<Vec<u8>, ParseError> {
    let mut bytes = Vec::new();

    for nonce in nonces {
        bytes.extend(nonce.serialize());
    }

    Ok(bytes)
}

pub fn bytes_to_signature(data: Vec<u8>) -> Result<PartialSignature, ParseError> {
    let signature =
        PartialSignature::from_slice(&data).map_err(|_| ParseError::InvalidSignature)?;

    Ok(signature)
}

pub fn bytes_to_signatures(data: Vec<u8>) -> Result<Vec<PartialSignature>, ParseError> {
    let mut signatures = Vec::new();

    for i in 0..data.len() / constants::COMPACT_SIGNATURE_SIZE {
        let signature_bytes = data
            [i * constants::COMPACT_SIGNATURE_SIZE..(i + 1) * constants::COMPACT_SIGNATURE_SIZE]
            .to_vec();
        let signature = bytes_to_signature(signature_bytes)?;
        signatures.push(signature);
    }

    Ok(signatures)
}

#[test]
fn nonce_enconding_test() -> Result<(), anyhow::Error> {
    let mut rng = bitcoin::key::rand::thread_rng();
    let sec_nonce = bitvmx_musig2::SecNonce::random(&mut rng);
    let nonce = sec_nonce.public_nonce();
    let deserialized = bytes_to_nonce(nonce.serialize().to_vec())?;
    assert_eq!(nonce, deserialized);
    Ok(())
}

pub fn bytes_to_participant_keys(value: Vec<u8>) -> Result<ParticipantKeys, ParseError> {
    let value_str = String::from_utf8(value).map_err(|_| ParseError::InvalidParticipantKeys)?;
    let participant_keys: ParticipantKeys =
        serde_json::from_str(&value_str).map_err(|_| ParseError::InvalidParticipantKeys)?;

    Ok(participant_keys)
}

#[test]
fn keys_encoding_test() -> Result<(), anyhow::Error> {
    let secp = Secp256k1::new();
    let keypair = Keypair::new(&secp, &mut rand::thread_rng());

    let pre_kickoff = "026e14224899cf9c780fef5dd200f92a28cc67f71c0af6fe30b5657ffc943f08f4"
        .parse::<PublicKey>()
        .unwrap();

    let (internal, _) = XOnlyPublicKey::from_keypair(&keypair);

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

    let participant = ParticipantKeys::new(
        pre_kickoff,
        internal,
        protocol,
        speedup_key,
        timelock_key,
        program_input,
        program_ending_state,
        program_ending_step_number,
        dispute_resolution,
    );

    let serialized = serde_json::to_string(&participant)?;
    let vec_bytes = serialized.as_bytes().to_vec();
    let pub_key_final = bytes_to_participant_keys(vec_bytes)?;

    assert_eq!(participant, pub_key_final);

    Ok(())
}
