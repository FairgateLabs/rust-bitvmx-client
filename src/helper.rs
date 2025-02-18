use std::str::FromStr;

use bitcoin::{
    key::{constants, rand, Keypair, Secp256k1},
    PublicKey, XOnlyPublicKey,
};
use bitvmx_musig2::{PartialSignature, PubNonce};
use key_manager::winternitz::{WinternitzPublicKey, WinternitzType};

use crate::{errors::ParseError, program::participant::ParticipantKeys};

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

pub fn bytes_to_participant_keys(value: Vec<u8>) -> Result<(), ParseError> {
    if value.len() != (1 * 32 + 1 * 33) {
        println!("Invalid byte length");
        println!("Value: {:?}", value.len());
        // return Err(ParseError::InvalidPublicKey);
    }

    let pre_kickoff_key =
        XOnlyPublicKey::from_slice(&value[0..32]).map_err(|_| ParseError::InvalidPublicKey)?; //32
    let internal_key =
        PublicKey::from_slice(&value[32..65]).map_err(|_| ParseError::InvalidPublicKey)?; //33
    let protocol_key =
        PublicKey::from_slice(&value[65..98]).map_err(|_| ParseError::InvalidPublicKey)?; //33
    let speedup_key =
        PublicKey::from_slice(&value[98..131]).map_err(|_| ParseError::InvalidPublicKey)?; //33
    let timelock_key =
        PublicKey::from_slice(&value[131..163]).map_err(|_| ParseError::InvalidPublicKey)?; //32

    let program_ending_step_number =
        WinternitzPublicKey::from_bytes(value[20..205].try_into().unwrap(), WinternitzType::SHA256)
            .unwrap();
    // let dispute_resolution_key =
    //     Vec::new(PublicKey::from_slice(&value[213..]).map_err(|_| ParseError::InvalidPublicKey)?);

    // Ok(ParticipantKeys::new(
    //     pre_kickoff_key,
    //     internal_key,
    //     protocol_key,
    //     speedup_key,
    //     timelock_key,
    //     program_ending_state,
    //     program_ending_step_number,
    //     dispute_resolution,
    // ))

    Ok(())
}

#[test]
fn keys_encoding_test() -> Result<(), anyhow::Error> {
    let secp = Secp256k1::new();
    let keypair = Keypair::new(&secp, &mut rand::thread_rng());

    // Extract the XOnlyPublicKey
    let (pre_kickoff_key, _) = XOnlyPublicKey::from_keypair(&keypair);

    let internal_key = "026e14224899cf9c780fef5dd200f92a28cc67f71c0af6fe30b5657ffc943f08f4"
        .parse::<PublicKey>()
        .unwrap();

    let protocol_key = "026e14224899cf9c780fef5dd200f92a28cc67f71c0af6fe30b5657ffc943f08f4"
        .parse::<PublicKey>()
        .unwrap();

    let speedup_key = "026e14224899cf9c780fef5dd200f92a28cc67f71c0af6fe30b5657ffc943f08f4"
        .parse::<PublicKey>()
        .unwrap();

    let timelock_key = "026e14224899cf9c780fef5dd200f92a28cc67f71c0af6fe30b5657ffc943f08f4"
        .parse::<PublicKey>()
        .unwrap();

    let program_ending_state =
        WinternitzPublicKey::from_bytes(&[0u8; 32], WinternitzType::SHA256).unwrap();
    println!(
        "program_ending_state: {:?}",
        program_ending_state.to_bytes()
    );

    let mut pub_key_bytes = Vec::new();

    pub_key_bytes.extend_from_slice(&pre_kickoff_key.serialize()); // pre_kickoff
    pub_key_bytes.extend_from_slice(&internal_key.to_bytes()); // internal
    pub_key_bytes.extend_from_slice(&protocol_key.to_bytes()); // protocol
    pub_key_bytes.extend_from_slice(&speedup_key.to_bytes()); // speedup
    pub_key_bytes.extend_from_slice(&timelock_key.to_bytes()); // timelock
    pub_key_bytes.extend_from_slice(&program_ending_state.to_bytes()); // program_ending_step_number
                                                                       // pub_key_bytes.extend_from_slice(&dispute_resolution_key.to_bytes()); // dispute_resolution

    let pub_key_final = bytes_to_participant_keys(pub_key_bytes)?;

    println!("protocol_key: {:?}", pub_key_final);
    //assert_eq!(protocol_key, *pub_key_final.protocol_key());

    Ok(())
}
