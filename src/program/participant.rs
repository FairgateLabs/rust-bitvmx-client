use bitcoin::{PublicKey, XOnlyPublicKey};
use key_manager::winternitz::WinternitzPublicKey;
use p2p_handler::PeerId;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ParticipantData {
    pub p2p_address: P2PAddress,
    pub keys: Option<ParticipantKeys>,
}

impl ParticipantData {
    pub fn new(address: &P2PAddress, keys: Option<ParticipantKeys>) -> Self {
        ParticipantData {
            p2p_address: address.clone(),
            keys,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ParticipantRole {
    Prover,
    Verifier,
}

impl fmt::Display for ParticipantRole {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ParticipantRole::Prover => write!(f, "Prover"),
            ParticipantRole::Verifier => write!(f, "Verifier"),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct ParticipantKeys {
    pub pre_kickoff: PublicKey,
    pub internal: XOnlyPublicKey,
    pub protocol: PublicKey,
    pub speedup: PublicKey,
    pub timelock: PublicKey,
    pub program_input_key: WinternitzPublicKey,
    pub program_ending_state: WinternitzPublicKey,
    pub program_ending_step_number: WinternitzPublicKey,
    pub dispute_resolution: Vec<WinternitzPublicKey>,
}

impl ParticipantKeys {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pre_kickoff: PublicKey,
        internal: XOnlyPublicKey,
        protocol: PublicKey,
        speedup: PublicKey,
        timelock: PublicKey,
        program_input_key: WinternitzPublicKey,
        program_ending_state: WinternitzPublicKey,
        program_ending_step_number: WinternitzPublicKey,
        dispute_resolution: Vec<WinternitzPublicKey>,
    ) -> Self {
        Self {
            pre_kickoff,
            internal,
            protocol,
            speedup,
            timelock,
            program_input_key,
            program_ending_state,
            program_ending_step_number,
            dispute_resolution,
        }
    }

    pub fn get_keys(&self) -> Vec<u8> {
        // TODO: Implement
        vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
    }
}

#[derive(PartialEq, Clone, Serialize, Deserialize, Debug)]
pub struct P2PAddress {
    pub address: String,
    pub peer_id: PeerId,
}

impl P2PAddress {
    pub fn new(address: &str, peer_id: PeerId) -> Self {
        Self {
            address: address.to_string(),
            peer_id,
        }
    }

    pub fn address_bytes(&self) -> Vec<u8> {
        self.address.as_bytes().to_vec().clone()
    }

    pub fn peer_id_bytes(&self) -> Vec<u8> {
        self.peer_id.to_string().as_bytes().to_vec().clone()
    }

    pub fn peer_id_bs58(&self) -> String {
        self.peer_id.to_base58()
    }
}
