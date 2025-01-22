use bitcoin::{PublicKey, XOnlyPublicKey};
use key_manager::winternitz::WinternitzPublicKey;
use p2p_handler::PeerId;
use std::fmt;

#[derive(Clone)]
pub struct Participant {
    address: P2PAddress,
    keys: Option<ParticipantKeys>,
}

impl Participant {
    pub fn new(address: &P2PAddress, keys: Option<ParticipantKeys>) -> Self {
        Participant {
            address: address.clone(),
            keys,
        }
    }

    pub fn address(&self) -> &P2PAddress {
        &self.address
    }

    pub fn keys(&self) -> &Option<ParticipantKeys> {
        &self.keys
    }

    /* CHECK: Is this function necessary ?
    pub fn prekickoff_key(&self) -> Option<PublicKey> {
        match &self.keys {
            Some(keys) => Some(keys.prekickoff_key().clone()),
            None => None,
        }
    }

    pub fn timelock_key(&self) -> Option<PublicKey> {
        match &self.keys {
            Some(keys) => Some(keys.timelock_key().clone()),
            None => None,
        }
    }

    pub fn speedup_key(&self) -> Option<PublicKey> {
        match &self.keys {
            Some(keys) => Some(keys.speedup_key().clone()),
            None => None,
        }
    }

    pub fn protocol_key(&self) -> Option<PublicKey> {
        match &self.keys {
            Some(keys) => Some(keys.protocol_key().clone()),
            None => None,
        }
    }

    pub fn internal_key(&self) -> Option<XOnlyPublicKey> {
        match &self.keys {
            Some(keys) => Some(keys.internal_key().clone()),
            None => None,
        }
    }

    pub fn dispute_resolution_keys(&self) -> Option<Vec<WinternitzPublicKey>> {
        match &self.keys {
            Some(keys) => Some(keys.dispute_resolution_keys().clone()),
            None => None,
        }
    }

    pub fn keys(&self) -> Option<ParticipantKeys> {
        self.keys.clone()
    }*/

    pub fn set_keys(&mut self, keys: ParticipantKeys) {
        self.keys = Some(keys);
    }
}

#[derive(Clone, PartialEq)]
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

impl ParticipantRole {
    pub fn counterparty_role(&self) -> ParticipantRole {
        match self {
            ParticipantRole::Prover => ParticipantRole::Verifier,
            ParticipantRole::Verifier => ParticipantRole::Prover,
        }
    }
}
#[derive(Clone)]
pub struct ParticipantKeys {
    pre_kickoff: PublicKey,
    internal: XOnlyPublicKey,
    protocol: PublicKey,
    speedup: PublicKey,
    timelock: PublicKey,
    program_ending_state: WinternitzPublicKey,
    program_ending_step_number: WinternitzPublicKey,
    dispute_resolution: Vec<WinternitzPublicKey>,
}

impl ParticipantKeys {
    pub fn new(
        pre_kickoff: PublicKey,
        internal: XOnlyPublicKey,
        protocol: PublicKey,
        speedup: PublicKey,
        timelock: PublicKey,
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
            program_ending_state,
            program_ending_step_number,
            dispute_resolution,
        }
    }

    pub fn get_keys(&self) -> Vec<u8> {
        // TODO: Implement
        vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
    }

    pub fn check_if_keys(&self, keys: Vec<u8>) -> bool {
        // TODO: Implement
        if keys == vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9] {
            true
        } else {
            false
        }
    }

    pub fn protocol_key(&self) -> &PublicKey {
        &self.protocol
    }

    pub fn internal_key(&self) -> &XOnlyPublicKey {
        &self.internal
    }

    pub fn speedup_key(&self) -> &PublicKey {
        &self.speedup
    }

    pub fn timelock_key(&self) -> &PublicKey {
        &self.timelock
    }

    pub fn prekickoff_key(&self) -> &PublicKey {
        &self.pre_kickoff
    }

    pub fn program_ending_state_key(&self) -> &WinternitzPublicKey {
        &self.program_ending_state
    }

    pub fn program_ending_step_number_key(&self) -> &WinternitzPublicKey {
        &self.program_ending_step_number
    }

    pub fn dispute_resolution_keys(&self) -> &Vec<WinternitzPublicKey> {
        &self.dispute_resolution
    }
}

#[derive(PartialEq, Clone)]
pub struct P2PAddress {
    address: String,
    peer_id: PeerId,
}

impl P2PAddress {
    pub fn new(address: &str, peer_id: PeerId) -> Self {
        Self {
            address: address.to_string(),
            peer_id,
        }
    }

    pub fn address(&self) -> &str {
        &self.address
    }

    pub fn peer_id(&self) -> &PeerId {
        &self.peer_id
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
