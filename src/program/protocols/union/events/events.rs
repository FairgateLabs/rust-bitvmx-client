use bitcoin::PublicKey;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fmt::Display};

use crate::program::participant::{P2PAddress, ParticipantRole};


#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Event {
    MembersSelected {
        my_role: ParticipantRole,
        my_take_pubkey: PublicKey,
        my_dispute_pubkey: PublicKey,
        take_pubkeys: Vec<PublicKey>,
        dispute_pubkeys: Vec<PublicKey>,
        addresses: HashMap<PublicKey, P2PAddress>,
        operator_count: u32,
        watchtower_count: u32,
    }
}

impl Display for Event {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Event::MembersSelected { .. } => write!(f, "members_selected"),
        }
    }
}
