use bitcoin::PublicKey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::program::participant::{P2PAddress, ParticipantRole};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MembersSelected {
    pub my_role: ParticipantRole,
    pub my_take_pubkey: PublicKey,
    pub my_dispute_pubkey: PublicKey,
    pub take_pubkeys: Vec<PublicKey>,
    pub dispute_pubkeys: Vec<PublicKey>,
    pub addresses: HashMap<PublicKey, P2PAddress>,
    pub operator_count: u32,
    pub watchtower_count: u32,
}

impl MembersSelected {
    pub fn name() -> String {
        "members_selected".to_string()
    }
}
