use bitcoin::PublicKey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::program::participant::{P2PAddress, ParticipantRole};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitteeCreated {
    pub my_role: ParticipantRole,
    pub my_take_pubkey: PublicKey,
    pub my_dispute_pubkey: PublicKey,
    pub take_aggregated_key: PublicKey,
    pub dispute_aggregated_key: PublicKey,
    pub addresses: HashMap<PublicKey, P2PAddress>,
    pub operator_count: u32,
    pub watchtower_count: u32,
}

impl CommitteeCreated {
    pub fn name() -> String {
        "committee_created".to_string()
    }
}
