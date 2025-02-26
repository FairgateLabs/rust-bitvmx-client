use crate::keychain::KeyChain;
use p2p_handler::P2pHandler;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub struct ProgramContext {
    pub key_chain: KeyChain,
    pub comms: P2pHandler,
}

impl ProgramContext {
    pub fn new(comms: P2pHandler, key_chain: KeyChain) -> Self {
        Self { comms, key_chain }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProgramStatus {
    pub program_id: Uuid,
    pub is_active: bool,
}

impl ProgramStatus {
    pub fn new(program_id: Uuid) -> Self {
        Self {
            program_id,
            is_active: true,
        }
    }
}
