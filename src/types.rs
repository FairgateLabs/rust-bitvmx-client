use crate::keychain::KeyChain;
use chrono::{DateTime, Utc};
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

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum ProgramStatusStore {
    SettingUp,
    Ready,
    Completed,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProgramStatus {
    pub program_id: Uuid,
    pub state: ProgramStatusStore,
}

impl ProgramStatus {
    pub fn new(program_id: Uuid) -> Self {
        Self {
            program_id,
            state: ProgramStatusStore::SettingUp,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProgramRequestInfo {
    pub retries: u32,
    pub last_request_time: DateTime<Utc>,
}

impl ProgramRequestInfo {
    pub fn new() -> Self {
        Self {
            retries: 0,
            last_request_time: Utc::now(),
        }
    }
}

impl Default for ProgramRequestInfo {
    fn default() -> Self {
        Self {
            retries: 0,
            last_request_time: Utc::now(),
        }
    }
}
