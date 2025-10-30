use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::program::protocols::union::types::ProtocolName;

#[derive(Debug, Error, Serialize, Deserialize)]
pub enum ProtocolErrorType {
    #[error("Invalid sighash (expected {expected:?}, found {found:?})")]
    InvalidSighash { expected: Vec<u8>, found: Vec<u8> },
}

#[derive(Debug, Error, Serialize, Deserialize)]
#[error("Error in protocol {protocol:?} (uuid={uuid}): {source}")]
pub struct ProtocolError {
    pub uuid: Uuid,
    pub protocol: ProtocolName,
    #[source]
    pub source: ProtocolErrorType,
}

impl ProtocolError {
    pub fn name() -> String {
        "protocol_error".to_string()
    }
}
