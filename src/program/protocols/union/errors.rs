use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error, Serialize, Deserialize)]
pub enum ProtocolErrorType {
    #[error("Invalid sighash (expected {expected:?}, found {found:?})")]
    InvalidSighash { expected: String, found: String },
}

#[derive(Debug, Error, Serialize, Deserialize)]
#[error("Error in protocol {protocol_name} (uuid={uuid}): {source}")]
pub struct ProtocolError {
    pub uuid: Uuid,
    pub protocol_name: String,
    #[source]
    pub source: ProtocolErrorType,
}

impl ProtocolError {
    pub fn name() -> String {
        "protocol_error".to_string()
    }
}
