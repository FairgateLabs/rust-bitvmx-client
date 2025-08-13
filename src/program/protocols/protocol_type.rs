use crate::{
    errors::BitVMXError,
    program::protocols::{dispute::DisputeResolutionProtocol, protocol_handler::ProtocolType},
};

impl ProtocolType {
    pub fn dispute(self) -> Result<DisputeResolutionProtocol, BitVMXError> {
        match self {
            ProtocolType::DisputeResolutionProtocol(protocol) => Ok(protocol),
            _ => Err(BitVMXError::InvalidMessageType),
        }
    }
}
