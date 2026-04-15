use crate::{
    errors::BitVMXError,
    program::protocols::{
        dispute::DisputeResolutionProtocol, gc_drp::GCDisputeResolutionProtocol,
        protocol_handler::ProtocolType,
    },
};

impl ProtocolType {
    pub fn dispute(&self) -> Result<&DisputeResolutionProtocol, BitVMXError> {
        match self {
            ProtocolType::DisputeResolutionProtocol(protocol) => Ok(protocol),
            _ => Err(BitVMXError::InvalidMessageType),
        }
    }

    pub fn gc_drp(&self) -> Result<&GCDisputeResolutionProtocol, BitVMXError> {
        match self {
            ProtocolType::GCDisputeResolutionProtocol(protocol) => Ok(protocol),
            _ => Err(BitVMXError::InvalidMessageType),
        }
    }
}
