use bitcoin::Transaction;
use uuid::Uuid;

use crate::{
    errors::BitVMXError,
    program::{
        dispute::Funding,
        participant::{P2PAddress, ParticipantRole},
    },
};

pub trait BitVMXApi {
    fn ping(&mut self, from: u32) -> Result<(), BitVMXError>;
    
    fn setup_program(
        &mut self,
        id: Uuid,
        role: ParticipantRole,
        peer_address: P2PAddress,
        funding: Funding,
    ) -> Result<(), BitVMXError>;

    fn dispatch_transaction(&mut self, id: Uuid, tx: Transaction) -> Result<(), BitVMXError>;

    fn handle_message(&mut self, msg: String, from: u32) -> Result<(), BitVMXError>;
} 
