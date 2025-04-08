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

    fn setup_key(&mut self) -> Result<(), BitVMXError>;

    fn get_aggregated_pubkey(&mut self) -> Result<(), BitVMXError>;

    fn generate_zkp(&mut self) -> Result<(), BitVMXError>;

    fn proof_ready(&mut self) -> Result<(), BitVMXError>;

    fn execute_zkp(&mut self) -> Result<(), BitVMXError>;

    fn get_zkp_execution_result(&mut self) -> Result<(), BitVMXError>;

    fn finalize(&mut self) -> Result<(), BitVMXError>;

    fn get_tx(&mut self) -> Result<(), BitVMXError>;

    fn subscribe_to_tx(&mut self) -> Result<(), BitVMXError>;

    fn subscribe_utxo(&mut self) -> Result<(), BitVMXError>;
} 
