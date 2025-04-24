use bitcoin::{Transaction, Txid};
use protocol_builder::types::Utxo;
use uuid::Uuid;

use crate::{
    errors::BitVMXError,
    program::participant::{P2PAddress, ParticipantRole},
};

pub trait BitVMXApi {
    fn ping(&mut self, from: u32) -> Result<(), BitVMXError>;

    fn setup_key(
        &mut self,
        from: u32,
        id: Uuid,
        participants: Vec<P2PAddress>,
        leader_idx: u16,
    ) -> Result<(), BitVMXError>;

    fn setup_slot(
        &mut self,
        id: Uuid,
        peer_address: Vec<P2PAddress>,
        leader: u16,
    ) -> Result<(), BitVMXError>;

    fn setup_program(
        &mut self,
        id: Uuid,
        role: ParticipantRole,
        peer_address: P2PAddress,
        utxo: Utxo,
    ) -> Result<(), BitVMXError>;

    fn dispatch_transaction_name(&mut self, id: Uuid, name: &str) -> Result<(), BitVMXError>;

    fn dispatch_transaction(
        &mut self,
        from: u32,
        id: Uuid,
        tx: Transaction,
    ) -> Result<(), BitVMXError>;

    fn handle_message(&mut self, msg: String, from: u32) -> Result<(), BitVMXError>;

    fn get_aggregated_pubkey(&mut self, from: u32, id: Uuid) -> Result<(), BitVMXError>;

    fn generate_zkp(&mut self) -> Result<(), BitVMXError>;

    fn proof_ready(&mut self) -> Result<(), BitVMXError>;

    fn execute_zkp(&mut self) -> Result<(), BitVMXError>;

    fn get_zkp_execution_result(&mut self) -> Result<(), BitVMXError>;

    fn finalize(&mut self) -> Result<(), BitVMXError>;

    fn get_transaction(&mut self, from: u32, id: Uuid, txid: Txid) -> Result<(), BitVMXError>;

    fn subscribe_to_tx(&mut self, from: u32, id: Uuid, txid: Txid) -> Result<(), BitVMXError>;

    fn subscribe_utxo(&mut self) -> Result<(), BitVMXError>;
}
