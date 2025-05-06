use bitcoin::{Transaction, Txid};
use uuid::Uuid;

use crate::{errors::BitVMXError, program::participant::P2PAddress};

pub trait BitVMXApi {
    fn ping(&mut self, from: u32) -> Result<(), BitVMXError>;

    fn setup_key(
        &mut self,
        from: u32,
        id: Uuid,
        participants: Vec<P2PAddress>,
        leader_idx: u16,
    ) -> Result<(), BitVMXError>;

    fn setup(
        &mut self,
        id: Uuid,
        program_type: String,
        peer_address: Vec<P2PAddress>,
        leader: u16,
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

    fn generate_zkp(&mut self, id: Uuid, input: u32) -> Result<(), BitVMXError>;

    fn proof_ready(&mut self) -> Result<(), BitVMXError>;

    fn execute_zkp(&mut self) -> Result<(), BitVMXError>;

    fn get_zkp_execution_result(&mut self) -> Result<(), BitVMXError>;

    fn finalize(&mut self) -> Result<(), BitVMXError>;

    fn get_transaction(&mut self, from: u32, id: Uuid, txid: Txid) -> Result<(), BitVMXError>;

    fn subscribe_to_tx(&mut self, from: u32, id: Uuid, txid: Txid) -> Result<(), BitVMXError>;

    fn subscribe_utxo(&mut self) -> Result<(), BitVMXError>;

    fn get_var(&mut self, from: u32, id: Uuid, key: &str) -> Result<(), BitVMXError>;

    fn get_witness(&mut self, from: u32, id: Uuid, key: &str) -> Result<(), BitVMXError>;
}
