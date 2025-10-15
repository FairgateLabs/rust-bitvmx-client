use crate::{errors::BitVMXError, program::participant::CommsAddress};
use bitcoin::{PublicKey, Transaction, Txid};
use bitvmx_broker::identification::identifier::Identifier;
use uuid::Uuid;

pub trait BitVMXApi {
    fn ping(&mut self, from: Identifier, uuid: Uuid) -> Result<Uuid, BitVMXError>;

    fn setup_key(
        &mut self,
        from: Identifier,
        id: Uuid,
        participants: Vec<CommsAddress>,
        participants_keys: Option<Vec<PublicKey>>,
        leader_idx: u16,
    ) -> Result<(), BitVMXError>;

    fn setup(
        &mut self,
        id: Uuid,
        program_type: String,
        peer_address: Vec<CommsAddress>,
        leader: u16,
    ) -> Result<(), BitVMXError>;

    fn dispatch_transaction_name(&mut self, id: Uuid, name: &str) -> Result<(), BitVMXError>;

    fn dispatch_transaction(
        &mut self,
        from: Identifier,
        id: Uuid,
        tx: Transaction,
    ) -> Result<(), BitVMXError>;

    fn handle_message(&mut self, msg: String, from: Identifier) -> Result<(), BitVMXError>;

    fn get_aggregated_pubkey(&mut self, from: Identifier, id: Uuid) -> Result<(), BitVMXError>;

    fn generate_zkp(
        &mut self,
        from: Identifier,
        id: Uuid,
        input: Vec<u8>,
        elf_file_path: String,
    ) -> Result<(), BitVMXError>;

    fn proof_ready(&mut self, from: Identifier, id: Uuid) -> Result<(), BitVMXError>;

    fn get_zkp_execution_result(&mut self, from: Identifier, id: Uuid) -> Result<(), BitVMXError>;

    fn get_transaction(
        &mut self,
        from: Identifier,
        id: Uuid,
        txid: Txid,
    ) -> Result<(), BitVMXError>;

    fn subscribe_to_tx(
        &mut self,
        from: Identifier,
        id: Uuid,
        txid: Txid,
    ) -> Result<(), BitVMXError>;

    fn subscribe_utxo(&mut self, uuid: Uuid) -> Result<Uuid, BitVMXError>;

    fn subscribe_to_rsk_pegin(&mut self) -> Result<(), BitVMXError>;

    fn get_var(&mut self, from: Identifier, id: Uuid, key: &str) -> Result<(), BitVMXError>;

    fn get_witness(&mut self, from: Identifier, id: Uuid, key: &str) -> Result<(), BitVMXError>;

    fn handle_prover_message(&mut self, msg: String) -> Result<(), BitVMXError>;

    fn get_spv_proof(&mut self, from: Identifier, txid: Txid) -> Result<(), BitVMXError>;
}
