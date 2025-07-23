use crate::{
    errors::ClientError,
    program::{
        participant::P2PAddress,
        variables::{VariableTypes, WitnessTypes},
    },
    types::{IncomingBitVMXApiMessages, OutgoingBitVMXApiMessages, BITVMX_ID},
};
use anyhow::Result;
use bitcoin::{PublicKey, Transaction, Txid};
use bitvmx_broker::{channel::channel::DualChannel, rpc::BrokerConfig};
use std::thread;
use std::time::{Duration, Instant};
use uuid::Uuid;

#[derive(Clone)]
pub struct BitVMXClient {
    channel: DualChannel,
    _client_id: u32,
}

impl BitVMXClient {
    pub fn new(broker_port: u16, client_id: u32) -> Self {
        let config = BrokerConfig::new(broker_port, None);
        let channel = DualChannel::new(&config, client_id);

        Self {
            channel,
            _client_id: client_id,
        }
    }

    pub fn ping(&self) -> Result<()> {
        self.send_message(IncomingBitVMXApiMessages::Ping())
    }

    pub fn setup(
        &self,
        id: Uuid,
        program_type: String,
        addresses: Vec<P2PAddress>,
        leader: u16,
    ) -> Result<()> {
        self.send_message(IncomingBitVMXApiMessages::Setup(
            id,
            program_type,
            addresses,
            leader,
        ))
    }

    pub fn dispatch_transaction(&self, id: Uuid, tx: Transaction) -> Result<()> {
        self.send_message(IncomingBitVMXApiMessages::DispatchTransaction(id, tx))
    }

    pub fn setup_key(
        &self,
        id: Uuid,
        participants: Vec<P2PAddress>,
        participants_keys: Option<Vec<PublicKey>>,
        leader_idx: u16,
    ) -> Result<()> {
        self.send_message(IncomingBitVMXApiMessages::SetupKey(
            id,
            participants,
            participants_keys,
            leader_idx,
        ))
    }

    pub fn get_aggregated_pubkey(&self, id: Uuid) -> Result<()> {
        self.send_message(IncomingBitVMXApiMessages::GetAggregatedPubkey(id))
    }

    pub fn get_pubkey(&self, id: Uuid, new: bool) -> Result<()> {
        self.send_message(IncomingBitVMXApiMessages::GetPubKey(id, new))
    }

    pub fn get_comm_info(&self) -> Result<()> {
        self.send_message(IncomingBitVMXApiMessages::GetCommInfo())
    }

    pub fn generate_zkp(&self, id: Uuid, input: Vec<u8>, elf_file_path: String) -> Result<()> {
        self.send_message(IncomingBitVMXApiMessages::GenerateZKP(
            id,
            input,
            elf_file_path,
        ))
    }

    pub fn proof_ready(&self, id: Uuid) -> Result<()> {
        self.send_message(IncomingBitVMXApiMessages::ProofReady(id))
    }

    pub fn get_zkp_execution_result(&self, id: Uuid) -> Result<()> {
        self.send_message(IncomingBitVMXApiMessages::GetZKPExecutionResult(id))
    }

    pub fn get_transaction(&self, request_id: Uuid, txid: Txid) -> Result<()> {
        self.send_message(IncomingBitVMXApiMessages::GetTransaction(request_id, txid))
    }

    pub fn get_transaction_by_name(&self, request_id: Uuid, name: String) -> Result<()> {
        self.send_message(IncomingBitVMXApiMessages::GetTransactionInfoByName(
            request_id, name,
        ))
    }

    pub fn subscribe_to_transaction(&self, request_id: Uuid, txid: Txid) -> Result<()> {
        self.send_message(IncomingBitVMXApiMessages::SubscribeToTransaction(
            request_id, txid,
        ))
    }

    pub fn subscribe_utxo(&self) -> Result<()> {
        self.send_message(IncomingBitVMXApiMessages::SubscribeUTXO())
    }

    pub fn subscribe_to_rsk_pegin(&self) -> Result<()> {
        self.send_message(IncomingBitVMXApiMessages::SubscribeToRskPegin())
    }

    pub fn get_spv_proof(&self, txid: Txid) -> Result<()> {
        self.send_message(IncomingBitVMXApiMessages::GetSPVProof(txid))
    }

    pub fn set_var(&self, program_id: Uuid, key: &str, value: VariableTypes) -> Result<()> {
        self.send_message(IncomingBitVMXApiMessages::SetVar(
            program_id,
            Self::serialize_key(key),
            value,
        ))
    }

    pub fn get_var(&self, id: Uuid, key: String) -> Result<()> {
        self.send_message(IncomingBitVMXApiMessages::GetVar(id, key))
    }

    pub fn set_witness(&self, id: Uuid, key: String, witness: WitnessTypes) -> Result<()> {
        self.send_message(IncomingBitVMXApiMessages::SetWitness(id, key, witness))
    }

    pub fn get_witness(&self, id: Uuid, key: String) -> Result<()> {
        self.send_message(IncomingBitVMXApiMessages::GetWitness(id, key))
    }

    pub fn send_message(&self, msg: IncomingBitVMXApiMessages) -> Result<()> {
        // BitVMX instance uses ID 1 by convention
        let serialized = serde_json::to_string(&msg)?;
        // info!("Sending message to {}: {:?}", BITVMX_ID, serialized);
        self.channel.send(BITVMX_ID, serialized)?;
        Ok(())
    }

    /// Busy wait for a message from the broker with configurable timeout and sleep duration
    ///
    /// # Arguments
    /// * `timeout` - Optional timeout duration. Default is 10 seconds.
    /// * `sleep_duration` - Optional sleep duration between checks. Default is 100ms.
    pub fn wait_message(
        &self,
        timeout: Option<Duration>,
        sleep_duration: Option<Duration>,
    ) -> Result<OutgoingBitVMXApiMessages> {
        let timeout = timeout.unwrap_or(Duration::from_secs(10));
        let sleep_duration = sleep_duration.unwrap_or(Duration::from_millis(100));
        let start = Instant::now();

        loop {
            if let Some((message, _from)) = self.get_message()? {
                return Ok(message);
            }

            if start.elapsed() > timeout {
                return Err(ClientError::MessageTimeout(timeout).into());
            }

            thread::sleep(sleep_duration);
        }
    }

    pub fn get_message(&self) -> Result<Option<(OutgoingBitVMXApiMessages, u32)>> {
        if let Ok(Some((msg, from))) = self.channel.recv() {
            let dezerialized = serde_json::from_str(&msg)?;
            Ok(Some((dezerialized, from)))
        } else {
            Ok(None)
        }
    }

    /// Encrypt a message for a given public key
    ///
    /// # Arguments
    /// * `id` - The ID of the message
    /// * `messages` - The messages to encrypt as bytes
    /// * `public_key` - The public key to encrypt the messages with as pkcs8 DER bytes
    pub fn encrypt(
        &self,
        id: Uuid,
        messages: Vec<u8>,
        public_key: Vec<u8>,
    ) -> Result<()> {
        self.send_message(IncomingBitVMXApiMessages::Encrypt(id, messages, public_key))
    }

    /// Decrypt a message with the client's private key
    ///
    /// # Arguments
    /// * `id` - The ID of the message
    /// * `messages` - The messages to decrypt as bytes
    pub fn decrypt(&self, id: Uuid, messages: Vec<u8>) -> Result<()> {
        self.send_message(IncomingBitVMXApiMessages::Decrypt(id, messages))
    }

    fn serialize_key(s: &str) -> String {
        s.to_string()
    }
}
