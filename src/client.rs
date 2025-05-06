use crate::{
    errors::ClientError,
    program::{
        participant::P2PAddress,
        variables::{VariableTypes, WitnessTypes},
    },
    types::{IncomingBitVMXApiMessages, OutgoingBitVMXApiMessages, BITVMX_ID},
};
use anyhow::Result;
use bitcoin::{Transaction, Txid};
use bitvmx_broker::{channel::channel::DualChannel, rpc::BrokerConfig};
use std::thread;
use std::time::{Duration, Instant};
use tracing::info;
use uuid::Uuid;

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
        leader_idx: u16,
    ) -> Result<()> {
        self.send_message(IncomingBitVMXApiMessages::SetupKey(
            id,
            participants,
            leader_idx,
        ))
    }

    pub fn get_aggregated_pubkey(&self, id: Uuid) -> Result<()> {
        self.send_message(IncomingBitVMXApiMessages::GetAggregatedPubkey(id))
    }

    pub fn generate_zkp(&self, id: Uuid, input: u32) -> Result<()> {
        self.send_message(IncomingBitVMXApiMessages::GenerateZKP(id, input))
    }

    pub fn proof_ready(&self) -> Result<()> {
        self.send_message(IncomingBitVMXApiMessages::ProofReady())
    }

    pub fn execute_zkp(&self) -> Result<()> {
        self.send_message(IncomingBitVMXApiMessages::ExecuteZKP())
    }

    pub fn get_zkp_execution_result(&self) -> Result<()> {
        self.send_message(IncomingBitVMXApiMessages::GetZKPExecutionResult())
    }

    pub fn finalize(&self) -> Result<()> {
        self.send_message(IncomingBitVMXApiMessages::Finalize())
    }

    pub fn get_transaction(&self, request_id: Uuid, txid: Txid) -> Result<()> {
        self.send_message(IncomingBitVMXApiMessages::GetTransaction(request_id, txid))
    }

    pub fn subscribe_to_transaction(&self, request_id: Uuid, txid: Txid) -> Result<()> {
        self.send_message(IncomingBitVMXApiMessages::SubscribeToTransaction(
            request_id, txid,
        ))
    }

    pub fn subscribe_utxo(&self) -> Result<()> {
        self.send_message(IncomingBitVMXApiMessages::SubscribeUTXO())
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
        info!("Sending message to {}: {:?}", BITVMX_ID, serialized);
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

    fn serialize_key(s: &str) -> String {
        s.to_string()
    }
}
