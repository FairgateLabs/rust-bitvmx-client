use crate::{
    program::participant::{P2PAddress, ParticipantRole},
    types::{IncomingBitVMXApiMessages, OutgoingBitVMXApiMessages, BITVMX_ID},
};
use anyhow::Result;
use bitcoin::{Transaction, Txid};
use bitvmx_broker::{channel::channel::DualChannel, rpc::BrokerConfig};
use protocol_builder::types::Utxo;
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
        role: ParticipantRole,
        address: P2PAddress,
        utxo: Utxo,
    ) -> Result<()> {
        self.send_message(IncomingBitVMXApiMessages::SetupProgram(
            id, role, address, utxo,
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

    pub fn generate_zkp(&self) -> Result<()> {
        self.send_message(IncomingBitVMXApiMessages::GenerateZKP())
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

    pub fn subscribe_tx(&self, request_id: Uuid, txid: Txid) -> Result<()> {
        self.send_message(IncomingBitVMXApiMessages::SubscribeToTransaction(
            request_id, txid,
        ))
    }

    pub fn subscribe_utxo(&self) -> Result<()> {
        self.send_message(IncomingBitVMXApiMessages::SubscribeUTXO())
    }

    pub fn send_message(&self, msg: IncomingBitVMXApiMessages) -> Result<()> {
        // BitVMX instance uses ID 1 by convention
        let serialized = serde_json::to_string(&msg)?;
        info!("Sending message to {}: {:?}", BITVMX_ID, serialized);
        self.channel.send(BITVMX_ID, serialized)?;
        Ok(())
    }

    /// Busy wait for a message from the broker
    pub fn wait_message(&self) -> Result<OutgoingBitVMXApiMessages> {
        // TODO: add timeout
        // TODO: add sleep
        let (msg, _from) = loop {
            if let Some(message) = self.get_message()? {
                break message;
            }
        };
        Ok(msg)
    }

    pub fn get_message(&self) -> Result<Option<(OutgoingBitVMXApiMessages, u32)>> {
        if let Ok(Some((msg, from))) = self.channel.recv() {
            let dezerialized = serde_json::from_str(&msg)?;
            Ok(Some((dezerialized, from)))
        } else {
            Ok(None)
        }
    }
}
