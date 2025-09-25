use crate::{
    config::{BrokerConfig, Component, ComponentsConfig},
    errors::ClientError,
    program::{
        participant::CommsAddress,
        variables::{VariableTypes, WitnessTypes},
    },
    types::{IncomingBitVMXApiMessages, OutgoingBitVMXApiMessages},
};
use anyhow::Result;
use bitcoin::{PublicKey, Transaction, Txid};
use bitvmx_broker::{
    channel::channel::DualChannel,
    identification::identifier::Identifier,
    rpc::{self, tls_helper::Cert},
};
use bitvmx_wallet::wallet::Destination;
use operator_comms::operator_comms::AllowList;
use std::time::{Duration, Instant};
use std::{
    sync::{Arc, Mutex},
    thread,
};
use uuid::Uuid;

#[derive(Clone)]
pub struct BitVMXClient {
    channel: DualChannel,
    components_config: ComponentsConfig,
}

impl BitVMXClient {
    pub fn new(
        components_config: &ComponentsConfig,
        broker_config: &BrokerConfig,
        client_config: &Component,
        allow_list: Arc<Mutex<AllowList>>,
    ) -> Result<Self> {
        let config =
            rpc::BrokerConfig::new(broker_config.port, None, broker_config.get_pubk_hash()?);
        let channel = DualChannel::new(
            &config,
            Cert::from_key_file(&client_config.priv_key)?,
            Some(client_config.id),
            allow_list,
        )?;

        Ok(Self {
            components_config: components_config.clone(),
            channel,
        })
    }

    pub fn ping(&self) -> Result<()> {
        self.send_message(IncomingBitVMXApiMessages::Ping())
    }

    pub fn setup(
        &self,
        id: Uuid,
        program_type: String,
        addresses: Vec<CommsAddress>,
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
        participants: Vec<CommsAddress>,
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
        self.channel
            .send(self.components_config.get_bitvmx_identifier()?, serialized)?;
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

    pub fn get_message(&self) -> Result<Option<(OutgoingBitVMXApiMessages, Identifier)>> {
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
    /// * `public_key` - The public key to encrypt the messages with as PEM string
    pub fn encrypt(&self, id: Uuid, messages: Vec<u8>, public_key: String) -> Result<()> {
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

    pub fn get_funding_address(&self, id: Uuid) -> Result<()> {
        self.send_message(IncomingBitVMXApiMessages::GetFundingAddress(id))
    }

    pub fn get_funding_balance(&self, id: Uuid) -> Result<()> {
        self.send_message(IncomingBitVMXApiMessages::GetFundingBalance(id))
    }

    pub fn send_funds(
        &self,
        id: Uuid,
        destination: Destination,
        fee_rate: Option<u64>,
    ) -> Result<()> {
        self.send_message(IncomingBitVMXApiMessages::SendFunds(
            id,
            destination,
            fee_rate,
        ))
    }

    fn serialize_key(s: &str) -> String {
        s.to_string()
    }
}
