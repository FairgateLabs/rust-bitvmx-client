use std::str::FromStr;

use crate::{config::ComponentsConfig, spv_proof::BtcTxSPVProof};
use bitcoin::{address::NetworkUnchecked, Address, PrivateKey, PublicKey, Transaction, Txid};
use bitcoin_coordinator::{coordinator::BitcoinCoordinator, TransactionStatus};
use bitvmx_broker::{
    broker_storage::BrokerStorage,
    channel::{
        channel::{DualChannel, LocalChannel},
        queue_channel::QueueChannel,
    },
    identification::identifier::Identifier,
};
use bitvmx_wallet::wallet::Destination;
use chrono::{DateTime, Utc};
use protocol_builder::types::Utxo;
use redact::Secret;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    errors::BitVMXError,
    keychain::KeyChain,
    leader_broadcast::LeaderBroadcastHelper,
    program::{
        participant::CommsAddress,
        variables::{Globals, VariableTypes, WitnessTypes, WitnessVars},
    },
};

pub struct ProgramContext {
    pub key_chain: KeyChain,
    pub comms: QueueChannel,
    pub bitcoin_coordinator: BitcoinCoordinator,
    pub broker_channel: LocalChannel<BrokerStorage>,
    pub globals: Globals,
    pub witness: WitnessVars,
    pub components_config: ComponentsConfig,
    pub leader_broadcast_helper: LeaderBroadcastHelper,
}

impl ProgramContext {
    pub fn new(
        comms: QueueChannel,
        key_chain: KeyChain,
        bitcoin_coordinator: BitcoinCoordinator,
        broker_channel: LocalChannel<BrokerStorage>,
        globals: Globals,
        witness: WitnessVars,
        components_config: ComponentsConfig,
        leader_broadcast_helper: LeaderBroadcastHelper,
    ) -> Self {
        Self {
            comms,
            key_chain,
            bitcoin_coordinator,
            broker_channel,
            globals,
            witness,
            components_config,
            leader_broadcast_helper,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq)]
pub enum ProgramVersion {
    Legacy,
    V2,
}

impl Default for ProgramVersion {
    fn default() -> Self {
        // Default to Legacy for backward compatibility with existing programs
        ProgramVersion::Legacy
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProgramStatus {
    pub program_id: Uuid,
    #[serde(default)]
    pub version: ProgramVersion,
}

impl ProgramStatus {
    pub fn new(program_id: Uuid) -> Self {
        Self {
            program_id,
            version: ProgramVersion::Legacy,
        }
    }

    pub fn new_v2(program_id: Uuid) -> Self {
        Self {
            program_id,
            version: ProgramVersion::V2,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProgramRequestInfo {
    pub retries: u32,
    pub last_request_time: DateTime<Utc>,
}

impl ProgramRequestInfo {
    pub fn new() -> Self {
        Self {
            retries: 0,
            last_request_time: Utc::now(),
        }
    }
}

impl Default for ProgramRequestInfo {
    fn default() -> Self {
        Self {
            retries: 0,
            last_request_time: Utc::now(),
        }
    }
}

//TODO: This should be moved to a common place that could be used to share the messages api
#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum IncomingBitVMXApiMessages {
    Ping(Uuid),
    SetVar(Uuid, String, VariableTypes),
    SetWitness(Uuid, String, WitnessTypes),
    SetFundingUtxo(Utxo),
    GetVar(Uuid, String),
    GetWitness(Uuid, String),
    GetCommInfo(Uuid),
    GetTransaction(Uuid, Txid),
    GetTransactionInfoByName(Uuid, String),
    GetHashedMessage(Uuid, String, u32, u32),
    Setup(ProgramId, String, Vec<CommsAddress>, u16),
    SetupV2(ProgramId, String, Vec<CommsAddress>, u16),
    SubscribeToTransaction(Uuid, Txid),
    SubscribeUTXO(Uuid),
    SubscribeToRskPegin(),
    GetSPVProof(Txid),
    DispatchTransaction(Uuid, Transaction, Option<u32>),
    DispatchTransactionName(Uuid, String),
    SetupKey(Uuid, Vec<CommsAddress>, Option<Vec<PublicKey>>, u16),
    GetAggregatedPubkey(Uuid),
    GetKeyPair(Uuid),
    GetPubKey(Uuid, bool),
    SignMessage(Uuid, Vec<u8>, PublicKey), // id, payload_to_sign, public_key_to_use
    GenerateZKP(Uuid, Vec<u8>, String),
    ProofReady(Uuid),
    GetZKPExecutionResult(Uuid),
    Encrypt(Uuid, Vec<u8>, String),
    Decrypt(Uuid, Vec<u8>, String),
    #[serde(skip)]
    Backup(Uuid, String, String, Secret<String>),
    #[cfg(feature = "testpanic")]
    Test(String),
    GetFundingAddress(Uuid),
    GetFundingBalance(Uuid),
    SendFunds(Uuid, Destination, Option<u64>),
    GetProtocolVisualization(Uuid),
    Shutdown(),
}
impl IncomingBitVMXApiMessages {
    pub fn to_string(&self) -> Result<String, BitVMXError> {
        Ok(serde_json::to_string(self)?)
    }
}

type ProgramId = Uuid;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum OutgoingBitVMXApiMessages {
    Pong(Uuid),
    // response for transaction get and dispatch
    Transaction(Uuid, TransactionStatus, Option<String>),
    // Represents when pegin transactions is found
    PeginTransactionFound(Txid, TransactionStatus),
    // Represents when a spending utxo transaction is found
    SpendingUTXOTransactionFound(Uuid, Txid, u32, TransactionStatus),
    // Represents when a program is running out of funds
    SpeedUpProgramNoFunds(Txid),
    // Setup Completed,
    SetupCompleted(ProgramId),
    // Add response types for the new messages if needed
    AggregatedPubkey(Uuid, PublicKey),
    AggregatedPubkeyNotReady(Uuid),
    TransactionInfo(Uuid, String, Transaction),
    ZKPResult(Uuid, Vec<u8>, Vec<u8>),
    ExecutionResult(/* Add appropriate type */),
    CommInfo(Uuid, CommsAddress),
    KeyPair(Uuid, PrivateKey, PublicKey),
    PubKey(Uuid, PublicKey),
    SignedMessage(Uuid, [u8; 32], [u8; 32], u8), // id, signature_r, signature_s, recovery_id
    Variable(Uuid, String, VariableTypes),
    Witness(Uuid, String, WitnessTypes),
    NotFound(Uuid, String),
    HashedMessage(Uuid, String, u32, u32, String),
    ProofReady(Uuid),
    ProofNotReady(Uuid),
    ProofGenerationError(Uuid, String),
    SPVProof(Txid, Option<BtcTxSPVProof>),
    Encrypted(Uuid, Vec<u8>),
    Decrypted(Uuid, Vec<u8>),
    BackupResult(Uuid, bool, String),
    FundingAddress(Uuid, Address<NetworkUnchecked>),
    FundingBalance(Uuid, u64),
    FundsSent(Uuid, Txid),
    WalletNotReady(Uuid),
    WalletError(Uuid, String),
    ProtocolVisualization(Uuid, String),
    SetInput(Vec<u8>),
}

impl OutgoingBitVMXApiMessages {
    pub fn to_string(&self) -> Result<String, BitVMXError> {
        Ok(serde_json::to_string(self)?)
    }

    pub fn from_string(msg: &str) -> Result<Self, BitVMXError> {
        let msg: OutgoingBitVMXApiMessages = serde_json::from_str(msg)?;
        Ok(msg)
    }

    pub fn comm_info(&self) -> Option<(Uuid, CommsAddress)> {
        match self {
            OutgoingBitVMXApiMessages::CommInfo(uuid, info) => Some((uuid.clone(), info.clone())),
            _ => None,
        }
    }
    pub fn aggregated_pub_key(&self) -> Option<PublicKey> {
        match self {
            OutgoingBitVMXApiMessages::AggregatedPubkey(_, pub_key) => Some(pub_key.clone()),
            _ => None,
        }
    }

    pub fn transaction(&self) -> Option<(Uuid, TransactionStatus, Option<String>)> {
        match self {
            OutgoingBitVMXApiMessages::Transaction(uuid, status, tx) => {
                Some((uuid.clone(), status.clone(), tx.clone()))
            }
            _ => None,
        }
    }

    pub fn key_pair(&self) -> Option<(Uuid, PrivateKey, PublicKey)> {
        match self {
            OutgoingBitVMXApiMessages::KeyPair(uuid, priv_key, pub_key) => {
                Some((uuid.clone(), priv_key.clone(), pub_key.clone()))
            }
            _ => None,
        }
    }

    pub fn public_key(&self) -> Option<(Uuid, PublicKey)> {
        match self {
            OutgoingBitVMXApiMessages::PubKey(uuid, pub_key) => {
                Some((uuid.clone(), pub_key.clone()))
            }
            _ => None,
        }
    }

    pub fn transaction_info(&self) -> Option<(Uuid, String, Transaction)> {
        match self {
            OutgoingBitVMXApiMessages::TransactionInfo(_, name, tx) => {
                Some((Uuid::new_v4(), name.clone(), tx.clone()))
            }
            _ => None,
        }
    }

    pub fn hashed_message(&self) -> Option<(Uuid, String, u32, u32, String)> {
        match self {
            OutgoingBitVMXApiMessages::HashedMessage(_, name, hash1, hash2, msg) => {
                Some((Uuid::new_v4(), name.clone(), *hash1, *hash2, msg.clone()))
            }
            _ => None,
        }
    }

    pub fn witness(&self) -> Option<(Uuid, String, WitnessTypes)> {
        match self {
            OutgoingBitVMXApiMessages::Witness(uuid, name, witness) => {
                Some((uuid.clone(), name.clone(), witness.clone()))
            }
            _ => None,
        }
    }

    pub fn variable(&self) -> Option<(Uuid, String, VariableTypes)> {
        match self {
            OutgoingBitVMXApiMessages::Variable(uuid, name, var_type) => {
                Some((uuid.clone(), name.clone(), var_type.clone()))
            }
            _ => None,
        }
    }

    pub fn encrypted(&self) -> Option<(Uuid, Vec<u8>)> {
        match self {
            OutgoingBitVMXApiMessages::Encrypted(uuid, encrypted) => {
                Some((uuid.clone(), encrypted.clone()))
            }
            _ => None,
        }
    }

    pub fn decrypted(&self) -> Option<(Uuid, Vec<u8>)> {
        match self {
            OutgoingBitVMXApiMessages::Decrypted(uuid, decrypted) => {
                Some((uuid.clone(), decrypted.clone()))
            }
            _ => None,
        }
    }

    pub fn input(&self) -> Option<Vec<u8>> {
        match self {
            OutgoingBitVMXApiMessages::SetInput(input) => Some(input.clone()),
            _ => None,
        }
    }

    pub fn name(&self) -> String {
        match self {
            OutgoingBitVMXApiMessages::Pong(_) => "Pong".to_string(),
            OutgoingBitVMXApiMessages::Transaction(_, _, _) => "Transaction".to_string(),
            OutgoingBitVMXApiMessages::PeginTransactionFound(_, _) => {
                "PeginTransactionFound".to_string()
            }
            OutgoingBitVMXApiMessages::SpendingUTXOTransactionFound(_, _, _, _) => {
                "SpendingUTXOTransactionFound".to_string()
            }
            OutgoingBitVMXApiMessages::SpeedUpProgramNoFunds(_) => {
                "SpeedUpProgramNoFunds".to_string()
            }
            OutgoingBitVMXApiMessages::SetupCompleted(_) => "SetupCompleted".to_string(),
            OutgoingBitVMXApiMessages::AggregatedPubkey(_, _) => "AggregatedPubkey".to_string(),
            OutgoingBitVMXApiMessages::AggregatedPubkeyNotReady(_) => {
                "AggregatedPubkeyNotReady".to_string()
            }
            OutgoingBitVMXApiMessages::TransactionInfo(_, _, _) => "TransactionInfo".to_string(),
            OutgoingBitVMXApiMessages::ZKPResult(_, _, _) => "ZKPResult".to_string(),
            OutgoingBitVMXApiMessages::ExecutionResult() => "ExecutionResult".to_string(),
            OutgoingBitVMXApiMessages::CommInfo(_, _) => "CommInfo".to_string(),
            OutgoingBitVMXApiMessages::KeyPair(_, _, _) => "KeyPair".to_string(),
            OutgoingBitVMXApiMessages::PubKey(_, _) => "PubKey".to_string(),
            OutgoingBitVMXApiMessages::SignedMessage(_, _, _, _) => "SignedMessage".to_string(),
            OutgoingBitVMXApiMessages::Variable(_, _, _) => "Variable".to_string(),
            OutgoingBitVMXApiMessages::Witness(_, _, _) => "Witness".to_string(),
            OutgoingBitVMXApiMessages::NotFound(_, _) => "NotFound".to_string(),
            OutgoingBitVMXApiMessages::HashedMessage(_, _, _, _, _) => "HashedMessage".to_string(),
            OutgoingBitVMXApiMessages::ProofReady(_) => "ProofReady".to_string(),
            OutgoingBitVMXApiMessages::ProofNotReady(_) => "ProofNotReady".to_string(),
            OutgoingBitVMXApiMessages::ProofGenerationError(_, _) => {
                "ProofGenerationError".to_string()
            }
            OutgoingBitVMXApiMessages::SPVProof(_, _) => "SPVProof".to_string(),
            OutgoingBitVMXApiMessages::BackupResult(_, _, _) => "BackupResult".to_string(),
            OutgoingBitVMXApiMessages::Encrypted(_, _) => "Encrypted".to_string(),
            OutgoingBitVMXApiMessages::Decrypted(_, _) => "Decrypted".to_string(),
            OutgoingBitVMXApiMessages::FundingAddress(_, _) => "FundingAddress".to_string(),
            OutgoingBitVMXApiMessages::FundingBalance(_, _) => "FundingBalance".to_string(),
            OutgoingBitVMXApiMessages::FundsSent(_, _) => "FundsSent".to_string(),
            OutgoingBitVMXApiMessages::WalletNotReady(_) => "WalletNotReady".to_string(),
            OutgoingBitVMXApiMessages::WalletError(_, _) => "WalletError".to_string(),
            OutgoingBitVMXApiMessages::ProtocolVisualization(_, _) => {
                "ProtocolVisualization".to_string()
            }
            OutgoingBitVMXApiMessages::SetInput(_) => "SetInput".to_string(),
        }
    }
}

impl FromStr for OutgoingBitVMXApiMessages {
    type Err = BitVMXError;

    fn from_str(msg: &str) -> Result<Self, Self::Err> {
        let msg: OutgoingBitVMXApiMessages = serde_json::from_str(msg)?;
        Ok(msg)
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct RequestId(Uuid);

impl RequestId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

#[derive(Clone, Debug)]
pub struct ParticipantChannel {
    pub id: Identifier,
    pub channel: DualChannel,
}

pub const PROGRAM_TYPE_AGGREGATED_KEY: &str = "aggregated_key";
pub const PROGRAM_TYPE_LOCK: &str = "lock";
pub const PROGRAM_TYPE_DRP: &str = "drp";
pub const PROGRAM_TYPE_SLOT: &str = "slot";
pub const PROGRAM_TYPE_TRANSFER: &str = "transfer";
pub const PROGRAM_TYPE_ACCEPT_PEGIN: &str = "accept_pegin";
pub const PROGRAM_TYPE_USER_TAKE: &str = "take";
pub const PROGRAM_TYPE_ADVANCE_FUNDS: &str = "advance_funds";
pub const PROGRAM_TYPE_REJECT_PEGIN: &str = "reject_pegin";
pub const PROGRAM_TYPE_DISPUTE_CORE: &str = "dispute_core";
pub const PROGRAM_TYPE_PAIRWISE_PENALIZATION: &str = "pairwise_penalization";
pub const PROGRAM_TYPE_FULL_PENALIZATION: &str = "full_penalization";
pub const PROGRAM_TYPE_PACKET: &str = "packet";
