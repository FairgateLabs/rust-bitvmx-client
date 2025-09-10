use std::str::FromStr;

use crate::spv_proof::BtcTxSPVProof;
use bitcoin::{PrivateKey, PublicKey, Transaction, Txid};
use bitcoin_coordinator::{coordinator::BitcoinCoordinator, TransactionStatus};
use bitvmx_broker::{broker_storage::BrokerStorage, channel::channel::LocalChannel};
use chrono::{DateTime, Utc};
use p2p_handler::P2pHandler;
use protocol_builder::types::Utxo;
use serde::{Deserialize, Serialize};

use uuid::Uuid;

use crate::{
    errors::BitVMXError,
    keychain::KeyChain,
    program::{
        participant::P2PAddress,
        variables::{Globals, VariableTypes, WitnessTypes, WitnessVars},
    },
};

pub struct ProgramContext {
    pub key_chain: KeyChain,
    pub comms: P2pHandler,
    pub bitcoin_coordinator: BitcoinCoordinator,
    pub broker_channel: LocalChannel<BrokerStorage>,
    pub globals: Globals,
    pub witness: WitnessVars,
}

pub const BITVMX_ID: u32 = 1;
pub const L2_ID: u32 = 100;
pub const EMULATOR_ID: u32 = 1000;
pub const PROVER_ID: u32 = 2000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvelopeError {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope<T> {
    pub version: u8,
    pub message_type: String,
    pub request_id: Uuid,
    pub session_id: Option<Uuid>,
    pub from: u32,
    pub dest: u32,
    pub payload: T,
    pub error: Option<EnvelopeError>,
}

impl<T> Envelope<T> {
    pub fn map_payload<U>(self, mapper: impl FnOnce(T) -> U) -> Envelope<U> {
        Envelope {
            version: self.version,
            message_type: self.message_type,
            request_id: self.request_id,
            session_id: self.session_id,
            from: self.from,
            dest: self.dest,
            payload: mapper(self.payload),
            error: self.error,
        }
    }
}

impl ProgramContext {
    pub fn new(
        comms: P2pHandler,
        key_chain: KeyChain,
        bitcoin_coordinator: BitcoinCoordinator,
        broker_channel: LocalChannel<BrokerStorage>,
        globals: Globals,
        witness: WitnessVars,
    ) -> Self {
        Self {
            comms,
            key_chain,
            bitcoin_coordinator,
            broker_channel,
            globals,
            witness,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProgramStatus {
    pub program_id: Uuid,
}

impl ProgramStatus {
    pub fn new(program_id: Uuid) -> Self {
        Self { program_id }
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
    Ping(),
    SetVar(Uuid, String, VariableTypes),
    SetWitness(Uuid, String, WitnessTypes),
    SetFundingUtxo(Utxo),
    GetVar(Uuid, String),
    GetWitness(Uuid, String),
    GetCommInfo(),
    GetTransaction(Uuid, Txid),
    GetTransactionInfoByName(Uuid, String),
    GetHashedMessage(Uuid, String, u32, u32),
    Setup(ProgramId, String, Vec<P2PAddress>, u16),
    SubscribeToTransaction(Uuid, Txid),
    SubscribeUTXO(),
    SubscribeToRskPegin(),
    GetSPVProof(Txid),
    DispatchTransaction(Uuid, Transaction),
    DispatchTransactionName(Uuid, String),
    SetupKey(Uuid, Vec<P2PAddress>, Option<Vec<PublicKey>>, u16),
    GetAggregatedPubkey(Uuid),
    GetKeyPair(Uuid),
    GetPubKey(Uuid, bool),
    SignMessage(Uuid, Vec<u8>, PublicKey), // id, payload_to_sign, public_key_to_use
    GenerateZKP(Uuid, Vec<u8>, String),
    ProofReady(Uuid),
    GetZKPExecutionResult(Uuid),
    Encrypt(Uuid, Vec<u8>, Vec<u8>),
    Decrypt(Uuid, Vec<u8>),
    Backup(String),
    #[cfg(any(test, feature = "test"))]
    Test(String),
}
impl IncomingBitVMXApiMessages {
    pub fn to_string(&self) -> Result<String, BitVMXError> {
        Ok(serde_json::to_string(self)?)
    }

    pub fn message_type(&self) -> &'static str {
        match self {
            IncomingBitVMXApiMessages::Ping() => "Ping",
            IncomingBitVMXApiMessages::SetVar(_, _, _) => "SetVar",
            IncomingBitVMXApiMessages::SetWitness(_, _, _) => "SetWitness",
            IncomingBitVMXApiMessages::SetFundingUtxo(_) => "SetFundingUtxo",
            IncomingBitVMXApiMessages::GetVar(_, _) => "GetVar",
            IncomingBitVMXApiMessages::GetWitness(_, _) => "GetWitness",
            IncomingBitVMXApiMessages::GetCommInfo() => "GetCommInfo",
            IncomingBitVMXApiMessages::GetTransaction(_, _) => "GetTransaction",
            IncomingBitVMXApiMessages::GetTransactionInfoByName(_, _) => "GetTransactionInfoByName",
            IncomingBitVMXApiMessages::GetHashedMessage(_, _, _, _) => "GetHashedMessage",
            IncomingBitVMXApiMessages::Setup(_, _, _, _) => "Setup",
            IncomingBitVMXApiMessages::SubscribeToTransaction(_, _) => "SubscribeToTransaction",
            IncomingBitVMXApiMessages::SubscribeUTXO() => "SubscribeUTXO",
            IncomingBitVMXApiMessages::SubscribeToRskPegin() => "SubscribeToRskPegin",
            IncomingBitVMXApiMessages::GetSPVProof(_) => "GetSPVProof",
            IncomingBitVMXApiMessages::DispatchTransaction(_, _) => "DispatchTransaction",
            IncomingBitVMXApiMessages::DispatchTransactionName(_, _) => "DispatchTransactionName",
            IncomingBitVMXApiMessages::SetupKey(_, _, _, _) => "SetupKey",
            IncomingBitVMXApiMessages::GetAggregatedPubkey(_) => "GetAggregatedPubkey",
            IncomingBitVMXApiMessages::GetKeyPair(_) => "GetKeyPair",
            IncomingBitVMXApiMessages::GetPubKey(_, _) => "GetPubKey",
            IncomingBitVMXApiMessages::SignMessage(_, _, _) => "SignMessage",
            IncomingBitVMXApiMessages::GenerateZKP(_, _, _) => "GenerateZKP",
            IncomingBitVMXApiMessages::ProofReady(_) => "ProofReady",
            IncomingBitVMXApiMessages::GetZKPExecutionResult(_) => "GetZKPExecutionResult",
            IncomingBitVMXApiMessages::Encrypt(_, _, _) => "Encrypt",
            IncomingBitVMXApiMessages::Decrypt(_, _) => "Decrypt",
            IncomingBitVMXApiMessages::Backup(_) => "Backup",
            #[cfg(any(test, feature = "test"))]
            IncomingBitVMXApiMessages::Test(_) => "Test",
        }
    }
}

type ProgramId = Uuid;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum OutgoingBitVMXApiMessages {
    Pong(),
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
    CommInfo(P2PAddress),
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
    BackupResult(bool, String),
}

impl OutgoingBitVMXApiMessages {
    pub fn to_string(&self) -> Result<String, BitVMXError> {
        Ok(serde_json::to_string(self)?)
    }

    pub fn from_string(msg: &str) -> Result<Self, BitVMXError> {
        let msg: OutgoingBitVMXApiMessages = serde_json::from_str(msg)?;
        Ok(msg)
    }

    pub fn comm_info(&self) -> Option<P2PAddress> {
        match self {
            OutgoingBitVMXApiMessages::CommInfo(info) => Some(info.clone()),
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

    pub fn message_type(&self) -> &'static str {
        match self {
            OutgoingBitVMXApiMessages::Pong() => "Pong",
            OutgoingBitVMXApiMessages::Transaction(_, _, _) => "Transaction",
            OutgoingBitVMXApiMessages::PeginTransactionFound(_, _) => "PeginTransactionFound",
            OutgoingBitVMXApiMessages::SpendingUTXOTransactionFound(_, _, _, _) => "SpendingUTXOTransactionFound",
            OutgoingBitVMXApiMessages::SpeedUpProgramNoFunds(_) => "SpeedUpProgramNoFunds",
            OutgoingBitVMXApiMessages::SetupCompleted(_) => "SetupCompleted",
            OutgoingBitVMXApiMessages::AggregatedPubkey(_, _) => "AggregatedPubkey",
            OutgoingBitVMXApiMessages::AggregatedPubkeyNotReady(_) => "AggregatedPubkeyNotReady",
            OutgoingBitVMXApiMessages::TransactionInfo(_, _, _) => "TransactionInfo",
            OutgoingBitVMXApiMessages::ZKPResult(_, _, _) => "ZKPResult",
            OutgoingBitVMXApiMessages::ExecutionResult() => "ExecutionResult",
            OutgoingBitVMXApiMessages::CommInfo(_) => "CommInfo",
            OutgoingBitVMXApiMessages::KeyPair(_, _, _) => "KeyPair",
            OutgoingBitVMXApiMessages::PubKey(_, _) => "PubKey",
            OutgoingBitVMXApiMessages::SignedMessage(_, _, _, _) => "SignedMessage",
            OutgoingBitVMXApiMessages::Variable(_, _, _) => "Variable",
            OutgoingBitVMXApiMessages::Witness(_, _, _) => "Witness",
            OutgoingBitVMXApiMessages::NotFound(_, _) => "NotFound",
            OutgoingBitVMXApiMessages::HashedMessage(_, _, _, _, _) => "HashedMessage",
            OutgoingBitVMXApiMessages::ProofReady(_) => "ProofReady",
            OutgoingBitVMXApiMessages::ProofNotReady(_) => "ProofNotReady",
            OutgoingBitVMXApiMessages::ProofGenerationError(_, _) => "ProofGenerationError",
            OutgoingBitVMXApiMessages::SPVProof(_, _) => "SPVProof",
            OutgoingBitVMXApiMessages::Encrypted(_, _) => "Encrypted",
            OutgoingBitVMXApiMessages::Decrypted(_, _) => "Decrypted",
            OutgoingBitVMXApiMessages::BackupResult(_, _) => "BackupResult",
        }
    }

    pub fn request_id_opt(&self) -> Option<Uuid> {
        match self {
            OutgoingBitVMXApiMessages::Transaction(id, _, _) => Some(*id),
            OutgoingBitVMXApiMessages::SpendingUTXOTransactionFound(id, _, _, _) => Some(*id),
            OutgoingBitVMXApiMessages::SetupCompleted(id) => Some(*id),
            OutgoingBitVMXApiMessages::AggregatedPubkey(id, _) => Some(*id),
            OutgoingBitVMXApiMessages::AggregatedPubkeyNotReady(id) => Some(*id),
            OutgoingBitVMXApiMessages::TransactionInfo(id, _, _) => Some(*id),
            OutgoingBitVMXApiMessages::ZKPResult(id, _, _) => Some(*id),
            OutgoingBitVMXApiMessages::KeyPair(id, _, _) => Some(*id),
            OutgoingBitVMXApiMessages::PubKey(id, _) => Some(*id),
            OutgoingBitVMXApiMessages::SignedMessage(id, _, _, _) => Some(*id),
            OutgoingBitVMXApiMessages::Variable(id, _, _) => Some(*id),
            OutgoingBitVMXApiMessages::Witness(id, _, _) => Some(*id),
            OutgoingBitVMXApiMessages::NotFound(id, _) => Some(*id),
            OutgoingBitVMXApiMessages::HashedMessage(id, _, _, _, _) => Some(*id),
            OutgoingBitVMXApiMessages::ProofReady(id) => Some(*id),
            OutgoingBitVMXApiMessages::ProofNotReady(id) => Some(*id),
            OutgoingBitVMXApiMessages::ProofGenerationError(id, _) => Some(*id),
            OutgoingBitVMXApiMessages::Encrypted(id, _) => Some(*id),
            OutgoingBitVMXApiMessages::Decrypted(id, _) => Some(*id),
            _ => None,
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

pub const PROGRAM_TYPE_LOCK: &str = "lock";
pub const PROGRAM_TYPE_DRP: &str = "drp";
pub const PROGRAM_TYPE_SLOT: &str = "slot";
pub const PROGRAM_TYPE_TRANSFER: &str = "transfer";
pub const PROGRAM_TYPE_ACCEPT_PEGIN: &str = "accept_pegin";
pub const PROGRAM_TYPE_USER_TAKE: &str = "take";
pub const PROGRAM_TYPE_ADVANCE_FUNDS: &str = "advance_funds";
pub const PROGRAM_TYPE_DISPUTE_CORE: &str = "dispute_core";
pub const PROGRAM_TYPE_PAIRWISE_PENALIZATION: &str = "pairwise_penalization";
pub const PROGRAM_TYPE_PACKET: &str = "packet";
