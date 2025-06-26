use std::str::FromStr;

use crate::spv_proof::BtcTxSPVProof;
use bitcoin::{PrivateKey, PublicKey, Transaction, Txid};
use bitcoin_coordinator::{types::BitcoinCoordinatorType, TransactionStatus};
use bitvmx_broker::{broker_storage::BrokerStorage, channel::channel::LocalChannel};
use chrono::{DateTime, Utc};
use p2p_handler::P2pHandler;
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
    pub bitcoin_coordinator: BitcoinCoordinatorType,
    pub broker_channel: LocalChannel<BrokerStorage>,
    pub globals: Globals,
    pub witness: WitnessVars,
}

pub const BITVMX_ID: u32 = 1;
pub const L2_ID: u32 = 100;
pub const EMULATOR_ID: u32 = 1000;
pub const PROVER_ID: u32 = 2000;

impl ProgramContext {
    pub fn new(
        comms: P2pHandler,
        key_chain: KeyChain,
        bitcoin_coordinator: BitcoinCoordinatorType,
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
    GetVar(Uuid, String),
    GetWitness(Uuid, String),
    GetCommInfo(),
    GetTransaction(Uuid, Txid),
    GetTransactionInofByName(Uuid, String),
    GetHashedMessage(Uuid, String, u32, u32),
    Setup(ProgramId, String, Vec<P2PAddress>, u16),
    SubscribeToTransaction(Uuid, Txid),
    SubscribeUTXO(),
    DispatchTransaction(Uuid, Transaction),
    DispatchTransactionName(Uuid, String),
    SetupKey(Uuid, Vec<P2PAddress>, u16),
    GetAggregatedPubkey(Uuid),
    GetKeyPair(Uuid),
    GetPubKey(Uuid),
    CreateKeyPair(Uuid, u32),
    GenerateZKP(Uuid, Vec<u8>),
    ProofReady(Uuid),
    ExecuteZKP(),
    GetZKPExecutionResult(),
    Finalize(),
}
impl IncomingBitVMXApiMessages {
    pub fn to_string(&self) -> Result<String, BitVMXError> {
        Ok(serde_json::to_string(self)?)
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
    ZKPResult(/* Add appropriate type */),
    ExecutionResult(/* Add appropriate type */),
    CommInfo(P2PAddress),
    KeyPair(Uuid, PrivateKey, PublicKey),
    PubKey(Uuid, PublicKey),
    Variable(Uuid, String, VariableTypes),
    Witness(Uuid, String, WitnessTypes),
    NotFound(Uuid, String),
    HashedMessage(Uuid, String, u32, u32, String),
    ProofReady(Uuid),
    ProofNotReady(Uuid),
    SPVProof(Txid, Option<BtcTxSPVProof>),
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
pub const PROGRAM_TYPE_TAKE: &str = "take";
pub const PROGRAM_TYPE_INIT: &str = "init";
pub const PROGRAM_TYPE_DISPUTE_CORE: &str = "dispute_core";
pub const PROGRAM_TYPE_PAIRWISE_PENALIZATION: &str = "pairwise_penalization";
pub const PROGRAM_TYPE_MULTIPARTY_PENALIZATION: &str = "multiparty_penalization";
pub const PROGRAM_TYPE_PACKET: &str = "packet";
