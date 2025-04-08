use crate::{
    keychain::KeyChain,
    program::{
        dispute::Funding,
        participant::{P2PAddress, ParticipantRole},
    },
};
use bitcoin::{Transaction, Txid};
use bitcoin_coordinator::types::TransactionNew;
use chrono::{DateTime, Utc};
use p2p_handler::P2pHandler;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
pub struct ProgramContext {
    pub key_chain: KeyChain,
    pub comms: P2pHandler,
}

impl ProgramContext {
    pub fn new(comms: P2pHandler, key_chain: KeyChain) -> Self {
        Self { comms, key_chain }
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
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub enum IncomingBitVMXApiMessages {
    Ping(),
    SetupProgram(ProgramId, ParticipantRole, P2PAddress, Funding),
    GetTransaction(Txid),
    SubscribeToTransaction(Txid),
    SubscribeUTXO(),
    DispatchTransaction(Uuid, Transaction),
    SetupKey(),
    GetAggregatedPubkey(),
    GenerateZKP(),
    ProofReady(),
    ExecuteZKP(),
    GetZKPExecutionResult(),
    Finalize(),
}

type ProgramId = Uuid;

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub enum OutgoingBitVMXApiMessages {
    Pong(),
    // Represents when pegin transactions is found
    PeginTransactionFound(TransactionNew),
    // Represents when a program is running out of funds
    SpeedUpProgramNoFunds(Vec<Uuid>),
    // Add response types for the new messages if needed
    AggregatedPubkey(/* Add appropriate type */),
    ZKPResult(/* Add appropriate type */),
    ExecutionResult(/* Add appropriate type */),
    TransactionResult(/* Add appropriate type */),
}
