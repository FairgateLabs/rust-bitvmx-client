//! Shared with `rust-bitvmx-client-types` — this file is copied verbatim on release.
//! Node-only code does not belong here; put it in the sibling `mod.rs`.

use std::{net::IpAddr, str::FromStr};

use bitcoin::{
    address::NetworkUnchecked, Address, BlockHash, PrivateKey, PublicKey, Transaction, Txid,
};
use bitcoin_coordinator::TransactionStatus;
use bitvmx_broker::identification::identifier::PubkHash;
use bitvmx_wallet::wallet::Destination;
use protocol_builder::types::Utxo;
use redact::Secret;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    errors::BitVMXError,
    program::{
        participant::CommsAddress,
        variables::{VariableTypes, WitnessTypes},
    },
    spv_proof::BtcTxSPVProof,
};
pub use bitcoin_coordinator::OutputPatternFilter;
pub const RSK_PEGIN_TAG: &[u8] = b"RSK_PEGIN";

pub const REQUEST_PEGIN_OP_RETURN_LEN: usize = 70;

pub const REQUEST_PEGIN_PUBKEY_OFFSET: usize = 37;

pub fn request_pegin_op_return_data(
    packet_number: u64,
    rootstock_address: [u8; 20],
    reimbursement_pubkey: &PublicKey,
) -> Result<Vec<u8>, BitVMXError> {
    if !reimbursement_pubkey.compressed {
        return Err(BitVMXError::InvalidConversion(format!(
            "reimbursement public key must be compressed, got {} bytes",
            reimbursement_pubkey.to_bytes().len()
        )));
    }

    let payload = [
        RSK_PEGIN_TAG,
        &packet_number.to_be_bytes(),
        &rootstock_address,
        &reimbursement_pubkey.to_bytes(),
    ]
    .concat();

    Ok(payload)
}

#[cfg(test)]
mod request_pegin_op_return_tests {
    use super::*;
    use std::str::FromStr;

    const EVEN_PUBKEY_HEX: &str =
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const ODD_PUBKEY_HEX: &str =
        "03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556";

    const PACKET_NUMBER: u64 = 42;
    const ROOTSTOCK_ADDRESS: [u8; 20] = [7u8; 20];

    fn expected_payload_hex(pubkey_hex: &str) -> String {
        format!(
            "{}{}{}{}",
            "52534b5f504547494e",
            "000000000000002a",
            "07".repeat(20),
            pubkey_hex
        )
    }

    #[test]
    fn even_parity_key_produces_expected_payload() {
        let pubkey = PublicKey::from_str(EVEN_PUBKEY_HEX).unwrap();
        let payload =
            request_pegin_op_return_data(PACKET_NUMBER, ROOTSTOCK_ADDRESS, &pubkey).unwrap();

        assert_eq!(payload.len(), REQUEST_PEGIN_OP_RETURN_LEN);
        assert_eq!(hex::encode(&payload), expected_payload_hex(EVEN_PUBKEY_HEX));
        assert_eq!(payload[REQUEST_PEGIN_PUBKEY_OFFSET], 0x02);

        let round_tripped = PublicKey::from_slice(
            &payload[REQUEST_PEGIN_PUBKEY_OFFSET..REQUEST_PEGIN_OP_RETURN_LEN],
        )
        .unwrap();
        assert_eq!(round_tripped, pubkey);
    }

    #[test]
    fn uncompressed_key_is_rejected() {
        let mut pubkey = PublicKey::from_str(EVEN_PUBKEY_HEX).unwrap();
        pubkey.compressed = false;

        assert!(request_pegin_op_return_data(PACKET_NUMBER, ROOTSTOCK_ADDRESS, &pubkey).is_err());
    }

    #[test]
    fn odd_parity_key_produces_expected_payload() {
        let pubkey = PublicKey::from_str(ODD_PUBKEY_HEX).unwrap();
        let payload =
            request_pegin_op_return_data(PACKET_NUMBER, ROOTSTOCK_ADDRESS, &pubkey).unwrap();

        assert_eq!(payload.len(), REQUEST_PEGIN_OP_RETURN_LEN);
        assert_eq!(hex::encode(&payload), expected_payload_hex(ODD_PUBKEY_HEX));
        assert_eq!(payload[REQUEST_PEGIN_PUBKEY_OFFSET], 0x03);

        let round_tripped = PublicKey::from_slice(
            &payload[REQUEST_PEGIN_PUBKEY_OFFSET..REQUEST_PEGIN_OP_RETURN_LEN],
        )
        .unwrap();
        assert_eq!(round_tripped, pubkey);
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
    SubscribeToTransaction(Uuid, Txid, Option<u32>),
    SubscribeToSpendingUTXO(Uuid, Txid, u32, Option<u32>), // id, txid, vout, confirmation_threshold
    SubscribeToOutputPattern(OutputPatternFilter, Option<u32>),
    SubscribeToRskPegin(Option<u32>),
    GetSPVProof(Txid),
    DispatchTransaction(Uuid, Transaction, Option<u32>, Option<u32>), // id, transaction, confirmation_threshold, stuck_in_mempool_blocks
    DispatchTransactionName(Uuid, String),
    SetupKey(Uuid, Vec<CommsAddress>, Option<Vec<PublicKey>>, u16),
    GetAggregatedPubkey(Uuid),
    GetKeyPair(Uuid),
    GetPubKey(Uuid, bool),
    GetEvenPubKey(Uuid),
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
    ListAllowList(Uuid),
    AddToAllowList(Uuid, PubkHash, Option<IpAddr>), // An absent address matches any source IP.
    RemoveFromAllowList(Uuid, PubkHash),
    SetAllowAll(Uuid, bool), // Blanket accept-everyone. Independent of the entries above.
    Shutdown(),
}
impl IncomingBitVMXApiMessages {
    pub fn to_string(&self) -> Result<String, BitVMXError> {
        Ok(serde_json::to_string(self)?)
    }
}

type ProgramId = Uuid;

#[derive(Eq, Hash, PartialEq, Clone, Copy, Debug, Serialize, Deserialize)]
pub enum JobDispatcherType {
    ZKP,
    Emulator,
    Garbler,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub enum SetupFailureReason {
    StepError(String),
    /// The sender's key was still missing on the final attempt.
    VerificationKeyMissing,
    /// A message from the sender ran out of retries.
    MessageLost,
    /// A message addressed to this peer could not be delivered.
    Undeliverable,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub enum ErrorScope {
    Node,
    Program(ProgramId),
    /// Reports carrying this are answered to the requester, not to L2.
    Request(Uuid),
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub enum ErrorReportKind {
    /// Terminal: no further messages for this program, and its id cannot be reused.
    SetupFailed {
        step: String,
        peer: Option<PubkHash>,
        reason: SetupFailureReason,
    },
    JobDispatcherUnresponsive(JobDispatcherType),
    JobDispatcherRecovered(JobDispatcherType),
    /// Storage or the broker failed; the node is exiting. Best-effort: may not arrive.
    Fatal,
    NodeStopping,
    BitcoinRpcUnavailable,
    BitcoinRpcRecovered,
    TransactionDispatchFailed {
        txid: Txid,
    },
    SpeedupDispatchFailed {
        txid: Txid,
    },
    TransactionStuckInMempool {
        txid: Txid,
    },
    FeeRateTooHigh {
        estimated: u64,
        max: u64,
    },
    MaxFeeRateReached {
        txid: Txid,
        effective_fee_rate: u64,
    },
    InsufficientFunds {
        available: u64,
        required: u64,
    },
    FundingNotAvailable,
    InvalidFundingUtxo {
        amount: u64,
        min_required: u64,
    },
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct ErrorReport {
    pub scope: ErrorScope,
    pub kind: ErrorReportKind,
    pub detail: Option<String>,
}

impl ErrorReport {
    pub fn new(scope: ErrorScope, kind: ErrorReportKind, detail: Option<String>) -> Self {
        Self {
            scope,
            kind,
            detail,
        }
    }

    pub fn node(kind: ErrorReportKind) -> Self {
        Self::new(ErrorScope::Node, kind, None)
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum OutgoingBitVMXApiMessages {
    Pong(Uuid),
    // response for transaction get and dispatch
    Transaction(Uuid, TransactionStatus, Option<String>),
    // Represents when a transaction matching a generic output pattern is found
    OutputPatternTransactionFound(Txid, TransactionStatus, Vec<u8>),
    // Represents when a RSK pegin transaction is found (kept for backward compatibility)
    PeginTransactionFound(Txid, TransactionStatus),
    // Represents when a spending utxo transaction is found
    SpendingUTXOTransactionFound(Uuid, Txid, u32, TransactionStatus),
    // Setup Completed,
    SetupCompleted(ProgramId),
    // Unprompted error report, scoped by `ErrorScope`
    Error(ErrorReport),
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
    NewBlock(BlockHash, u32),
    // Comms allow list: entries, then the blanket allow_all flag.
    AllowListEntries(Uuid, Vec<(PubkHash, Option<IpAddr>)>, bool),
    // A mutation was applied. `false` means it could not be persisted and will
    // not survive a restart.
    AllowListUpdated(Uuid, bool),
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
            OutgoingBitVMXApiMessages::OutputPatternTransactionFound(_, _, _) => {
                "OutputPatternTransactionFound".to_string()
            }
            OutgoingBitVMXApiMessages::PeginTransactionFound(_, _) => {
                "PeginTransactionFound".to_string()
            }
            OutgoingBitVMXApiMessages::SpendingUTXOTransactionFound(_, _, _, _) => {
                "SpendingUTXOTransactionFound".to_string()
            }
            OutgoingBitVMXApiMessages::SetupCompleted(_) => "SetupCompleted".to_string(),
            OutgoingBitVMXApiMessages::Error(_) => "Error".to_string(),
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
            OutgoingBitVMXApiMessages::NewBlock(_, _) => "NewBlock".to_string(),
            OutgoingBitVMXApiMessages::AllowListEntries(_, _, _) => "AllowListEntries".to_string(),
            OutgoingBitVMXApiMessages::AllowListUpdated(_, _) => "AllowListUpdated".to_string(),
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
