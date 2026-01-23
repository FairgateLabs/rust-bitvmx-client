use bitcoin::{consensus::encode::FromHexError, network::ParseNetworkError, Witness};
use bitcoin_coordinator::errors::BitcoinCoordinatorError;
use bitcoincore_rpc::bitcoin::{key::ParsePublicKeyError, sighash::SighashTypeParseError};
use bitvmx_broker::{identification::errors::IdentificationError, rpc::errors::BrokerError};
use bitvmx_cpu_definitions::challenge::EmulatorResultError;
use bitvmx_job_dispatcher::dispatcher_error::DispatcherError;
use config as settings;
use emulator::{loader::program_definition::ProgramDefinitionError, EmulatorError};
use key_manager::{
    errors::{KeyManagerError, WinternitzError},
    musig2::errors::Musig2SignerError,
};
use protocol_builder::errors::{ProtocolBuilderError, ScriptError, UnspendableKeyError};
use std::sync::PoisonError;
use std::time::Duration;
use storage_backend::error::StorageError;
use thiserror::Error;
use uuid::Uuid;

#[derive(Error, Debug)]
pub enum BitVMXError {
    /* =========================
     * Configuration & Init
     * ========================= */
    #[error("Invalid configuration")]
    ConfigurationError(#[from] ConfigError),

    #[error("Invalid parameter in configuration. {0}")]
    InvalidParameter(String),

    #[error("Initialization error: {0}")]
    InitializationError(String),

    #[error("This feature is not implemented yet {0}")]
    NotImplemented(String),

    /* =========================
     * IO / System / Time
     * ========================= */
    #[error("IO error: {0}")]
    IOError(#[from] std::io::Error),

    #[error("Time error: {0}")]
    TimeError(#[from] std::time::SystemTimeError),

    #[error("Poisoned lock error: {0}")]
    PoisonedLockError(String),

    #[error("Problem creating directory {0}: {1}")]
    DirectoryCreationError(String, std::io::Error),

    /* =========================
     * Parsing / Serialization
     * ========================= */
    #[error("Error parsing int")]
    ParseIntError(#[from] std::num::ParseIntError),

    #[error("Error parsing from script int")]
    ScriptIntParseError(#[from] bitcoin::script::Error),

    #[error("Error decoding hex string: {0}")]
    FromHexError(#[from] hex::FromHexError),

    #[error("Serialization error {0}")]
    SerdeSerializationError(#[from] serde_json::Error),

    #[error("Failed to serialize or deserialize message")]
    SerializationError,

    #[error("TryFromSlice error: {0}")]
    TryFromSliceError(#[from] std::array::TryFromSliceError),

    /* =========================
     * Cryptography / Keys / Signatures
     * ========================= */
    #[error("Error when using KeyManager: {0}")]
    KeyManagerError(#[from] KeyManagerError),

    #[error("KeyChain error: {0}")]
    KeyChainError(String),

    #[error("Error when creating unspendable key: {0}")]
    UnspendableKeyError(#[from] UnspendableKeyError),

    #[error("Failed in MuSig2 signer {0}")]
    MuSig2SignerError(#[from] Musig2SignerError),

    #[error("Failed to process a Winternitz signature: {0}")]
    WinternitzError(#[from] WinternitzError),

    #[error("Invalid RSA signature from peer {peer} for message type {msg_type:?} in program {program_id}")]
    InvalidSignature {
        peer: String,
        msg_type: String,
        program_id: String,
    },

    #[error("Missing verification key for sender {peer}. Known keys: {known_count}")]
    MissingVerificationKey { peer: String, known_count: usize },

    #[error("Failed to extract verification key from VerificationKey message: {reason}")]
    VerificationKeyExtractionError { reason: String },

    #[error("Failed to reconstruct message for signature verification: {reason}")]
    MessageReconstructionError { reason: String },

    #[error("Verification key announcement hash mismatch for peer {peer}: expected {expected}, got {got}")]
    VerificationKeyHashMismatch {
        peer: String,
        expected: String,
        got: String,
    },

    #[error("Verification key fingerprint mismatch for peer {peer}:  computed {computed}")]
    VerificationKeyFingerprintMismatch { peer: String, computed: String },

    /* =========================
     * Wallet / Storage
     * ========================= */
    #[error("Wallet error {0}")]
    WalletError(#[from] bitvmx_wallet::wallet::errors::WalletError),

    #[error("Error when creating the storagge: {0}")]
    StorageError(#[from] StorageError),

    #[error("Storage unavailable/not found for protocol {0}")]
    StorageUnavailable(String),

    /* =========================
     * Program / Protocol
     * ========================= */
    #[error("Error when creating protocol: {0}")]
    ProtocolBuilderError(#[from] ProtocolBuilderError),

    #[error("Dispute resolution protocol setup error: {0}")]
    DisputeResolutionProtocolSetup(String),

    #[error("ProgramDefinition Error {0}")]
    ProgramDefinitionError(#[from] ProgramDefinitionError),

    #[error("Program already exists")]
    ProgramAlreadyExists(Uuid),

    #[error("Program {0} is not ready to run. Please install it first.")]
    ProgramNotReady(Uuid),

    #[error("Cannot find program with id {0}")]
    ProgramNotFound(Uuid),

    #[error("Cannot find protocol with name {0}")]
    ProtocolNotFound(String),

    #[error("A program error has occurred: {0}")]
    ProgramError(#[from] ProgramError),

    /* =========================
     * Execution / Emulator / ZKP
     * ========================= */
    #[error("Emulator Error {0}")]
    EmulatorError(#[from] EmulatorError),

    #[error("Emulator Result Error {0}")]
    EmulatorResultError(#[from] EmulatorResultError),

    #[error("Execution error: {0}")]
    ExecutionError(#[from] emulator::ExecutionResult),

    #[error("Inconsistent data retrieved of ZKP execution result from job {0}")]
    InconsistentZKPData(Uuid),

    /* =========================
     * Witness / Merkle / Scripts
     * ========================= */
    #[error("Invalid witness type")]
    InvalidWitnessType,

    #[error("Invalid witness: {0:?}")]
    InvalidWitness(Witness),

    #[error("Invalid merkle tree")]
    InvalidMerkleTree,

    #[error("Script not found for program id {0}")]
    ScriptNotFound(Uuid),

    #[error("Error creating script {0}")]
    ScriptError(#[from] ScriptError),

    #[error("Invalid leaf: {0}")]
    InvalidLeaf(String),

    /* =========================
     * Messaging / Dispatcher / Comms
     * ========================= */
    #[error("Job type error {0}")]
    DispatcherError(#[from] DispatcherError),

    #[error("Job Dispatcher {0} is not responding")]
    JobDispatcherNotResponding(String),

    #[error("Failed to use Comms layer")]
    CommsCommunicationError,

    #[error("Invalid Comms address: {0}")]
    InvalidCommsAddress(String),

    #[error("Broker channel error")]
    BrokerError(#[from] BrokerError),

    #[error("Client error")]
    ClientError(#[from] ClientError),

    #[error("Invalid parser version")]
    InvalidMsgVersion,

    #[error("Invalid message type")]
    InvalidMessageType,

    #[error("Invalid receive message format")]
    InvalidMessageFormat,

    #[error("Invalid message: {0}")]
    InvalidMessage(String),

    #[error("Failed to process message")]
    MessageProcessingError,

    #[error("Identification error: {0}")]
    IdentificationError(#[from] IdentificationError),

    /* =========================
     * Timestamp / Replay
     * ========================= */
    #[error("Message timestamp {timestamp} from peer {peer} is too far in the future (now: {now}, drift: {drift_ms}ms, max allowed: {max_drift_ms}ms)")]
    TimestampTooFarInFuture {
        peer: String,
        timestamp: i64,
        now: i64,
        drift_ms: i64,
        max_drift_ms: i64,
    },

    #[error("Message timestamp {timestamp} from peer {peer} is too old (now: {now}, drift: {drift_ms}ms, max allowed: {max_drift_ms}ms)")]
    TimestampTooOld {
        peer: String,
        timestamp: i64,
        now: i64,
        drift_ms: i64,
        max_drift_ms: i64,
    },

    #[error("Replay attack detected: timestamp {timestamp} from peer {peer} is not newer than last seen timestamp {last_timestamp}")]
    TimestampReplayAttack {
        peer: String,
        timestamp: i64,
        last_timestamp: i64,
    },

    /* =========================
     * Bitcoin / Transactions
     * ========================= */
    #[error("Error when using Bitcoin client: {0}")]
    BitcoinError(#[from] BitcoinClientError),

    #[error("Failed to use Bitcoin Coordinator: {0}")]
    BitcoinCoordinatorError(#[from] BitcoinCoordinatorError),

    #[error("Invalid transaction name {0}")]
    InvalidTransactionName(String),

    #[error("Invalid transaction status {0}")]
    InvalidTransactionStatus(String),

    #[error("Transaction not found in block")]
    TransactionNotFoundInBlock,

    #[error("Insufficient amount to send the transaction")]
    InsufficientAmount,

    #[error("Missing input signature for transaction {tx_name}, input index {input_index}, script index {script_index:?}")]
    MissingInputSignature {
        tx_name: String,
        input_index: usize,
        script_index: Option<usize>,
    },

    #[error("Error signing input for transaction {tx_name}, input index {input_index}, script index {script_index:?}: {source}")]
    ErrorSigningInput {
        tx_name: String,
        input_index: usize,
        script_index: Option<usize>,
        source: ProtocolBuilderError,
    },

    /* =========================
     * Validation / State / Logic
     * ========================= */
    #[error("Invalid state: {0}")]
    InvalidState(String),

    #[error("Invalid variable type: {0}")]
    InvalidVariableType(String),

    #[error("Invalid string operation: {0}")]
    InvalidStringOperation(String),

    #[error("Peer id {0} not found in the list of participants")]
    InvalidParticipant(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Invalid inputs: {0:?}")]
    InvalidInputs(Vec<(usize, String)>),

    #[error("Invalid list: {0}")]
    InvalidList(String),

    /* =========================
     * Missing / Not Found
     * ========================= */
    #[error("Variable {0}.{1} not found")]
    VariableNotFound(Uuid, String),

    #[error("Keys not found in program {0}")]
    KeysNotFound(Uuid),

    #[error("Missing block info")]
    MissingBlockInfo,

    #[error("Missing parameter: {0}")]
    MissingParameter(String),

    #[error("Missing nonces for program id {0}")]
    NoncesNotFound(Uuid),

    #[error("Missing partial signatures for program id {0}")]
    PartialSignaturesNotFound(Uuid),

    #[error("No signatures found for aggregated public key {0} and id {1}")]
    MissingPartialSignatures(String, String),

    #[error("No public nonces found for aggregated public key {0} and id {1}")]
    MissingPublicNonces(String, String),

    #[error("Section not found: {0}")]
    SectionNotFound(String),

    #[error("Challenge {0} not found")]
    ChallengeNotFound(String),

    #[error("Challenge with idx {0} not found")]
    ChallengeIdxNotFound(u32),

    #[error("Rom data {0} not found")]
    RomDataNotFound(u32),

    #[error("Instruction {0} not found")]
    InstructionNotFound(String),

    #[error("Not found {0}")]
    NotFound(String),
}

impl<T> From<PoisonError<T>> for BitVMXError {
    fn from(err: PoisonError<T>) -> Self {
        BitVMXError::PoisonedLockError(format!("Lock poisoned: {err}"))
    }
}

impl BitVMXError {
    /// Returns whether the error should be considered fatal.
    ///
    /// NOTE: For now, we mark all errors as fatal to avoid masking issues and ensure coordinated
    /// shutdown paths are exercised.
    /// Once the system is stable, we should revisit this and separate truly fatal errors
    /// (e.g., storage corruption) from recoverable ones.
    pub fn is_fatal(&self) -> bool {
        true
    }
}

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Error while trying to build configuration")]
    ConfigFileError(#[from] settings::ConfigError),

    #[error("Public key in config is invalid")]
    InvalidPublicKey(#[from] ParsePublicKeyError),

    #[error("SighashType in config is invalid")]
    InvalidSighashType(#[from] SighashTypeParseError),

    #[error("Winternitz seed is invalid")]
    InvalidWinternitzSeed,

    #[error("Key derivation seed is invalid")]
    InvalidKeyDerivationSeed,

    #[error("Network is invalid")]
    InvalidNetwork(#[from] ParseNetworkError),

    #[error("Hex value is invalid")]
    InvalidHexValue(#[from] FromHexError),

    #[error("Invalid program path {0}")]
    ProgramPathError(String),

    #[error("Invalid configuation path {0}")]
    InvalidConfigPath(String),

    #[error("Invalid configuration from file")]
    ConfigurationError(#[from] bitvmx_settings::errors::ConfigError),

    #[error("Invalid private key {0}")]
    InvalidPrivateKey(String),

    #[error("Broker error: {0}")]
    BrokerError(#[from] BrokerError),
}

#[derive(Error, Debug)]
pub enum ProgramError {
    #[error("Storage path configured for program is invalid {0}")]
    InvalidProgramStoragePath(String),

    #[error("Error while building dispute resolution protocol")]
    FailedToBuildDisputeResolutionProtocol(#[from] ProtocolBuilderError),

    #[error("Error loading Program")]
    LoadError(#[from] StorageError),

    #[error("Program not found in storage. Program id: {0}")]
    ProgramNotFound(Uuid),

    #[error("Storage unavailable")]
    StorageUnavailable,
}

#[derive(Error, Debug)]
pub enum BitcoinClientError {
    #[error("Failed to fund address")]
    FailedToFundAddress { error: String },

    #[error("Failed to send transaction")]
    FailedToSendTransaction { error: String },

    #[error("Failed to create new wallet")]
    FailedToCreateWallet { error: String },

    #[error("Failed to get new address")]
    FailedToGetNewAddress { error: String },

    #[error("Failed to mine blocks")]
    FailedToMineBlocks { error: String },

    #[error("Failed to get transaction details")]
    FailedToGetTransactionDetails { error: String },

    #[error("Failed to create client")]
    FailedToCreateClient { error: String },

    #[error("Failed to load wallet")]
    FailedToLoadWallet { error: String },

    #[error("Failed to list wallets")]
    FailedToListWallets { error: String },

    #[error("Rpc error")]
    RpcError(#[from] bitvmx_bitcoin_rpc::errors::BitcoinClientError),
}

#[derive(Error, Debug)]
pub enum ClientError {
    #[error("Invalid command line arguments {0}")]
    InvalidArguments(String),

    #[error("Timeout waiting for message after {0:?}")]
    MessageTimeout(Duration),
}

#[derive(Error, Debug, PartialEq)]
pub enum ParseError {
    #[error("Invalid nonce")]
    InvalidNonces,

    #[error("Invalid public key")]
    InvalidPublicKeys,

    #[error("Invalid signature")]
    InvalidPartialSignatures,

    #[error("Invalid participant keys")]
    InvalidParticipantKeys,
}
