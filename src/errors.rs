use bitcoin::{consensus::encode::FromHexError, network::ParseNetworkError};
use bitcoin_coordinator::errors::BitcoinCoordinatorError;
use bitcoincore_rpc::bitcoin::{key::ParsePublicKeyError, sighash::SighashTypeParseError};
use bitvmx_broker::{identification::errors::IdentificationError, rpc::errors::BrokerError};
use bitvmx_cpu_definitions::challenge::EmulatorResultError;
use bitvmx_job_dispatcher::dispatcher_error::DispatcherError;
use bitvmx_operator_comms::helper::OperatorCommsError;
use config as settings;
use emulator::{loader::program_definition::ProgramDefinitionError, EmulatorError};
use key_manager::{
    errors::{KeyManagerError, WinternitzError},
    musig2::errors::Musig2SignerError,
};
use protocol_builder::errors::{ProtocolBuilderError, ScriptError, UnspendableKeyError};
use std::time::Duration;
use storage_backend::error::StorageError;
use thiserror::Error;
use uuid::Uuid;

#[derive(Error, Debug)]
pub enum BitVMXError {
    #[error("Error on dispute resolution protocol setup: {0}")]
    DisputeResolutionProtocolSetup(String),

    #[error("Invalid configuration")]
    ConfigurationError(#[from] ConfigError),

    #[error("Invalid parameter in configuration. {0}")]
    InvalidParameter(String),

    #[error("Error parsing int")]
    ParseIntError(#[from] std::num::ParseIntError),

    #[error("Error when using KeyManager: {0}")]
    KeyManagerError(#[from] KeyManagerError),

    #[error("Error when using Bitcoin client: {0}")]
    BitcoinError(#[from] BitcoinClientError),

    #[error("Error when creating unspendable key: {0}")]
    UnspendableKeyError(#[from] UnspendableKeyError),

    #[error("Error when creating protocol: {0}")]
    ProtocolBuilderError(#[from] ProtocolBuilderError),

    #[error("Error decoding hex string: {0}")]
    FromHexError(#[from] hex::FromHexError),

    #[error("Error when creating the storagge: {0}")]
    StorageError(#[from] StorageError),

    #[error("Cannot find program with id {0}")]
    ProgramNotFound(Uuid),

    #[error("Cannot find protocol with name {0}")]
    ProtocolNotFound(String),

    #[error("A program error has occurred: {0}")]
    ProgramError(#[from] ProgramError),

    #[error("Failed to process a Winternitz signature: {0}")]
    WinternitzError(#[from] WinternitzError),

    #[error("Program {0} is not ready to run. Please install it first.")]
    ProgramNotReady(Uuid),

    #[error("Cannot find the variable {0}.{1}")]
    VariableNotFound(Uuid, String),

    #[error("Invalid variable type: {0}")]
    InvalidVariableType(String),

    #[error("Invalid witness type")]
    InvalidWitnessType,

    #[error("Job type error {0}")]
    DispatcherError(#[from] DispatcherError),

    // #[error("Failed to create communications key")]
    // CommunicationsKeyGenerationError(#[from] DecodingError),
    #[error("Failed to encode Comms data: {0}")]
    CommsEncodingError(#[from] OperatorCommsError),

    #[error("Failed to use Comms layer")]
    CommsCommunicationError,

    #[error("Invalid Comms address: {0}")]
    InvalidCommsAddress(String),

    #[error("Keys not found in program {0}")]
    KeysNotFound(Uuid),

    #[error("Failed to use Bitcoin Coordinator: {0}")]
    BitcoinCoordinatorError(#[from] BitcoinCoordinatorError),

    #[error("Broker channel error")]
    BrokerError(#[from] BrokerError),

    #[error("Serialization error {0}")]
    SerdeSerializationError(#[from] serde_json::Error),

    #[error("Invalid parser version")]
    InvalidMsgVersion,

    #[error("Invalid message type")]
    InvalidMessageType,

    #[error("Failed to serialize or deserialize message")]
    SerializationError,

    #[error("Invalid receive message format")]
    InvalidMessageFormat,

    #[error("Invalid transaction name {0}")]
    InvalidTransactionName(String),

    #[error("Failed to process message")]
    MessageProcessingError,

    #[error("Failed in MuSig2 signer {0}")]
    MuSig2SignerError(#[from] Musig2SignerError),

    #[error("Program already exists")]
    ProgramAlreadyExists(Uuid),

    #[error("Error creating script {0}")]
    ScriptError(#[from] ScriptError),

    #[error("Client error")]
    ClientError(#[from] ClientError),

    #[error("This feature is not implemented yet {0}")]
    NotImplemented(String),

    #[error("Emulator Error {0}")]
    EmulatorError(#[from] EmulatorError),

    #[error("Emulator Result Error {0}")]
    EmulatorResultError(#[from] EmulatorResultError),

    #[error("ProgramDefinition Error {0}")]
    ProgramDefinitionError(#[from] ProgramDefinitionError),

    #[error("Instrucion {0} not found")]
    InstructionNotFound(String),

    #[error("Challenge {0} not found")]
    ChallengeNotFound(String),

    #[error("Challenge with idx {0} not found")]
    ChallengeIdxNotFound(u32),

    #[error("Rom data {0} not found")]
    RomDataNotFound(u32),

    #[error("Insufficient amount to send the transaction")]
    InsufficientAmount,

    #[error("Transaction not found in block")]
    TransactionNotFoundInBlock,

    #[error("Inconsistent data retrieved of ZKP execution result from job {0}")]
    InconsistentZKPData(Uuid),

    #[error("Problem creating directory {0}: {1}")]
    DirectoryCreationError(String, std::io::Error),

    #[error("Peer id {0} not found in the list of participants")]
    InvalidParticipant(String),

    #[error("No signatures found for aggregated public key {0} and id {1}")]
    MissingPartialSignatures(String, String),

    #[error("No public nonces found for aggregated public key {0} and id {1}")]
    MissingPublicNonces(String, String),

    #[error("Wallet error {0}")]
    WalletError(#[from] bitvmx_wallet::wallet::errors::WalletError),

    #[error("Invalid List: {0}")]
    InvalidList(String),

    #[error("Identification error: {0}")]
    IdentificationError(#[from] IdentificationError),
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
