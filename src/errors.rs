use bitcoin::{consensus::encode::FromHexError, network::ParseNetworkError};
use bitcoincore_rpc::bitcoin::{key::ParsePublicKeyError, sighash::SighashTypeParseError};
use bitvmx_orchestrator::errors::OrchestratorError;
use config as settings;
use key_manager::errors::{KeyManagerError, KeyStoreError, WinternitzError};
use p2p_handler::P2pHandlerError;
use protocol_builder::errors::{ProtocolBuilderError, UnspendableKeyError};
use storage_backend::error::StorageError;
use thiserror::Error;
use uuid::Uuid;

#[derive(Error, Debug)]
pub enum BitVMXError {
    #[error("Invalid configuration")]
    ConfigurationError(#[from] ConfigError),

    #[error("Error when using KeyStore")]
    KeyStoreError(#[from] KeyStoreError),

    #[error("Error when using KeyManager")]
    KeyManagerError(#[from] KeyManagerError),

    #[error("Error when using Bitcoin client")]
    BitcoinError(#[from] BitcoinClientError),

    #[error("Error when creating unspendable key")]
    UnspendableKeyError(#[from] UnspendableKeyError),

    #[error("Error when creating protocol")]
    ProtocolBuilderError(#[from] ProtocolBuilderError),

    #[error("Error when creating the storagge")]
    StorageError(#[from] StorageError),

    #[error("Cannot find program with id {0}")]
    ProgramNotFound(Uuid),

    #[error("A program error has occurred")]
    ProgramError(#[from] ProgramError),

    #[error("Failed to process a Winternitz signature")]
    WinternitzError(#[from] WinternitzError),

    #[error("Program {0} is not ready to run. Please install it first.")]
    ProgramNotReady(Uuid),

    // #[error("Failed to create communications key")]
    // CommunicationsKeyGenerationError(#[from] DecodingError),
    #[error("Failed to encode P2P data")]
    P2PEncodingError(#[from] P2pHandlerError),

    #[error("Failed to use P2P layer")]
    P2PCommunicationError,

    #[error("Keys not found in program {0}")]
    KeysNotFound(Uuid),

    #[error("Failed to use Orchestrator")]
    OrchestratorError(#[from] OrchestratorError),

    #[error("Invalid parser version")]
    InvalidMsgVersion,

    #[error("Invalid message type")]
    InvalidMessageType,

    #[error("Failed to serialize or deserialize message")]
    SerializationError,

    #[error("Invalid receive message format")]
    InvalidMessageFormat,
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
}

#[derive(Error, Debug)]
pub enum ProgramError {
    #[error("Storage path configured for program is invalid {0}")]
    InvalidProgramStoragePath(String),

    #[error("Error while building dispute resolution protocol")]
    FailedToBuildDisputeResolutionProtocol(#[from] ProtocolBuilderError),
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
}
