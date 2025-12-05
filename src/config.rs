use std::net::{IpAddr, SocketAddr};

use bitcoin_coordinator::config::CoordinatorSettingsConfig;
use bitvmx_bitcoin_rpc::rpc_config::RpcConfig;
use bitvmx_broker::{identification::identifier::Identifier, rpc::tls_helper::Cert};
use bitvmx_operator_comms::operator_comms::PubKeyHash;
use bitvmx_wallet::wallet::config::WalletConfig;
use key_manager::config::KeyManagerConfig;
use serde::{Deserialize, Serialize};
use storage_backend::storage_config::StorageConfig;
use tracing::info;

use crate::errors::ConfigError;

#[derive(Debug, Deserialize, Clone)]
pub struct ProtocolBuilderConfig {
    pub protocol_amount: u64,
    pub speedup_amount: u64,
    pub locked_amount: u64,
    pub locked_blocks: u16,
    pub ecdsa_sighash_type: String,
    pub taproot_sighash_type: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CommsConfig {
    pub address: SocketAddr,
    pub priv_key: String,
    pub storage_path: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ClientConfig {
    pub retry: u32,
    pub retry_delay: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ThrotthleUpdate {
    pub throtthle_bitcoin_updates_until_sync: u64,
    pub throtthle_bitcoin_updates: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct BrokerConfig {
    pub allow_list: String,
    pub routing_table: String,
    pub priv_key: String,
    pub port: u16,
    pub ip: IpAddr,
    // pub id: u8, // Asume that id is 0 always
    pub storage: StorageConfig,
}

impl BrokerConfig {
    pub fn get_address(&self) -> SocketAddr {
        SocketAddr::new(self.ip, self.port)
    }
    pub fn get_pubk_hash(&self) -> Result<PubKeyHash, ConfigError> {
        let cert = Cert::from_key_file(&self.priv_key.clone())?;
        Ok(cert.get_pubk_hash()?)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ComponentConfig {
    pub priv_key: String,
    pub id: u8,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TestConfig {
    pub l2: ComponentConfig,
    pub emulator: ComponentConfig,
    pub prover: ComponentConfig,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ComponentsConfig {
    pub l2: Identifier,
    pub bitvmx: Identifier,
    pub emulator: Identifier,
    pub prover: Identifier,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct PingConfig {
    pub enabled: bool,
    pub interval_secs: u64,
    pub timeout_secs: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct TimestampVerifierConfig {
    pub enabled: bool,
    pub max_drift_ms: i64,
}

impl Default for TimestampVerifierConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_drift_ms: 2000,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)] // enforce strict field compliance
pub struct Config {
    pub bitcoin: RpcConfig,
    pub key_manager: KeyManagerConfig,
    pub key_storage: StorageConfig,
    pub storage: StorageConfig,
    pub comms: CommsConfig,
    pub broker: BrokerConfig,
    pub client: ClientConfig,
    pub components: ComponentsConfig,
    pub testing: TestConfig, //This is here for testing purposes only
    pub coordinator_settings: Option<CoordinatorSettingsConfig>,
    pub coordinator: ThrotthleUpdate,
    pub wallet: WalletConfig,
    pub job_dispatcher_ping: Option<PingConfig>,
    pub timestamp_verifier: Option<TimestampVerifierConfig>,
}

impl Config {
    pub fn new(config: Option<String>) -> Result<Config, ConfigError> {
        match config {
            Some(config) => {
                info!("Using configuration: {}", config);
                Ok(bitvmx_settings::settings::load_config_file::<Config>(
                    Some(config),
                )?)
            }
            None => Ok(bitvmx_settings::settings::load::<Config>()?),
        }
    }

    pub fn comms_address(&self) -> &SocketAddr {
        &self.comms.address
    }

    pub fn comms_key(&self) -> &str {
        self.comms.priv_key.as_str()
    }
}
