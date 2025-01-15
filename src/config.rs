use bitcoin::Network;
use bitvmx_orchestrator::config::MonitorConfig;
use config as settings;
use key_manager::config::{KeyManagerConfig, KeyStorageConfig};
use serde::Deserialize;
use std::{
    env,
    path::{Path, PathBuf},
};
use tracing::{info, warn};
use uuid::Uuid;

use crate::errors::ConfigError;

static DEFAULT_ENV: &str = "development";
static CONFIG_PATH: &str = "config";

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
pub struct BitcoinConfig {
    pub network: String,
    pub url: String,
    pub username: String,
    pub password: String,
    pub wallet: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct P2PConfig {
    pub address: String,
    pub key: String,
    pub peer_id_file: String,
    pub timeout: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct StorageConfig {
    pub password: String,
    pub db: String,
    pub program: String, //TODO: Unifiy stroage
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)] // enforce strict field compliance
pub struct Config {
    pub bitcoin: BitcoinConfig,
    pub builder: ProtocolBuilderConfig,
    pub key_manager: KeyManagerConfig,
    pub key_storage: KeyStorageConfig,
    pub storage: StorageConfig,
    pub p2p: P2PConfig,
    pub monitor: MonitorConfig,
}

impl Config {
    pub fn new(config: Option<String>) -> Result<Config, ConfigError> {
        let env = match config {
            Some(c) => {
                info!("Using config: {}", c);
                c
            }
            None => Config::get_env(),
        };

        Config::parse_config(env)
    }

    fn get_env() -> String {
        env::var("BITVMX_ENV").unwrap_or_else(|_| {
            let default_env = DEFAULT_ENV.to_string();
            warn!(
                "BITVMX_ENV not set. Using default environment: {}",
                default_env
            );
            default_env
        })
    }

    fn parse_config(env: String) -> Result<Config, ConfigError> {
        let config_path = format!("{}/{}.json", CONFIG_PATH, env);

        let settings = settings::Config::builder()
            .add_source(config::File::with_name(&config_path))
            .build()
            .map_err(ConfigError::ConfigFileError)?;

        settings
            .try_deserialize::<Config>()
            .map_err(ConfigError::ConfigFileError)
    }

    pub fn network(&self) -> Result<Network, ConfigError> {
        self.bitcoin
            .network
            .parse::<Network>()
            .map_err(ConfigError::InvalidNetwork)
    }

    pub fn bitcoin_rpc_url(&self) -> &str {
        self.bitcoin.url.as_str()
    }

    pub fn bitcoin_rpc_username(&self) -> &str {
        self.bitcoin.username.as_str()
    }

    pub fn bitcoin_rpc_password(&self) -> &str {
        self.bitcoin.password.as_str()
    }

    pub fn bitcoin_rpc_wallet(&self) -> &str {
        self.bitcoin.wallet.as_str()
    }

    pub fn p2p_address(&self) -> &str {
        self.p2p.address.as_str()
    }

    pub fn p2p_key(&self) -> &str {
        self.p2p.key.as_str()
    }

    pub fn p2p_timeout(&self) -> u64 {
        self.p2p.timeout
    }

    pub fn program_storage_path(&self, program_id: Uuid) -> PathBuf {
        let root = Path::new(self.storage.program.as_str());
        root.join(program_id.to_string())
    }
}
