use bitvmx_bitcoin_rpc::rpc_config::RpcConfig;
use bitvmx_orchestrator::config::MonitorConfig;
use key_manager::config::{KeyManagerConfig, KeyStorageConfig};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tracing::info;
use uuid::Uuid;

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

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ClientConfig {
    pub retry: u32,
    pub retry_delay: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)] // enforce strict field compliance
pub struct Config {
    pub bitcoin: RpcConfig,
    pub builder: ProtocolBuilderConfig,
    pub key_manager: KeyManagerConfig,
    pub key_storage: KeyStorageConfig,
    pub storage: StorageConfig,
    pub p2p: P2PConfig,
    pub monitor: MonitorConfig,
    pub broker_storage: String,
    pub broker_port: u16,
    pub client: ClientConfig,
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
