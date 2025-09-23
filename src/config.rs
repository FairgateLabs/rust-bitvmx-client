use bitcoin_coordinator::config::CoordinatorSettingsConfig;
use bitvmx_bitcoin_rpc::rpc_config::RpcConfig;
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
pub struct P2PConfig {
    pub address: String,
    pub key: String,
    pub peer_id_file: String,
    pub timeout: u64,
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
#[serde(deny_unknown_fields)] // enforce strict field compliance
pub struct Config {
    pub bitcoin: RpcConfig,
    pub key_manager: KeyManagerConfig,
    pub key_storage: StorageConfig,
    pub storage: StorageConfig,
    pub p2p: P2PConfig,
    pub broker_storage: StorageConfig,
    pub broker_port: u16,
    pub client: ClientConfig,
    pub coordinator_settings: Option<CoordinatorSettingsConfig>,
    pub coordinator: ThrotthleUpdate,
    pub wallet: WalletConfig,
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
}
