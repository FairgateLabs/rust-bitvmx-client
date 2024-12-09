use bitcoin::Network;
use config as settings;
use key_manager::config::KeyManagerConfig;
use serde::Deserialize;
use tracing::{info, warn};
use uuid::Uuid;
use std::{env, path::{Path, PathBuf}};

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
    pub peer_id_file: String,
    pub timeout: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CliConfig {
    pub root: String,
    pub program_home: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct StorageConfig {
    pub password: String,
    pub db: String,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)] // enforce strict field compliance
pub struct Config {
    pub bitcoin: BitcoinConfig,
    pub builder: ProtocolBuilderConfig,
    pub key_manager: KeyManagerConfig,
    pub storage: StorageConfig,
    pub p2p: P2PConfig,
    pub cli: CliConfig,
}

impl Config {
    pub fn new(config: Option<String>) -> Result<Config, ConfigError> {
        let env = match config {
            Some(c) => {
                info!("Using config: {}", c);
                c
            }
            None => Config::get_env()
        };

        Config::parse_config(env)
    }

    fn get_env() -> String {
        env::var("BITVMX_ENV")
            .unwrap_or_else(|_| {
                let default_env = DEFAULT_ENV.to_string();
                warn!("BITVMX_ENV not set. Using default environment: {}", default_env);
                default_env
            }
        )
    }

    fn parse_config(env: String) -> Result<Config, ConfigError> {
        let config_path = format!("{}/{}.json", CONFIG_PATH, env);

        let settings = settings::Config::builder()
            .add_source(config::File::with_name(&config_path))
            .build()
            .map_err(ConfigError::ConfigFileError)?;

        settings.try_deserialize::<Config>()
            .map_err(ConfigError::ConfigFileError)
    }

    pub fn network(&self) -> Result<Network, ConfigError> {
        self.bitcoin.network.parse::<Network>().map_err(ConfigError::InvalidNetwork)
    }

    pub fn key_derivation_path(&self) -> &str {
        self.key_manager.key_derivation_path.as_str()
    }

    pub fn keystore_path(&self) -> PathBuf {
        let root = Path::new(self.cli.root.as_str());
        root.join(self.storage.db.as_str())
    }

    pub fn keystore_password(&self) -> Vec<u8> {
        self.storage.password.as_bytes().to_vec()
    }

    pub fn key_derivation_seed(&self) -> Result<[u8; 32], ConfigError> {
        let bytes = hex::decode(self.key_manager.key_derivation_seed.clone()).map_err(| _ | ConfigError::InvalidKeyDerivationSeed)?;
        bytes.try_into().map_err(| _ | ConfigError::InvalidKeyDerivationSeed)
    }

    pub fn winternitz_seed(&self) -> Result<[u8; 32], ConfigError> {
        let bytes = hex::decode(self.key_manager.winternitz_seed.clone()).map_err(| _ | ConfigError::InvalidWinternitzSeed)?;
        bytes.try_into().map_err(| _ | ConfigError::InvalidWinternitzSeed)
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

    pub fn peer_id_file_path(&self) -> PathBuf {
        let root = Path::new(self.cli.root.as_str());
        root.join(self.p2p.peer_id_file.as_str())
    }

    pub fn p2p_timeout(&self) -> u64 {
        self.p2p.timeout
    }

    pub fn program_home(&self) -> PathBuf {
        let root = Path::new(self.cli.root.as_str());
        root.join(self.cli.program_home.as_str())
    }

    pub fn program_storage_path(&self, program_id: Uuid) -> PathBuf {
        // let dir = env::temp_dir();
        // let path = dir.join(program_id.to_string());
        // std::fs::create_dir_all(&path).map_err(|_| ConfigError::ProtocolStoragePathError(path.to_string_lossy().into_owned()))?;
        let root = Path::new(self.cli.root.as_str());
        let programs = root.join(self.cli.program_home.as_str());
        programs.join(program_id.to_string())
    }
}
