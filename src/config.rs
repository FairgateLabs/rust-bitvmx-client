use std::net::{IpAddr, SocketAddr};

use bitcoin_coordinator::config::CoordinatorSettings;
use bitvmx_bitcoin_rpc::rpc_config::RpcConfig;
use bitvmx_broker::{identification::identifier::Identifier, rpc::tls_helper::Cert};
use key_manager::config::KeyManagerConfig;
use p2p_handler::p2p_handler::PubKeyHash;
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
    pub address: SocketAddr,
    pub priv_key: String,
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
pub struct BrokerConfig {
    pub allow_list: String,
    pub routing_table: String,
    pub priv_key: String,
    pub port: u16,
    pub ip: IpAddr,
    pub id: u8,
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
pub struct Component {
    pub priv_key: String,
    pub address: SocketAddr,
    pub id: u8,
}

impl Component {
    pub fn get_pubk_hash(&self) -> Result<PubKeyHash, ConfigError> {
        let cert = Cert::from_key_file(&self.priv_key.clone())?;
        Ok(cert.get_pubk_hash()?)
    }
    pub fn get_address(&self) -> SocketAddr {
        self.address
    }
    pub fn get_identifier(&self) -> Result<Identifier, ConfigError> {
        Ok(Identifier::new(
            self.get_pubk_hash()?,
            self.id,
            self.get_address(),
        ))
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ComponentsConfig {
    pub l2: Component,
    pub bitvmx: Component,
    pub emulator: Component,
    pub prover: Component,
}

impl ComponentsConfig {
    pub fn get_l2_identifier(&self) -> Result<Identifier, ConfigError> {
        Ok(Identifier::new(
            self.l2.get_pubk_hash()?,
            self.l2.id,
            self.l2.get_address(),
        ))
    }
    pub fn get_bitvmx_identifier(&self) -> Result<Identifier, ConfigError> {
        Ok(Identifier::new(
            self.bitvmx.get_pubk_hash()?,
            self.bitvmx.id,
            self.bitvmx.get_address(),
        ))
    }
    pub fn get_emulator_identifier(&self) -> Result<Identifier, ConfigError> {
        Ok(Identifier::new(
            self.emulator.get_pubk_hash()?,
            self.emulator.id,
            self.emulator.get_address(),
        ))
    }
    pub fn get_prover_identifier(&self) -> Result<Identifier, ConfigError> {
        Ok(Identifier::new(
            self.prover.get_pubk_hash()?,
            self.prover.id,
            self.prover.get_address(),
        ))
    }
    pub fn get_bitvmx_config(&self) -> &Component {
        &self.bitvmx
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)] // enforce strict field compliance
pub struct Config {
    pub bitcoin: RpcConfig,
    pub key_manager: KeyManagerConfig,
    pub key_storage: StorageConfig,
    pub storage: StorageConfig,
    pub p2p: P2PConfig,
    pub broker: BrokerConfig,
    pub client: ClientConfig,
    pub components: ComponentsConfig,
    pub coordinator_settings: Option<CoordinatorSettings>,
    pub coordinator: ThrotthleUpdate,
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

    pub fn p2p_address(&self) -> &SocketAddr {
        &self.p2p.address
    }

    pub fn p2p_key(&self) -> &str {
        self.p2p.priv_key.as_str()
    }

    pub fn p2p_timeout(&self) -> u64 {
        self.p2p.timeout
    }
}
