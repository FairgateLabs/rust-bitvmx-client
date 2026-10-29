use std::net::{IpAddr, SocketAddr};

use bitcoin_coordinator::config::configs::BitcoinSettings;
use bitvmx_bitcoin_rpc::rpc_config::RpcConfig;
use bitvmx_broker::{
    identification::identifier::{Identifier, PubkHash},
    rpc::{config::BrokerSettings, tls_helper::Cert},
};
use bitvmx_settings::settings;
use bitvmx_wallet::wallet::config::WalletConfig;
use key_manager::config::KeyManagerConfig;
use serde::{Deserialize, Serialize};
use storage_backend::storage_config::StorageConfig;
use tracing::info;

use crate::{errors::ConfigError, throttle::ThrottleConfig, types::JobDispatcherType};

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
    /// Local socket the node binds and listens on. Never sent to peers, so it can be private,
    /// a Docker network IP or `0.0.0.0` (then `public_address` is required).
    pub address: SocketAddr,
    /// Address peers dial to reach this node, returned by `GetCommInfo`. Set it when `address`
    /// is not reachable by peers (Docker, NAT); defaults to `address`. Public, or private only
    /// when every peer shares that network. Must be a literal `IP:port`: hostnames are
    /// rejected, since peers dial and allow-list by IP. It does not set the source IP of
    /// outgoing connections; the OS and NAT decide that.
    pub public_address: Option<SocketAddr>,
    /// Accept a loopback, private or otherwise non-public address peers dial. Only for nodes
    /// whose peers all share that network (local tests, Docker, a VPC or VPN).
    #[serde(default)]
    pub allow_private_address: bool,
    pub priv_key: String,
    pub storage_path: String,
    pub allow_list: String,
}

impl CommsConfig {
    /// Address peers should dial: `public_address`, or the listen `address` when unset.
    /// Fails on an unspecified IP (`0.0.0.0`, `::`) or port 0, which no peer can dial, and on a
    /// non-public IP unless `allow_private_address` is set.
    pub fn public_address(&self) -> Result<SocketAddr, ConfigError> {
        let address = self.public_address.unwrap_or(self.address);
        if address.ip().is_unspecified() || address.port() == 0 {
            return Err(ConfigError::UndialableCommsAddress(address));
        }
        if !self.allow_private_address && !is_public_ip(address.ip()) {
            return Err(ConfigError::PrivateCommsAddress(address));
        }
        Ok(address)
    }
}

/// Whether peers outside this host's network can reach `ip`.
fn is_public_ip(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(ip) => {
            let [a, b, ..] = ip.octets();
            !(ip.is_loopback()
                || ip.is_private()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.is_multicast()
                || ip.is_broadcast()
                || ip.is_documentation()
                // 100.64/10 shared (CGNAT), 198.18/15 benchmarking and 240/4 reserved
                // (`Ipv4Addr::is_shared`, `is_benchmarking`, `is_reserved` are unstable).
                || (a == 100 && b & 0xc0 == 64)
                || (a == 198 && b & 0xfe == 18)
                || a >= 240)
        }
        IpAddr::V6(ip) => {
            !(ip.is_loopback()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || ip.is_unspecified()
                || ip.is_multicast()
                // 2001:db8::/32 documentation range (`Ipv6Addr::is_documentation` is unstable).
                || ip.segments()[..2] == [0x2001, 0x0db8])
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ClientConfig {
    pub retry: u32,
    pub retry_delay: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct BrokerConfig {
    #[serde(deserialize_with = "load_broker_settings")]
    pub settings: BrokerSettings,

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
    pub fn get_pubk_hash(&self) -> Result<PubkHash, ConfigError> {
        let cert = Cert::new_with_privk(settings::decrypt_or_read_file(&self.priv_key)?.as_str())?;
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
    pub garbler: ComponentConfig,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ComponentsConfig {
    pub l2: Identifier,
    pub bitvmx: Identifier,
    pub emulator: Identifier,
    pub prover: Identifier,
    pub garbler: Identifier,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct PingConfig {
    pub interval_secs: Option<u64>,
    pub timeout_secs: Option<u64>,
    #[serde(default)]
    pub services: Vec<JobDispatcherType>, // dispatchers to ping: Emulator, Garbler, ZKP
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
    pub coordinator_settings: Option<BitcoinSettings>,
    pub coordinator_throttle: ThrottleConfig,
    pub bitvmx_throttle: ThrottleConfig,
    pub wallet: WalletConfig,
    pub job_dispatcher_ping: Option<PingConfig>,
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

    pub fn comms_key(&self) -> &str {
        self.comms.priv_key.as_str()
    }
}

fn load_broker_settings<'de, D>(d: D) -> Result<BrokerSettings, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let path = String::deserialize(d)?;
    BrokerSettings::new(&path).map_err(serde::de::Error::custom)
}

#[cfg(test)]
mod tests {
    use super::CommsConfig;
    use crate::errors::ConfigError;

    fn comms(
        address: &str,
        public_address: Option<&str>,
    ) -> Result<CommsConfig, serde_json::Error> {
        serde_json::from_value(serde_json::json!({
            "address": address,
            "public_address": public_address,
            "priv_key": "",
            "storage_path": "",
            "allow_list": "",
        }))
    }

    fn private_comms(address: &str) -> CommsConfig {
        CommsConfig {
            allow_private_address: true,
            ..comms(address, None).unwrap()
        }
    }

    #[test]
    fn public_address_defaults_to_listen_address() {
        let config = comms("8.8.8.8:61180", None).unwrap();
        assert_eq!(config.public_address().unwrap(), config.address);
    }

    #[test]
    fn public_address_overrides_listen_address() {
        let config = comms("0.0.0.0:61180", Some("8.8.8.8:61180")).unwrap();
        assert_eq!(
            config.public_address().unwrap(),
            "8.8.8.8:61180".parse().unwrap()
        );
    }

    #[test]
    fn public_address_rejects_undialable_addresses() {
        for (address, public_address) in [
            ("0.0.0.0:61180", None),
            ("[::]:61180", None),
            ("127.0.0.1:61180", Some("0.0.0.0:61180")),
            ("8.8.8.8:0", None),
        ] {
            let mut config = comms(address, public_address).unwrap();
            for allow_private_address in [false, true] {
                config.allow_private_address = allow_private_address;
                assert!(
                    matches!(
                        config.public_address(),
                        Err(ConfigError::UndialableCommsAddress(_))
                    ),
                    "{address} / {public_address:?} / {allow_private_address}"
                );
            }
        }
    }

    #[test]
    fn public_address_rejects_private_addresses_unless_allowed() {
        for rejected in [
            "127.0.0.1:61181",
            "10.0.0.1:61181",
            "172.20.0.12:61181",
            "192.168.1.1:61181",
            "169.254.0.1:61181",
            "[::1]:61181",
            "[fd00::1]:61181",
            "[fe80::1]:61181",
            "[::ffff:10.0.0.1]:61181",
            "224.0.0.1:61181",
            "255.255.255.255:61181",
            "203.0.113.12:61181",
            "198.51.100.1:61181",
            "192.0.2.1:61181",
            "[ff02::1]:61181",
            "[2001:db8::1]:61181",
            "100.64.0.1:61181",
            "100.127.255.255:61181",
            "198.18.0.1:61181",
            "198.19.255.255:61181",
            "240.0.0.1:61181",
        ] {
            assert!(
                matches!(
                    comms(rejected, None).unwrap().public_address(),
                    Err(ConfigError::PrivateCommsAddress(_))
                ),
                "{rejected}"
            );
            assert!(
                private_comms(rejected).public_address().is_ok(),
                "{rejected}"
            );
        }
        for accepted in [
            "8.8.8.8:61181",
            "100.63.255.255:61181",
            "100.128.0.1:61181",
            "198.17.255.255:61181",
            "198.20.0.1:61181",
            "223.255.255.254:61181",
            "[2606:4700::1111]:61181",
        ] {
            assert!(
                comms(accepted, None).unwrap().public_address().is_ok(),
                "{accepted}"
            );
        }
    }

    #[test]
    fn public_address_rejects_hostnames() {
        assert!(comms("127.0.0.1:61180", Some("node1.example.com:61180")).is_err());
    }
}
