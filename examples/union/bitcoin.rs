use core::time::Duration;
use std::thread;

use anyhow::Result;
use bitcoin::Network;
use bitvmx_bitcoin_rpc::rpc_config::NetworkFlavor;
use bitcoind::{
    bitcoind::{Bitcoind, BitcoindFlags},
    config::BitcoindConfig,
};
use bitvmx_bitcoin_rpc::bitcoin_client::BitcoinClient;
use bitvmx_bitcoin_rpc::bitcoin_client::BitcoinClientApi;
use bitvmx_client::config::Config;
use tracing::{debug, info};

/// Number of blocks to mine initially to ensure sufficient coin maturity
pub const INITIAL_BLOCK_COUNT: u64 = 110;
pub const HIGH_FEE_NODE_ENABLED: bool = true;

pub struct BitcoinWrapper {
    client: BitcoinClient,
    network_flavor: NetworkFlavor,
}

// Allow transparent access to BitcoinClient methods
impl std::ops::Deref for BitcoinWrapper {
    type Target = BitcoinClient;

    fn deref(&self) -> &Self::Target {
        &self.client
    }
}

impl BitcoinWrapper {
    pub fn new(client: BitcoinClient, network_flavor: NetworkFlavor) -> Self {
        Self { client, network_flavor }
    }

    pub fn new_from_config(config: &Config) -> Result<Self> {
        let client = BitcoinClient::new(
            &config.bitcoin.url,
            &config.bitcoin.username,
            &config.bitcoin.password,
        )?;
        Ok(Self {
            client,
            network_flavor: config.bitcoin.network_flavor,
        })
    }

    pub fn wait_for_blocks(&self, blocks: u32) -> Result<()> {
        if blocks == 0 {
            return Ok(());
        }

        let mut height = self.get_best_block()?;
        let last_block = height + blocks;
        info!("Height: {}. Waiting until block: {}", height, last_block);

        let sleep_secs = match self.network_flavor {
            NetworkFlavor::Regtest => 1, // Give some time to bitvmx client to process new blocks and send news
            // Blocks land roughly every 10s; poll faster so we notice promptly.
            NetworkFlavor::Simchain => 2,
            NetworkFlavor::Testnet | NetworkFlavor::Testnet4 | NetworkFlavor::Signet => 10,
            NetworkFlavor::Bitcoin => 60,
        };

        while height < last_block {
            // Only where blocks are ours to mint. Simchain would happily serve
            // `generatetoaddress` despite mining its own blocks, so this must be
            // gated on the capability rather than on the network.
            if self.network_flavor.can_mine_on_demand() {
                debug!("Mining 1 block...");
                self.mine_blocks(1)?;
            }
            debug!("Waiting {} seconds...", sleep_secs);
            thread::sleep(Duration::from_secs(sleep_secs));
            height = self.get_best_block()?;
            debug!("Current height: {}", height);
        }
        Ok(())
    }

    pub fn network_flavor(&self) -> NetworkFlavor {
        self.network_flavor
    }

    /// Address encoding identity for this chain.
    pub fn network(&self) -> Network {
        self.network_flavor.bitcoin_network()
    }
}

/// Helper function to clear database directories
pub fn clear_db(path: &str) {
    let _ = std::fs::remove_dir_all(path);
}

pub fn stop_existing_bitcoind() -> Result<()> {
    info!("Checking for existing bitcoind instance...");

    let config = Config::new(Some("config/development.yaml".to_string()))?;

    // Create a temporary Bitcoind instance to check if one is running and stop it
    let temp_bitcoind = Bitcoind::new(BitcoindConfig::default(), config.bitcoin, None);

    // Attempt to stop any existing instance
    match temp_bitcoind.stop() {
        Ok(_) => info!("Successfully stopped existing bitcoind instance"),
        Err(e) => {
            // This is expected if no instance was running
            info!(
                "No existing bitcoind instance found or error stopping: {}",
                e
            );
        }
    }

    Ok(())
}

pub fn prepare_bitcoin() -> Result<(BitcoinClient, Bitcoind)> {
    let config = Config::new(Some("config/development.yaml".to_string()))?;
    // Clear indexer, monitor, key manager and wallet data.
    clear_db(&config.storage.path);
    clear_db(&config.key_storage.path);
    // Wallet::clear_db(&config.wallet)?;

    info!("Starting bitcoind");
    let bitcoind_config = BitcoindConfig::default();

    let bitcoind = match HIGH_FEE_NODE_ENABLED {
        true => {
            // Config to trigger speedup transactions in Regtest
            Bitcoind::new(
                bitcoind_config,
                config.bitcoin.clone(),
                Some(BitcoindFlags {
                    min_relay_tx_fee: 0.00001,
                    block_min_tx_fee: 0.00008,
                    debug: 1,
                    fallback_fee: 0.0002,
                    maxmempool: None,
                }),
            )
        }
        false => Bitcoind::new(bitcoind_config, config.bitcoin.clone(), None),
    };

    bitcoind.start()?;

    let bitcoin_client = BitcoinClient::new_from_config(&config.bitcoin)?;

    let _address = bitcoin_client.init_wallet(&config.bitcoin.wallet)?;
    bitcoin_client.mine_blocks_to_address(INITIAL_BLOCK_COUNT, &_address)?;

    Ok((bitcoin_client, bitcoind))
}

pub fn init_client(config: Config) -> Result<(BitcoinClient, NetworkFlavor)> {
    // Built from the config so the simchain guard rails are armed.
    let bitcoin_client = BitcoinClient::new_from_config(&config.bitcoin)?;
    let network_flavor = config.bitcoin.network_flavor;

    Ok((bitcoin_client, network_flavor))
}
