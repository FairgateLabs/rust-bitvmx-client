use core::time::Duration;
use std::thread;

use anyhow::Result;
use bitcoin::Network;
use bitcoind::{bitcoind::{Bitcoind, BitcoindFlags}, config::BitcoindConfig};
use bitvmx_bitcoin_rpc::bitcoin_client::BitcoinClient;
use bitvmx_bitcoin_rpc::bitcoin_client::BitcoinClientApi;
use bitvmx_client::config::Config;
use tracing::{debug, info};

/// Number of blocks to mine initially to ensure sufficient coin maturity
pub const INITIAL_BLOCK_COUNT: u64 = 110;
pub const HIGH_FEE_NODE_ENABLED: bool = true;

pub struct BitcoinWrapper {
    client: BitcoinClient,
    network: bitcoin::Network,
}

// Allow transparent access to BitcoinClient methods
impl std::ops::Deref for BitcoinWrapper {
    type Target = BitcoinClient;

    fn deref(&self) -> &Self::Target {
        &self.client
    }
}

impl BitcoinWrapper {
    pub fn new(client: BitcoinClient, network: Network) -> Self {
        Self { client, network }
    }

    pub fn new_from_config(config: &Config) -> Result<Self> {
        let client = BitcoinClient::new(
            &config.bitcoin.url,
            &config.bitcoin.username,
            &config.bitcoin.password,
        )?;
        Ok(Self {
            client,
            network: config.bitcoin.network,
        })
    }

    pub fn wait_for_blocks(&self, blocks: u32) -> Result<()> {
        if blocks == 0 {
            return Ok(());
        }

        let mut height = self.get_best_block()?;
        let last_block = height + blocks;
        info!("Height: {}. Waiting until block: {}", height, last_block);

        let sleep_secs = match self.network {
            Network::Regtest => 1, // Give some time to bitvmx client to process new blocks and send news
            Network::Testnet | Network::Signet => 10,
            Network::Bitcoin => 60,
            _ => return Err(anyhow::anyhow!("Unsupported network")),
        };

        while height < last_block {
            if self.network == Network::Regtest {
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

    pub fn network(&self) -> Network {
        self.network
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
    let temp_bitcoind = Bitcoind::new(
        "bitcoin-regtest",
        "bitcoin/bitcoin:29.1",
        config.bitcoin.clone(),
    );

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
    let bitcoind_config = BitcoindConfig::new(
        "bitcoin-regtest".to_string(),
        "bitcoin/bitcoin:29.1".to_string(),
        None,
        config.bitcoin.clone(),
    );

    let bitcoind = match HIGH_FEE_NODE_ENABLED {
        true => {
            // Config to trigger speedup transactions in Regtest
            Bitcoind::new(
                bitcoind_config,
                Some(BitcoindFlags {
                    min_relay_tx_fee: 0.00001,
                    block_min_tx_fee: 0.00008,
                    debug: 1,
                    fallback_fee: 0.0002,
                }),
            )
        }
        false => Bitcoind::new(
            bitcoind_config,
            None
        ),
    };

    bitcoind.start()?;

    let bitcoin_client = BitcoinClient::new(
        &config.bitcoin.url,
        &config.bitcoin.username,
        &config.bitcoin.password,
    )?;

    let _address = bitcoin_client.init_wallet(&config.bitcoin.wallet)?;
    bitcoin_client.mine_blocks_to_address(INITIAL_BLOCK_COUNT, &_address)?;

    Ok((bitcoin_client, bitcoind))
}

pub fn init_client(config: Config) -> Result<(BitcoinClient, Network)> {
    let bitcoin_client = BitcoinClient::new(
        &config.bitcoin.url,
        &config.bitcoin.username,
        &config.bitcoin.password,
    )?;

    Ok((bitcoin_client, config.bitcoin.network))
}
