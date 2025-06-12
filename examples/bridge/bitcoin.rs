use anyhow::Result;
use bitcoin::Network;
use bitcoind::bitcoind::Bitcoind;
use bitvmx_bitcoin_rpc::bitcoin_client::BitcoinClient;
use bitvmx_client::config::Config;
use bitvmx_wallet::wallet::Wallet;
use tracing::info;
use tracing_subscriber::EnvFilter;

/// Number of blocks to mine initially to ensure sufficient coin maturity
const INITIAL_BLOCK_COUNT: u64 = 101;
const WALLET_NAME: &str = "wallet";
const FUNDING_ID: &str = "fund_1";

/// Helper function to clear database directories
fn clear_db(path: &str) {
    let _ = std::fs::remove_dir_all(path);
}

/// Initialize tracing/logging
fn config_trace() {
    let default_modules = [
        "info",
        "libp2p=off",
        "bitvmx_transaction_monitor=off",
        "bitcoin_indexer=off",
        "bitcoin_coordinator=off",
        "p2p_protocol=off",
        "p2p_handler=off",
        "tarpc=off",
        "key_manager=off",
        "memory=off",
        "broker=off",
    ];

    let filter = EnvFilter::builder()
        .parse(default_modules.join(","))
        .expect("Invalid filter");

    tracing_subscriber::fmt()
        .with_target(true)
        .with_env_filter(filter)
        .init();
}

pub fn prepare_bitcoin() -> Result<(BitcoinClient, Bitcoind, Wallet)> {
    let config = Config::new(Some("config/op_1.yaml".to_string()))?;

    let bitcoind = Bitcoind::new(
        "bitcoin-regtest",
        "ruimarinho/bitcoin-core",
        config.bitcoin.clone(),
    );
    info!("Starting bitcoind");
    bitcoind.start()?;

    let wallet_config = match config.bitcoin.network {
        Network::Regtest => "config/wallet_regtest.yaml",
        Network::Testnet => "config/wallet_testnet.yaml",
        _ => panic!("Not supported network {}", config.bitcoin.network),
    };

    let wallet_config = bitvmx_settings::settings::load_config_file::<
        bitvmx_wallet::config::WalletConfig,
    >(Some(wallet_config.to_string()))?;
    if config.bitcoin.network == Network::Regtest {
        clear_db(&wallet_config.storage.path);
        clear_db(&wallet_config.key_storage.path);
    }
    let wallet = Wallet::new(wallet_config, true)?;
    wallet.mine(INITIAL_BLOCK_COUNT)?;

    wallet.create_wallet(WALLET_NAME)?;
    wallet.regtest_fund(WALLET_NAME, FUNDING_ID, 100_000_000)?;

    let bitcoin_client = BitcoinClient::new(
        &config.bitcoin.url,
        &config.bitcoin.username,
        &config.bitcoin.password,
    )?;

    Ok((bitcoin_client, bitcoind, wallet))
}

fn main() -> Result<()> {
    // Initialize logging
    config_trace();
    
    info!("Starting Bitcoin preparation script...");
    
    // Prepare Bitcoin setup
    let (bitcoin_client, bitcoind, wallet) = prepare_bitcoin()?;
    
    info!("Bitcoin setup completed successfully!");
    info!("Bitcoin client initialized");
    info!("Bitcoind container started");
    info!("Wallet created and funded");
    
    // You can add additional logic here to use the bitcoin_client, bitcoind, and wallet
    
    info!("Script completed successfully");
    
    Ok(())
}
