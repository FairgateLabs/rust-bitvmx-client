use anyhow::Result;
use bitcoin::Network;
use bitvmx_bitcoin_rpc::bitcoin_client::{BitcoinClient, BitcoinClientApi};
use bitvmx_broker::{channel::channel::DualChannel, rpc::BrokerConfig};
use std::{thread, time::Duration};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use bitvmx_client::{bitvmx::BitVMX, config::Config};

fn config_trace() {
    let filter = EnvFilter::builder()
        // .parse("info,libp2p=off,bitvmx_transaction_monitor=off,bitcoin_indexer=off,bitcoin_coordinator=off,p2p_protocol=off,p2p_handler=off,tarpc=off")
        .parse("info,libp2p=off,bitvmx_transaction_monitor=off,bitcoin_coordinator=off,p2p_protocol=off,p2p_handler=off,tarpc=off")
        // .parse("info,libp2p=off,p2p_protocol=off,p2p_handler=off,tarpc=off")
        .expect("Invalid filter");

    tracing_subscriber::fmt()
        .without_time()
        .with_target(true)
        .with_env_filter(filter)
        .init();
}

fn clear_db(path: &str) {
    let _ = std::fs::remove_dir_all(path);
}

fn init_bitvmx(role: &str) -> Result<(BitVMX, DualChannel)> {
    let config = Config::new(Some(format!("config/{}.yaml", role)))?;
    let broker_config = BrokerConfig::new(config.broker_port, None);
    let bridge_client = DualChannel::new(&broker_config, 2);

    clear_db(&config.storage.db);
    clear_db(&config.key_storage.path);
    clear_db(&config.broker_storage);

    info!("config: {:?}", config.storage.db);

    let bitvmx = BitVMX::new(config)?;
    Ok((bitvmx, bridge_client))
}

fn run_bitvmx(role: &str) -> Result<()> {
    info!("Starting BitVMX instance with role: {}", role);

    let (mut bitvmx, _bridge_channel) = init_bitvmx(role)?;

    info!("BitVMX instance initialized");
    info!("P2P Address: {}", bitvmx.address());
    info!("Peer ID: {}", bitvmx.peer_id());

    // Main processing loop
    loop {
        match bitvmx.tick() {
            Ok(_) => {
                // prevent busy waiting
                // thread::sleep(Duration::from_millis(100));
            }
            Err(e) => {
                error!("Error in BitVMX tick: {:?}", e);
                break;
            }
        }
    }

    Ok(())
}

fn main() -> Result<()> {
    config_trace();

    // Get role from command line args
    let args: Vec<String> = std::env::args().collect();
    let role = args.get(1).map(String::as_str).unwrap_or("prover");

    if role != "prover" && role != "verifier" {
        error!("Invalid role. Must be either 'prover' or 'verifier'");
        std::process::exit(1);
    }

    let config = Config::new(Some(format!("config/{}.yaml", role)))?;
    // let bitcoind = Bitcoind::new(
    //     "bitcoin-regtest",
    //     "ruimarinho/bitcoin-core",
    //     config.bitcoin.clone(),
    // );
    // info!("Starting bitcoind");
    // bitcoind.start()?;

    let wallet_name = format!("test_wallet_{}", role);
    let bitcoin_client = BitcoinClient::new(
        &format!("{}/wallet/{}", config.bitcoin.url, wallet_name),
        &config.bitcoin.username,
        &config.bitcoin.password,
    )?;

    let wallet = bitcoin_client
        .init_wallet(Network::Regtest, &wallet_name)
        .unwrap();

    info!("Mine 1 block to address {:?}", wallet);
    bitcoin_client.mine_blocks_to_address(1, &wallet).unwrap();

    run_bitvmx(role)
}
