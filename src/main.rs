use std::{thread, time::Duration};

use anyhow::Result;
use bitcoin::Network;
use bitvmx_bitcoin_rpc::bitcoin_client::{BitcoinClient, BitcoinClientApi};
use tracing::info;
use tracing_subscriber::EnvFilter;

use bitvmx_client::{bitvmx::BitVMX, config::Config};

fn config_trace() {
    let filter = EnvFilter::builder()
        .parse("info,libp2p=off,bitvmx_transaction_monitor=info,bitcoin_indexer=off,bitcoin_coordinator=off,p2p_protocol=off,p2p_handler=off,tarpc=off")
        .expect("Invalid filter");

    tracing_subscriber::fmt()
        //.without_time()
        .with_target(true)
        .with_env_filter(filter)
        .init();
}

fn clear_db(path: &str) {
    let _ = std::fs::remove_dir_all(path);
}

fn init_bitvmx(opn: &str) -> Result<BitVMX> {
    #[cfg(not(feature = "testnet"))]
    let config = Config::new(Some(format!("config/{}.yaml", opn)))?;
    #[cfg(feature = "testnet")]
    let config = Config::new(Some(format!("config/{}_testnet.yaml", opn)))?;

    clear_db(&config.storage.db);
    clear_db(&config.key_storage.path);
    clear_db(&config.broker_storage);

    info!("config: {:?}", config.storage.db);

    let bitvmx = BitVMX::new(config)?;
    Ok(bitvmx)
}

fn run_bitvmx(opn: &str) -> Result<()> {
    info!("Starting BitVMX instance with operator: {}", opn);

    let mut instances = if opn == "all" {
        vec![
            init_bitvmx("op_1")?,
            init_bitvmx("op_2")?,
            init_bitvmx("op_3")?,
            init_bitvmx("op_4")?,
        ]
    } else {
        vec![init_bitvmx(opn)?]
    };

    info!("BitVMX instance initialized");
    for bitvmx in &instances {
        info!("P2P Address: {}", bitvmx.address());
        info!("Peer ID: {}", bitvmx.peer_id());
    }

    // Set up Ctrl+C handler
    let (tx, rx) = std::sync::mpsc::channel();
    ctrlc::set_handler(move || {
        let _ = tx.send(());
    })
    .expect("Error setting Ctrl+C handler");

    let mut ready = false;

    // Main processing loop
    loop {
        // Check if Ctrl+C was pressed
        if rx.try_recv().is_ok() {
            info!("Ctrl+C received, shutting down...");
            break;
        }
        for bitvmx in instances.iter_mut() {
            if ready {
                bitvmx.tick()?;
                thread::sleep(Duration::from_millis(10));
            } else {
                ready = bitvmx.process_bitcoin_updates()?;
                if !ready {
                    info!("Waiting to get to the top of the Bitcoin chain...");
                } else {
                    info!("Bitcoin updates processed, ready to run.");
                }
                thread::sleep(Duration::from_millis(10));
            }
        }
    }

    Ok(())
}

fn main() -> Result<()> {
    config_trace();

    // Get role from command line args
    let args: Vec<String> = std::env::args().collect();
    let opn = args
        .get(1)
        .map(String::as_str)
        .expect("Define the config file to use. Example: op_1, and optionaly -init_wallet");

    // let bitcoind = Bitcoind::new(
    //     "bitcoin-regtest",
    //     "ruimarinho/bitcoin-core",
    //     config.bitcoin.clone(),
    // );
    // info!("Starting bitcoind");
    // bitcoind.start()?;

    let initwallet = args.get(2).map(String::as_str).unwrap_or("");
    if initwallet == "--init_wallet" {

        #[cfg(not(feature = "testnet"))]
        let config = Config::new(Some(format!("config/{}.yaml", opn)))?;
        #[cfg(feature = "testnet")]
        let config = Config::new(Some(format!("config/{}_testnet.yaml", opn)))?;
    

        let wallet_name = format!("test_wallet_{}", opn);
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
    } else if !initwallet.is_empty() {
        panic!("The second optional argument must be --init_wallet");
    }

    run_bitvmx(opn)
}
