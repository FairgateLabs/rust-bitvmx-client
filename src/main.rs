use std::{
    sync::mpsc::{Receiver, Sender},
    thread,
    time::Duration,
};

use anyhow::Result;
use tracing::info;
use tracing_subscriber::EnvFilter;

use bitvmx_client::{bitvmx::BitVMX, config::Config};

fn config_trace() {
    let filter = EnvFilter::builder()
        .parse("info,bitvmx_transaction_monitor=off,bitcoin_indexer=off,bitcoin_coordinator=info,operator_comms=off,tarpc=off,broker=off")
        // .parse("info,operator_comms=off,tarpc=off")
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
    let config = Config::new(Some(format!("config/{}.yaml", opn)))?;

    clear_db(&config.storage.path);
    clear_db(&config.key_storage.path);
    clear_db(&config.broker.storage.path);

    info!("config: {:?}", config.storage.path);

    let bitvmx = BitVMX::new(config)?;
    Ok(bitvmx)
}

fn run_bitvmx(opn: &str, rx: Receiver<()>, tx: Option<Sender<()>>) -> Result<()> {
    info!("Starting BitVMX instance with operator: {}", opn);

    let mut instances = if opn == "all" {
        vec![
            init_bitvmx("op_1")?,
            init_bitvmx("op_2")?,
            init_bitvmx("op_3")?,
            init_bitvmx("op_4")?,
        ]
    } else if opn == "all-testnet" {
        vec![
            init_bitvmx("testnet_op_1")?,
            init_bitvmx("testnet_op_2")?,
            init_bitvmx("testnet_op_3")?,
            init_bitvmx("testnet_op_4")?,
        ]
    } else {
        vec![init_bitvmx(opn)?]
    };

    info!("BitVMX instance initialized");
    for bitvmx in &instances {
        info!("Comms Address: {}", bitvmx.address());
        info!("Peer Public Key Hash: {}", bitvmx.pubkey_hash()?);
    }

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
                    if let Some(tx) = &tx {
                        let _ = tx.send(());
                    }
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
        .expect("Define the config file to use. Example: op_1. Also can be used [all|all-testnet]");

    // Set up Ctrl+C handler
    let (tx, rx) = std::sync::mpsc::channel();
    ctrlc::set_handler(move || {
        let _ = tx.send(());
    })
    .expect("Error setting Ctrl+C handler");

    run_bitvmx(opn, rx, None)
}
