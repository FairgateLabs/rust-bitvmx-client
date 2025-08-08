use std::{
    sync::mpsc::{Receiver, Sender},
    thread,
    time::Duration,
};

use anyhow::Result;
use tracing::{debug, info, info_span};
use tracing_subscriber::EnvFilter;

use bitvmx_client::{bitvmx::BitVMX, config::Config};

struct OperatorInstance {
    name: String,
    bitvmx: BitVMX,
    ready: bool,
}

impl OperatorInstance {
    fn new(name: &str) -> Result<Self> {
        let _span = info_span!("", id = name).entered();
        Ok(Self {
            name: name.to_string(),
            bitvmx: init_bitvmx(name)?,
            ready: false,
        })
    }
}

fn config_trace() {
    // Try to read from RUST_LOG environment variable first, fall back to default if not set
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new("info,libp2p=off,bitvmx_transaction_monitor=off,bitcoin_indexer=off,bitcoin_coordinator=off,p2p_protocol=off,p2p_handler=off,tarpc=off,broker=off"))
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
    clear_db(&config.broker_storage.path);

    info!("config: {:?}", config.storage.path);

    let bitvmx = BitVMX::new(config)?;
    Ok(bitvmx)
}

fn run_bitvmx(opn: &str, rx: Receiver<()>, tx: Option<Sender<()>>) -> Result<()> {
    info!("Starting BitVMX instance with operator: {}", opn);

    // Determine which operators to run
    let operator_names: Vec<&str> = match opn {
        "all" => vec!["op_1", "op_2", "op_3", "op_4"],
        "all-testnet" => vec!["testnet_op_1", "testnet_op_2", "testnet_op_3", "testnet_op_4"],
        single_op => vec![single_op],
    };

    // Create instances for each operator
    let mut instances: Vec<OperatorInstance> = operator_names
        .into_iter()
        .map(OperatorInstance::new)
        .collect::<Result<Vec<_>>>()?;

    info!("BitVMX instance initialized");
    for instance in &instances {
        let _span = info_span!("", id = instance.name).entered();
        info!("P2P Address: {}", instance.bitvmx.address());
        info!("Peer ID: {}", instance.bitvmx.peer_id());
        info!("Starting Bitcoin blockchain sync");
    }

    // Main processing loop
    loop {
        // Check if Ctrl+C was pressed to gracefully shutdown
        if rx.try_recv().is_ok() {
            info!("Ctrl+C received, shutting down");
            break;
        }

        for instance in instances.iter_mut() {
            // include operator name in logs
            let _span = info_span!("", id = instance.name).entered();

            if instance.ready {
                // This instance is synced with Bitcoin chain. Call tick() to process pending
                // operations, handle P2P messages, and execute BitVMX protocol logic.
                instance.bitvmx.tick()?;
                thread::sleep(Duration::from_millis(10));
            } else {
                // Still syncing with Bitcoin blockchain. Process bitcoin updates to catch up to the
                // current chain tip
                instance.ready = instance.bitvmx.process_bitcoin_updates()?;
                if !instance.ready {
                    // TODO move this log to indexer/coordinator if we need to see sync progress
                    debug!("Waiting for sync to complete");
                } else {
                    // Sync complete - ready to start normal operation
                    info!("Sync complete, starting normal operation");
                    // Signal to any waiting threads that initialization is complete
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
