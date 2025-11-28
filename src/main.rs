use std::{
    path::Path,
    sync::mpsc::{Receiver, Sender},
    thread,
    time::Duration,
};

use anyhow::Result;
use bitcoin::Network;
use bitvmx_wallet::wallet::{RegtestWallet, Wallet};
use clap::{Arg, Command};
use tracing::{debug, info, info_span};
use tracing_subscriber::EnvFilter;

use bitvmx_client::{bitvmx::BitVMX, config::Config};

struct OperatorInstance {
    name: String,
    bitvmx: BitVMX,
    ready: bool,
}

impl OperatorInstance {
    fn new(name: &str, fresh: bool) -> Result<Self> {
        let _span = info_span!("", id = name).entered();
        Ok(Self {
            name: name.to_string(),
            bitvmx: init_bitvmx(name, fresh)?,
            ready: false,
        })
    }
}

fn config_trace() {
    // Try to read from RUST_LOG environment variable first, fall back to default if not set
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new("info,bitvmx_transaction_monitor=off,bitcoin_indexer=off,bitcoin_coordinator=info,tarpc=off,bitvmx_broker=off,broker=off,bitvmx_wallet=info,bitvmx_bitcoin_rpc=off"))
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

fn init_bitvmx(opn: &str, fresh: bool) -> Result<BitVMX> {
    let filename = format!("config/{}.yaml", opn);
    if !Path::new(&filename).exists() {
        panic!(
            "Config file at path {} does not exist. Please create the configuration file before running the client.",
            filename
        );
    }
    let config = Config::new(Some(filename))?;

    if fresh {
        clear_db(&config.storage.path);
        clear_db(&config.key_storage.path);
        clear_db(&config.broker.storage.path);
        clear_db(&config.comms.storage_path);

        if config.bitcoin.network == Network::Regtest {
            Wallet::clear_db(&config.wallet).unwrap();
        }
    }

    info!("config: {:?}", config.storage.path);

    let mut bitvmx = BitVMX::new(config)?;
    bitvmx.sync_wallet()?;
    Ok(bitvmx)
}

fn run_bitvmx(opn: &str, fresh: bool, rx: Receiver<()>, tx: Option<Sender<()>>) -> Result<()> {
    info!("Starting BitVMX instance with operator: {}", opn);

    // Determine which operators to run
    let operator_names: Vec<&str> = match opn {
        "all" => vec!["op_1", "op_2", "op_3", "op_4"],
        "all-testnet" => vec![
            "testnet_op_1",
            "testnet_op_2",
            "testnet_op_3",
            "testnet_op_4",
        ],
        single_op => vec![single_op],
    };

    // Create instances for each operator
    let mut instances: Vec<OperatorInstance> = operator_names
        .into_iter()
        .map(|name| OperatorInstance::new(name, fresh))
        .collect::<Result<Vec<_>>>()?;

    info!("BitVMX instance initialized");
    for instance in &instances {
        let _span = info_span!("", id = instance.name).entered();
        info!("Comms Address: {}", instance.bitvmx.address());
        info!("Peer Public Key Hash: {}", instance.bitvmx.pubkey_hash()?);
        info!("Starting Bitcoin blockchain sync");
    }

    // Chain the default hook so RUST_BACKTRACE=1 prints full backtraces
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        // print full backtrace (honors RUST_BACKTRACE)
        default_hook(info);
        // optional: also log a compact line via tracing
        if let Some(loc) = info.location() {
            tracing::error!("panic at {}:{}: {}", loc.file(), loc.line(), info);
        }
    }));

    // Main processing loop wrapped in catch_unwind to ensure coordinated shutdown on panic
    let loop_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
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
                    if let Err(e) = instance.bitvmx.tick() {
                        tracing::error!("Error in tick(): {e:?}");
                        // escalate fatal errors to shutdown signal
                        if e.is_fatal() {
                            info!("Fatal error detected, initiating shutdown");
                            return; // break out to shutdown
                        }
                        thread::sleep(Duration::from_millis(100));
                    } else {
                        thread::sleep(Duration::from_millis(10));
                    }
                } else {
                    // Still syncing with Bitcoin blockchain. Process bitcoin updates to catch up to the
                    // current chain tip
                    match instance.bitvmx.process_bitcoin_updates() {
                        Ok(ready) => {
                            instance.ready = ready;
                            if !instance.ready {
                                // TODO move this log to indexer/coordinator if we need to see sync progress
                                debug!("Waiting for sync to complete");
                                thread::sleep(Duration::from_millis(25));
                            } else {
                                // Sync complete - ready to start normal operation
                                info!("Sync complete, starting normal operation");
                                // Signal to any waiting threads that initialization is complete
                                if let Some(tx) = &tx {
                                    let _ = tx.send(());
                                }
                            }
                        }
                        Err(e) => {
                            tracing::error!("Error syncing bitcoin updates: {e:?}");
                            if e.is_fatal() {
                                info!("Fatal error during sync, initiating shutdown");
                                return; // break out to shutdown
                            }
                            thread::sleep(Duration::from_millis(100));
                        }
                    }
                }
            }
        }
    }));

    if loop_result.is_err() {
        info!("Panic captured in main loop, initiating shutdown");
    }

    // Coordinated shutdown: give each instance a chance to finish and persist state
    for instance in instances.iter_mut() {
        let _span = info_span!("", id = instance.name).entered();
        let _ = instance.bitvmx.shutdown(Duration::from_secs(5));
    }

    Ok(())
}

fn main() -> Result<()> {
    config_trace();

    // CLI: operator name and flags
    let matches = Command::new("BitVMX Client")
        .about("Runs BitVMX operators")
        .arg(
            Arg::new("operator")
                .required(true)
                .value_name("OPERATOR")
                .help("Operator profile to run: op_1 | op_2 | op_3 | op_4 | all | all-testnet"),
        )
        .arg(
            Arg::new("fresh")
                .long("fresh")
                .action(clap::ArgAction::SetTrue)
                .help("If set, clears local databases and keys before starting"),
        )
        .get_matches();

    let opn = matches
        .get_one::<String>("operator")
        .map(String::as_str)
        .expect("operator is required");
    let fresh = matches.get_flag("fresh");

    // Set up Ctrl+C handler
    let (tx, rx) = std::sync::mpsc::channel();
    ctrlc::set_handler(move || {
        let _ = tx.send(());
    })
    .expect("Error setting Ctrl+C handler");

    run_bitvmx(opn, fresh, rx, None)
}
