use std::{str::FromStr, thread, time::Duration};
use anyhow::Result;
use bitcoin::{Network, PublicKey, Txid};
use bitvmx_broker::{channel::channel::DualChannel, rpc::BrokerConfig};
use tracing::{info, error};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

use bitvmx_client::{
    bitvmx::BitVMX,
    config::Config,
    program::{
        dispute::Funding,
        participant::{P2PAddress, ParticipantRole},
    },
    types::IncomingBitVMXApiMessages,
};

fn config_trace() {
    let filter = EnvFilter::builder()
        .parse("info,libp2p=off,bitvmx_transaction_monitor=off,bitcoin_indexer=off,bitcoin_coordinator=off,p2p_protocol=off,p2p_handler=off,tarpc=off")
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
    
    let (mut bitvmx, bridge_channel) = init_bitvmx(role)?;
    
    info!("BitVMX instance initialized");
    info!("P2P Address: {}", bitvmx.address());
    info!("Peer ID: {}", bitvmx.peer_id());

    // Main processing loop
    loop {
        match bitvmx.tick() {
            Ok(_) => {
                // // Process any messages from the broker
                // if let Ok(Some((msg, from))) = bridge_channel.recv() {
                //     info!("Received message from {}: {}", from, msg);
                // }

                // prevent busy waiting
                thread::sleep(Duration::from_millis(100));
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

    run_bitvmx(role)
}
