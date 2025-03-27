use std::{str::FromStr, thread, time::Duration};

use anyhow::Result;
use bitcoin::{Network, PublicKey, Txid};
use bitcoind::bitcoind::Bitcoind;
use bitvmx_bitcoin_rpc::bitcoin_client::{BitcoinClient, BitcoinClientApi};
use bitvmx_broker::{channel::channel::DualChannel, rpc::BrokerConfig};
use bitvmx_client::{
    bitvmx::BitVMX, client::BitVMXClient, config::Config, program::{
        dispute::Funding,
        participant::{P2PAddress, ParticipantRole},
    }, types::IncomingBitVMXApiMessages
};
use p2p_handler::PeerId;
use tracing::{info, error};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

fn config_trace() {
    let filter = EnvFilter::builder()
        .parse("info")
        .expect("Invalid filter");

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .init();
}

//cargo test --release  -- --ignored
#[ignore]
#[test]
pub fn client() -> Result<()> {
    config_trace();
    
    info!("Starting client");
    let client = BitVMXClient::new(22222, 478);

    info!("Sending message");
    client.send_message(IncomingBitVMXApiMessages::Ping()).unwrap();

    let msg = client.get_message();
    info!("Received message: {:?}", msg);
    
    info!("Bye");
    Ok(())
}
