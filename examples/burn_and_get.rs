use anyhow::{Ok, Result};
use bitvmx_bitcoin_rpc::bitcoin_client::BitcoinClient;
use bitvmx_broker::{channel::channel::DualChannel, rpc::BrokerConfig};
use bitvmx_client::config::Config;

use bitcoin::Txid;
use tracing::info;
use tracing_subscriber::EnvFilter;
pub fn get_bitcoin_client() -> Result<BitcoinClient> {
    let config = Config::new(Some("config/op_1.yaml".to_string()))?;

    let bitcoin_client = BitcoinClient::new(
        &config.bitcoin.url,
        &config.bitcoin.username,
        &config.bitcoin.password,
    )?;

    Ok(bitcoin_client)
}

fn config_trace_aux() {
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
    ];

    let filter = EnvFilter::builder()
        .parse(default_modules.join(","))
        .expect("Invalid filter");

    tracing_subscriber::fmt()
        //.without_time()
        //.with_ansi(false)
        .with_target(true)
        .with_env_filter(filter)
        .init();
}

pub fn main() -> Result<()> {
    config_trace_aux();
    let _bitcoin_client = get_bitcoin_client()?;

    let channel = DualChannel::new(&BrokerConfig::new(54321, None), 2);
    channel.send(1, "burn".to_string())?;

    let happy_txid: Txid;
    let secret_key: String;
    loop {
        let msg = channel.recv()?;
        if let Some(msg) = msg {
            (happy_txid, secret_key) = serde_json::from_str(&msg.0)?;
            info!("Received aggregtaed: {:?}", msg);
            break;
        } else {
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }

    info!(
        "Can take the NFT through happy path: {:?} and secret: {}",
        happy_txid, secret_key
    );

    Ok(())
}
