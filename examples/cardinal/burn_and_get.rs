use anyhow::{Ok, Result};
use bitvmx_broker::{channel::channel::DualChannel, rpc::BrokerConfig};

use bitcoin::Txid;
use tracing::info;

use crate::common::get_bitcoin_client;

pub fn main() -> Result<()> {
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
