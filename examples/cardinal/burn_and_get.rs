use std::net::{IpAddr, Ipv4Addr};

use anyhow::{Ok, Result};
use bitvmx_broker::{
    channel::channel::DualChannel,
    identification::identifier::Identifier,
    rpc::{
        tls_helper::{init_tls, Cert},
        BrokerConfig,
    },
};

use bitcoin::Txid;
use operator_comms::operator_comms::AllowList;
use tracing::info;

use crate::common::get_bitcoin_client;

pub fn main() -> Result<()> {
    init_tls();
    let _bitcoin_client = get_bitcoin_client()?;
    let (broker_config, _identifier, _) = BrokerConfig::new_only_address(54321, None)?;
    let cert = Cert::from_key_file("config/keys/l2.key")?;
    let allow_list = AllowList::new();
    allow_list.lock().unwrap().allow_all();
    let channel = DualChannel::new(
        &broker_config,
        cert,
        Some(3),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        Some(allow_list),
    )?;
    let identifier = Identifier::new_local("local".to_string(), 0);
    channel.send(identifier, "burn".to_string())?;

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
