#![allow(dead_code)]
use std::str::FromStr;

use anyhow::Result;
use bitcoin::{Address, Network};
use bitcoind::bitcoind::Bitcoind;
use bitvmx_bitcoin_rpc::bitcoin_client::{BitcoinClient, BitcoinClientApi};
use bitvmx_broker::{channel::channel::DualChannel, rpc::BrokerConfig};
use bitvmx_client::{
    bitvmx::BitVMX, config::Config, program::participant::P2PAddress, types::L2_ID,
};
use p2p_handler::PeerId;
use tracing::info;

/// Number of blocks to mine initially in tests to ensure sufficient coin maturity
pub const INITIAL_BLOCK_COUNT: u64 = 101;

pub fn clear_db(path: &str) {
    let _ = std::fs::remove_dir_all(path);
}

pub fn init_bitvmx(role: &str) -> Result<(BitVMX, P2PAddress, DualChannel)> {
    let config = Config::new(Some(format!("config/{}.yaml", role)))?;
    let broker_config = BrokerConfig::new(config.broker_port, None);
    let bridge_client = DualChannel::new(&broker_config, L2_ID);

    clear_db(&config.storage.db);
    clear_db(&config.key_storage.path);
    clear_db(&config.broker_storage);

    info!("config: {:?}", config.storage.db);

    let bitvmx = BitVMX::new(config)?;

    let address = P2PAddress::new(&bitvmx.address(), PeerId::from_str(&bitvmx.peer_id())?);
    info!("peer id {:?}", bitvmx.peer_id());

    //This messages will come from the bridge client.

    Ok((bitvmx, address, bridge_client))
}

pub fn tick(instance: &mut BitVMX) {
    instance.process_api_messages().unwrap();
    instance.process_p2p_messages().unwrap();
    instance.process_programs().unwrap();
    instance.process_collaboration().unwrap();
    instance.process_pending_messages().unwrap();
}

pub fn wait_message_from_channel(
    channel: &DualChannel,
    instances: &mut Vec<&mut BitVMX>,
    fake_tick: bool,
) -> Result<(String, u32)> {
    //loop to timeout
    for i in 0..40000 {
        if i % 50 == 0 {
            let msg = channel.recv()?;
            if msg.is_some() {
                //info!("Received message from channel: {:?}", msg);
                return Ok(msg.unwrap());
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        for instance in instances.iter_mut() {
            if fake_tick {
                tick(instance);
            } else {
                instance.tick()?;
            }
        }
    }
    panic!("Timeout waiting for message from channel");
}

pub fn prepare_bitcoin() -> Result<(BitcoinClient, Bitcoind, Address)> {
    let config = Config::new(Some("config/op_1.yaml".to_string()))?;

    let bitcoind = Bitcoind::new(
        "bitcoin-regtest",
        "ruimarinho/bitcoin-core",
        config.bitcoin.clone(),
    );
    info!("Starting bitcoind");
    bitcoind.start()?;

    let bitcoin_client = BitcoinClient::new(
        &config.bitcoin.url,
        &config.bitcoin.username,
        &config.bitcoin.password,
    )?;

    let wallet = bitcoin_client
        .init_wallet(Network::Regtest, "test_wallet")
        .unwrap();

    info!(
        "Mine {} blocks to address {:?}",
        INITIAL_BLOCK_COUNT, wallet
    );
    bitcoin_client
        .mine_blocks_to_address(INITIAL_BLOCK_COUNT, &wallet)
        .unwrap();

    Ok((bitcoin_client, bitcoind, wallet))
}
