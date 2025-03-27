use std::str::FromStr;

use anyhow::Result;
use bitcoin::{Network, PublicKey, Txid};
use bitcoind::bitcoind::Bitcoind;
use bitvmx_bitcoin_rpc::bitcoin_client::{BitcoinClient, BitcoinClientApi};
use bitvmx_broker::{channel::channel::DualChannel, rpc::BrokerConfig};
use bitvmx_client::{
    bitvmx::BitVMX,
    config::Config,
    program::{
        dispute::Funding,
        participant::{P2PAddress, ParticipantRole},
    },
    types::IncomingBitVMXApiMessages,
};
use p2p_handler::PeerId;
use tracing::info;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

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

fn init_bitvmx(role: &str) -> Result<(BitVMX, Funding, P2PAddress, DualChannel)> {
    let config = Config::new(Some(format!("config/{}.yaml", role)))?;
    let broker_config = BrokerConfig::new(config.broker_port, None);
    let bridge_client = DualChannel::new(&broker_config, 2);

    clear_db(&config.storage.db);
    clear_db(&config.key_storage.path);

    info!("config: {:?}", config.storage.db);

    let bitvmx = BitVMX::new(config)?;
    //TODO: Pre-kickoff only prover ?? make independent ??
    let txid =
        Txid::from_str("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b").unwrap();
    let pubkey =
        PublicKey::from_str("032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af")?;

    let funding = Funding::new(txid, 0, pubkey, 100_000_000, 2450000, 95000000, 2450000);

    let address = P2PAddress::new(&bitvmx.address(), PeerId::from_str(&bitvmx.peer_id())?);

    //This messages will come from the bridge client.

    Ok((bitvmx, funding, address, bridge_client))
}

//cargo test --release  -- --ignored
#[ignore]
#[test]
pub fn test_single_run() -> Result<()> {
    config_trace();

    let config = Config::new(Some("config/prover.yaml".to_string()))?;

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

    info!("Mine 1 block to address {:?}", wallet);
    bitcoin_client.mine_blocks_to_address(10, &wallet).unwrap();

    let (mut prover_bitvmx, prover_funding, prover_address, prover_bridge_channel) =
        init_bitvmx("prover")?;

    let (mut verifier_bitvmx, verifier_funding, verifier_address, verifier_bridge_channel) =
        init_bitvmx("verifier")?;

    let program_id = Uuid::new_v4();

    let setup_msg = serde_json::to_string(&IncomingBitVMXApiMessages::SetupProgram(
        program_id,
        ParticipantRole::Prover,
        verifier_address.clone(),
        verifier_funding,
    ))?;

    prover_bridge_channel.send(1, setup_msg)?;

    let setup_msg = serde_json::to_string(&IncomingBitVMXApiMessages::SetupProgram(
        program_id,
        ParticipantRole::Verifier,
        prover_address.clone(),
        prover_funding,
    ))?;

    verifier_bridge_channel.send(1, setup_msg)?;

    info!("PROVER: Setting up program...");
    prover_bitvmx.tick()?;

    info!("VERIFIER: Setting up program...");
    verifier_bitvmx.tick()?;

    //TODO: main loop
    for i in 0..1000 {
        if i % 20 == 0 {
            bitcoin_client.mine_blocks_to_address(1, &wallet).unwrap();
        }

        prover_bitvmx.tick()?;

        // if let Ok(Some((msg, _from))) = prover_bridge_channel.recv() {
        //     info!("PROVER received message: {}", msg);
        // }

        std::thread::sleep(std::time::Duration::from_millis(100));

        // if let Ok(Some((msg, _from))) = verifier_bridge_channel.recv() {
        //     info!("VERIFIER received message: {}", msg);
        // }

        verifier_bitvmx.tick()?;
    }

    info!("Stopping bitcoind");
    bitcoind.stop()?;

    Ok(())
}
