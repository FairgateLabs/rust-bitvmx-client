use std::str::FromStr;

use anyhow::Result;
use bitcoin::{secp256k1, Address, Amount, KnownHrp, Network, PublicKey, XOnlyPublicKey};
use bitcoind::bitcoind::Bitcoind;
use bitvmx_bitcoin_rpc::bitcoin_client::{BitcoinClient, BitcoinClientApi};
use bitvmx_broker::{channel::channel::DualChannel, rpc::BrokerConfig};
use bitvmx_client::{
    bitvmx::BitVMX, config::Config, program::participant::{P2PAddress, ParticipantRole}, types::IncomingBitVMXApiMessages
};
use p2p_handler::PeerId;
use protocol_builder::{builder::Utxo, scripts};
use tracing::info;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

fn config_trace() {
    let default_modules = [
        "info",
        "libp2p=off",
        "bitvmx_transaction_monitor",
        "bitcoin_indexer=off",
        "bitcoin_coordinator=off",
        "p2p_protocol=off",
        "p2p_handler=off",
        "tarpc=off",
    ];

    let filter = EnvFilter::builder()
        .parse(default_modules.join(","))
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

fn init_bitvmx(role: &str) -> Result<(BitVMX, P2PAddress, DualChannel)> {
    let config = Config::new(Some(format!("config/{}.yaml", role)))?;
    let broker_config = BrokerConfig::new(config.broker_port, None);
    let bridge_client = DualChannel::new(&broker_config, 2);

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

fn init_utxo(bitcoin_client: &BitcoinClient) -> Result<Utxo> {
    // TODO perform a key aggregation with participants public keys. This is a harcoded key for now.
    let secp = secp256k1::Secp256k1::new();
    let public_key = PublicKey::from_str("020d48dbe8043e0114f3255f205152fa621dd7f4e1bbf69d4e255ddb2aaa2878d2")?;
    let untweaked_key = XOnlyPublicKey::from(public_key);

    let spending_scripts = vec![scripts::timelock_renew(&public_key)];
    let taproot_spend_info = scripts::build_taproot_spend_info(&secp, &untweaked_key, &spending_scripts)?;
    let p2tr_address = Address::p2tr(&secp, untweaked_key, taproot_spend_info.merkle_root(), KnownHrp::Regtest);
    
    let (tx, vout) = bitcoin_client.fund_address(&p2tr_address, Amount::from_sat(100_000_000))?;
    
    let utxo = Utxo::new(
        "External".to_string(),
        tx.compute_txid(),
        vout,
        100_000_000,
        &public_key,
    );

    // Spend the UTXO to test Musig2 signature aggregation
    // spend_utxo(bitcoin_client, utxo.clone(), public_key, p2tr_address, taproot_spend_info)?;

    Ok(utxo)
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

    info!("Mine 101 blocks to address {:?}", wallet);
    bitcoin_client.mine_blocks_to_address(202, &wallet).unwrap();

    info!("Initializing UTXO for program");
    let utxo = init_utxo(&bitcoin_client)?;

    let (mut prover_bitvmx, prover_address, prover_bridge_channel) =
        init_bitvmx("prover")?;

    let (mut verifier_bitvmx, verifier_address, verifier_bridge_channel) =
        init_bitvmx("verifier")?;

    let program_id = Uuid::new_v4();

    let setup_msg = serde_json::to_string(&IncomingBitVMXApiMessages::SetupProgram(
        program_id,
        ParticipantRole::Prover,
        verifier_address.clone(),
        utxo.clone(),
    ))?;

    prover_bridge_channel.send(1, setup_msg)?;

    let setup_msg = serde_json::to_string(&IncomingBitVMXApiMessages::SetupProgram(
        program_id,
        ParticipantRole::Verifier,
        prover_address.clone(),
        utxo,
    ))?;

    verifier_bridge_channel.send(1, setup_msg)?;

    info!("PROVER: Setting up program...");
    prover_bitvmx.tick()?;

    info!("VERIFIER: Setting up program...");
    verifier_bitvmx.tick()?;

    //TODO: main loop
    for i in 0..200 {
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
