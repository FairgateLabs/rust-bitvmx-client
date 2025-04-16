use std::str::FromStr;

use anyhow::Result;
use bitcoin::{secp256k1, Address, Amount, KnownHrp, Network, PublicKey, XOnlyPublicKey};
use bitcoind::bitcoind::Bitcoind;
use bitvmx_bitcoin_rpc::bitcoin_client::{BitcoinClient, BitcoinClientApi};
use bitvmx_broker::{channel::channel::DualChannel, rpc::BrokerConfig};
use bitvmx_client::{
    bitvmx::BitVMX,
    config::Config,
    program::participant::{P2PAddress, ParticipantRole},
    types::{IncomingBitVMXApiMessages, OutgoingBitVMXApiMessages, BITVMX_ID, L2_ID},
};
use p2p_handler::PeerId;
use protocol_builder::{scripts, types::Utxo};
use tracing::info;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

fn config_trace() {
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

fn clear_db(path: &str) {
    let _ = std::fs::remove_dir_all(path);
}

fn init_bitvmx(role: &str) -> Result<(BitVMX, P2PAddress, DualChannel)> {
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

fn init_utxo(bitcoin_client: &BitcoinClient, aggregated_pub_key: PublicKey) -> Result<Utxo> {
    // TODO perform a key aggregation with participants public keys. This is a harcoded key for now.
    let secp = secp256k1::Secp256k1::new();
    let untweaked_key = XOnlyPublicKey::from(aggregated_pub_key);

    let spending_scripts = vec![scripts::timelock_renew(&aggregated_pub_key)];
    let taproot_spend_info =
        scripts::build_taproot_spend_info(&secp, &untweaked_key, &spending_scripts)?;
    let p2tr_address = Address::p2tr(
        &secp,
        untweaked_key,
        taproot_spend_info.merkle_root(),
        KnownHrp::Regtest,
    );

    let (tx, vout) = bitcoin_client.fund_address(&p2tr_address, Amount::from_sat(100_000_000))?;

    let utxo = Utxo::new(
        tx.compute_txid(),
        vout,
        100_000_000,
        &aggregated_pub_key,
    );

    info!("UTXO: {:?}", utxo);
    // Spend the UTXO to test Musig2 signature aggregation
    // spend_utxo(bitcoin_client, utxo.clone(), public_key, p2tr_address, taproot_spend_info)?;

    Ok(utxo)
}

fn wait_message_from_channel(
    channel: &DualChannel,
    instances: &mut Vec<&mut BitVMX>,
) -> Result<(String, u32)> {
    //loop to timeout
    for i in 0..10000 {
        if i % 50 == 0 {
            let msg = channel.recv()?;
            if msg.is_some() {
                info!("Received message from channel: {:?}", msg);
                return Ok(msg.unwrap());
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        for instance in instances.iter_mut() {
            instance.tick()?;
        }
    }
    panic!("Timeout waiting for message from channel");
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
    bitcoin_client.mine_blocks_to_address(101, &wallet).unwrap();

    let (mut prover_bitvmx, prover_address, prover_bridge_channel) = init_bitvmx("prover")?;

    let (mut verifier_bitvmx, verifier_address, verifier_bridge_channel) = init_bitvmx("verifier")?;

    let mut instances = vec![&mut prover_bitvmx, &mut verifier_bitvmx];

    //get to the top of the blockchain
    for _ in 0..101 {
        for instance in instances.iter_mut() {
            instance.process_bitcoin_updates()?;
        }
    }

    //let aggregated_pub_key =
    //    PublicKey::from_str("020d48dbe8043e0114f3255f205152fa621dd7f4e1bbf69d4e255ddb2aaa2878d2")?;

    //ask the peers to generate the aggregated public key
    let aggregation_id = Uuid::new_v4();
    let command = IncomingBitVMXApiMessages::GenerateAggregatedPubkey(
        aggregation_id,
        vec![prover_address.clone(), verifier_address.clone()],
        0,
    )
    .to_string()?;
    prover_bridge_channel.send(BITVMX_ID, command.clone())?;
    verifier_bridge_channel.send(BITVMX_ID, command)?;

    let msg = wait_message_from_channel(&prover_bridge_channel, &mut instances)?;
    info!("PROVER: Received message from channel: {:?}", msg);
    let msg = wait_message_from_channel(&verifier_bridge_channel, &mut instances)?;
    info!("VERIFIER: Received message from channel: {:?}", msg);

    info!("Initializing UTXO for program");
    let msg = OutgoingBitVMXApiMessages::from_string(&msg.0)?;
    let aggregated_pub_key = match msg {
        OutgoingBitVMXApiMessages::AggregatedPubkey(_uuid, aggregated_pub_key) => {
            aggregated_pub_key
        }
        _ => panic!("Expected AggregatedPubkey message"),
    };

    let utxo = init_utxo(&bitcoin_client, aggregated_pub_key)?;

    let program_id = Uuid::new_v4();
    let setup_msg = serde_json::to_string(&IncomingBitVMXApiMessages::SetupProgram(
        program_id,
        ParticipantRole::Prover,
        verifier_address.clone(),
        utxo.clone(),
    ))?;

    prover_bridge_channel.send(BITVMX_ID, setup_msg)?;

    let setup_msg = serde_json::to_string(&IncomingBitVMXApiMessages::SetupProgram(
        program_id,
        ParticipantRole::Verifier,
        prover_address.clone(),
        utxo,
    ))?;

    verifier_bridge_channel.send(BITVMX_ID, setup_msg)?;

    info!("Waiting for setup messages...");

    //Wait
    let msg = wait_message_from_channel(&prover_bridge_channel, &mut instances)?;
    info!("PROVER: Received message from channel: {:?}", msg);
    let msg = wait_message_from_channel(&verifier_bridge_channel, &mut instances)?;
    info!("VERIFIER: Received message from channel: {:?}", msg);

    //Bridge send signal to send the kickoff message
    let _ = verifier_bridge_channel.send(
        BITVMX_ID,
        IncomingBitVMXApiMessages::DispatchTransactionName(program_id, "prekickoff".to_string())
            .to_string()?,
    );

    //TODO: main loop
    for i in 0..200 {
        if i % 10 == 0 {
            bitcoin_client.mine_blocks_to_address(1, &wallet).unwrap();
        }

        prover_bitvmx.tick()?;

        // if let Ok(Some((msg, _from))) = prover_bridge_channel.recv() {
        //     info!("PROVER received message: {}", msg);
        // }

        std::thread::sleep(std::time::Duration::from_millis(10));

        // if let Ok(Some((msg, _from))) = verifier_bridge_channel.recv() {
        //     info!("VERIFIER received message: {}", msg);
        // }

        verifier_bitvmx.tick()?;
    }

    info!("Stopping bitcoind");
    bitcoind.stop()?;

    Ok(())
}
