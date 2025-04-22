use std::str::FromStr;

use anyhow::Result;
use bitcoin::{secp256k1, Address, Amount, KnownHrp, Network, PublicKey, XOnlyPublicKey};
use bitcoind::bitcoind::Bitcoind;
use bitvmx_bitcoin_rpc::bitcoin_client::{BitcoinClient, BitcoinClientApi};
use bitvmx_broker::{channel::channel::DualChannel, rpc::BrokerConfig};
use bitvmx_client::{
    bitvmx::BitVMX,
    config::Config,
    program::{
        self,
        participant::{P2PAddress, ParticipantRole},
        variables::{VariableTypes, WitnessTypes},
    },
    types::{IncomingBitVMXApiMessages, OutgoingBitVMXApiMessages, BITVMX_ID, L2_ID},
};
use p2p_handler::PeerId;
use protocol_builder::{scripts, types::Utxo};
use sha2::{Digest, Sha256};
use tracing::info;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

use std::sync::Once;

static INIT: Once = Once::new();

fn config_trace() {
    INIT.call_once(|| {
        config_trace_aux();
    });
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
    ];

    let filter = EnvFilter::builder()
        .parse(default_modules.join(","))
        .expect("Invalid filter");

    tracing_subscriber::fmt()
        //.without_time()
        .with_ansi(false)
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

fn init_utxo(
    bitcoin_client: &BitcoinClient,
    aggregated_pub_key: PublicKey,
    secret: Option<Vec<u8>>,
) -> Result<Utxo> {
    // TODO perform a key aggregation with participants public keys. This is a harcoded key for now.
    let secp = secp256k1::Secp256k1::new();
    let untweaked_key = XOnlyPublicKey::from(aggregated_pub_key);

    let spending_scripts = if secret.is_some() {
        vec![scripts::reveal_secret(secret.unwrap(), &aggregated_pub_key)]
        //vec![scripts::check_aggregated_signature(&aggregated_pub_key)]
    } else {
        vec![scripts::timelock_renew(&aggregated_pub_key)]
    };

    let taproot_spend_info =
        scripts::build_taproot_spend_info(&secp, &untweaked_key, &spending_scripts)?;
    let p2tr_address = Address::p2tr(
        &secp,
        untweaked_key,
        taproot_spend_info.merkle_root(),
        KnownHrp::Regtest,
    );

    let (tx, vout) = bitcoin_client.fund_address(&p2tr_address, Amount::from_sat(100_000_000))?;

    let utxo = Utxo::new(tx.compute_txid(), vout, 100_000_000, &aggregated_pub_key);

    info!("UTXO: {:?}", utxo);
    // Spend the UTXO to test Musig2 signature aggregation
    // spend_utxo(bitcoin_client, utxo.clone(), public_key, p2tr_address, taproot_spend_info)?;

    Ok(utxo)
}

fn tick(instance: &mut BitVMX) {
    instance.process_api_messages().unwrap();
    instance.process_p2p_messages().unwrap();
    instance.process_programs().unwrap();
    instance.process_collaboration().unwrap();
}

fn wait_message_from_channel(
    channel: &DualChannel,
    instances: &mut Vec<&mut BitVMX>,
    fake_tick: bool,
) -> Result<(String, u32)> {
    //loop to timeout
    for i in 0..40000 {
        if i % 50 == 0 {
            let msg = channel.recv()?;
            if msg.is_some() {
                info!("Received message from channel: {:?}", msg);
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

fn prepare_bitcoin() -> Result<(BitcoinClient, Bitcoind, Address)> {
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

    Ok((bitcoin_client, bitcoind, wallet))
}

//cargo test --release  -- test_single_run --ignored
#[ignore]
#[test]
pub fn test_single_run() -> Result<()> {
    config_trace();

    let (bitcoin_client, bitcoind, wallet) = prepare_bitcoin()?;

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
    let command = IncomingBitVMXApiMessages::SetupKey(
        aggregation_id,
        vec![prover_address.clone(), verifier_address.clone()],
        0,
    )
    .to_string()?;
    prover_bridge_channel.send(BITVMX_ID, command.clone())?;
    verifier_bridge_channel.send(BITVMX_ID, command)?;

    let msg = wait_message_from_channel(&prover_bridge_channel, &mut instances, false)?;
    info!("PROVER: Received message from channel: {:?}", msg);
    let msg = wait_message_from_channel(&verifier_bridge_channel, &mut instances, false)?;
    info!("VERIFIER: Received message from channel: {:?}", msg);

    info!("Initializing UTXO for program");
    let msg = OutgoingBitVMXApiMessages::from_string(&msg.0)?;
    let aggregated_pub_key = match msg {
        OutgoingBitVMXApiMessages::AggregatedPubkey(_uuid, aggregated_pub_key) => {
            aggregated_pub_key
        }
        _ => panic!("Expected AggregatedPubkey message"),
    };

    let utxo = init_utxo(&bitcoin_client, aggregated_pub_key, None)?;

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
    let msg = wait_message_from_channel(&prover_bridge_channel, &mut instances, false)?;
    info!("PROVER: Received message from channel: {:?}", msg);
    let msg = wait_message_from_channel(&verifier_bridge_channel, &mut instances, false)?;
    info!("VERIFIER: Received message from channel: {:?}", msg);

    //Bridge send signal to send the kickoff message
    let _ = verifier_bridge_channel.send(
        BITVMX_ID,
        IncomingBitVMXApiMessages::DispatchTransactionName(
            program_id,
            program::dispute::START_CH.to_string(),
        )
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

//Test aggregation with three parts
#[ignore]
#[test]
pub fn test_aggregation() -> Result<()> {
    config_trace();

    let (_bitcoin_client, bitcoind, _wallet) = prepare_bitcoin()?;

    let (mut bitvmx_1, addres_1, bridge_1) = init_bitvmx("prover")?;
    let (mut bitvmx_2, addres_2, bridge_2) = init_bitvmx("verifier")?;
    let (mut bitvmx_3, addres_3, bridge_3) = init_bitvmx("third")?;

    let mut instances = vec![&mut bitvmx_1, &mut bitvmx_2, &mut bitvmx_3];

    //ask the peers to generate the aggregated public key
    let aggregation_id = Uuid::new_v4();
    let command = IncomingBitVMXApiMessages::SetupKey(
        aggregation_id,
        vec![addres_1.clone(), addres_2.clone(), addres_3.clone()],
        0,
    )
    .to_string()?;

    bridge_1.send(BITVMX_ID, command.clone())?;
    bridge_2.send(BITVMX_ID, command.clone())?;
    bridge_3.send(BITVMX_ID, command.clone())?;

    let msg_1 = wait_message_from_channel(&bridge_1, &mut instances, true)?;
    let _msg_2 = wait_message_from_channel(&bridge_2, &mut instances, true)?;
    let _msg_3 = wait_message_from_channel(&bridge_3, &mut instances, true)?;

    let msg = OutgoingBitVMXApiMessages::from_string(&msg_1.0)?;
    let _aggregated_pub_key = match msg {
        OutgoingBitVMXApiMessages::AggregatedPubkey(_uuid, aggregated_pub_key) => {
            aggregated_pub_key
        }
        _ => panic!("Expected AggregatedPubkey message"),
    };

    bitcoind.stop()?;
    Ok(())
}

pub fn sha256(data: Vec<u8>) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(&data);
    hasher.finalize().to_vec()
}

#[ignore]
#[test]
pub fn test_slot() -> Result<()> {
    config_trace();

    let (bitcoin_client, bitcoind, wallet) = prepare_bitcoin()?;

    let (mut bitvmx_1, addres_1, bridge_1) = init_bitvmx("prover")?;
    let (mut bitvmx_2, addres_2, bridge_2) = init_bitvmx("verifier")?;
    let (mut bitvmx_3, addres_3, bridge_3) = init_bitvmx("third")?;

    let mut instances = vec![&mut bitvmx_1, &mut bitvmx_2, &mut bitvmx_3];

    //get to the top of the blockchain
    for _ in 0..101 {
        for instance in instances.iter_mut() {
            instance.process_bitcoin_updates()?;
        }
    }

    let addresses = vec![addres_1.clone(), addres_2.clone(), addres_3.clone()];

    //ask the peers to generate the aggregated public key
    let aggregation_id = Uuid::new_v4();
    let command =
        IncomingBitVMXApiMessages::SetupKey(aggregation_id, addresses.clone(), 0).to_string()?;

    bridge_1.send(BITVMX_ID, command.clone())?;
    bridge_2.send(BITVMX_ID, command.clone())?;
    bridge_3.send(BITVMX_ID, command.clone())?;

    let msg_1 = wait_message_from_channel(&bridge_1, &mut instances, true)?;
    let _msg_2 = wait_message_from_channel(&bridge_2, &mut instances, true)?;
    let _msg_3 = wait_message_from_channel(&bridge_3, &mut instances, true)?;

    let msg = OutgoingBitVMXApiMessages::from_string(&msg_1.0)?;
    let aggregated_pub_key = match msg {
        OutgoingBitVMXApiMessages::AggregatedPubkey(_uuid, aggregated_pub_key) => {
            aggregated_pub_key
        }
        _ => panic!("Expected AggregatedPubkey message"),
    };

    let program_id = Uuid::new_v4();

    let preimage = "top_secret".to_string();
    let hash = sha256(preimage.as_bytes().to_vec());

    let utxo = init_utxo(&bitcoin_client, aggregated_pub_key, Some(hash.clone()))?;

    let setup_msg = serde_json::to_string(&IncomingBitVMXApiMessages::SetVar(
        program_id,
        "secret".to_string(),
        VariableTypes::Secret(hash),
    ))?;
    bridge_1.send(BITVMX_ID, setup_msg.clone())?;
    bridge_2.send(BITVMX_ID, setup_msg.clone())?;
    bridge_3.send(BITVMX_ID, setup_msg.clone())?;

    let setup_msg = serde_json::to_string(&IncomingBitVMXApiMessages::SetupSlot(
        program_id,
        addresses,
        0,
        utxo.clone(),
    ))?;

    bridge_1.send(BITVMX_ID, setup_msg.clone())?;
    bridge_2.send(BITVMX_ID, setup_msg.clone())?;
    bridge_3.send(BITVMX_ID, setup_msg.clone())?;

    let _msg_1 = wait_message_from_channel(&bridge_1, &mut instances, true)?;
    let _msg_2 = wait_message_from_channel(&bridge_2, &mut instances, true)?;
    let _msg_3 = wait_message_from_channel(&bridge_3, &mut instances, true)?;

    //Bridge send signal to send the kickoff message
    let witness_msg = serde_json::to_string(&IncomingBitVMXApiMessages::SetWitness(
        program_id,
        "secret".to_string(),
        WitnessTypes::Secret(preimage.as_bytes().to_vec()),
    ))?;
    bridge_2.send(BITVMX_ID, witness_msg.clone())?;

    let _ = bridge_2.send(
        BITVMX_ID,
        IncomingBitVMXApiMessages::DispatchTransactionName(
            program_id,
            program::slot::ACCEPT_TX.to_string(),
        )
        .to_string()?,
    );

    //TODO: main loop
    for i in 0..200 {
        if i % 10 == 0 {
            bitcoin_client.mine_blocks_to_address(1, &wallet).unwrap();
        }

        for instance in instances.iter_mut() {
            instance.tick()?;
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    bitcoind.stop()?;
    Ok(())
}
