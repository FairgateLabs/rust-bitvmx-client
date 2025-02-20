use std::str::FromStr;

use anyhow::Result;
use bitcoin::{OutPoint, PublicKey, Txid};
use bitvmx_broker::{channel::channel::DualChannel, rpc::BrokerConfig};
use bitvmx_client::{
    bitvmx::{BitVMX, BitVMXApiMessages},
    config::Config,
    program::{
        dispute::Funding,
        participant::{P2PAddress, ParticipantRole},
    },
};
use p2p_handler::PeerId;
use tracing::info;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

mod utils;
use utils::bitcoind::Bitcoind;

fn config_trace() {
    let filter = EnvFilter::builder()
        .parse("info,libp2p=off,bitvmx_transaction_monitor=off,bitcoin_indexer=off,bitvmx_orchestrator=off,p2p_protocol=off,p2p_handler=off,tarpc=off") 
        .expect("Invalid filter");

    tracing_subscriber::fmt()
        .without_time()
        .with_target(true)
        .with_env_filter(filter)
        .init();
}

type FundingAddress = String;

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

    //This messagas will come from the bridge client.

    Ok((bitvmx, funding, address, bridge_client))
}

//cargo test --release  -- --ignored
#[ignore]
#[test]
pub fn test_single_run() -> Result<()> {
    config_trace();

    let config = Config::new(Some(format!("config/prover.yaml")))?;

    let bitcoind = Bitcoind::new(
        "bitcoin-regtest2",
        "ruimarinho/bitcoin-core",
        config.bitcoin,
    );
    bitcoind.start()?;

    info!("start prover");

    let (mut prover_bitvmx, prover_funding, prover_address, prover_bridge_channel) =
        init_bitvmx("prover")?;

    info!("start verifier");

    let (mut verifier_bitvmx, verifier_funding, verifier_address, verifier_bridge_channel) =
        init_bitvmx("verifier")?;

    let program_id = Uuid::new_v4();

    let setup_msg = serde_json::to_string(&BitVMXApiMessages::SetupProgram(
        program_id.clone(),
        ParticipantRole::Prover,
        verifier_address.clone(),
        verifier_funding,
    ))
    .unwrap();

    prover_bridge_channel.send(1, setup_msg)?;

    let setup_msg = serde_json::to_string(&BitVMXApiMessages::SetupProgram(
        program_id.clone(),
        ParticipantRole::Verifier,
        prover_address.clone(),
        prover_funding,
    ))
    .unwrap();
    verifier_bridge_channel.send(1, setup_msg)?;

    info!("tick in prover to detect program setup");
    prover_bitvmx.tick()?;

    info!("tick in verifier to detect program setup");
    verifier_bitvmx.tick()?;

    //TODO: Serializer / Deserialize keys this exachange should happen with p2p

    info!("Start sending");
    prover_bitvmx.start_sending(program_id)?;

    //TODO: Serializer / Deserialize keys
    // prover_bitvmx.setup_counterparty_keys(&program_id, verifier_pub_keys)?;
    // verifier_bitvmx.setup_counterparty_keys(&program_id, prover_pub_keys)?;

    prover_bitvmx.partial_sign(&program_id)?;
    //TODO: Partial signs by counterparty
    prover_bitvmx.deploy_program(&program_id)?;

    //TODO: main loop
    for i in 0..1000 {
        if i % 20 == 0 {
            //bitcoind.mine_block()?;
        }
        prover_bitvmx.tick()?;
        verifier_bitvmx.tick()?;
    }

    bitcoind.stop()?;

    //TODO: Push witness and then claim
    //prover_bitvmx.claim_program(&id)?;

    //TODO: Verifier waiting for any claim

    //sleep for 2 secs
    std::thread::sleep(std::time::Duration::from_secs(2));

    Ok(())
}
