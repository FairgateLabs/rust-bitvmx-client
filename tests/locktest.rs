#![cfg(all(feature = "cardinal", test))]
use anyhow::Result;
use bitcoin::{
    key::rand::rngs::OsRng,
    secp256k1::{self, PublicKey as SecpPublicKey, SecretKey},
    Network, PublicKey as BitcoinPubKey,
};
use bitvmx_bitcoin_rpc::bitcoin_client::BitcoinClient;
use bitvmx_client::{
    bitvmx::BitVMX,
    config::Config,
    program::{
        self,
        protocols::cardinal::{
            lock::{lock_protocol_dust_cost, LOCK_TX},
            lock_config::LockProtocolConfiguration,
        },
        variables::WitnessTypes,
    },
    types::{IncomingBitVMXApiMessages, OutgoingBitVMXApiMessages, ParticipantChannel},
};
use bitvmx_wallet::wallet::{RegtestWallet, Wallet};
use common::{
    config_trace, get_all, init_bitvmx, init_broker, mine_and_wait, prepare_bitcoin, send_all,
    wait_message_from_channel,
};
use key_manager::verifier::SignatureVerifier;
use protocol_builder::scripts::{build_taproot_spend_info, ProtocolScript};
use tracing::info;
use uuid::Uuid;

use crate::{common::set_speedup_funding, fixtures::create_lockreq_ready};

mod common;
mod fixtures;

pub fn prepare_bitcoin_running() -> Result<(BitcoinClient, Wallet)> {
    let config = Config::new(Some("config/op_1.yaml".to_string()))?;

    let bitcoin_client = BitcoinClient::new(
        &config.bitcoin.url,
        &config.bitcoin.username,
        &config.bitcoin.password,
    )?;

    let config_path = match config.bitcoin.network {
        Network::Regtest => "config/wallet_regtest.yaml",
        Network::Testnet => "config/wallet_testnet.yaml",
        _ => panic!("Not supported network {}", config.bitcoin.network),
    };

    let wallet_config = bitvmx_settings::settings::load_config_file::<
        bitvmx_wallet::wallet::config::Config,
    >(Some(config_path.to_string()))?;

    let mut wallet =
        Wallet::from_config(wallet_config.bitcoin.clone(), wallet_config.wallet.clone())?;
    wallet.sync_wallet()?;
    Ok((bitcoin_client, wallet))
}

#[ignore]
#[test]
pub fn test_lock() -> Result<()> {
    test_lock_aux(false, false)
}

/*
#[ignore]
#[test]
pub fn test_integration() -> Result<()> {
    LockProtocol(true, true)
}*/

pub fn test_lock_aux(independent: bool, fake_hapy_path: bool) -> Result<()> {
    config_trace();

    const NETWORK: Network = Network::Regtest;

    let (bitcoin_client, bitcoind, mut wallet) = if independent {
        let (bitcoin_client, wallet) = prepare_bitcoin_running()?;
        (bitcoin_client, None, wallet)
    } else {
        let (client, deamon, wallet) = prepare_bitcoin()?;
        (client, Some(deamon), wallet)
    };

    let (id_channel_pairs, mut instances) = if independent {
        let bridge_1 = init_broker("op_1")?;
        let bridge_2 = init_broker("op_2")?;
        let bridge_3 = init_broker("op_3")?;
        let bridge_4 = init_broker("op_4")?;

        let instances: Vec<BitVMX> = Vec::new();
        let channels = vec![bridge_1, bridge_2, bridge_3, bridge_4];
        (channels, instances)
    } else {
        let (bitvmx_1, _addres_1, bridge_1, _) = init_bitvmx("op_1", false)?;
        let (bitvmx_2, _addres_2, bridge_2, _) = init_bitvmx("op_2", false)?;
        let (bitvmx_3, _addres_3, bridge_3, _) = init_bitvmx("op_3", false)?;
        let (bitvmx_4, _addres_4, bridge_4, _) = init_bitvmx("op_4", false)?;
        let instances = vec![bitvmx_1, bitvmx_2, bitvmx_3, bitvmx_4];
        let channels = vec![bridge_1, bridge_2, bridge_3, bridge_4];
        let identifiers = vec![
            instances[0]
                .get_components_config()
                .get_bitvmx_identifier()?,
            instances[1]
                .get_components_config()
                .get_bitvmx_identifier()?,
            instances[2]
                .get_components_config()
                .get_bitvmx_identifier()?,
            instances[3]
                .get_components_config()
                .get_bitvmx_identifier()?,
        ];
        let id_channel_pairs: Vec<ParticipantChannel> = identifiers
            .into_iter()
            .zip(channels.into_iter())
            .map(|(identifier, channel)| ParticipantChannel {
                id: identifier,
                channel,
            })
            .collect();
        (id_channel_pairs, instances)
    };

    let channels = id_channel_pairs
        .iter()
        .map(|pc| pc.channel.clone())
        .collect::<Vec<_>>();

    //get to the top of the blockchain
    for _ in 0..101 {
        for instance in instances.iter_mut() {
            instance.process_bitcoin_updates()?;
        }
    }

    let funding_public_id = Uuid::new_v4();
    let command = IncomingBitVMXApiMessages::GetPubKey(funding_public_id, true).to_string()?;
    send_all(&id_channel_pairs, &command)?;
    let msgs = get_all(&channels, &mut instances, false)?;
    let funding_key_0 = msgs[0].public_key().unwrap().1;
    let funding_key_1 = msgs[1].public_key().unwrap().1;
    let funding_key_2 = msgs[2].public_key().unwrap().1;
    let funding_key_3 = msgs[3].public_key().unwrap().1;
    set_speedup_funding(
        10_000_000,
        &funding_key_0,
        &channels[0],
        &mut wallet,
        &instances[0].get_components_config().get_bitvmx_config(),
    )?;
    set_speedup_funding(
        10_000_000,
        &funding_key_1,
        &channels[1],
        &mut wallet,
        &instances[1].get_components_config().get_bitvmx_config(),
    )?;
    set_speedup_funding(
        10_000_000,
        &funding_key_2,
        &channels[2],
        &mut wallet,
        &instances[2].get_components_config().get_bitvmx_config(),
    )?;
    set_speedup_funding(
        10_000_000,
        &funding_key_3,
        &channels[3],
        &mut wallet,
        &instances[3].get_components_config().get_bitvmx_config(),
    )?;

    let command = IncomingBitVMXApiMessages::GetCommInfo().to_string()?;
    send_all(&id_channel_pairs, &command)?;
    let comm_info: Vec<OutgoingBitVMXApiMessages> = get_all(&channels, &mut instances, false)?;
    let addresses = comm_info
        .iter()
        .map(|msg| msg.comm_info().unwrap())
        .collect::<Vec<_>>();

    //ask the peers to generate the aggregated public key
    let aggregation_id = Uuid::new_v4();
    let command = IncomingBitVMXApiMessages::SetupKey(aggregation_id, addresses.clone(), None, 0)
        .to_string()?;

    info!("Command to all: {:?}", command);
    send_all(&id_channel_pairs, &command)?;
    info!("Waiting for AggregatedPubkey message from all channels");
    let msgs = get_all(&channels, &mut instances, false)?;
    info!("Received AggregatedPubkey message from all channels");

    let aggregated_pub_key = msgs[0].aggregated_pub_key().unwrap();

    // THE AGGREGATED_HAPPY_PATH NEEDS TO BE USED FOR THE HAPPY PATH
    // THE OPTION FOR FAKE ONE IS UNTIL THE AGGREGATED SECRET IS IMPLEMENTED
    // TO SIGN THE HAPPY PATH TX
    let (aggregated_happy_path, fake_secret) = if fake_hapy_path {
        // emulate the user keypair
        let secp = secp256k1::Secp256k1::new();
        let mut rng = OsRng;
        let too_sk = SecretKey::new(&mut rng);
        let too_pk = secp256k1::PublicKey::from_secret_key(&secp, &too_sk);
        let (too_pk, too_sk) = fixtures::adjust_parity(&secp, too_pk, too_sk);
        let aggregated_happy_path = BitcoinPubKey {
            compressed: true,
            inner: too_pk,
        };
        (
            aggregated_happy_path,
            format!("{}", too_sk.display_secret()),
        )
    } else {
        //aggregated for happy path
        let aggregation_id = Uuid::new_v4();
        let command =
            IncomingBitVMXApiMessages::SetupKey(aggregation_id, addresses.clone(), None, 0)
                .to_string()?;
        send_all(&id_channel_pairs, &command)?;
        let msgs = get_all(&channels, &mut instances, false)?;
        info!("Received AggregatedPubkey message from all channels");
        let aggregated_happy_path = msgs[0].aggregated_pub_key().unwrap();

        // get keypair to share with the user for happy path too
        let command = IncomingBitVMXApiMessages::GetKeyPair(aggregation_id).to_string()?;
        send_all(&id_channel_pairs, &command)?;
        let _msgs = get_all(&channels, &mut instances, false)?;
        (aggregated_happy_path, "".to_string())
    };

    // USER CREATES LOCKREQ TX
    let preimage = "top_secret".to_string();
    let hash = fixtures::sha256(preimage.as_bytes().to_vec());

    info!("==========================");
    info!("Preparing lockreq");
    info!("==========================");

    let (txid, pubuser, ordinal_fee) = create_lockreq_ready(
        aggregated_pub_key,
        hash.clone(),
        NETWORK,
        lock_protocol_dust_cost(4),
        &bitcoin_client,
        4000,
    )?;

    // OPERATORS WAITS FOR LOCKREQ TX
    let lockreqtx_on_chain = Uuid::new_v4();
    let command =
        IncomingBitVMXApiMessages::SubscribeToTransaction(lockreqtx_on_chain, txid).to_string()?;
    send_all(&id_channel_pairs, &command)?;
    mine_and_wait(&bitcoin_client, &channels, &mut instances, &wallet)?;

    // SETUP LOCK BEGIN
    info!("==========================");
    info!("Setup lock");
    info!("==========================");

    let program_id = Uuid::new_v4();
    let lock_protocol_configuration = LockProtocolConfiguration::new(
        program_id,
        aggregated_pub_key,
        aggregated_happy_path,
        fixtures::hardcoded_unspendable().into(),
        pubuser.into(),
        hash,
        (txid, 0, Some(ordinal_fee.to_sat()), None),
        (txid, 1, Some(lock_protocol_dust_cost(4)), None),
        10,
        100,
    );

    lock_protocol_configuration.setup(&id_channel_pairs, addresses.clone(), 0)?;

    get_all(&channels, &mut instances, false)?;

    //Bridge send signal to send the kickoff message
    let op = 1;
    //Bridge send signal to send the kickoff message
    let witness_msg = serde_json::to_string(&IncomingBitVMXApiMessages::SetWitness(
        program_id,
        "secret".to_string(),
        WitnessTypes::Secret(preimage.as_bytes().to_vec()),
    ))?;

    channels[op].send(id_channel_pairs[op].id.clone(), witness_msg.clone())?;

    let _ = channels[op].send(
        id_channel_pairs[op].id.clone(),
        IncomingBitVMXApiMessages::GetTransactionInfoByName(program_id, LOCK_TX.to_string())
            .to_string()?,
    );

    let mut mutinstances = instances.iter_mut().collect::<Vec<_>>();
    let msg = wait_message_from_channel(&channels[op], &mut mutinstances, false)?;
    let (_id, name, tx) = OutgoingBitVMXApiMessages::from_string(&msg.0)?
        .transaction_info()
        .unwrap();
    info!("Transaction name: {} details: {:?} ", name, tx);
    info!(
        "SIGNATURE: ====> {:?}",
        hex::encode(tx.input[0].witness[0].to_vec())
    );

    let _ = channels[op].send(
        id_channel_pairs[op].id.clone(),
        IncomingBitVMXApiMessages::GetHashedMessage(
            program_id,
            program::protocols::cardinal::lock::LOCK_TX.to_string(),
            0,
            1,
        )
        .to_string()?,
    );

    let msg = wait_message_from_channel(&channels[op], &mut mutinstances, false)?;
    let (_uuid, _name, _vout, _leaf, hashed) = OutgoingBitVMXApiMessages::from_string(&msg.0)?
        .hashed_message()
        .unwrap();
    info!("HASHED MESSAGE: ====> {:?}", hashed);
    info!("AGGREGATED PUB: ====> {}", aggregated_pub_key);

    let verifier = SignatureVerifier::new();
    let mut signature = tx.input[0].witness[0].to_vec();
    signature.pop();
    let hashed = hex::decode(hashed).unwrap();
    let hashed_array: [u8; 32] = hashed.try_into().expect("Hash must be 32 bytes");
    let message = secp256k1::Message::from_digest(hashed_array);
    let signature = secp256k1::schnorr::Signature::from_slice(&signature.as_slice())?;
    assert!(verifier.verify_schnorr_signature(&signature, &message, aggregated_pub_key));

    drop(mutinstances);

    info!("==========================");
    info!("Going to send the lock tx");
    info!("==========================");
    let _ = channels[op].send(
        id_channel_pairs[op].id.clone(),
        IncomingBitVMXApiMessages::DispatchTransactionName(
            program_id,
            program::protocols::cardinal::lock::LOCK_TX.to_string(),
        )
        .to_string()?,
    );

    mine_and_wait(&bitcoin_client, &channels, &mut instances, &wallet)?;

    //EVENTUALY L2 DECIDED TO SEND THE HAPPY PATH
    //TODO: It should actually be signed in this moment and not before (could be signed but not shared the partials)
    let _ = channels[op].send(
        id_channel_pairs[op].id.clone(),
        IncomingBitVMXApiMessages::DispatchTransactionName(
            program_id,
            program::protocols::cardinal::lock::HAPPY_PATH_TX.to_string(),
        )
        .to_string()?,
    );

    mine_and_wait(&bitcoin_client, &channels, &mut instances, &wallet)?;

    info!("happy path secret: {}", fake_secret);
    info!("happy path public: {}", aggregated_happy_path);

    if bitcoind.is_some() {
        bitcoind.unwrap().stop()?;
    }
    Ok(())
}

pub fn build_taptree_for_lockreq_tx_outputs(
    secp: &secp256k1::Secp256k1<secp256k1::All>,
    unspendable_pub_key: SecpPublicKey,
    timelock_script: ProtocolScript,
    reveal_secret_script: ProtocolScript,
) -> Result<bitcoin::taproot::TaprootSpendInfo> {
    /* NOTE: we want to force the script path spend, so we will finalize with an un-spendable key */
    let (internal_key_for_taptree_xonly, _parity) = unspendable_pub_key.x_only_public_key();
    println!("Unspendable key: {}", unspendable_pub_key);
    tracing::debug!(
        "X only Unspendable key: {:?} parity: {:?}",
        internal_key_for_taptree_xonly,
        _parity
    );
    let taproot_spend_info = build_taproot_spend_info(
        secp,
        &internal_key_for_taptree_xonly,
        &[timelock_script, reveal_secret_script],
    )?;

    Ok(taproot_spend_info)
}

pub fn hardcoded_unspendable() -> SecpPublicKey {
    // hardcoded unspendable
    let key_bytes =
        hex::decode("02f286025adef23a29582a429ee1b201ba400a9c57e5856840ca139abb629889ad")
            .expect("Invalid hex input");
    SecpPublicKey::from_slice(&key_bytes).expect("Invalid public key")
}

#[ignore]
#[test]
pub fn test_send_lockreq_tx() -> Result<()> {
    common::config_trace();

    let (bitcoin_client, bitcoind, wallet) = prepare_bitcoin()?;

    let mut rng = OsRng;
    let secp = secp256k1::Secp256k1::new();

    /* This is a simulation, the aggregated address between all the operators should be retrieved form the directory or
    provided by BitVMX API after creating a new Session */
    let ops_agg_sk = SecretKey::new(&mut rng);
    let ops_agg_pk = secp256k1::PublicKey::from_secret_key(&secp, &ops_agg_sk);
    // let ops_agg_keypair = Keypair::from_secret_key(&secp, &ops_agg_sk);
    let ops_agg_pubkey = BitcoinPubKey {
        compressed: true,
        inner: ops_agg_pk,
    };

    let preimage = "top_secret".to_string();
    let hash = fixtures::sha256(preimage.as_bytes().to_vec());

    let (txid, pubuser, ordinal_fee) = fixtures::create_lockreq_ready(
        ops_agg_pubkey,
        hash,
        Network::Regtest,
        lock_protocol_dust_cost(4),
        &bitcoin_client,
        1000,
    )?;

    info!("Lockreq txid: {:?}", txid);
    info!("User public key: {:?}", pubuser);
    info!("Ordinal fee: {:?}", ordinal_fee);

    // Mine 1 block to confirm transaction
    wallet.mine(1)?;

    bitcoind.stop()?;

    Ok(())
}

#[ignore]
#[test]
pub fn test_prepare_bitcoin() -> Result<()> {
    common::config_trace();
    prepare_bitcoin()?;
    Ok(())
}
