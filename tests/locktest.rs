use std::{fs::File, io::Write};

use anyhow::Result;
use bitcoin::{
    key::rand::rngs::OsRng,
    secp256k1::{self, PublicKey as SecpPublicKey, SecretKey},
    Address, Amount, Network, PublicKey as BitcoinPubKey,
};
use bitvmx_bitcoin_rpc::bitcoin_client::{BitcoinClient, BitcoinClientApi};
use bitvmx_client::{
    bitvmx::BitVMX,
    config::Config,
    program::{
        self,
        variables::{VariableTypes, WitnessTypes},
    },
    types::{IncomingBitVMXApiMessages, OutgoingBitVMXApiMessages, BITVMX_ID, PROGRAM_TYPE_LOCK},
};
use common::{
    config_trace, get_all, init_bitvmx, init_broker, mine_and_wait, prepare_bitcoin, send_all,
    wait_message_from_channel,
};
use key_manager::verifier::SignatureVerifier;
use protocol_builder::scripts::{build_taproot_spend_info, ProtocolScript};
use serde_json::json;
use tracing::info;
use uuid::Uuid;

mod common;
mod fixtures;

pub fn prepare_bitcoin_running() -> Result<(BitcoinClient, Address)> {
    let config = Config::new(Some("config/op_1.yaml".to_string()))?;

    let bitcoin_client = BitcoinClient::new(
        &config.bitcoin.url,
        &config.bitcoin.username,
        &config.bitcoin.password,
    )?;

    let wallet = bitcoin_client
        .init_wallet(Network::Regtest, "test_wallet")
        .unwrap();

    info!("Mine 1 blocks to address {:?}", wallet);
    bitcoin_client.mine_blocks_to_address(1, &wallet).unwrap();

    Ok((bitcoin_client, wallet))
}

#[ignore]
#[test]
pub fn test_lock() -> Result<()> {
    let network = Network::Regtest; //TODO: Get from config or elsewhere
    test_lock_aux(false, false, network)
}

/*
#[ignore]
#[test]
pub fn test_integration() -> Result<()> {
    LockProtocol(true, true)
}*/

pub fn test_lock_aux(independent: bool, fake_hapy_path: bool, network: Network) -> Result<()> {
    config_trace();

    let is_regtest = network == Network::Regtest;

    let (bitcoin_client, bitcoind, wallet) = if is_regtest {
        let (bitcoin_client, bitcoind, wallet) = if independent {
            let (bitcoin_client, wallet) = prepare_bitcoin_running()?;
            (bitcoin_client, None, Some(wallet))
        } else {
            let (client, deamon, wallet) = prepare_bitcoin()?;
            (client, Some(deamon), Some(wallet))
        };

        let bitvmx_wallet = fixtures::create_wallet()?;

        let address = bitvmx_wallet.get_address()?;
    
        let amount = Amount::from_sat(20000);
    
        let (tx, vout) = bitcoin_client.fund_address(&address, amount)?;
        let txid = tx.compute_txid();

        let utxo = json!({
            "txid": txid,
            "vout": vout
        });
        let json_string = serde_json::to_string_pretty(&utxo).unwrap();
        let mut file = File::create("utxo.json")?;
        file.write_all(json_string.as_bytes())?;
        
        (bitcoin_client, bitcoind, wallet)
    
    } else {
        let config = Config::new(Some("config/op_1.yaml".to_string()))?;
        let bitcoin_client = BitcoinClient::new(
            &config.bitcoin.url,
            &config.bitcoin.username,
            &config.bitcoin.password,
        )?;
        (bitcoin_client, None, None)
    };

    let (channels, mut instances) = if independent {
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
        let instances = vec![bitvmx_1, bitvmx_2];
        let channels = vec![bridge_1, bridge_2];
        (channels, instances)
    };

    //get to the top of the blockchain
    for _ in 0..101 {
        for instance in instances.iter_mut() {
            instance.process_bitcoin_updates()?;
        }
    }

    let command = IncomingBitVMXApiMessages::GetCommInfo().to_string()?;
    send_all(&channels, &command)?;
    let comm_info: Vec<OutgoingBitVMXApiMessages> = get_all(&channels, &mut instances, false)?;
    let addresses = comm_info
        .iter()
        .map(|msg| msg.comm_info().unwrap())
        .collect::<Vec<_>>();

    //ask the peers to generate the aggregated public key
    let aggregation_id = Uuid::new_v4();
    let command =
        IncomingBitVMXApiMessages::SetupKey(aggregation_id, addresses.clone(), 0).to_string()?;

    info!("Command to all: {:?}", command);
    send_all(&channels, &command)?;
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
        let command = IncomingBitVMXApiMessages::SetupKey(aggregation_id, addresses.clone(), 0)
            .to_string()?;
        send_all(&channels, &command)?;
        let msgs = get_all(&channels, &mut instances, false)?;
        info!("Received AggregatedPubkey message from all channels");
        let aggregated_happy_path = msgs[0].aggregated_pub_key().unwrap();

        // get keypair to share with the user for happy path too
        let command = IncomingBitVMXApiMessages::GetKeyPair(aggregation_id).to_string()?;
        send_all(&channels, &command)?;
        let _msgs = get_all(&channels, &mut instances, false)?;
        (aggregated_happy_path, "".to_string())
    };

    // USER CREATES LOCKREQ TX
    let preimage = "top_secret".to_string();
    let hash = fixtures::sha256(preimage.as_bytes().to_vec());

    let (txid, pubuser, ordinal_fee, protocol_fee) =
        fixtures::create_lockreq_ready(aggregated_pub_key, hash.clone(), network, &bitcoin_client)?;

    // OPERATORS WAITS FOR LOCKREQ TX
    let lockreqtx_on_chain = Uuid::new_v4();
    let command =
        IncomingBitVMXApiMessages::SubscribeToTransaction(lockreqtx_on_chain, txid).to_string()?;
    send_all(&channels, &command)?;

    mine_and_wait(
        &bitcoin_client,
        &channels,
        &mut instances,
        &wallet,
        is_regtest,
    )?;

    // SETUP LOCK BEGIN

    let program_id = Uuid::new_v4();
    let set_ops_aggregated = VariableTypes::PubKey(aggregated_pub_key)
        .set_msg(program_id, "operators_aggregated_pub")?;
    send_all(&channels, &set_ops_aggregated)?;

    let set_ops_aggregated_hp = VariableTypes::PubKey(aggregated_happy_path)
        .set_msg(program_id, "operators_aggregated_happy_path")?;
    send_all(&channels, &set_ops_aggregated_hp)?;

    let set_unspendable = VariableTypes::PubKey(fixtures::hardcoded_unspendable().into())
        .set_msg(program_id, "unspendable")?;
    send_all(&channels, &set_unspendable)?;

    let set_secret = VariableTypes::Secret(hash).set_msg(program_id, "secret")?;
    send_all(&channels, &set_secret)?;

    let set_ordinal_utxo = VariableTypes::Utxo((txid, 0, Some(ordinal_fee.to_sat())))
        .set_msg(program_id, "ordinal_utxo")?;
    send_all(&channels, &set_ordinal_utxo)?;

    let set_protocol_fee = VariableTypes::Utxo((txid, 1, Some(protocol_fee.to_sat())))
        .set_msg(program_id, "protocol_utxo")?;
    send_all(&channels, &set_protocol_fee)?;

    let set_user_pubkey = VariableTypes::PubKey(bitcoin::PublicKey::from(pubuser))
        .set_msg(program_id, "user_pubkey")?;
    send_all(&channels, &set_user_pubkey)?;

    let setup_msg =
        IncomingBitVMXApiMessages::Setup(program_id, PROGRAM_TYPE_LOCK.to_string(), addresses, 0)
            .to_string()?;
    send_all(&channels, &setup_msg)?;

    get_all(&channels, &mut instances, false)?;

    //Bridge send signal to send the kickoff message
    let witness_msg = serde_json::to_string(&IncomingBitVMXApiMessages::SetWitness(
        program_id,
        "secret".to_string(),
        WitnessTypes::Secret(preimage.as_bytes().to_vec()),
    ))?;
    channels[1].send(BITVMX_ID, witness_msg.clone())?;

    let _ = channels[1].send(
        BITVMX_ID,
        IncomingBitVMXApiMessages::GetTransactionInofByName(
            program_id,
            program::protocols::lock::LOCK_TX.to_string(),
        )
        .to_string()?,
    );

    let mut mutinstances = instances.iter_mut().collect::<Vec<_>>();
    let msg = wait_message_from_channel(&channels[1], &mut mutinstances, false)?;
    let (_id, name, tx) = OutgoingBitVMXApiMessages::from_string(&msg.0)?
        .transaction_info()
        .unwrap();
    info!("Transaction name: {} details: {:?} ", name, tx);
    info!(
        "SIGNATURE: ====> {:?}",
        hex::encode(tx.input[0].witness[0].to_vec())
    );

    let _ = channels[1].send(
        BITVMX_ID,
        IncomingBitVMXApiMessages::GetHashedMessage(
            program_id,
            program::protocols::lock::LOCK_TX.to_string(),
            0,
            1,
        )
        .to_string()?,
    );

    let msg = wait_message_from_channel(&channels[1], &mut mutinstances, false)?;
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

    let _ = channels[1].send(
        BITVMX_ID,
        IncomingBitVMXApiMessages::DispatchTransactionName(
            program_id,
            program::protocols::lock::LOCK_TX.to_string(),
        )
        .to_string()?,
    );

    mine_and_wait(
        &bitcoin_client,
        &channels,
        &mut instances,
        &wallet,
        is_regtest,
    )?;

    //EVENTUALY L2 DECIDED TO SEND THE HAPPY PATH
    //TODO: It should actually be signed in this moment and not before (could be signed but not shared the partials)
    let _ = channels[1].send(
        BITVMX_ID,
        IncomingBitVMXApiMessages::DispatchTransactionName(
            program_id,
            program::protocols::lock::HAPPY_PATH_TX.to_string(),
        )
        .to_string()?,
    );

    mine_and_wait(
        &bitcoin_client,
        &channels,
        &mut instances,
        &wallet,
        is_regtest,
    )?;

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

    let (txid, pubuser, ordinal_fee, protocol_fee) =
        fixtures::create_lockreq_ready(ops_agg_pubkey, hash, Network::Regtest, &bitcoin_client)?;

    info!("Lockreq txid: {:?}", txid);
    info!("User public key: {:?}", pubuser);
    info!("Protocol fee: {:?}", protocol_fee);
    info!("Ordinal fee: {:?}", ordinal_fee);

    // Mine 1 block to confirm transaction
    bitcoin_client.mine_blocks_to_address(1, &wallet)?;

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


