#![cfg(feature = "cardinal")]

use anyhow::Result;
use bitcoin::{
    key::rand::rngs::OsRng,
    secp256k1::{self, PublicKey as SecpPublicKey, SecretKey},
    Amount, Network, OutPoint, PublicKey, PublicKey as BitcoinPubKey, Transaction, Txid,
};
use bitvmx_bitcoin_rpc::bitcoin_client::{BitcoinClient, BitcoinClientApi};
use bitvmx_client::{
    bitvmx::BitVMX,
    config::Config,
    program::{
        self,
        protocols::cardinal::{
            EOL_TIMELOCK_DURATION, FEE, GID_MAX, OPERATORS_AGGREGATED_PUB, PROTOCOL_COST,
            SPEEDUP_DUST, UNSPENDABLE,
        },
        variables::{VariableTypes, WitnessTypes},
    },
    types::{IncomingBitVMXApiMessages, OutgoingBitVMXApiMessages, BITVMX_ID, PROGRAM_TYPE_LOCK},
};
use bitvmx_wallet::wallet::Wallet;
use common::{
    config_trace, get_all, init_bitvmx, init_broker, mine_and_wait, prepare_bitcoin, send_all,
    wait_message_from_channel,
};
use key_manager::verifier::SignatureVerifier;
use protocol_builder::scripts::{build_taproot_spend_info, ProtocolScript};
use tracing::info;
use uuid::Uuid;

mod common;
mod fixtures;

pub fn prepare_bitcoin_running() -> Result<(BitcoinClient, Wallet)> {
    let config = Config::new(Some("config/op_1.yaml".to_string()))?;

    let bitcoin_client = BitcoinClient::new(
        &config.bitcoin.url,
        &config.bitcoin.username,
        &config.bitcoin.password,
    )?;

    let wallet_config = match config.bitcoin.network {
        Network::Regtest => "config/wallet_regtest.yaml",
        Network::Testnet => "config/wallet_testnet.yaml",
        _ => panic!("Not supported network {}", config.bitcoin.network),
    };

    let wallet_config = bitvmx_settings::settings::load_config_file::<
        bitvmx_wallet::config::WalletConfig,
    >(Some(wallet_config.to_string()))?;
    let wallet = Wallet::new(wallet_config, true)?;

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

    let (bitcoin_client, bitcoind, wallet) = if independent {
        let (bitcoin_client, wallet) = prepare_bitcoin_running()?;
        (bitcoin_client, None, wallet)
    } else {
        let (client, deamon, wallet) = prepare_bitcoin()?;
        (client, Some(deamon), wallet)
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
        let (bitvmx_3, _addres_3, bridge_3, _) = init_bitvmx("op_3", false)?;
        let (bitvmx_4, _addres_4, bridge_4, _) = init_bitvmx("op_4", false)?;
        let instances = vec![bitvmx_1, bitvmx_2, bitvmx_3, bitvmx_4];
        let channels = vec![bridge_1, bridge_2, bridge_3, bridge_4];
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
    let command = IncomingBitVMXApiMessages::SetupKey(aggregation_id, addresses.clone(), None, 0)
        .to_string()?;

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
        let command =
            IncomingBitVMXApiMessages::SetupKey(aggregation_id, addresses.clone(), None, 0)
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
        fixtures::create_lockreq_ready(aggregated_pub_key, hash.clone(), NETWORK, &bitcoin_client)?;

    // OPERATORS WAITS FOR LOCKREQ TX
    let lockreqtx_on_chain = Uuid::new_v4();
    let command =
        IncomingBitVMXApiMessages::SubscribeToTransaction(lockreqtx_on_chain, txid).to_string()?;
    send_all(&channels, &command)?;
    mine_and_wait(&bitcoin_client, &channels, &mut instances, &wallet)?;

    // SETUP LOCK BEGIN

    let program_id = Uuid::new_v4();
    let set_fee = VariableTypes::Number(3000).set_msg(program_id, FEE)?;
    send_all(&channels, &set_fee)?;

    let set_fee = VariableTypes::Number(10000).set_msg(program_id, "FEE_ZKP")?;
    send_all(&channels, &set_fee)?;

    let set_ops_aggregated =
        VariableTypes::PubKey(aggregated_pub_key).set_msg(program_id, OPERATORS_AGGREGATED_PUB)?;
    send_all(&channels, &set_ops_aggregated)?;

    let set_ops_aggregated_hp = VariableTypes::PubKey(aggregated_happy_path)
        .set_msg(program_id, "operators_aggregated_happy_path")?;
    send_all(&channels, &set_ops_aggregated_hp)?;

    let set_unspendable = VariableTypes::PubKey(fixtures::hardcoded_unspendable().into())
        .set_msg(program_id, UNSPENDABLE)?;
    send_all(&channels, &set_unspendable)?;

    let set_secret = VariableTypes::Secret(hash).set_msg(program_id, "secret")?;
    send_all(&channels, &set_secret)?;

    let set_ordinal_utxo = VariableTypes::Utxo((txid, 0, Some(ordinal_fee.to_sat()), None))
        .set_msg(program_id, "ordinal_utxo")?;
    send_all(&channels, &set_ordinal_utxo)?;

    let set_protocol_fee = VariableTypes::Utxo((txid, 1, Some(protocol_fee.to_sat()), None))
        .set_msg(program_id, "protocol_utxo")?;
    send_all(&channels, &set_protocol_fee)?;

    let set_user_pubkey = VariableTypes::PubKey(bitcoin::PublicKey::from(pubuser))
        .set_msg(program_id, "user_pubkey")?;
    send_all(&channels, &set_user_pubkey)?;

    let eol_timelock_duration =
        VariableTypes::Number(100).set_msg(program_id, EOL_TIMELOCK_DURATION)?;
    send_all(&channels, &eol_timelock_duration)?;

    let protocol_cost = VariableTypes::Number(20_000).set_msg(program_id, PROTOCOL_COST)?;
    send_all(&channels, &protocol_cost)?;

    let speedup_dust = VariableTypes::Number(500).set_msg(program_id, SPEEDUP_DUST)?;
    send_all(&channels, &speedup_dust)?;

    let gid_max = VariableTypes::Number(8).set_msg(program_id, GID_MAX)?;
    send_all(&channels, &gid_max)?;

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
            program::protocols::cardinal::lock::LOCK_TX.to_string(),
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
            program::protocols::cardinal::lock::LOCK_TX.to_string(),
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
            program::protocols::cardinal::lock::LOCK_TX.to_string(),
        )
        .to_string()?,
    );

    mine_and_wait(&bitcoin_client, &channels, &mut instances, &wallet)?;

    //EVENTUALY L2 DECIDED TO SEND THE HAPPY PATH
    //TODO: It should actually be signed in this moment and not before (could be signed but not shared the partials)
    let _ = channels[1].send(
        BITVMX_ID,
        IncomingBitVMXApiMessages::DispatchTransactionName(
            program_id,
            program::protocols::cardinal::lock::HAPPY_PATH_TX.to_string(),
        )
        .to_string()?,
    );

    mine_and_wait(&bitcoin_client, &channels, &mut instances, &wallet)?;

    info!("happy path secret: {}", fake_secret);
    info!("happy path public: {}", aggregated_happy_path);

    let zkp = "b75f20d1aee5a1a0908edd107a25189ccc38b6d20c5dc33362a066157a6ee60350a09cfbfebe38c8d9f04a6dafe46ae2e30f6638f3eb93c1d2aeff2d52d66d0dcd68bf7f8fc07485dd04a573d233df3663d63e71568bc035ef82e8ab3525f025b487aaa4456aaf93be3141b210cda5165a714225d9fd63163f59d741bdaa8b93";
    let set_zkp = VariableTypes::Input(hex::decode(zkp)?).set_msg(program_id, "zkp")?;
    send_all(&channels, &set_zkp)?;

    let _ = channels[0].send(
        BITVMX_ID,
        IncomingBitVMXApiMessages::DispatchTransactionName(
            program_id,
            program::protocols::cardinal::lock::PUBLISH_ZKP.to_string(),
        )
        .to_string()?,
    );

    mine_and_wait(&bitcoin_client, &channels, &mut instances, &wallet)?;

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

pub fn create_lockreq_ready(
    aggregated_operators: PublicKey,
    secret_hash: Vec<u8>,
    network: Network,
    bitcoin_client: &BitcoinClient,
) -> Result<(Txid, SecpPublicKey, Amount, Amount)> {
    //PublicKey user, txid, 0 :amount-ordinal, 1: amount-fees

    let secp = secp256k1::Secp256k1::new();
    let mut rng = OsRng;

    // hardcoded unspendable
    let unspendable = hardcoded_unspendable();

    // emulate the user keypair
    let user_sk = SecretKey::new(&mut rng);
    let user_pk = SecpPublicKey::from_secret_key(&secp, &user_sk);
    let (user_pk, user_sk) = fixtures::adjust_parity(&secp, user_pk, user_sk);
    let user_pubkey = BitcoinPubKey {
        compressed: true,
        inner: user_pk,
    };
    let user_address: bitcoin::Address = bitcoin_client.get_new_address(user_pubkey, network);
    info!(
        "User Address({}): {:?}",
        user_address.address_type().unwrap(),
        user_address
    );

    const ONE_BTC: Amount = Amount::from_sat(10_000_000);

    // Ordinal funding
    const ORDINAL_AMOUNT: Amount = Amount::from_sat(10_000);
    let funding_amount_ordinal = ORDINAL_AMOUNT;
    let funding_tx_ordinal: Transaction;
    let vout_ordinal: u32;
    (funding_tx_ordinal, vout_ordinal) = bitcoin_client
        .fund_address(&user_address, funding_amount_ordinal)
        .unwrap();
    let ordinal_txout = funding_tx_ordinal.output[vout_ordinal as usize].clone();

    // Protocol fees funding
    let funding_amount_used_for_protocol_fees = ONE_BTC;
    let funding_tx_protocol_fees: Transaction;
    let vout_protocol_fees: u32;
    (funding_tx_protocol_fees, vout_protocol_fees) = bitcoin_client
        .fund_address(&user_address, funding_amount_used_for_protocol_fees)
        .unwrap();
    let protocol_fees_txout = funding_tx_protocol_fees.output[vout_protocol_fees as usize].clone();

    let ordinal_outpoint = OutPoint::new(funding_tx_ordinal.compute_txid(), vout_ordinal);
    tracing::debug!("Ordinal outpoint: {:?}", ordinal_outpoint);

    let protocol_fees_outpoint =
        OutPoint::new(funding_tx_protocol_fees.compute_txid(), vout_protocol_fees);
    tracing::debug!("Protocol fees outpoint: {:?}", protocol_fees_outpoint);

    let protocol_fee = Amount::from_sat(1_000_000);

    const MINER_FEE: Amount = Amount::from_sat(355_000);

    let signed_lockreq_tx = fixtures::create_lockreq_tx_and_sign(
        &secp,
        funding_amount_ordinal,
        ordinal_outpoint,
        ordinal_txout,
        10,
        funding_amount_used_for_protocol_fees,
        protocol_fee,
        protocol_fees_outpoint,
        protocol_fees_txout,
        &aggregated_operators,
        &user_sk,
        &user_pubkey,
        &user_address,
        MINER_FEE,
        secret_hash,
        unspendable,
    );

    tracing::debug!("Signed lockreq transaction: {:#?}", signed_lockreq_tx);

    let lockreq_txid = bitcoin_client.send_transaction(&signed_lockreq_tx).unwrap();

    Ok((lockreq_txid, user_pk, funding_amount_ordinal, protocol_fee))
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
