use anyhow::Result;
use bitcoin::{
    absolute,
    key::{rand::rngs::OsRng, Parity, Secp256k1},
    secp256k1::{self, All, Message, PublicKey as SecpPublicKey, SecretKey},
    sighash::SighashCache,
    transaction, Amount, Network, OutPoint, PrivateKey as BitcoinPrivKey, PublicKey,
    PublicKey as BitcoinPubKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use bitvmx_bitcoin_rpc::bitcoin_client::{BitcoinClient, BitcoinClientApi};
use bitvmx_broker::channel::channel::DualChannel;
use bitvmx_client::{
    program::{
        self,
        variables::{VariableTypes, WitnessTypes},
    },
    types::{IncomingBitVMXApiMessages, OutgoingBitVMXApiMessages, BITVMX_ID},
};
use common::{init_bitvmx, prepare_bitcoin, wait_message_from_channel};
use protocol_builder::scripts::{
    build_taproot_spend_info, reveal_secret, timelock, ProtocolScript,
};
use sha2::{Digest, Sha256};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

use std::sync::Once;
mod common;

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
        //.with_ansi(false)
        .with_target(true)
        .with_env_filter(filter)
        .init();
}

pub fn sha256(data: Vec<u8>) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(&data);
    hasher.finalize().to_vec()
}

pub fn send_all(channels: &Vec<&DualChannel>, msg: &str) -> Result<()> {
    for channel in channels {
        channel.send(BITVMX_ID, msg.to_string())?;
    }
    Ok(())
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
    let channels = vec![&bridge_1, &bridge_2, &bridge_3];

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

    send_all(&channels, &command)?;

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

    //let utxo = init_utxo(&bitcoin_client, aggregated_pub_key, Some(hash.clone()))?;

    let (txid, pubuser, ordinal_fee, protocol_fee) = create_loqreq_ready(
        aggregated_pub_key,
        hash.clone(),
        Network::Regtest,
        &bitcoin_client,
    )?;

    let set_ops_aggregated = IncomingBitVMXApiMessages::SetVar(
        program_id,
        "operators_aggregated_pub".to_string(),
        VariableTypes::PubKey(aggregated_pub_key),
    )
    .to_string()?;
    send_all(&channels, &set_ops_aggregated)?;

    let set_secret = IncomingBitVMXApiMessages::SetVar(
        program_id,
        "secret".to_string(),
        VariableTypes::Secret(hash),
    )
    .to_string()?;
    send_all(&channels, &set_secret)?;

    let set_ordinal_utxo = IncomingBitVMXApiMessages::SetVar(
        program_id,
        "ordinal_utxo".to_string(),
        VariableTypes::Utxo((txid, 0, Some(ordinal_fee.to_sat()))),
    )
    .to_string()?;
    /*let set_ordinal_utxo = IncomingBitVMXApiMessages::SetVar(
        program_id,
        "ordinal_utxo".to_string(),
        VariableTypes::Utxo((utxo.txid, utxo.vout, Some(utxo.amount))),
    )
    .to_string()?;*/

    send_all(&channels, &set_ordinal_utxo)?;

    let set_protocol_fee = IncomingBitVMXApiMessages::SetVar(
        program_id,
        "protocol_utxo".to_string(),
        VariableTypes::Utxo((txid, 1, Some(protocol_fee.to_sat()))),
    )
    .to_string()?;
    send_all(&channels, &set_protocol_fee)?;

    let set_user_pubkey = IncomingBitVMXApiMessages::SetVar(
        program_id,
        "user_pubkey".to_string(),
        VariableTypes::PubKey(bitcoin::PublicKey::from(pubuser)),
    )
    .to_string()?;
    send_all(&channels, &set_user_pubkey)?;

    let setup_msg = IncomingBitVMXApiMessages::SetupSlot(program_id, addresses, 0).to_string()?;
    send_all(&channels, &setup_msg)?;

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
            program::slot::LOCK_TX.to_string(),
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

pub fn create_loqreq_ready(
    aggregated_operators: PublicKey,
    secret_hash: Vec<u8>,
    network: Network,
    bitcoin_client: &BitcoinClient,
) -> Result<(Txid, SecpPublicKey, Amount, Amount)> {
    //PublicKey user, txid, 0 :amount-ordinal, 1: amount-fees

    let secp = secp256k1::Secp256k1::new();
    let mut rng = OsRng;

    // hardcoded unspendable
    let key_bytes =
        hex::decode("02f286025adef23a29582a429ee1b201ba400a9c57e5856840ca139abb629889ad")
            .expect("Invalid hex input");
    let unspendable = SecpPublicKey::from_slice(&key_bytes).expect("Invalid public key");

    // emulate the user keypair
    let user_sk = SecretKey::new(&mut rng);
    let user_pk = SecpPublicKey::from_secret_key(&secp, &user_sk);
    let (user_pk, user_sk) = adjust_parity(&secp, user_pk, user_sk);
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

    const ONE_BTC: Amount = Amount::from_sat(100_000_000);

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

    let signed_lockreq_tx = create_lockreq_tx_and_sign(
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
    config_trace();

    let (bitcoin_client, bitcoind, wallet) = prepare_bitcoin()?;

    let mut rng = OsRng;
    let secp = secp256k1::Secp256k1::new();

    /* This is a simulation, the aggregated address between all the operators should be retrieved form the directory or
    provided by BitVMX API after creating a new Session */
    let ops_agg_sk = SecretKey::new(&mut rng);
    let ops_agg_pk = SecpPublicKey::from_secret_key(&secp, &ops_agg_sk);
    // let ops_agg_keypair = Keypair::from_secret_key(&secp, &ops_agg_sk);
    let ops_agg_pubkey = BitcoinPubKey {
        compressed: true,
        inner: ops_agg_pk,
    };

    let preimage = "top_secret".to_string();
    let hash = sha256(preimage.as_bytes().to_vec());

    let (txid, pubuser, ordinal_fee, protocol_fee) =
        create_loqreq_ready(ops_agg_pubkey, hash, Network::Regtest, &bitcoin_client)?;

    info!("Lockreq txid: {:?}", txid);
    info!("User public key: {:?}", pubuser);
    info!("Protocol fee: {:?}", protocol_fee);
    info!("Ordinal fee: {:?}", ordinal_fee);

    // Mine 1 block to confirm transaction
    bitcoin_client.mine_blocks_to_address(1, &wallet)?;

    bitcoind.stop()?;

    Ok(())
}

// This method changes the parity of a keypair to be even, this is needed for Taproot.
fn adjust_parity(
    secp: &Secp256k1<All>,
    pubkey: SecpPublicKey,
    seckey: SecretKey,
) -> (SecpPublicKey, SecretKey) {
    let (_, parity) = pubkey.x_only_public_key();

    if parity == Parity::Odd {
        (pubkey.negate(&secp), seckey.negate())
    } else {
        (pubkey, seckey)
    }
}
fn create_lockreq_tx_and_sign(
    secp: &secp256k1::Secp256k1<secp256k1::All>,
    ordinal_amount: Amount,
    ordinal_prev_outpoint: OutPoint,
    ordinal_prev_txout: TxOut,
    timelock_blocks: u16,
    funding_amount: Amount,
    protocol_fee_amount: Amount,
    protocol_fee_prev_outpoint: OutPoint,
    protocol_fee_prev_txout: TxOut,
    ops_agg_pubkey: &BitcoinPubKey,
    user_seckey: &SecretKey,
    user_pubkey: &BitcoinPubKey,
    user_address: &bitcoin::Address,
    miner_fee: Amount,
    secret_hash: Vec<u8>,
    unspendable_pub_key: SecpPublicKey,
) -> Transaction {
    let timelock_script = timelock(timelock_blocks, &user_pubkey);

    let reveal_secret_script = reveal_secret(secret_hash.to_vec(), &ops_agg_pubkey);
    let lockreq_tx_output_taptree = build_taptree_for_lockreq_tx_outputs(
        &secp,
        unspendable_pub_key,
        timelock_script,
        reveal_secret_script,
    )
    .unwrap();

    let ordinal_input = TxIn {
        previous_output: ordinal_prev_outpoint,
        script_sig: ScriptBuf::default(), // For a p2wpkh script_sig is empty.
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME, // we want to be able to replace this transaction
        witness: Witness::default(),                // Filled in after, at signing time.
    };

    let protocol_fees_input = TxIn {
        previous_output: protocol_fee_prev_outpoint,
        script_sig: ScriptBuf::default(), // For a p2wpkh script_sig is empty.
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME, // we want to be able to replace this transaction
        witness: Witness::default(),                // Filled in after, at signing time.
    };

    /*
        Note: The spend output is locked to the some of the taptree spend paths,
        In this case as we are finalizing the taptree with an un-spendable key to force the script path
    */
    let script_pk = ScriptBuf::new_p2tr(
        secp,
        lockreq_tx_output_taptree.internal_key(),
        lockreq_tx_output_taptree.merkle_root(),
    );

    // Note: See that both outpus (ordinal and protocol fees) use the same taptree script
    let ordinal_output = TxOut {
        value: ordinal_amount,
        script_pubkey: script_pk.clone(),
    };

    let protocol_fees_output = TxOut {
        value: protocol_fee_amount,
        script_pubkey: script_pk,
    };

    // Calculate change (Ordinal amount is sum and the subtracted so is cancelled)
    let change_amount = funding_amount
        .unchecked_sub(protocol_fee_amount)
        .unchecked_sub(miner_fee);

    let change_output = TxOut {
        value: change_amount,
        script_pubkey: user_address.script_pubkey(),
    };

    let mut unsigned_lockreq_tx = Transaction {
        version: transaction::Version::TWO,  // Post BIP-68.
        lock_time: absolute::LockTime::ZERO, // Ignore the transaction lvl absolute locktime.
        input: vec![ordinal_input, protocol_fees_input],
        output: vec![ordinal_output, protocol_fees_output, change_output],
    };

    let wpkh = user_pubkey.wpubkey_hash().expect("key is compressed");
    let script_pubkey = ScriptBuf::new_p2wpkh(&wpkh);

    assert_eq!(&ordinal_prev_txout.script_pubkey, &script_pubkey);

    let mut sighasher = SighashCache::new(&mut unsigned_lockreq_tx);

    let user_bitcoin_privkey = BitcoinPrivKey {
        compressed: true,
        network: bitcoin::NetworkKind::Test,
        inner: *user_seckey,
    };

    let user_comp_pubkey =
        bitcoin::CompressedPublicKey::from_private_key(&secp, &user_bitcoin_privkey).unwrap();
    let uncompressed_pk = secp256k1::PublicKey::from_slice(&user_comp_pubkey.to_bytes()).unwrap();

    // Sign ordinal input
    let ordinal_input_index = 0;
    let ordinal_sighash_type = bitcoin::EcdsaSighashType::All;
    let ordinal_sighash = sighasher
        .p2wpkh_signature_hash(
            ordinal_input_index,
            &script_pubkey,
            ordinal_amount,
            ordinal_sighash_type,
        )
        .expect("failed to create ordinal input sighash");
    let ordinal_msg = Message::from(ordinal_sighash);
    let ordinal_signature = secp.sign_ecdsa(&ordinal_msg, user_seckey);

    let ord_signature = bitcoin::ecdsa::Signature {
        signature: ordinal_signature,
        sighash_type: ordinal_sighash_type,
    };

    *sighasher.witness_mut(ordinal_input_index).unwrap() =
        Witness::p2wpkh(&ord_signature, &uncompressed_pk);

    // the following code is another way to psuh the signature, let's say more raw version
    // let mut ordinal_sig_ser = ordinal_signature.serialize_der().to_vec();
    // ordinal_sig_ser.push(ordinal_sighash_type.to_u32() as u8);
    // unsigned_lockreq_tx.input[ordinal_input_index].witness.push(ordinal_sig_ser); // pushes signature + sig hash type
    // unsigned_lockreq_tx.input[ordinal_input_index].witness.push(user_pubkey.to_bytes()); // pushes user pubkey

    assert_eq!(&protocol_fee_prev_txout.script_pubkey, &script_pubkey);
    // Sign protocol fees input
    let protocol_fees_input_index = 1;
    let protocol_fees_sighash_type = bitcoin::EcdsaSighashType::All;
    let protocol_fees_sighash = sighasher
        .p2wpkh_signature_hash(
            protocol_fees_input_index,
            &script_pubkey,
            funding_amount,
            protocol_fees_sighash_type,
        )
        .expect("failed to create protocol fees input sighash");
    let protocol_fees_msg = Message::from(protocol_fees_sighash);
    let protocol_fees_signature = secp.sign_ecdsa(&protocol_fees_msg, user_seckey);

    let proto_fees_signature = bitcoin::ecdsa::Signature {
        signature: protocol_fees_signature,
        sighash_type: protocol_fees_sighash_type,
    };

    *sighasher.witness_mut(protocol_fees_input_index).unwrap() =
        Witness::p2wpkh(&proto_fees_signature, &uncompressed_pk);

    // the following code is another way to push the signature, let's say more raw version
    // let mut protocol_fees_sig_ser = protocol_fees_signature.serialize_der().to_vec();
    // protocol_fees_sig_ser.push(protocol_fees_sighash_type.to_u32() as u8);
    // unsigned_lockreq_tx.input[protocol_fees_input_index].witness.push(protocol_fees_sig_ser); // pushes signature + sig hash type
    // unsigned_lockreq_tx.input[protocol_fees_input_index].witness.push(user_pubkey.to_bytes()); // pushes user pubkey

    // Now the transaction is signed
    let signed_transaction = sighasher.into_transaction().to_owned();

    signed_transaction
}
