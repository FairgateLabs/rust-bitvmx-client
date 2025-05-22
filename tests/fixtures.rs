#![allow(dead_code)]
use std::str::FromStr;

use anyhow::Result;
use bitcoin::{
    absolute,
    key::{Parity, Secp256k1},
    secp256k1::{self, All, Message, PublicKey as SecpPublicKey, SecretKey},
    sighash::SighashCache,
    transaction, Amount, Network, OutPoint, PrivateKey as BitcoinPrivKey, PublicKey,
    PublicKey as BitcoinPubKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use bitvmx_bitcoin_rpc::bitcoin_client::{BitcoinClient, BitcoinClientApi};
use bitvmx_client::config::Config;
use protocol_builder::scripts::{
    build_taproot_spend_info, reveal_secret, timelock, ProtocolScript, SignMode,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
//use tracing::info;

pub fn sha256(data: Vec<u8>) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(&data);
    hasher.finalize().to_vec()
}

pub fn hardcoded_unspendable() -> SecpPublicKey {
    // hardcoded unspendable
    let key_bytes =
        hex::decode("02f286025adef23a29582a429ee1b201ba400a9c57e5856840ca139abb629889ad")
            .expect("Invalid hex input");
    SecpPublicKey::from_slice(&key_bytes).expect("Invalid public key")
}

// This method changes the parity of a keypair to be even, this is needed for Taproot.
pub fn adjust_parity(
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

pub fn build_taptree_for_lockreq_tx_outputs(
    secp: &secp256k1::Secp256k1<secp256k1::All>,
    unspendable_pub_key: SecpPublicKey,
    timelock_script: ProtocolScript,
    reveal_secret_script: ProtocolScript,
) -> Result<bitcoin::taproot::TaprootSpendInfo> {
    /* NOTE: we want to force the script path spend, so we will finalize with an un-spendable key */
    let (internal_key_for_taptree_xonly, _parity) = unspendable_pub_key.x_only_public_key();
    // println!("Unspendable key: {}", unspendable_pub_key);
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

pub fn create_lockreq_ready(
    aggregated_operators: PublicKey,
    secret_hash: Vec<u8>,
    network: Network,
    bitcoin_client: &BitcoinClient,
) -> Result<(Txid, SecpPublicKey, Amount, Amount)> {
    //PublicKey user, txid, 0 :amount-ordinal, 1: amount-fees

    tracing::info!("Creating lockreq transaction");
    let secp = secp256k1::Secp256k1::new();

    // hardcoded unspendable
    let unspendable = hardcoded_unspendable();

    let data = std::fs::read_to_string("utxo.json")?;
    let parsed: Value = serde_json::from_str(&data).expect("Failed to parse JSON");

    let txid1 = parsed["txid1"].as_str().unwrap_or("missing");
    let vout1 = parsed["vout1"]
        .as_u64()
        .unwrap_or(0) as u32;
    let txid2 = parsed["txid2"].as_str().unwrap_or("missing");
    let vout2 = parsed["vout2"]
        .as_u64()
        .unwrap_or(0) as u32;

    let user_sk = SecretKey::from_str(parsed["signer"].as_str().unwrap())?;
    let private_key = bitcoin::PrivateKey::new(user_sk.clone(), network);
    let user_pubkey = BitcoinPubKey::from_private_key(&secp, &private_key);
    let user_cpk = bitcoin::CompressedPublicKey::from_private_key(&secp, &private_key).unwrap();
    let user_address = bitcoin::Address::p2wpkh(&user_cpk, network);


    let funding_txid1 = Txid::from_str(txid1)?;
    let funding_txid2 = Txid::from_str(txid2)?;

    let ordinal_prev_outpoint = OutPoint::new(funding_txid1, vout1);
    let funding_tx1 = bitcoin_client
        .get_transaction(&funding_txid1)?
        .unwrap();
    let funding_tx2 = bitcoin_client
        .get_transaction(&funding_txid2)?
        .unwrap();
    let ordinal_prev_txout = funding_tx1.output[vout1 as usize].clone();

    let protocol_fees_outpoint = OutPoint::new(funding_txid2, vout2);
    let protocol_fees_txout = funding_tx2.output[vout2 as usize].clone();

    let funding_amount_used_for_protocol_fees = funding_tx2.output[vout2 as usize].value;
    let funding_amount_ordinal = Amount::from_sat(10_000);
    let protocol_fee = Amount::from_sat(3000);
    let miner_fee = Amount::from_sat(300);

    let signed_lockreq_tx = create_lockreq_tx_and_sign(
        &secp,
        funding_amount_ordinal,
        ordinal_prev_outpoint,
        ordinal_prev_txout,
        10,
        funding_amount_used_for_protocol_fees,
        protocol_fee,
        protocol_fees_outpoint,
        protocol_fees_txout,
        &aggregated_operators,
        &user_sk,
        &user_pubkey,
        &user_address,
        miner_fee,
        secret_hash,
        unspendable,
    );

    tracing::debug!("Signed lockreq transaction: {:#?}", signed_lockreq_tx);

    let lockreq_txid = bitcoin_client.send_transaction(&signed_lockreq_tx).unwrap();

    tracing::info!("Lockreq transaction sent!");

    Ok((lockreq_txid, user_pubkey.inner, funding_amount_ordinal, protocol_fee))
}

pub fn create_lockreq_tx_and_sign(
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
    let timelock_script = timelock(timelock_blocks, &user_pubkey, SignMode::Single);

    let reveal_secret_script =
        reveal_secret(secret_hash.to_vec(), &ops_agg_pubkey, SignMode::Aggregate);
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

    // Now the transaction is signed
    let signed_transaction = sighasher.into_transaction().to_owned();

    signed_transaction
}

pub fn  create_wallet() -> Result<rust_bitvmx_wallet::wallet::Wallet> {
    let config = Config::new(Some("config/wallet_testnet.yaml".to_string()))?;

    let bitvmx_wallet = rust_bitvmx_wallet::wallet::Wallet::new(
        config.bitcoin,
        config.key_manager,
        config.key_storage,
        config.storage,
    );

    Ok(bitvmx_wallet)
}