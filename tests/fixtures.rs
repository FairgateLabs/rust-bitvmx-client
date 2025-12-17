#![allow(dead_code)]
#![cfg(test)]
use anyhow::Result;
use bitcoin::{
    absolute,
    hex::FromHex,
    key::{rand::rngs::OsRng, Parity, Secp256k1},
    secp256k1::{self, All, Message, PublicKey as SecpPublicKey, SecretKey},
    sighash::SighashCache,
    transaction, Amount, Network, OutPoint, PrivateKey as BitcoinPrivKey, PublicKey,
    PublicKey as BitcoinPubKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
    XOnlyPublicKey,
};
use bitvmx_bitcoin_rpc::bitcoin_client::{BitcoinClient, BitcoinClientApi};
use protocol_builder::scripts::{
    build_taproot_spend_info, op_return_script, reveal_secret, timelock, ProtocolScript, SignMode,
};
use sha2::{Digest, Sha256};
use tracing::info;

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

pub fn emulated_user_keypair(
    secp: &Secp256k1<All>,
    bitcoin_client: &BitcoinClient,
    network: Network,
) -> Result<(bitcoin::Address, BitcoinPubKey, SecretKey)> {
    let mut rng = OsRng;

    // emulate the user keypair
    let user_sk = SecretKey::new(&mut rng);
    let user_pk = SecpPublicKey::from_secret_key(&secp, &user_sk);
    let (user_pk, user_sk) = adjust_parity(&secp, user_pk, user_sk);
    let user_pubkey = BitcoinPubKey {
        compressed: true,
        inner: user_pk,
    };
    let user_address: bitcoin::Address = bitcoin_client.get_new_address(user_pubkey, network)?;
    info!(
        "User Address({}): {:?}",
        user_address.address_type().unwrap(),
        user_address
    );
    Ok((user_address, user_pubkey, user_sk))
}

pub fn address_to_bytes(address: &str) -> Result<[u8; 20]> {
    let mut address_bytes = [0u8; 20];
    address_bytes.copy_from_slice(Vec::from_hex(address).unwrap().as_slice());
    Ok(address_bytes)
}

pub fn sign_p2wpkh_transaction_single_input(
    secp: &Secp256k1<All>,
    network: Network,
    transaction: &mut Transaction,
    user_pubkey: &BitcoinPubKey,
    user_sk: SecretKey,
    value: u64,
) -> Result<Transaction> {
    let user_bitcoin_privkey = BitcoinPrivKey {
        compressed: true,
        network: network.into(),
        inner: user_sk,
    };

    let user_comp_pubkey =
        bitcoin::CompressedPublicKey::from_private_key(&secp, &user_bitcoin_privkey).unwrap();
    let uncompressed_pk = secp256k1::PublicKey::from_slice(&user_comp_pubkey.to_bytes()).unwrap();

    // Sign the transactions inputs
    let wpkh = user_pubkey.wpubkey_hash().expect("key is compressed");
    let script_pubkey = ScriptBuf::new_p2wpkh(&wpkh);
    let mut sighasher = SighashCache::new(transaction);

    let input_index = 0;
    let sighash_type = bitcoin::EcdsaSighashType::All;
    let sighash = sighasher
        .p2wpkh_signature_hash(
            input_index,
            &script_pubkey,
            Amount::from_sat(value),
            sighash_type,
        )
        .expect("failed to create rsk request pegin input sighash");

    let signature = bitcoin::ecdsa::Signature {
        signature: secp.sign_ecdsa(&Message::from(sighash), &user_sk),
        sighash_type: sighash_type,
    };

    *sighasher.witness_mut(input_index).unwrap() = Witness::p2wpkh(&signature, &uncompressed_pk);

    // Now the transaction is signed
    let signed_transaction = sighasher.into_transaction().to_owned();
    Ok(signed_transaction)
}

// ======= RSK Pegin Functions =======

pub fn request_pegin_op_return_data(
    packet_number: u64,
    rootstock_address: [u8; 20],
    reimbursement_xpk: XOnlyPublicKey,
) -> Result<Vec<u8>> {
    let mut user_data = [0u8; 69];
    user_data.copy_from_slice(
        [
            b"RSK_PEGIN".as_slice(),
            &packet_number.to_be_bytes(),
            &rootstock_address,
            &reimbursement_xpk.serialize(),
        ]
        .concat()
        .as_slice(),
    );
    Ok(user_data.to_vec())
}

pub fn create_rsk_request_pegin_transaction(
    aggregated_key: PublicKey,
    network: Network,
    bitcoin_client: &BitcoinClient,
) -> Result<Txid> {
    let secp = secp256k1::Secp256k1::new();
    // RSK Pegin constants
    pub const STREAM_VALUE: u64 = 100_000;
    pub const KEY_SPEND_FEE: u64 = 335;
    pub const OP_RETURN_FEE: u64 = 300;
    pub const SPEED_UP_AMOUNT: u64 = 300;
    pub const TIMELOCK_BLOCKS: u16 = 1;

    let value = STREAM_VALUE;
    let fee = KEY_SPEND_FEE;
    let op_return_fee = OP_RETURN_FEE;
    let total_amount = value + fee + op_return_fee;

    // Locally created user keypair
    let (user_address, user_pubkey, user_sk) =
        emulated_user_keypair(&secp, bitcoin_client, network)?;
    // Fund the user address with enough to cover the taproot output + fees
    let (funding_tx, vout) = bitcoin_client
        .fund_address(&user_address, Amount::from_sat(total_amount))
        .unwrap();

    // RSK Pegin values
    let packet_number: u64 = 0;
    let rootstock_address = address_to_bytes("7ac5496aee77c1ba1f0854206a26dda82a81d6d8")?;
    let reimbursement_xpk = user_pubkey.into();

    // Create the Request pegin transaction
    // Inputs
    let funds_input = TxIn {
        previous_output: OutPoint::new(funding_tx.compute_txid(), vout),
        script_sig: ScriptBuf::default(), // For a p2wpkh script_sig is empty.
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME, // we want to be able to replace this transaction
        witness: Witness::default(),                // Filled in after, at signing time.
    };

    // Outputs
    // Taproot output
    let op_data = vec![rootstock_address.as_slice(), value.to_be_bytes().as_slice()].concat();
    let script_op_return = op_return_script(op_data)?;
    let script_timelock = timelock(TIMELOCK_BLOCKS, &user_pubkey, SignMode::Single);

    let taproot_spend_info = build_taproot_spend_info(
        &secp,
        &aggregated_key.into(),
        &[script_timelock, script_op_return],
    )?;

    let taproot_script_pubkey = ScriptBuf::new_p2tr(
        &secp,
        taproot_spend_info.internal_key(),
        taproot_spend_info.merkle_root(),
    );

    let taproot_output = TxOut {
        value: Amount::from_sat(value),
        script_pubkey: taproot_script_pubkey,
    };

    // OP_RETURN output
    let op_return_data =
        request_pegin_op_return_data(packet_number, rootstock_address, reimbursement_xpk)?;
    let op_return_output = TxOut {
        value: Amount::from_sat(0), // OP_RETURN outputs should have 0 value
        script_pubkey: op_return_script(op_return_data)?.get_script().clone(),
    };

    let mut request_pegin_transaction = Transaction {
        version: transaction::Version::TWO,  // Post BIP-68.
        lock_time: absolute::LockTime::ZERO, // Ignore the transaction lvl absolute locktime.
        input: vec![funds_input],
        output: vec![taproot_output, op_return_output],
    };

    let signed_transaction = sign_p2wpkh_transaction_single_input(
        &secp,
        network,
        &mut request_pegin_transaction,
        &user_pubkey,
        user_sk,
        total_amount,
    )?;
    tracing::debug!(
        "Signed RSK request pegin transaction: {:#?}",
        signed_transaction
    );

    let signed_transaction_txid = bitcoin_client
        .send_transaction(&signed_transaction)
        .unwrap();
    Ok(signed_transaction_txid)
}

// ======= Cardinal Functions =======
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
    lock_protocol_cost: u64,
    bitcoin_client: &BitcoinClient,
    fee_for_lockreq: u64,
) -> Result<(Txid, SecpPublicKey, Amount)> {
    //PublicKey user, txid, 0 :amount-ordinal, 1: amount-fees
    let secp = secp256k1::Secp256k1::new();

    // hardcoded unspendable
    let unspendable = hardcoded_unspendable();

    // emulate the user keypair
    let (user_address, user_pubkey, user_sk) =
        emulated_user_keypair(&secp, bitcoin_client, network)?;

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
    let funding_amount_used_for_protocol_fees =
        Amount::from_sat(lock_protocol_cost + fee_for_lockreq);
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

    let miner_fee: Amount = Amount::from_sat(fee_for_lockreq);

    let signed_lockreq_tx = create_lockreq_tx_and_sign(
        &secp,
        funding_amount_ordinal,
        ordinal_outpoint,
        ordinal_txout,
        10,
        funding_amount_used_for_protocol_fees,
        Amount::from_sat(lock_protocol_cost),
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

    Ok((lockreq_txid, user_pubkey.inner, funding_amount_ordinal))
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
    let mut outputs = vec![ordinal_output, protocol_fees_output];
    if change_amount > Amount::ZERO {
        outputs.push(change_output);
    }

    let mut unsigned_lockreq_tx = Transaction {
        version: transaction::Version::TWO,  // Post BIP-68.
        lock_time: absolute::LockTime::ZERO, // Ignore the transaction lvl absolute locktime.
        input: vec![ordinal_input, protocol_fees_input],
        output: outputs,
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
