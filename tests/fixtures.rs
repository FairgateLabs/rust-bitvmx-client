// // Run with: RUSTFLAGS="-Awarnings" cargo run --example cardinal_lock_protocol

// General imports
use bitcoin::{
    taproot::TaprootSpendInfo, Amount, PublicKey, ScriptBuf, TxOut, Txid, XOnlyPublicKey,
};
use bitcoin::Transaction;
use rust_bitvmx_transactions::context::ONE_BTC;

use bitvmx_bitcoin_rpc::bitcoin_client::*;
use sha2::{Digest, Sha256};

// Internal dependencies imports
use protocol_builder::{
    builder::{Protocol, ProtocolBuilder, SpendingArgs},
    errors::ProtocolBuilderError,
    graph::output::OutputSpendingType,
    scripts::{self, build_taproot_spend_info, ProtocolScript},
    unspendable::unspendable_key,
};
use rust_bitvmx_transactions::context::Context;

pub const DEBUG: bool = false;
pub const DUST_THRESHOLD_PER_OUTPUT: u64 = 330; // taproot output case
pub const ANY_TX_SPEEDUP_VALUE: u64 = DUST_THRESHOLD_PER_OUTPUT * 3;
pub const SECRET: &str = "secret";
pub const LOCKREQ_TX_NAME: &str = "lockreq_tx";
pub const LOCK_TX_NAME: &str = "lock_tx";
pub const RECLAIM_TX_TIMELOCK_BLOCKS: u16 = 10;
pub const END_OF_LIFE_TX_TIMELOCK_BLOCKS: u16 = 100;
pub const NETWORK: bitcoin::Network = bitcoin::Network::Regtest;

fn main() {
    println!("Please run the tests instead of this example. run with:");
    println!();
    println!("  RUSTFLAGS=\"-Awarnings\" cargo test --example cardinal_lock_protocol -- --test-threads=1 --show-output");
    println!();
}

pub fn create_lockreq_tx(
    c: &mut Context,
    txid_ordinal: Txid,
    output_index_ordinal: u32,
    txid_protocol_fees: Txid,
    output_index_protocol_fees: u32,
    funding_amount_ordinal: u64, // TODO this is not in the interface... discuss with futo
    funding_amount_protocol_fees: u64,
    timelock_duration: u16,
    secret: Vec<u8>,
    user_key: PublicKey,
    all_ops_aggregated_key: PublicKey,
) -> Result<Protocol, anyhow::Error> {
    const PROTOCOL_NAME: &str = "cardinal_lockreq";
    let protocol_storage = c.protocol_storage(PROTOCOL_NAME)?;

    const LOCKREQ_TX_MINER_FEE: u64 = 355_000;

    // lockreq_tx fees
    const PROTOCOL_FEES_OUTPUT_VALUE: u64 = 1_000_000;
    const ORDINAL_OUTPUT_VALUE: u64 = DUST_THRESHOLD_PER_OUTPUT * 3;

    // Calculate change (Ordinal amount is sum and the subtracted so is cancelled)
    let change: u64 = funding_amount_protocol_fees
        - PROTOCOL_FEES_OUTPUT_VALUE
        - LOCKREQ_TX_MINER_FEE;

    let unspendable_key = XOnlyPublicKey::from(unspendable_key(&mut c.rng())?);

    let output_segwit_spending_type_ordinal = OutputSpendingType::new_segwit_key_spend(
        &user_key,
        Amount::from_sat(funding_amount_ordinal),
    );

    let output_segwit_spending_type_protocol_fees = OutputSpendingType::new_segwit_key_spend(
        &user_key,
        Amount::from_sat(funding_amount_protocol_fees),
    );

    // The following script is the output that user timeout could use as input
    let taproot_script_reclaim_timelock_expired_tx_lockreq =
        scripts::timelock(timelock_duration, &user_key);

    let taproot_script_reveal_secret_tx_lockreq =
        scripts::reveal_secret(sha256(secret), &all_ops_aggregated_key);

    let mut builder = ProtocolBuilder::new(PROTOCOL_NAME, protocol_storage)?;
    let lockreq_tx_protocol = builder
        // [lockreq_tx] Connect with external transaction [ORDINAL]
        .connect_with_external_transaction(
            txid_ordinal,
            output_index_ordinal,
            output_segwit_spending_type_ordinal,
            LOCKREQ_TX_NAME,
            &c.ecdsa_sighash_type(),
        )?
        // [lockreq_tx] Connect with external transaction [Protocol fees]
        .connect_with_external_transaction(
            txid_protocol_fees,
            output_index_protocol_fees,
            output_segwit_spending_type_protocol_fees,
            LOCKREQ_TX_NAME,
            &c.ecdsa_sighash_type(),
        )?
        // [Ordinal timelock]
        // taproot output sending the ordinal to the All-operators aggregated key with a timelock to be able to rollback
        .add_timelock_output(
            LOCKREQ_TX_NAME,
            ORDINAL_OUTPUT_VALUE,
            &XOnlyPublicKey::from(user_key), // The operators can't spend without presenting the secret // TODO use the unspendable key fix: Witness program hash mismatch
            &taproot_script_reclaim_timelock_expired_tx_lockreq,
            &taproot_script_reveal_secret_tx_lockreq,
        )?
        // [Protocol fees timelock]
        // taproot output sending the fee (incentive to bridge) to the All-operators aggregated key with a timelock to be able to rollback
        .add_timelock_output(
            LOCKREQ_TX_NAME,
            PROTOCOL_FEES_OUTPUT_VALUE,
            &XOnlyPublicKey::from(user_key), // The operators can't spend without presenting the secret // TODO use the unspendable key fix: Witness program hash mismatch
            &taproot_script_reclaim_timelock_expired_tx_lockreq,
            &taproot_script_reveal_secret_tx_lockreq,
        )?
        // Change output
        .add_p2wpkh_output(LOCKREQ_TX_NAME, change, &user_key)?
        // Note: Speedup output is not needed, user can do a RBF if needed
        .build_and_sign(c.keys())
        .unwrap();

    if DEBUG {
        visualize_protocol(&lockreq_tx_protocol);
    }
    Ok(lockreq_tx_protocol)
}

pub fn create_lock_transaction(
    c: &mut Context,
    lockreq_tx_id: Txid,
    eol_timelock_duration: u16,
    all_ops_aggregated_pubkey: PublicKey,
    user_key: PublicKey,
    fee_pubkey: PublicKey,
    secret: Vec<u8>, // TODO this is not in the interface... discuss with Futo
) -> Result<Protocol, anyhow::Error> {
    const PROTOCOL_NAME: &str = "cardinal_lock";
    let protocol_storage = c.protocol_storage(PROTOCOL_NAME).unwrap();
    // let rng = c.rng();

    const LOCK_TX_MINER_FEE: u64 = 355_000;
    // tx_lockreq fees
    const PROTOCOL_FEES_OUTPUT_VALUE: u64 = 1_000_000;
    const ORDINAL_OUTPUT_VALUE: u64 = DUST_THRESHOLD_PER_OUTPUT * 3;
    const LOCK_TX_SPEEDUP_VALUE: u64 = ANY_TX_SPEEDUP_VALUE;

    let speedup_lock_tx_key = c.keys().derive_keypair(3).unwrap();

    // The following script is the output that user timeout could use as input
    let taproot_script_timelock_expired_tx_lockreq =
        scripts::timelock(RECLAIM_TX_TIMELOCK_BLOCKS, &user_key);
    let taproot_script_reveal_secret_tx_lockreq =
        scripts::reveal_secret(sha256(secret), &all_ops_aggregated_pubkey);
    let spending_scripts: &[ProtocolScript] = &[
        taproot_script_timelock_expired_tx_lockreq,
        taproot_script_reveal_secret_tx_lockreq,
    ]; // Must be in the same order

    // This un-spendable key is not the same key used in the lockreq_tx but as it is "un-spendable", we don't care
    let unspendable_key = XOnlyPublicKey::from(unspendable_key(&mut c.rng())?);

    // TODO, possibly protocol builder bug:
    /* Creating the TaprootSpendInfo with an unspendable key fails with: SignatureError(EntryNotFound)
    In this case we can use any valid key, as we are not going to execute the key path spend anyway */

    // TODO in a protocol builder future version use the unspendable key, and indicate that when connecting the outputs
    /* In this particular case, while we wait for the protocol builder feature to support unspendable keys,
    we are using the user key, as the user only neets to trust himself... when replacing it be aware of the error (Witness program hash mismatch) */
    let internal_key = XOnlyPublicKey::from(user_key);

    let spend_info: TaprootSpendInfo =
        build_taproot_spend_info(c.secp(), &internal_key, spending_scripts).unwrap();

    let prevouts: Vec<TxOut> = vec![
        TxOut {
            value: Amount::from_sat(ORDINAL_OUTPUT_VALUE),
            script_pubkey: ScriptBuf::new_p2tr(
                c.secp(),
                spend_info.internal_key(),
                spend_info.merkle_root(),
            ),
        },
        TxOut {
            value: Amount::from_sat(PROTOCOL_FEES_OUTPUT_VALUE),
            script_pubkey: ScriptBuf::new_p2tr(
                c.secp(),
                spend_info.internal_key(),
                spend_info.merkle_root(),
            ),
        },
    ];

    let output_spending_taproot_type_ordinal = OutputSpendingType::new_taproot_script_spend(
        spending_scripts,
        &spend_info,
        prevouts.clone(),
    );

    let output_spending_taproot_type_protocol_fees =
        OutputSpendingType::new_taproot_script_spend(spending_scripts, &spend_info, prevouts);

    // The following script is the output that user timeout could use as input
    let taproot_script_eol_timelock_expired_tx_lock =
        scripts::timelock(eol_timelock_duration, &user_key);
    let taproot_script_all_sign_tx_lock =
        scripts::check_aggregated_signature(&all_ops_aggregated_pubkey);

    let taproot_script_protocol_fee_addres_signature_in_tx_lock =
        scripts::check_aggregated_signature(&fee_pubkey);

    let mut builder = ProtocolBuilder::new(PROTOCOL_NAME, protocol_storage).unwrap();
    let lock_tx_protocol = builder
        // [tx_lock] Connect with external transaction (lockreq_tx) [ORDINAL]
        .connect_with_external_transaction(
            lockreq_tx_id,
            0,
            output_spending_taproot_type_ordinal,
            LOCK_TX_NAME,
            &c.taproot_sighash_type(),
        )?
        // [tx_lock] Connect with external transaction (lockreq_tx) [Protocol fees]
        .connect_with_external_transaction(
            lockreq_tx_id,
            1,
            output_spending_taproot_type_protocol_fees,
            LOCK_TX_NAME,
            &c.taproot_sighash_type(),
        )?
        // [Ordinal EOF timelock]
        // taproot output sending the ordinal to the All-operators aggregated key with a timelock to be able to execute the end of life
        .add_timelock_output(
            LOCK_TX_NAME,
            ORDINAL_OUTPUT_VALUE,
            &XOnlyPublicKey::from(all_ops_aggregated_pubkey), // TODO: discuss with Futo, do we want an internal key and a key spend path in this taptree. it will work, but i will generate more test cases
            &taproot_script_eol_timelock_expired_tx_lock,
            &taproot_script_all_sign_tx_lock,
        )?
        // [Protocol fees taproot output]
        // taproot output sending the fee (incentive to bridge) to the fee address
        // TODO discuss with Futo, do we want a key spend or a script spend checking the fee address signature? an script spend will be faster and easier to implement at this point. (no tweaking)
        .add_taproot_script_spend_output(
            LOCK_TX_NAME,
            PROTOCOL_FEES_OUTPUT_VALUE - LOCK_TX_SPEEDUP_VALUE - LOCK_TX_MINER_FEE, // TODO Check with Futo, I'am discounting miner fees from protocol fees here. is that ok?
            &XOnlyPublicKey::from(fee_pubkey), // TODO, perhaps we want un un-spendable key here to force the script path spend
            &[taproot_script_protocol_fee_addres_signature_in_tx_lock],
        )?
        // Speedup output
        .add_speedup_output(LOCK_TX_NAME, LOCK_TX_SPEEDUP_VALUE, &speedup_lock_tx_key)?
        .build_and_sign(c.keys())
        .unwrap();

    if DEBUG {
        visualize_protocol(&lock_tx_protocol);
    }
    Ok(lock_tx_protocol)
}

pub fn visualize_protocol(protocol: &Protocol) {
    println!();
    println!(
        "{} Protocol visualization - [ To be pasted in https://viz-js.com/ ]:\n",
        protocol.name()
    );
    println!("{}", protocol.visualize().unwrap());
    println!();
}

pub fn sha256(data: Vec<u8>) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(&data);
    hasher.finalize().to_vec()
}

pub fn sign_ecdsa_and_get_lockreq_tx(
    protocol: &Protocol,
    tx_name: &str,
    first_input_index: usize,
) -> Result<bitcoin::Transaction, ProtocolBuilderError> {
    // Sign the transaction for input 0
    let ecdsa_signature0 = protocol.input_ecdsa_signature(tx_name, first_input_index)?;
    let mut tx_spending_args0 = SpendingArgs::new_args();
    tx_spending_args0.push_ecdsa_signature(ecdsa_signature0);

    // Sign the transaction for input 1
    let ecdsa_signature1 = protocol.input_ecdsa_signature(tx_name, first_input_index + 1)?;
    let mut tx_spending_args1 = SpendingArgs::new_args();
    tx_spending_args1.push_ecdsa_signature(ecdsa_signature1);

    // Get the transaction
    protocol.transaction_to_send(tx_name, &[tx_spending_args0, tx_spending_args1])
}

pub fn push_taproot_signatures_and_get_lock_tx(
    protocol: &Protocol,
    tx_name: &str,
    leaf_index: usize,
    secret: Vec<u8>,
) -> Result<bitcoin::Transaction, ProtocolBuilderError> {
    // Sign the transaction

    // 1st signature [ORDINAL]
    let input_index_ordinal = 0;
    let taproot_signature_ordinal =
        protocol.input_taproot_script_spend_signature(tx_name, input_index_ordinal, leaf_index)?;
    let taproot_leaf_ordinal =
        protocol.get_script_to_spend(tx_name, input_index_ordinal as u32, leaf_index as u32)?;
    let taproot_leaf_ordinal_script = taproot_leaf_ordinal.get_script();
    let mut tx_spending_args_ordinal = SpendingArgs::new_taproot_args(taproot_leaf_ordinal_script);
    tx_spending_args_ordinal.push_taproot_signature(taproot_signature_ordinal);
    tx_spending_args_ordinal.push_slice(secret.as_slice());

    // 2nd signature [PROTOCOL FEES]
    let input_index_proto_fees = 1;
    let taproot_signature_proto_fees = protocol.input_taproot_script_spend_signature(
        tx_name,
        input_index_proto_fees,
        leaf_index,
    )?;
    let taproot_leaf_proto_fees =
        protocol.get_script_to_spend(tx_name, input_index_proto_fees as u32, leaf_index as u32)?;
    let taproot_leaf_proto_fees_script = taproot_leaf_proto_fees.get_script();
    let mut tx_spending_args_proto_fees =
        SpendingArgs::new_taproot_args(taproot_leaf_proto_fees_script);
    tx_spending_args_proto_fees.push_taproot_signature(taproot_signature_proto_fees);
    tx_spending_args_proto_fees.push_slice(secret.as_slice());

    // Get the transaction
    protocol.transaction_to_send(
        tx_name,
        &[tx_spending_args_ordinal, tx_spending_args_proto_fees],
    )
}

pub fn send_transaction(
    context: &mut Context,
    tx: bitcoin::Transaction,
    tx_name: &str,
) -> Result<(), anyhow::Error> {
    match context.bitcoin().send_transaction(&tx) {
        Ok(_) => {
            println!(
                "{} transaction sent successfully -> tx id: {}\n",
                tx_name,
                tx.compute_txid()
            );
            Ok(())
        }
        Err(e) => {
            eprintln!("Error sending {}: {}", tx_name, e);
            Err(anyhow::Error::new(e))
        }
    }
}

pub fn setup() -> Result<bitcoin::Transaction, anyhow::Error> {
    let mut c = Context::new().unwrap();

    // The user key
    let user_pubkey = c.keys().derive_keypair(0).unwrap();
    if DEBUG {
        println!("User PubKey: {:?}", user_pubkey);
    }
    let user_address: bitcoin::Address = c.bitcoin().get_new_address(user_pubkey, NETWORK);
    println!("User Address: {:?}", user_address);

    // The aggregated key between the operators
    // TODO NOTE: in future version of BitVMX we will use another function to get the aggregated key (ask this key to the session)
    let all_ops_aggregated_pubkey = c.keys().derive_keypair(1).unwrap();
    if DEBUG {
        println!("All Ops aggregated PubKey: {:?}", all_ops_aggregated_pubkey);
    }
    let all_ops_aggregated_address: bitcoin::Address =
        c.bitcoin().get_new_address(all_ops_aggregated_pubkey, NETWORK);
    println!(
        "All ops aggregated Address: {:?}",
        all_ops_aggregated_address
    );

    // The protocol fee address
    // TODO NOTE: in the future we will use another function to get this key
    let fee_pubkey = c.keys().derive_keypair(2).unwrap();
    if DEBUG {
        println!("All Ops aggregated PubKey: {:?}", all_ops_aggregated_pubkey);
    }
    let fee_address: bitcoin::Address = c.bitcoin().get_new_address(fee_pubkey, NETWORK);
    println!("Protocol Fee Address: {:?}\n", fee_address);

    // --- BEGIN lockreq_tx ---

    let secret = SECRET.as_bytes().to_vec();

    // Ordinal funding
    let funding_amount_ordinal = DUST_THRESHOLD_PER_OUTPUT;
    let funding_tx_ordinal: Transaction;
    let vout_ordinal: u32;
    (funding_tx_ordinal, vout_ordinal) = c.bitcoin().fund_address(&user_address, Amount::from_sat(funding_amount_ordinal)).unwrap();

    // Protocol fees funding
    let funding_amount_protocol_fees = ONE_BTC;
    let funding_tx_protocol_fees: Transaction;
    let vout_protocol_fees: u32;
    (funding_tx_protocol_fees, vout_protocol_fees) = c.bitcoin().fund_address(&user_address, Amount::from_sat(funding_amount_protocol_fees))
        .unwrap();

    // API SIGNATURE -> Create-lockrequest_tx(ordinal_ptr, funding_ptr, fee_amount, timelock_duration, secret, user_address, all_op_address)
    let lockreq_tx_protocol = create_lockreq_tx(
        &mut c,
        // ordinal_ptr
        funding_tx_ordinal.compute_txid(),
        vout_ordinal,
        // funding_ptr
        funding_tx_protocol_fees.compute_txid(),
        vout_protocol_fees,
        funding_amount_ordinal, // TODO this is not in the interface... discuss with futo, this can be hardcoded if we assume always the same amount for an ordinal
        funding_amount_protocol_fees,
        RECLAIM_TX_TIMELOCK_BLOCKS,
        secret.clone(),
        user_pubkey,
        all_ops_aggregated_pubkey,
    )
    .unwrap();

    // Sign lockreq_tx
    let lockreq_tx_result =
        sign_ecdsa_and_get_lockreq_tx(&lockreq_tx_protocol, LOCKREQ_TX_NAME, 0);
    let lockreq_tx = lockreq_tx_result.unwrap();
    if DEBUG {
        println!("lockreq tx: \n{:#?}\n", lockreq_tx);
    }

    // Send lockreq_tx
    send_transaction(&mut c, lockreq_tx.clone(), LOCKREQ_TX_NAME).unwrap();

    // --- END lockreq_tx ---

    // --- BEGIN lock_tx ---

    // API SIGNATRURE -> Create_lock_transaction(lockreq_tx_id, eol_timelock_duration, all_op_address, user_address, fee_address)
    let lock_tx_protocol = create_lock_transaction(
        &mut c,
        lockreq_tx.compute_txid(),
        END_OF_LIFE_TX_TIMELOCK_BLOCKS,
        all_ops_aggregated_pubkey,
        user_pubkey,
        fee_pubkey,
        secret.clone(),
    )
    .unwrap();

    // Sign lock_tx, using happy path leaf index 1 // TODO in future versions of the protocol builder the tapscript happy path will be index 0
    let happy_path_leaf_index = 1;
    let lock_tx_result = push_taproot_signatures_and_get_lock_tx(
        &lock_tx_protocol,
        LOCK_TX_NAME,
        happy_path_leaf_index,
        secret,
    );
    let lock_tx = lock_tx_result.unwrap();
    if DEBUG {
        println!("lock tx: \n{:#?}\n", lock_tx);
    }

    // Send lock_tx
    // send_transaction(&mut c, lock_tx.clone(), LOCK_TX_NAME).unwrap();

    // --- END lock_tx ---

    // TODO do we want to consume the lock_tx output 0 creating the new tx that calls BitVMX? key path and script path?
    // TODO do we want to consume the lock_tx output 1 creating the new tx withdraw the protocol fees? key path and script path?
    Ok(lockreq_tx)
}
