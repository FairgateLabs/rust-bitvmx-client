// Run with: ../stop.sh; sleep 3 &&  ../start.sh && sleep 3 && RUSTFLAGS="-Awarnings" cargo run --example cardinal_lock_protocol
use bitcoin::{Amount, PublicKey, Transaction, Txid, XOnlyPublicKey, secp256k1};
use bitcoin::taproot::TaprootSpendInfo;
use bitcoincore_rpc::RawTx;
use protocol_builder::scripts::build_taproot_spend_info;
use protocol_builder::{
    builder::{Protocol, ProtocolBuilder, SpendingArgs}, errors::ProtocolBuilderError, graph::output::OutputSpendingType, scripts::{self, ProtocolScript}
};
use rust_bitvmx_transactions::context::{Context, ONE_BTC};
use sha2::{Sha256, Digest};

const DEBUG: bool = false;
const DUST_THRESHOLD_PER_OUTPUT: u64 = 330; // taproot output case
const ANY_TX_SPEEDUP_VALUE: u64 = DUST_THRESHOLD_PER_OUTPUT * 3;
const LOCKREQ_TX_NAME: &str = "tx_lockreq";
const LOCK_TX_NAME: &str = "tx_lock";
const RECLAIM_TX_TIMELOCK_BLOCKS: u16 = 100;
const END_OF_LIFE_TX_TIMELOCK_BLOCKS: u16 = 100;

pub fn make_fixtures() -> Result<bitcoin::Transaction, anyhow::Error> {
    
    let mut c = Context::new().map_err(|e| {
        println!("Failed to create context: {}", e);
        e
    })?;

    // The user key
    let user_pubkey = c.keys().derive_keypair(0).unwrap();
    // println!("User PubKey: {:?}", user_pubkey);
    let user_address: bitcoin::Address = c.bitcoin().get_new_address(user_pubkey);
    println!("User Address: {:?}", user_address);

    // The aggregated key between the operators
    let all_ops_aggregated_pubkey = c.keys().derive_keypair(1).unwrap();
    // println!("All Ops aggregated PubKey: {:?}", all_ops_aggregated_pubkey);
    let all_ops_aggregated_address: bitcoin::Address = c.bitcoin().get_new_address(all_ops_aggregated_pubkey);
    println!("All ops aggregated Address: {:?}", all_ops_aggregated_address);

    // Ordinal funding
    let funding_amount_ordinal = DUST_THRESHOLD_PER_OUTPUT;
    let funding_tx_ordinal: Transaction;
    let vout_ordinal: u32;
    (funding_tx_ordinal, vout_ordinal) = c
        .fund_user_address(funding_amount_ordinal, &user_address)
        .unwrap();

    // Protocol fees funding
    let funding_amount_protocol_fees = ONE_BTC;
    let funding_tx_protocol_fees: Transaction;
    let vout_protocol_fees: u32;
    (funding_tx_protocol_fees, vout_protocol_fees) = c
        .fund_user_address(funding_amount_protocol_fees, &user_address)
        .unwrap();

    let lockreq_tx_protocol = create_lockreq_tx(
        &mut c,

        // ordinal_ptr
        funding_tx_ordinal.compute_txid(),
        vout_ordinal,

        // funding_ptr
        funding_tx_protocol_fees.compute_txid(),
        vout_protocol_fees,

        funding_amount_ordinal, // TODO this is not in the interface... discuss with futo
        funding_amount_protocol_fees,
        RECLAIM_TX_TIMELOCK_BLOCKS,
        "secret".as_bytes().to_vec(),
        user_pubkey,
        all_ops_aggregated_pubkey,
        ).unwrap();

    // Sign tx_create
    let lockreq_tx_result = sign_ecdsa_and_get_lockreq(&lockreq_tx_protocol, LOCKREQ_TX_NAME, 0);

    let lockreq_tx = lockreq_tx_result.unwrap();
    // println!("Tx input len: {:?}", lockreq_tx.clone().input.len());
    println!("Tx lockreq: {:?}", lockreq_tx);
    println!("Tx lockreq raw: {:?}", lockreq_tx.raw_hex());

    // Send tx_create
    // send_transaction(&mut c, lockreq_tx.clone(), LOCKREQ_TX_NAME);
    Ok(lockreq_tx)
}

fn create_lockreq_tx(
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
    // let rng = c.rng();

    const LOCKREQ_TX_MINER_FEE: u64 = 355_000;
    // tx_lockreq fees
    const PROTOCOL_FEES_OUTPUT_VALUE: u64 = 1_000_000;
    const ORDINAL_OUTPUT_VALUE: u64 = DUST_THRESHOLD_PER_OUTPUT * 3;

    // Calculate change
    let change: u64 = funding_amount_protocol_fees - PROTOCOL_FEES_OUTPUT_VALUE - ORDINAL_OUTPUT_VALUE - LOCKREQ_TX_MINER_FEE;

    let output_segwit_spending_type_ordinal =
        OutputSpendingType::new_segwit_key_spend(&user_key, Amount::from_sat(funding_amount_ordinal));

    let output_segwit_spending_type_protocol_fees =
        OutputSpendingType::new_segwit_key_spend(&user_key, Amount::from_sat(funding_amount_protocol_fees));

    // The following script is the output that user timeout could use as input
    let taproot_script_reclaim_timelock_expired_tx_lockreq = scripts::timelock(timelock_duration, &user_key);

    let taproot_script_reveal_secret_tx_lockreq = scripts::reveal_secret(sha256(secret), &all_ops_aggregated_key);

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
            &XOnlyPublicKey::from(all_ops_aggregated_key), // TODO: discuss with Futo, do we want an internal key and a key spend path in this taptree?
            &taproot_script_reclaim_timelock_expired_tx_lockreq,
            &taproot_script_reveal_secret_tx_lockreq)?
        // [Protocol fees timelock]
        // taproot output sending the fee (incentive to bridge) to the All-operators aggregated key with a timelock to be able to rollback
        .add_timelock_output(
            LOCKREQ_TX_NAME,
            PROTOCOL_FEES_OUTPUT_VALUE,
            &XOnlyPublicKey::from(all_ops_aggregated_key), // TODO: discuss with Futo, do we want an internal key and a key spend path in this taptree?
            &taproot_script_reclaim_timelock_expired_tx_lockreq,
            &taproot_script_reveal_secret_tx_lockreq)?
        // Change output
        .add_p2wpkh_output(LOCKREQ_TX_NAME, change, &user_key)?
        // Note: Speedup output is not needed, user can do a RBF if needed

        .build_and_sign(c.keys()).unwrap();

    // Visualize the protocol
    println!();
    println!("{} Protocol visualization - [ To be pasted in https://viz-js.com/ ]:\n", PROTOCOL_NAME);
    println!("{}", lockreq_tx_protocol.visualize()?);
    println!();

    Ok(lockreq_tx_protocol)

}


fn create_lock_transaction(
    c: &mut Context,
    lockreq_tx_id: Txid,
    eol_timelock_duration: u16,
    all_ops_aggregated_pubkey: PublicKey,
    user_key: PublicKey,
    fee_pubkey: PublicKey,
    secret: Vec<u8>  // TODO this is not in the interface... discuss with Futo
) -> Result<Protocol, anyhow::Error> {

    const PROTOCOL_NAME: &str = "cardinal_lock";
    let protocol_storage = c.protocol_storage(PROTOCOL_NAME)?;
    // let rng = c.rng();


    const LOCK_TX_MINER_FEE: u64 = 355_000;
    // tx_lockreq fees
    const PROTOCOL_FEES_OUTPUT_VALUE: u64 = 1_000_000;
    const ORDINAL_OUTPUT_VALUE: u64 = DUST_THRESHOLD_PER_OUTPUT * 3;
    const LOCK_TX_SPEEDUP_VALUE: u64 = ANY_TX_SPEEDUP_VALUE;

    let speedup_lock_tx_key = c.keys().derive_keypair(3)?;

    // TODO CHECK WITH DIEGO M.
    let secp = secp256k1::Secp256k1::new(); // TODO, ask Diego M. if we want to expose the secp from context
    // The following script is the output that user timeout could use as input
    let taproot_script_timelock_expired_tx_lockreq = scripts::timelock(RECLAIM_TX_TIMELOCK_BLOCKS, &user_key);
    let taproot_script_reveal_secret_tx_lockreq = scripts::reveal_secret(sha256(secret), &all_ops_aggregated_pubkey);
    let spending_scripts: &[ProtocolScript] = &[taproot_script_timelock_expired_tx_lockreq, taproot_script_reveal_secret_tx_lockreq];

    let internal_key = &XOnlyPublicKey::from(all_ops_aggregated_pubkey); // TODO: discuss with Futo, do we want an internal key and a key spend path in this taptree?
    let spend_info: TaprootSpendInfo = build_taproot_spend_info(&secp, internal_key, spending_scripts).unwrap();

    let output_spending_taproot_type_ordinal =
        OutputSpendingType::new_taproot_script_spend(spending_scripts, &spend_info);

    let output_spending_taproot_type_protocol_fees =
        OutputSpendingType::new_taproot_script_spend(spending_scripts, &spend_info);

    // The following script is the output that user timeout could use as input
    let taproot_script_eol_timelock_expired_tx_lock = scripts::timelock(eol_timelock_duration, &user_key);
    let taproot_script_all_sign_tx_lock = scripts::check_aggregated_signature(&all_ops_aggregated_pubkey);

    let taproot_script_protocol_fee_addres_signature_in_tx_lock = scripts::check_aggregated_signature(&fee_pubkey);

    let mut builder = ProtocolBuilder::new(PROTOCOL_NAME, protocol_storage)?;
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
            &XOnlyPublicKey::from(all_ops_aggregated_pubkey), // TODO: discuss with Futo, do we want an internal key and a key spend path in this taptree?
            &taproot_script_eol_timelock_expired_tx_lock,
            &taproot_script_all_sign_tx_lock)?
        // [Protocol fees taproot output]
        // taproot output sending the fee (incentive to bridge) to the fee address
        // TODO discuss with Futo, do we want a key spend or a script spend checking the fee address signature?
        .add_taproot_script_spend_output(
            LOCK_TX_NAME,
            PROTOCOL_FEES_OUTPUT_VALUE - LOCK_TX_SPEEDUP_VALUE - LOCK_TX_MINER_FEE, // TODO Check, I'am discounting miner fees from protocol fees here. is that ok?
            &XOnlyPublicKey::from(fee_pubkey),
            &[taproot_script_protocol_fee_addres_signature_in_tx_lock])?
        // Speedup output
        .add_speedup_output(
            LOCK_TX_NAME,
            LOCK_TX_SPEEDUP_VALUE,
            &speedup_lock_tx_key)?

        .build_and_sign(c.keys()).unwrap();

    // Visualize the protocol
    println!();
    println!("{} Protocol visualization - [ To be pasted in https://viz-js.com/ ]:\n", PROTOCOL_NAME);
    println!("{}", lock_tx_protocol.visualize()?);
    println!();

    Ok(lock_tx_protocol)

    // Err(anyhow::Error::msg("Protocol not implemented"))

}

fn sha256(data: Vec<u8>) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(&data);
    hasher.finalize().to_vec()
}


fn sign_ecdsa_and_get_lockreq(protocol: &Protocol, tx_name: &str, first_input_index: usize) -> Result<bitcoin::Transaction, ProtocolBuilderError> {
    // Sign the transaction for input 0
    let ecdsa_signature0 = protocol.input_ecdsa_signature(tx_name, first_input_index)?;
    let mut tx_spending_args0 = SpendingArgs::new_args();
    tx_spending_args0.push_ecdsa_signature(ecdsa_signature0);


    // Sign the transaction for input 1
    let ecdsa_signature1 = protocol.input_ecdsa_signature(tx_name, first_input_index+1)?;
    let mut tx_spending_args1 = SpendingArgs::new_args();
    tx_spending_args1.push_ecdsa_signature(ecdsa_signature1);

    // Get the transaction
    protocol.transaction_to_send(tx_name, &[tx_spending_args0, tx_spending_args1])
}

fn send_transaction(context:&mut Context, tx: bitcoin::Transaction, tx_name: &str) {
    match context.bitcoin().send_transaction(&tx) {
        Ok(_) => {
            println!("{} transaction sent successfully -> tx id: {}\n", tx_name, tx.compute_txid());
            if DEBUG { println!("{:#?}", tx); }
        }
        Err(e) => {
            eprintln!("Error sending {}: {}", tx_name, e);
        }
    }
}
