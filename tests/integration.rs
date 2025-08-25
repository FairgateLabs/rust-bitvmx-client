use anyhow::Result;
use bitvmx_client::types::{IncomingBitVMXApiMessages, OutgoingBitVMXApiMessages, BITVMX_ID};
use common::{
    config_trace,
    dispute::{execute_dispute, prepare_dispute, ForcedChallenges},
    get_all, init_bitvmx, init_utxo_new, prepare_bitcoin, send_all, wait_message_from_channel,
};
use protocol_builder::{
    scripts::{self, SignMode},
    types::Utxo,
};
use tracing::info;
use uuid::Uuid;

use crate::common::{FEE, FUNDING_ID, WALLET_NAME};

mod common;

//cargo test --release  -- test_drp --features regtest
#[cfg(feature = "testnet")]
#[test]
pub fn test_drp() -> Result<()> {

    config_trace();

    let (bitcoin_client, bitcoind, wallet) = prepare_bitcoin()?;

    let (prover_bitvmx, prover_address, prover_bridge_channel, prover_emulator_channel) =
        init_bitvmx("op_1", true)?;

    let (verifier_bitvmx, verifier_address, verifier_bridge_channel, verifier_emulator_channel) =
        init_bitvmx("op_2", true)?;

    let mut instances = vec![prover_bitvmx, verifier_bitvmx];
    let channels = vec![prover_bridge_channel, verifier_bridge_channel];

    //get to the top of the blockchain
    for _ in 0..101 {
        for instance in instances.iter_mut() {
            instance.process_bitcoin_updates()?;
        }
    }

    //one time per bitvmx instance, we need to get the public key for the speedup funding utxo
    let funding_public_id = Uuid::new_v4();
    let command = IncomingBitVMXApiMessages::GetPubKey(funding_public_id, true).to_string()?;
    send_all(&channels, &command)?;
    let msgs = get_all(&channels, &mut instances, false)?;
    let funding_key_0 = msgs[0].public_key().unwrap().1;
    let funding_key_1 = msgs[1].public_key().unwrap().1;

    let fund_txid_0 = wallet.fund_address(
        WALLET_NAME,
        FUNDING_ID,
        funding_key_0,
        &vec![10_000_000],
        FEE,
        false,
        true,
        None,
    )?;

    wallet.mine(1)?;
    let fund_txid_1 = wallet.fund_address(
        WALLET_NAME,
        FUNDING_ID,
        funding_key_1,
        &vec![10_000_000],
        FEE,
        false,
        true,
        None,
    )?;
    wallet.mine(1)?;

    let funds_utxo_0 = Utxo::new(fund_txid_0, 0, 10_000_000, &funding_key_0);
    let command = IncomingBitVMXApiMessages::SetFundingUtxo(funds_utxo_0).to_string()?;
    channels[0].send(BITVMX_ID, command)?;
    let funds_utxo_1 = Utxo::new(fund_txid_1, 0, 10_000_000, &funding_key_1);
    let command = IncomingBitVMXApiMessages::SetFundingUtxo(funds_utxo_1).to_string()?;
    channels[1].send(BITVMX_ID, command)?;

    let participants = vec![prover_address.clone(), verifier_address.clone()];
    let emulator_channels = vec![
        prover_emulator_channel.unwrap(),
        verifier_emulator_channel.unwrap(),
    ];

    let aggregation_id = Uuid::new_v4();
    let command =
        IncomingBitVMXApiMessages::SetupKey(aggregation_id, participants.clone(), None, 0)
            .to_string()?;
    send_all(&channels, &command)?;

    let msgs = get_all(&channels, &mut instances, false)?;
    let aggregated_pub_key = msgs[0].aggregated_pub_key().unwrap();

    info!("Initializing UTXO for program");

    let spending_condition = vec![
        scripts::check_aggregated_signature(&aggregated_pub_key, SignMode::Aggregate),
        scripts::check_aggregated_signature(&aggregated_pub_key, SignMode::Aggregate),
    ];
    let (utxo, initial_out_type) = init_utxo_new(
        &wallet,
        &aggregated_pub_key,
        spending_condition.clone(),
        20_000,
        None,
    )?;

    info!("Initializing UTXO for the prover action");
    let (prover_win_utxo, prover_win_out_type) = init_utxo_new(
        &wallet,
        &aggregated_pub_key,
        spending_condition.clone(),
        11_000,
        None,
    )?;

    let prog_id = Uuid::new_v4();
    prepare_dispute(
        prog_id,
        participants,
        channels.clone(),
        &aggregated_pub_key,
        utxo,
        initial_out_type,
        prover_win_utxo,
        prover_win_out_type,
        false,
        false,
        ForcedChallenges::No,
        None,
        None,
    )?;
    let _msgs = get_all(&channels, &mut instances, false)?;

    execute_dispute(
        channels,
        &mut instances,
        emulator_channels,
        &bitcoin_client,
        &wallet,
        prog_id,
        false,
        None,
    )?;

    //prover final trace
    // process_dispatcher(&mut dispatchers, &mut instances);
    // let _msgs = mine_and_wait(&bitcoin_client, &channels, &mut instances, &wallet)?;

    //TODO: allow fake and true job dispatcher execution and responses so we can test the whole flow

    info!("Stopping bitcoind");
    if let Some(ref bitcoind_instance) = bitcoind {
        bitcoind_instance.stop()?;
    }

    Ok(())
}

//Test aggregation with three parts
#[cfg(feature = "regtest")]
#[test]
pub fn test_aggregation() -> Result<()> {
    config_trace();

    let (_bitcoin_client, bitcoind, _wallet) = prepare_bitcoin()?;

    let (mut bitvmx_1, addres_1, bridge_1, _) = init_bitvmx("op_1", false)?;
    let (mut bitvmx_2, addres_2, bridge_2, _) = init_bitvmx("op_2", false)?;
    let (mut bitvmx_3, addres_3, bridge_3, _) = init_bitvmx("op_3", false)?;

    let mut instances = vec![&mut bitvmx_1, &mut bitvmx_2, &mut bitvmx_3];

    //ask the peers to generate the aggregated public key
    let aggregation_id = Uuid::new_v4();
    let command = IncomingBitVMXApiMessages::SetupKey(
        aggregation_id,
        vec![addres_1.clone(), addres_2.clone(), addres_3.clone()],
        None,
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

    if let Some(ref bitcoind_instance) = bitcoind {
        bitcoind_instance.stop()?;
    }
    Ok(())
}