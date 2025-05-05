use anyhow::Result;
use bitvmx_bitcoin_rpc::bitcoin_client::BitcoinClientApi;
use bitvmx_client::{
    program::{self, variables::VariableTypes},
    types::{IncomingBitVMXApiMessages, OutgoingBitVMXApiMessages, BITVMX_ID, PROGRAM_TYPE_DRP},
};
use common::{config_trace, init_bitvmx, init_utxo, prepare_bitcoin, wait_message_from_channel};
use tracing::info;
use uuid::Uuid;

mod common;

//cargo test --release  -- test_single_run --ignored
#[ignore]
#[test]
pub fn test_single_run() -> Result<()> {
    config_trace();

    let (bitcoin_client, bitcoind, wallet) = prepare_bitcoin()?;

    let (mut prover_bitvmx, prover_address, prover_bridge_channel) = init_bitvmx("op_1")?;

    let (mut verifier_bitvmx, verifier_address, verifier_bridge_channel) = init_bitvmx("op_2")?;

    let mut instances = vec![&mut prover_bitvmx, &mut verifier_bitvmx];

    //get to the top of the blockchain
    for _ in 0..101 {
        for instance in instances.iter_mut() {
            instance.process_bitcoin_updates()?;
        }
    }

    let participants = vec![prover_address.clone(), verifier_address.clone()];

    //ask the peers to generate the aggregated public key
    let aggregation_id = Uuid::new_v4();
    let command =
        IncomingBitVMXApiMessages::SetupKey(aggregation_id, participants.clone(), 0).to_string()?;
    prover_bridge_channel.send(BITVMX_ID, command.clone())?;
    verifier_bridge_channel.send(BITVMX_ID, command)?;

    let msg = wait_message_from_channel(&prover_bridge_channel, &mut instances, false)?;
    info!("PROVER: Received message from channel: {:?}", msg);
    let msg = wait_message_from_channel(&verifier_bridge_channel, &mut instances, false)?;
    info!("VERIFIER: Received message from channel: {:?}", msg);

    info!("Initializing UTXO for program");
    let msg = OutgoingBitVMXApiMessages::from_string(&msg.0)?;
    let aggregated_pub_key = match msg {
        OutgoingBitVMXApiMessages::AggregatedPubkey(_uuid, aggregated_pub_key) => {
            aggregated_pub_key
        }
        _ => panic!("Expected AggregatedPubkey message"),
    };

    let utxo = init_utxo(&bitcoin_client, aggregated_pub_key, None, None)?;

    let program_id = Uuid::new_v4();

    let set_aggregated_msg = IncomingBitVMXApiMessages::SetVar(
        program_id,
        "aggregated".to_string(),
        VariableTypes::PubKey(utxo.pub_key),
    )
    .to_string()?;
    prover_bridge_channel.send(BITVMX_ID, set_aggregated_msg.clone())?;
    verifier_bridge_channel.send(BITVMX_ID, set_aggregated_msg)?;

    let set_utxo_msg = IncomingBitVMXApiMessages::SetVar(
        program_id,
        "utxo".to_string(),
        VariableTypes::Utxo((utxo.txid, utxo.vout, Some(utxo.amount))),
    )
    .to_string()?;
    prover_bridge_channel.send(BITVMX_ID, set_utxo_msg.clone())?;
    verifier_bridge_channel.send(BITVMX_ID, set_utxo_msg)?;

    let setup_msg =
        IncomingBitVMXApiMessages::Setup(program_id, PROGRAM_TYPE_DRP.to_string(), participants, 1)
            .to_string()?;

    prover_bridge_channel.send(BITVMX_ID, setup_msg.clone())?;
    verifier_bridge_channel.send(BITVMX_ID, setup_msg)?;

    info!("Waiting for setup messages...");

    //Wait
    let msg = wait_message_from_channel(&prover_bridge_channel, &mut instances, false)?;
    info!("PROVER: Received message from channel: {:?}", msg);
    let msg = wait_message_from_channel(&verifier_bridge_channel, &mut instances, false)?;
    info!("VERIFIER: Received message from channel: {:?}", msg);

    //Bridge send signal to send the kickoff message
    let _ = verifier_bridge_channel.send(
        BITVMX_ID,
        IncomingBitVMXApiMessages::DispatchTransactionName(
            program_id,
            program::protocols::dispute::START_CH.to_string(),
        )
        .to_string()?,
    );

    //TODO: main loop
    for i in 0..200 {
        if i % 10 == 0 {
            bitcoin_client.mine_blocks_to_address(1, &wallet).unwrap();
        }

        prover_bitvmx.tick()?;

        // if let Ok(Some((msg, _from))) = prover_bridge_channel.recv() {
        //     info!("PROVER received message: {}", msg);
        // }

        std::thread::sleep(std::time::Duration::from_millis(10));

        // if let Ok(Some((msg, _from))) = verifier_bridge_channel.recv() {
        //     info!("VERIFIER received message: {}", msg);
        // }

        verifier_bitvmx.tick()?;
    }

    info!("Stopping bitcoind");
    bitcoind.stop()?;

    Ok(())
}

//Test aggregation with three parts
#[ignore]
#[test]
pub fn test_aggregation() -> Result<()> {
    config_trace();

    let (_bitcoin_client, bitcoind, _wallet) = prepare_bitcoin()?;

    let (mut bitvmx_1, addres_1, bridge_1) = init_bitvmx("op_1")?;
    let (mut bitvmx_2, addres_2, bridge_2) = init_bitvmx("op_2")?;
    let (mut bitvmx_3, addres_3, bridge_3) = init_bitvmx("op_3")?;

    let mut instances = vec![&mut bitvmx_1, &mut bitvmx_2, &mut bitvmx_3];

    //ask the peers to generate the aggregated public key
    let aggregation_id = Uuid::new_v4();
    let command = IncomingBitVMXApiMessages::SetupKey(
        aggregation_id,
        vec![addres_1.clone(), addres_2.clone(), addres_3.clone()],
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

    bitcoind.stop()?;
    Ok(())
}
