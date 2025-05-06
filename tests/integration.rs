use anyhow::Result;
use bitvmx_client::{
    program::{self, variables::VariableTypes},
    types::{IncomingBitVMXApiMessages, OutgoingBitVMXApiMessages, BITVMX_ID, PROGRAM_TYPE_DRP},
};
use common::{
    config_trace, get_all, init_bitvmx, init_utxo, mine_and_wait, prepare_bitcoin, send_all,
    wait_message_from_channel,
};
use tracing::info;
use uuid::Uuid;

mod common;

//cargo test --release  -- test_single_run --ignored
#[ignore]
#[test]
pub fn test_single_run() -> Result<()> {
    config_trace();

    let (bitcoin_client, bitcoind, wallet) = prepare_bitcoin()?;

    let (prover_bitvmx, prover_address, prover_bridge_channel) = init_bitvmx("op_1")?;

    let (verifier_bitvmx, verifier_address, verifier_bridge_channel) = init_bitvmx("op_2")?;

    let mut instances = vec![prover_bitvmx, verifier_bitvmx];
    let channels = vec![prover_bridge_channel, verifier_bridge_channel];

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
    send_all(&channels, &command)?;

    let msgs = get_all(&channels, &mut instances, false)?;
    let aggregated_pub_key = msgs[0].aggregated_pub_key().unwrap();

    info!("Initializing UTXO for program");
    let utxo = init_utxo(&bitcoin_client, aggregated_pub_key, None, None)?;

    let program_id = Uuid::new_v4();

    let set_aggregated_msg =
        VariableTypes::PubKey(utxo.pub_key).set_msg(program_id, "aggregated")?;
    send_all(&channels, &set_aggregated_msg)?;

    let set_utxo_msg = VariableTypes::Utxo((utxo.txid, utxo.vout, Some(utxo.amount)))
        .set_msg(program_id, "utxo")?;
    send_all(&channels, &set_utxo_msg)?;

    let set_program = VariableTypes::String(
        "../BitVMX-CPU/docker-riscv32/riscv32/build/hello-world.yaml".to_string(),
    )
    .set_msg(program_id, "program_definition")?;
    send_all(&channels, &set_program)?;

    let setup_msg =
        IncomingBitVMXApiMessages::Setup(program_id, PROGRAM_TYPE_DRP.to_string(), participants, 1)
            .to_string()?;
    send_all(&channels, &setup_msg)?;

    info!("Waiting for setup messages...");

    //Wait
    let _msgs = get_all(&channels, &mut instances, false)?;

    //Bridge send signal to send the kickoff message
    let _ = channels[1].send(
        BITVMX_ID,
        IncomingBitVMXApiMessages::DispatchTransactionName(
            program_id,
            program::protocols::dispute::START_CH.to_string(),
        )
        .to_string()?,
    );

    mine_and_wait(&bitcoin_client, &channels, &mut instances, &wallet)?;

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
