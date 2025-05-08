use anyhow::Result;
use bitvmx_client::{
    program::{self, variables::VariableTypes},
    types::{IncomingBitVMXApiMessages, OutgoingBitVMXApiMessages, BITVMX_ID, PROGRAM_TYPE_DRP},
};
use bitvmx_job_dispatcher_types::emulator_messages::EmulatorJobType;
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

    //WAIT SETUP READY
    let _msgs = get_all(&channels, &mut instances, false)?;

    //CHALLENGERS STARTS CHALLENGE
    let _ = channels[1].send(
        BITVMX_ID,
        IncomingBitVMXApiMessages::DispatchTransactionName(
            program_id,
            program::protocols::dispute::START_CH.to_string(),
        )
        .to_string()?,
    );

    // PROVER OBSERVES THE CHALLENGE
    // AND RESPONDS WITH THE INPUT
    let msgs = mine_and_wait(&bitcoin_client, &channels, &mut instances, &wallet)?;
    let (_uuid, _txid, name) = msgs[0].transaction().unwrap();
    assert_eq!(
        name.unwrap_or_default(),
        program::protocols::dispute::START_CH.to_string()
    );

    // set input value
    let set_input_1 = VariableTypes::Input(hex::decode("11111100").unwrap())
        .set_msg(program_id, "program_input_1")?;
    let _ = channels[0].send(BITVMX_ID, set_input_1)?;

    // send the tx
    let _ = channels[0].send(
        BITVMX_ID,
        IncomingBitVMXApiMessages::DispatchTransactionName(
            program_id,
            program::protocols::dispute::INPUT_1.to_string(),
        )
        .to_string()?,
    );

    // VERIFIER DETECTS THE INPUT
    let msgs = mine_and_wait(&bitcoin_client, &channels, &mut instances, &wallet)?;
    let (_uuid, _txid, name) = msgs[1].transaction().unwrap();
    assert_eq!(
        name.unwrap_or_default(),
        program::protocols::dispute::INPUT_1.to_string()
    );

    let _ = channels[1].send(
        BITVMX_ID,
        IncomingBitVMXApiMessages::GetWitness(program_id, "program_input_1".to_string())
            .to_string()?,
    )?;

    let mut mutinstances = instances.iter_mut().collect::<Vec<_>>();
    let msg = wait_message_from_channel(&channels[1], &mut mutinstances, false)?;
    let (_uuid, _name, witness) = OutgoingBitVMXApiMessages::from_string(&msg.0)?
        .witness()
        .unwrap();

    let input1 = &witness.winternitz().unwrap().message_bytes();
    info!("Verifier observed Input 1: {:?}", input1);

    let mut prover_dispatcher = bitvmx_job_dispatcher::DispatcherHandler::<EmulatorJobType>::new(
        prover_emulator_channel.unwrap(),
    );
    let mut verifier_dispatcher = bitvmx_job_dispatcher::DispatcherHandler::<EmulatorJobType>::new(
        verifier_emulator_channel.unwrap(),
    );

    for _ in 0..10 {
        prover_dispatcher.tick();
        verifier_dispatcher.tick();
        instances[0].tick()?;
        instances[1].tick()?;
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    prover_dispatcher.tick();

    let _msgs = mine_and_wait(&bitcoin_client, &channels, &mut instances, &wallet)?;
    //info!("Msgs: {:?}", msgs);

    //prover_emulator.tic

    //TODO: check for transactions and interact with input, and execution
    //TODO: allow fake and true job dispatcher execution and responses so we can test the whole flow

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

    let (mut bitvmx_1, addres_1, bridge_1, _) = init_bitvmx("op_1", false)?;
    let (mut bitvmx_2, addres_2, bridge_2, _) = init_bitvmx("op_2", false)?;
    let (mut bitvmx_3, addres_3, bridge_3, _) = init_bitvmx("op_3", false)?;

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
