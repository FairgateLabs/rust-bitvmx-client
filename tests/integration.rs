use anyhow::Result;
use bitvmx_bitcoin_rpc::bitcoin_client::BitcoinClientApi;
use bitvmx_client::{
    bitvmx::BitVMX,
    program::{self, protocols::dispute::EXECUTE, variables::VariableTypes},
    types::{IncomingBitVMXApiMessages, OutgoingBitVMXApiMessages, BITVMX_ID, PROGRAM_TYPE_DRP},
};
use bitvmx_job_dispatcher::DispatcherHandler;
use bitvmx_job_dispatcher_types::emulator_messages::EmulatorJobType;
use common::{
    config_trace, get_all, init_bitvmx, init_utxo, mine_and_wait, prepare_bitcoin, send_all,
    wait_message_from_channel,
};
use tracing::info;
use uuid::Uuid;

mod common;

//cargo test --release  -- test_drp --ignored
#[ignore]
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

    let participants = vec![prover_address.clone(), verifier_address.clone()];

    //ask the peers to generate the aggregated public key
    let aggregation_id = Uuid::new_v4();
    let command =
        IncomingBitVMXApiMessages::SetupKey(aggregation_id, participants.clone(), 0).to_string()?;
    send_all(&channels, &command)?;

    let msgs = get_all(&channels, &mut instances, false)?;
    let aggregated_pub_key = msgs[0].aggregated_pub_key().unwrap();

    info!("Initializing UTXO for program");
    let utxo = init_utxo(&bitcoin_client, aggregated_pub_key, None, Some(200_000))?;

    info!("Initializing UTXO for the prover action");
    let prover_win_utxo = init_utxo(&bitcoin_client, aggregated_pub_key, None, Some(11_000))?;

    let program_id = Uuid::new_v4();
    let set_fee = VariableTypes::Number(10_000).set_msg(program_id, "FEE")?;
    send_all(&channels, &set_fee)?;

    let set_aggregated_msg =
        VariableTypes::PubKey(utxo.pub_key).set_msg(program_id, "aggregated")?;
    send_all(&channels, &set_aggregated_msg)?;

    let set_utxo_msg = VariableTypes::Utxo((utxo.txid, utxo.vout, Some(utxo.amount)))
        .set_msg(program_id, "utxo")?;
    send_all(&channels, &set_utxo_msg)?;

    let set_prover_win_utxo = VariableTypes::Utxo((
        prover_win_utxo.txid,
        prover_win_utxo.vout,
        Some(prover_win_utxo.amount),
    ))
    .set_msg(program_id, "utxo_prover_win_action")?;
    send_all(&channels, &set_prover_win_utxo)?;

    //let program_path = "../BitVMX-CPU/docker-riscv32/verifier/build/zkverifier-new-mul.yaml";
    let program_path = "../BitVMX-CPU/docker-riscv32/riscv32/build/hello-world.yaml";
    let set_program = VariableTypes::String(program_path.to_string())
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
    //let data = "010000007bd5d42e4057965ff389683ef2304190d5e902f10190dba2887d46cccdd3389de95b00b98b086eb81f86988b252c704455eadff8f52710189e9c7d6c29b02a1ce355dcc4b00d84572a8a3414d40ecc209e5cea4e34b119b84e7455877726d3185c2847d1f4bcae30a0cd1b2da4bb3b85fa59b41dee6d9fea0258ced1e9a17c93";
    let data = "11111111";
    let set_input_1 =
        VariableTypes::Input(hex::decode(data).unwrap()).set_msg(program_id, "program_input")?;
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
        IncomingBitVMXApiMessages::GetWitness(program_id, "program_input_0".to_string())
            .to_string()?,
    )?;

    let mut mutinstances = instances.iter_mut().collect::<Vec<_>>();
    let msg = wait_message_from_channel(&channels[1], &mut mutinstances, false)?;
    let (_uuid, _name, witness) = OutgoingBitVMXApiMessages::from_string(&msg.0)?
        .witness()
        .unwrap();

    let input1 = &witness.winternitz().unwrap().message_bytes();
    info!("Verifier observed Input 1: {:?}", input1);

    let prover_dispatcher = bitvmx_job_dispatcher::DispatcherHandler::<EmulatorJobType>::new(
        prover_emulator_channel.unwrap(),
    );
    let verifier_dispatcher = bitvmx_job_dispatcher::DispatcherHandler::<EmulatorJobType>::new(
        verifier_emulator_channel.unwrap(),
    );

    let mut dispatchers = vec![prover_dispatcher, verifier_dispatcher];

    //wait for prover execution
    process_dispatcher(&mut dispatchers, &mut instances);
    let _msgs = mine_and_wait(&bitcoin_client, &channels, &mut instances, &wallet)?;

    //wait for verifier execution
    process_dispatcher(&mut dispatchers, &mut instances);
    process_dispatcher(&mut dispatchers, &mut instances);
    let _msgs = mine_and_wait(&bitcoin_client, &channels, &mut instances, &wallet)?;

    loop {
        process_dispatcher(&mut dispatchers, &mut instances);
        let msgs = mine_and_wait(&bitcoin_client, &channels, &mut instances, &wallet)?;
        let tx = msgs[0].transaction();
        if tx.is_some() {
            let (_uuid, _txid, name) = tx.unwrap();
            if name.as_ref().unwrap() == EXECUTE {
                info!("Prover executed the program");
                break;
            }
            if name.unwrap() == "EXECUTE_TO" {
                info!("Verifier wins by timeout");
                break;
            }
        }
    }

    //wait for claim start
    let msgs = mine_and_wait(&bitcoin_client, &channels, &mut instances, &wallet)?;
    info!("Observerd: {:?}", msgs[0].transaction().unwrap().2);
    //success wait
    bitcoin_client.mine_blocks_to_address(10, &wallet).unwrap();
    let msgs = mine_and_wait(&bitcoin_client, &channels, &mut instances, &wallet)?;
    info!("Observerd: {:?}", msgs[0].transaction().unwrap().2);
    //action wait
    let msgs = mine_and_wait(&bitcoin_client, &channels, &mut instances, &wallet)?;
    info!("Observerd: {:?}", msgs[0].transaction().unwrap().2);

    //prover final trace
    //process_dispatcher(&mut dispatchers, &mut instances);
    //let _msgs = mine_and_wait(&bitcoin_client, &channels, &mut instances, &wallet)?;

    //TODO: allow fake and true job dispatcher execution and responses so we can test the whole flow

    info!("Stopping bitcoind");
    bitcoind.stop()?;

    Ok(())
}

fn process_dispatcher(
    dispatchers: &mut Vec<DispatcherHandler<EmulatorJobType>>,
    instances: &mut Vec<BitVMX>,
) {
    info!("Processing dispatcher");
    let mut counter = 0;
    loop {
        counter += 1;
        if counter > 1000 {
            panic!("Dispatcher timeout");
        }

        for dispatcher in dispatchers.iter_mut() {
            if dispatcher.tick() {
                info!("Dispatcher completed a job");
                return;
            }
        }
        for instance in instances.iter_mut() {
            instance.tick().unwrap();
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
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
