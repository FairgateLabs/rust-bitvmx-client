use anyhow::Result;
use bitcoin::{Address, PublicKey};
use bitvmx_bitcoin_rpc::bitcoin_client::{BitcoinClient, BitcoinClientApi};
use bitvmx_broker::channel::channel::DualChannel;
use bitvmx_client::{
    bitvmx::BitVMX,
    program::{
        self, participant::P2PAddress, protocols::dispute::EXECUTE, variables::VariableTypes,
    },
    types::{IncomingBitVMXApiMessages, OutgoingBitVMXApiMessages, BITVMX_ID, PROGRAM_TYPE_DRP},
};
use bitvmx_job_dispatcher::DispatcherHandler;
use bitvmx_job_dispatcher_types::emulator_messages::EmulatorJobType;

use protocol_builder::types::{OutputType, Utxo};
use tracing::info;
use uuid::Uuid;

use crate::common::{get_all, mine_and_wait, send_all, wait_message_from_channel};

pub fn prepare_dispute(
    participants: Vec<P2PAddress>,
    channels: Vec<DualChannel>,
    mut instances: &mut Vec<BitVMX>,
    aggregated_pub_key: &PublicKey,
    initial_utxo: Utxo,
    initial_output_type: OutputType,
    prover_win_utxo: Utxo,
    prover_win_output_type: OutputType,
    fee: u32,
    fake: bool,
) -> Result<Uuid> {
    let program_id = Uuid::new_v4();

    if fake {
        let set_fake = VariableTypes::Number(1).set_msg(program_id, "FAKE_RUN")?;
        send_all(&channels, &set_fake)?;
    }

    let set_fee = VariableTypes::Number(fee).set_msg(program_id, "FEE")?;
    send_all(&channels, &set_fee)?;

    let set_aggregated_msg =
        VariableTypes::PubKey(*aggregated_pub_key).set_msg(program_id, "aggregated")?;
    send_all(&channels, &set_aggregated_msg)?;

    let set_utxo_msg = VariableTypes::Utxo((
        initial_utxo.txid,
        initial_utxo.vout,
        Some(initial_utxo.amount),
        Some(initial_output_type),
    ))
    .set_msg(program_id, "utxo")?;
    send_all(&channels, &set_utxo_msg)?;

    let set_prover_win_utxo = VariableTypes::Utxo((
        prover_win_utxo.txid,
        prover_win_utxo.vout,
        Some(prover_win_utxo.amount),
        Some(prover_win_output_type),
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
    Ok(program_id)
}

pub fn execute_dispute(
    channels: Vec<DualChannel>,
    mut instances: &mut Vec<BitVMX>,
    emulator_channels: Vec<DualChannel>,
    bitcoin_client: &BitcoinClient,
    wallet: &Address,
    program_id: Uuid,
    fake: bool,
) -> Result<()> {
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
    if fake {
        let msgs = mine_and_wait(&bitcoin_client, &channels, &mut instances, &wallet)?;
        info!("Observerd: {:?}", msgs[0].transaction().unwrap().2);
        return Ok(());
    }

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
        emulator_channels[0].clone(),
    );
    let verifier_dispatcher = bitvmx_job_dispatcher::DispatcherHandler::<EmulatorJobType>::new(
        emulator_channels[1].clone(),
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

    Ok(())
}

pub fn process_dispatcher(
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
