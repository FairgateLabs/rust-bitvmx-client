#![cfg(test)]
use anyhow::Result;
use bitcoin::PublicKey;
use bitvmx_bitcoin_rpc::bitcoin_client::BitcoinClient;
use bitvmx_broker::channel::channel::DualChannel;
use bitvmx_client::{
    bitvmx::BitVMX,
    program::{
        self,
        participant::{CommsAddress, ParticipantRole},
        protocols::dispute::{
            input_tx_name, program_input, timeout_tx, EXECUTE, TIMELOCK_BLOCKS, TIMELOCK_BLOCKS_KEY,
        },
        variables::VariableTypes,
    },
    types::{
        IncomingBitVMXApiMessages, OutgoingBitVMXApiMessages, ParticipantChannel, PROGRAM_TYPE_DRP,
    },
};
use bitvmx_cpu_definitions::{
    constants::LAST_STEP_INIT,
    memory::{MemoryAccessType, MemoryWitness},
    trace::{ProgramCounter, TraceRWStep, TraceRead, TraceReadPC, TraceStep, TraceWrite},
};
use bitvmx_job_dispatcher::DispatcherHandler;
use bitvmx_job_dispatcher_types::emulator_messages::EmulatorJobType;

use bitvmx_wallet::wallet::{RegtestWallet, Wallet};
use console::style;
use emulator::{
    decision::challenge::{ForceChallenge, ForceCondition},
    executor::utils::{FailConfiguration, FailExecute, FailOpcode, FailReads, FailWrite},
};
use protocol_builder::types::{OutputType, Utxo};
use tracing::{error, info};
use uuid::Uuid;

use crate::common::mine_and_wait_blocks;

use super::{mine_and_wait, send_all, wait_message_from_channel};

pub enum ForcedChallenges {
    TraceHash(ParticipantRole),
    TraceHashZero(ParticipantRole),
    EntryPoint(ParticipantRole),
    ProgramCounter(ParticipantRole),
    Input(ParticipantRole),
    Opcode(ParticipantRole),
    ReadSection(ParticipantRole),
    WriteSection(ParticipantRole),
    ProgramCounterSection(ParticipantRole),
    Rom(ParticipantRole),
    No,
    Execution,
}

pub fn prepare_dispute(
    program_id: Uuid,
    participants: Vec<CommsAddress>,
    id_channel_pairs: Vec<ParticipantChannel>,
    aggregated_pub_key: &PublicKey,
    initial_utxo: Utxo,
    initial_output_type: OutputType,
    prover_win_utxo: Utxo,
    prover_win_output_type: OutputType,
    fail_force_config: ForcedChallenges,
    fail_data: Option<(
        Option<FailConfiguration>,
        Option<FailConfiguration>,
        ForceChallenge,
        ForceCondition,
    )>,
    program_path: Option<String>,
) -> Result<()> {
    let (fail_config_prover, fail_config_verifier, force, force_condition) =
        fail_data.unwrap_or(get_fail_force_config(fail_force_config));

    let set_fail_force_config = VariableTypes::FailConfiguration(
        fail_config_prover,
        fail_config_verifier,
        force,
        force_condition,
    )
    .set_msg(program_id, "fail_force_config")?;
    send_all(&id_channel_pairs, &set_fail_force_config)?;

    let set_aggregated_msg =
        VariableTypes::PubKey(*aggregated_pub_key).set_msg(program_id, "aggregated")?;
    send_all(&id_channel_pairs, &set_aggregated_msg)?;

    let set_utxo_msg = VariableTypes::Utxo((
        initial_utxo.txid,
        initial_utxo.vout,
        Some(initial_utxo.amount),
        Some(initial_output_type),
    ))
    .set_msg(program_id, "utxo")?;
    send_all(&id_channel_pairs, &set_utxo_msg)?;

    let set_prover_win_utxo = VariableTypes::Utxo((
        prover_win_utxo.txid,
        prover_win_utxo.vout,
        Some(prover_win_utxo.amount),
        Some(prover_win_output_type),
    ))
    .set_msg(program_id, "utxo_prover_win_action")?;
    send_all(&id_channel_pairs, &set_prover_win_utxo)?;

    //let program_path = "../BitVMX-CPU/docker-riscv32/verifier/build/zkverifier-new-mul.yaml";
    let hello_world = "../BitVMX-CPU/docker-riscv32/riscv32/build/hello-world.yaml";
    let set_program = VariableTypes::String(program_path.unwrap_or(hello_world.to_string()))
        .set_msg(program_id, "program_definition")?;
    send_all(&id_channel_pairs, &set_program)?;

    let timelock_blocks =
        VariableTypes::Number(TIMELOCK_BLOCKS.into()).set_msg(program_id, TIMELOCK_BLOCKS_KEY)?;
    send_all(&id_channel_pairs, &timelock_blocks)?;

    let setup_msg =
        IncomingBitVMXApiMessages::Setup(program_id, PROGRAM_TYPE_DRP.to_string(), participants, 1)
            .to_string()?;
    send_all(&id_channel_pairs, &setup_msg)?;

    info!("Waiting for setup messages...");

    Ok(())
}

pub fn execute_dispute(
    id_channel_pairs: Vec<ParticipantChannel>,
    mut instances: &mut Vec<BitVMX>,
    emulator_channels: Vec<DualChannel>,
    bitcoin_client: &BitcoinClient,
    wallet: &Wallet,
    program_id: Uuid,
    input: Option<(String, u32)>,
) -> Result<()> {
    let channels = id_channel_pairs
        .iter()
        .map(|pair| pair.channel.clone())
        .collect::<Vec<_>>();
    //CHALLENGERS STARTS CHALLENGE
    let _ = channels[1].send(
        &id_channel_pairs[1].id,
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
    let (data, input_pos) = input.unwrap_or(("11111111".to_string(), 0));
    let set_input_1 = VariableTypes::Input(hex::decode(data).unwrap())
        .set_msg(program_id, &program_input(input_pos))?;
    let _ = channels[0].send(&id_channel_pairs[0].id, set_input_1)?;

    // send the tx
    let _ = channels[0].send(
        &id_channel_pairs[0].id,
        IncomingBitVMXApiMessages::DispatchTransactionName(program_id, input_tx_name(input_pos))
            .to_string()?,
    );

    // VERIFIER DETECTS THE INPUT
    let msgs = mine_and_wait(&bitcoin_client, &channels, &mut instances, &wallet)?;
    let (_uuid, _txid, name) = msgs[1].transaction().unwrap();
    assert_eq!(name.unwrap_or_default(), input_tx_name(input_pos));

    let _ = channels[1].send(
        &id_channel_pairs[1].id,
        IncomingBitVMXApiMessages::GetVar(program_id, program_input(input_pos)).to_string()?,
    )?;

    let mut mutinstances = instances.iter_mut().collect::<Vec<_>>();
    let msg = wait_message_from_channel(&channels[1], &mut mutinstances, false)?;
    let (_uuid, _name, var_type) = OutgoingBitVMXApiMessages::from_string(&msg.0)?
        .variable()
        .unwrap();

    let input1 = &var_type.input()?;
    info!("Verifier observed Input 1: {:?}", input1);

    let prover_dispatcher = bitvmx_job_dispatcher::DispatcherHandler::<EmulatorJobType>::new(
        emulator_channels[0].clone(),
        instances[0].get_store(),
    )?;
    let verifier_dispatcher = bitvmx_job_dispatcher::DispatcherHandler::<EmulatorJobType>::new(
        emulator_channels[1].clone(),
        instances[1].get_store(),
    )?;

    let mut dispatchers = vec![prover_dispatcher, verifier_dispatcher];
    //wait for prover execution
    process_dispatcher(&mut dispatchers, &mut instances)?;
    let _msgs = mine_and_wait(&bitcoin_client, &channels, &mut instances, &wallet)?;

    //wait for verifier execution
    process_dispatcher(&mut dispatchers, &mut instances)?;
    process_dispatcher(&mut dispatchers, &mut instances)?;
    let _msgs = mine_and_wait(&bitcoin_client, &channels, &mut instances, &wallet)?;

    loop {
        process_dispatcher(&mut dispatchers, &mut instances)?;
        let msgs = mine_and_wait(&bitcoin_client, &channels, &mut instances, &wallet)?;
        let tx = msgs[0].transaction();
        if tx.is_some() {
            let (_uuid, _txid, name) = tx.unwrap();
            if name.as_ref().unwrap() == EXECUTE {
                info!("Prover executed the program");
                break;
            }
            if name.unwrap() == timeout_tx(EXECUTE) {
                info!("Verifier wins by timeout");
                return Ok(());
            }
        }
    }

    //process verifier choose challenge
    process_dispatcher(&mut dispatchers, &mut instances)?;

    info!("Wait for TXs");

    //wait for claim start
    let msgs = mine_and_wait_blocks(&bitcoin_client, &channels, &mut instances, &wallet, 30)?;
    info!(
        "Observed: {:?}",
        style(msgs[0].transaction().unwrap().2).green()
    );
    //success wait
    wallet.mine(10)?;
    let msgs = mine_and_wait_blocks(&bitcoin_client, &channels, &mut instances, &wallet, 30)?;
    info!(
        "Observed: {:?}",
        style(msgs[0].transaction().unwrap().2).green()
    );
    //action wait
    let msgs = mine_and_wait_blocks(&bitcoin_client, &channels, &mut instances, &wallet, 30)?;
    info!(
        "Observed: {:?}",
        style(msgs[0].transaction().unwrap().2).green()
    );

    Ok(())
}

pub fn process_dispatcher(
    dispatchers: &mut Vec<DispatcherHandler<EmulatorJobType>>,
    instances: &mut Vec<BitVMX>,
) -> Result<()> {
    info!("Processing dispatcher");
    let mut counter = 0;
    loop {
        counter += 1;
        if counter > 1000 {
            panic!("Dispatcher timeout");
        }

        for dispatcher in dispatchers.iter_mut() {
            if dispatcher.tick()? {
                info!("Dispatcher completed a job");
                return Ok(());
            }
        }
        for instance in instances.iter_mut() {
            let ret = instance.tick();
            if ret.is_err() {
                error!("Error processing instance: {:?}", ret);
                return Ok(());
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

pub fn get_fail_force_config(
    fail_force_config: ForcedChallenges,
) -> (
    Option<FailConfiguration>,
    Option<FailConfiguration>,
    ForceChallenge,
    ForceCondition,
) {
    match fail_force_config {
        ForcedChallenges::TraceHash(ParticipantRole::Prover) => (
            Some(FailConfiguration::new_fail_hash(100)),
            None,
            ForceChallenge::No,
            ForceCondition::ValidInputWrongStepOrHash,
        ),
        ForcedChallenges::TraceHashZero(ParticipantRole::Prover) => (
            Some(FailConfiguration::new_fail_hash(1)),
            None,
            ForceChallenge::No,
            ForceCondition::ValidInputWrongStepOrHash,
        ),
        ForcedChallenges::EntryPoint(ParticipantRole::Prover) => (
            Some(FailConfiguration::new_fail_pc(0)),
            None,
            ForceChallenge::No,
            ForceCondition::ValidInputWrongStepOrHash,
        ),
        ForcedChallenges::ProgramCounter(ParticipantRole::Prover) => (
            Some(FailConfiguration::new_fail_pc(1)),
            None,
            ForceChallenge::No,
            ForceCondition::ValidInputWrongStepOrHash,
        ),
        ForcedChallenges::Input(ParticipantRole::Prover) => (
            Some(FailConfiguration::new_fail_reads(FailReads::new(
                None,
                Some(&vec![
                    "1106".to_string(),
                    "0xaa000000".to_string(),
                    "0x11111100".to_string(),
                    "0xaa000000".to_string(),
                    "0xffffffffffffffff".to_string(),
                ]),
            ))),
            None,
            ForceChallenge::No,
            ForceCondition::ValidInputWrongStepOrHash,
        ),
        ForcedChallenges::Opcode(ParticipantRole::Prover) => (
            Some(FailConfiguration::new_fail_opcode(FailOpcode::new(&vec![
                "2".to_string(),
                "0x100073".to_string(),
            ]))),
            None,
            ForceChallenge::No,
            ForceCondition::ValidInputWrongStepOrHash,
        ),
        ForcedChallenges::ReadSection(ParticipantRole::Prover) => (
            Some(FailConfiguration::new_fail_execute(FailExecute {
                step: 9,
                fake_trace: TraceRWStep::new(
                    9,
                    TraceRead::new(4026531900, 0, 8),
                    // reads from nullptr (address 0)
                    TraceRead::new(0, 0, 0xffffffffffffffff),
                    TraceReadPC::new(ProgramCounter::new(2147483672, 0), 501635),
                    TraceStep::new(
                        TraceWrite::new(4026531900, 0),
                        ProgramCounter::new(2147483676, 0),
                    ),
                    None,
                    MemoryWitness::new(
                        MemoryAccessType::Register,
                        MemoryAccessType::Memory,
                        MemoryAccessType::Register,
                    ),
                ),
            })),
            None,
            ForceChallenge::No,
            ForceCondition::No,
        ),
        ForcedChallenges::WriteSection(ParticipantRole::Prover) => (
            Some(FailConfiguration::new_fail_execute(FailExecute {
                step: 10,
                fake_trace: TraceRWStep::new(
                    10,
                    TraceRead::new(4026531900, 0, 8),
                    TraceRead::new(4026531896, 1234, 9),
                    TraceReadPC::new(ProgramCounter::new(2147483676, 0), 15179811),
                    // writes to nullptr (address 0)
                    TraceStep::new(TraceWrite::new(0, 1234), ProgramCounter::new(2147483680, 0)),
                    None,
                    MemoryWitness::new(
                        MemoryAccessType::Register,
                        MemoryAccessType::Register,
                        MemoryAccessType::Memory,
                    ),
                ),
            })),
            None,
            ForceChallenge::No,
            ForceCondition::No,
        ),
        ForcedChallenges::ProgramCounterSection(ParticipantRole::Prover) => (
            Some(FailConfiguration::new_fail_execute(FailExecute {
                step: 9,
                fake_trace: TraceRWStep::new(
                    9,
                    TraceRead::new(4026531844, 2147483700, 2),
                    TraceRead::default(),
                    // ProgramCounter points to nullptr (address 0)
                    TraceReadPC::new(ProgramCounter::new(0, 0), 32871), // Jalr
                    TraceStep::new(TraceWrite::default(), ProgramCounter::new(2147483700, 0)),
                    None,
                    MemoryWitness::new(
                        MemoryAccessType::Register,
                        MemoryAccessType::Unused,
                        MemoryAccessType::Unused,
                    ),
                ),
            })),
            None,
            ForceChallenge::No,
            ForceCondition::No,
        ),
        ForcedChallenges::Rom(ParticipantRole::Prover) => {
            let fail_execute = FailExecute {
                step: 32,
                fake_trace: TraceRWStep::new(
                    32,
                    TraceRead::new(4026531900, 2952790016, 31),
                    TraceRead::new(2952790016, 0, LAST_STEP_INIT), // read a different value from ROM
                    TraceReadPC::new(ProgramCounter::new(2147483708, 0), 509699),
                    TraceStep::new(
                        TraceWrite::new(4026531896, 0),
                        ProgramCounter::new(2147483712, 0),
                    ),
                    None,
                    MemoryWitness::new(
                        MemoryAccessType::Register,
                        MemoryAccessType::Memory,
                        MemoryAccessType::Register,
                    ),
                ),
            };
            (
                Some(FailConfiguration::new_fail_execute(fail_execute)),
                None,
                ForceChallenge::No,
                ForceCondition::ValidInputWrongStepOrHash,
            )
        }
        ForcedChallenges::TraceHash(ParticipantRole::Verifier) => (
            None,
            Some(FailConfiguration::new_fail_hash(100)),
            ForceChallenge::TraceHash,
            ForceCondition::ValidInputWrongStepOrHash,
        ),
        ForcedChallenges::TraceHashZero(ParticipantRole::Verifier) => (
            None,
            Some(FailConfiguration::new_fail_hash(1)),
            ForceChallenge::TraceHashZero,
            ForceCondition::ValidInputWrongStepOrHash,
        ),
        ForcedChallenges::EntryPoint(ParticipantRole::Verifier) => (
            None,
            Some(FailConfiguration::new_fail_pc(0)),
            ForceChallenge::EntryPoint,
            ForceCondition::ValidInputWrongStepOrHash,
        ),
        ForcedChallenges::ProgramCounter(ParticipantRole::Verifier) => (
            None,
            Some(FailConfiguration::new_fail_pc(1)),
            ForceChallenge::ProgramCounter,
            ForceCondition::ValidInputWrongStepOrHash,
        ),
        ForcedChallenges::Input(ParticipantRole::Verifier) => (
            None,
            Some(FailConfiguration::new_fail_reads(FailReads::new(
                None,
                Some(&vec![
                    "1106".to_string(),
                    "0xaa000000".to_string(),
                    "0x11111100".to_string(),
                    "0xaa000000".to_string(),
                    "0xffffffffffffffff".to_string(),
                ]),
            ))),
            ForceChallenge::InputData,
            ForceCondition::ValidInputWrongStepOrHash,
        ),
        ForcedChallenges::Opcode(ParticipantRole::Verifier) => (
            None,
            Some(FailConfiguration::new_fail_opcode(FailOpcode::new(&vec![
                "2".to_string(),
                "0x100073".to_string(),
            ]))),
            ForceChallenge::Opcode,
            ForceCondition::ValidInputWrongStepOrHash,
        ),
        ForcedChallenges::ReadSection(ParticipantRole::Verifier) => (
            None,
            Some(FailConfiguration::new_fail_reads(FailReads::new(
                None,
                Some(&vec![
                    "1106".to_string(),
                    "0xaa000000".to_string(),
                    "0x11111100".to_string(),
                    "0x00000000".to_string(),
                    "0xffffffffffffffff".to_string(),
                ]),
            ))),
            ForceChallenge::AddressesSections,
            ForceCondition::No,
        ),
        ForcedChallenges::WriteSection(ParticipantRole::Verifier) => (
            None,
            Some(FailConfiguration::new_fail_write(FailWrite::new(&vec![
                "1106".to_string(),
                "0xaa000000".to_string(),
                "0x11111100".to_string(),
                "0x00000000".to_string(),
            ]))),
            ForceChallenge::AddressesSections,
            ForceCondition::ValidInputWrongStepOrHash,
        ),
        ForcedChallenges::ProgramCounterSection(ParticipantRole::Verifier) => (
            None,
            Some(FailConfiguration::new_fail_execute(FailExecute {
                step: 9,
                fake_trace: TraceRWStep::new(
                    9,
                    TraceRead::new(4026531844, 2147483700, 2),
                    TraceRead::default(),
                    // ProgramCounter points to nullptr (address 0)
                    TraceReadPC::new(ProgramCounter::new(0, 0), 32871), // Jalr
                    TraceStep::new(TraceWrite::default(), ProgramCounter::new(2147483700, 0)),
                    None,
                    MemoryWitness::new(
                        MemoryAccessType::Register,
                        MemoryAccessType::Unused,
                        MemoryAccessType::Unused,
                    ),
                ),
            })),
            ForceChallenge::AddressesSections,
            ForceCondition::ValidInputWrongStepOrHash,
        ),
        ForcedChallenges::Rom(ParticipantRole::Verifier) => {
            let fail_execute = FailExecute {
                step: 32,
                fake_trace: TraceRWStep::new(
                    32,
                    TraceRead::new(4026531900, 2952790016, 31),
                    TraceRead::new(2952790016, 0, LAST_STEP_INIT), // read a different value from ROM
                    TraceReadPC::new(ProgramCounter::new(2147483708, 0), 509699),
                    TraceStep::new(
                        TraceWrite::new(4026531896, 0),
                        ProgramCounter::new(2147483712, 0),
                    ),
                    None,
                    MemoryWitness::new(
                        MemoryAccessType::Register,
                        MemoryAccessType::Memory,
                        MemoryAccessType::Register,
                    ),
                ),
            };
            (
                None,
                Some(FailConfiguration::new_fail_execute(fail_execute)),
                ForceChallenge::RomData,
                ForceCondition::ValidInputWrongStepOrHash,
            )
        }

        ForcedChallenges::No => (None, None, ForceChallenge::No, ForceCondition::No),
        ForcedChallenges::Execution => (None, None, ForceChallenge::No, ForceCondition::Allways),
    }
}
