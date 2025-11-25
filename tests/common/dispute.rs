#![cfg(test)]
use anyhow::Result;
use bitcoin::PublicKey;
use bitvmx_bitcoin_rpc::bitcoin_client::BitcoinClient;
use bitvmx_broker::channel::channel::DualChannel;
use bitvmx_client::program::protocols::dispute::config::{ConfigResult, ConfigResults};
use bitvmx_client::program::protocols::dispute::{COMMITMENT, POST_COMMITMENT, PRE_COMMITMENT};
use bitvmx_client::{
    bitvmx::BitVMX,
    program::{
        self,
        participant::{CommsAddress, ParticipantRole},
        protocols::dispute::{
            config::DisputeConfiguration, input_tx_name, program_input, timeout_tx, CHALLENGE_READ,
            EXECUTE, TIMELOCK_BLOCKS,
        },
        variables::VariableTypes,
    },
    types::{IncomingBitVMXApiMessages, OutgoingBitVMXApiMessages, ParticipantChannel},
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

use crate::common::{mine_and_wait_blocks, mine_and_wait_with_dispatcher};

use super::{mine_and_wait, send_all, wait_message_from_channel};

#[derive(Clone, Debug)]
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
    Initialized(ParticipantRole),
    Uninitialized(ParticipantRole),
    FutureRead(ParticipantRole),
    WitnessDiv(ParticipantRole),
    // 2nd n-ary search
    ReadValue(ParticipantRole),
    CorrectHash(ParticipantRole),
    // Default
    No,
    Execution,
    // Other
    Personalized(ConfigResults),
}

impl ForcedChallenges {
    pub fn get_role(&self) -> Option<ParticipantRole> {
        use ForcedChallenges::*;
        match self {
            TraceHash(role)
            | TraceHashZero(role)
            | EntryPoint(role)
            | ProgramCounter(role)
            | Input(role)
            | Opcode(role)
            | ReadSection(role)
            | WriteSection(role)
            | ProgramCounterSection(role)
            | Initialized(role)
            | Uninitialized(role)
            | FutureRead(role)
            | WitnessDiv(role)
            | ReadValue(role)
            | CorrectHash(role) => Some(role.clone()),
            No | Execution | Personalized(_) => None,
        }
    }
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
    program_path: Option<String>,
) -> Result<()> {
    let program = format!(
        "{}/{}",
        "../BitVMX-CPU/docker-riscv32/riscv32/build/",
        match fail_force_config {
            ForcedChallenges::Uninitialized(_) => "hello-world-uninitialized.yaml",
            ForcedChallenges::ProgramCounterSection(ParticipantRole::Prover) => "pc_invalid.yaml",
            ForcedChallenges::WriteSection(ParticipantRole::Prover) => "write_invalid.yaml",
            ForcedChallenges::ReadSection(ParticipantRole::Prover) => "read_invalid.yaml",
            ForcedChallenges::WitnessDiv(_) => "audit_09.yaml",
            _ => "hello-world.yaml",
        }
    );
    let program_definition = program_path.unwrap_or(program.to_string());

    let config_results = get_fail_force_config(fail_force_config.clone());

    let test_enabler = OutputType::segwit_key(500, aggregated_pub_key).unwrap();

    let dispute_configuration = DisputeConfiguration::new(
        program_id,
        *aggregated_pub_key,
        (
            (
                initial_utxo.txid,
                initial_utxo.vout,
                Some(initial_utxo.amount),
                Some(initial_output_type),
            ),
            vec![1],
        ),
        vec![(
            (
                prover_win_utxo.txid,
                prover_win_utxo.vout,
                Some(prover_win_utxo.amount),
                Some(prover_win_output_type.clone()),
            ),
            vec![1],
        )],
        vec![test_enabler.clone()],
        vec![(
            (
                prover_win_utxo.txid,
                prover_win_utxo.vout,
                Some(prover_win_utxo.amount),
                Some(prover_win_output_type),
            ),
            vec![1],
        )],
        vec![test_enabler.clone(), test_enabler],
        TIMELOCK_BLOCKS,
        program_definition,
        Some(config_results),
    );

    for msg in dispute_configuration.get_setup_messages(participants, 1)? {
        send_all(&id_channel_pairs, &msg)?;
    }

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
    forced_challenge: ForcedChallenges,
    last_tx_to_dispatch: Option<&str>, // To force timeout
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
        .set_msg(program_id, &program_input(input_pos, None))?;
    let _ = channels[0].send(&id_channel_pairs[0].id, set_input_1)?;

    // send the tx
    let _ = channels[0].send(
        &id_channel_pairs[0].id,
        IncomingBitVMXApiMessages::DispatchTransactionName(program_id, input_tx_name(input_pos))
            .to_string()?,
    );

    let prover_dispatcher = bitvmx_job_dispatcher::DispatcherHandler::<EmulatorJobType>::new(
        emulator_channels[0].clone(),
        instances[0].get_store(),
    )?;
    let verifier_dispatcher = bitvmx_job_dispatcher::DispatcherHandler::<EmulatorJobType>::new(
        emulator_channels[1].clone(),
        instances[1].get_store(),
    )?;

    let mut dispatcher_p = vec![prover_dispatcher];
    let mut dispatcher_v = vec![verifier_dispatcher];

    // VERIFIER DETECTS THE INPUT
    let msgs = mine_and_wait_with_dispatcher(
        &bitcoin_client,
        &channels,
        &mut instances,
        &wallet,
        &mut dispatcher_p,
        false,
    )?;
    let (_uuid, _txid, name) = msgs[1].transaction().unwrap();
    assert_eq!(name.unwrap_or_default(), input_tx_name(input_pos));

    let _ = channels[1].send(
        &id_channel_pairs[1].id,
        IncomingBitVMXApiMessages::GetVar(program_id, program_input(input_pos, None))
            .to_string()?,
    )?;

    let mut mutinstances = instances.iter_mut().collect::<Vec<_>>();

    // Pre-commitment
    wait_msg_channel(PRE_COMMITMENT, &mut mutinstances, channels.clone())?;

    // Commitment
    wait_msg_channel(COMMITMENT, &mut mutinstances, channels.clone())?;

    // Post-commitment
    wait_msg_channel(POST_COMMITMENT, &mut mutinstances, channels.clone())?;

    let msg = wait_message_from_channel(&channels[1], &mut mutinstances, false)?;
    let (_uuid, _name, var_type) = OutgoingBitVMXApiMessages::from_string(&msg.0)?
        .variable()
        .unwrap();
    let input1 = &var_type.input()?;
    info!("Verifier observed Input 1: {:?}", input1);

    // Verifier check execution
    process_dispatcher(&mut dispatcher_v, &mut instances)?;

    dispatcher_p.append(&mut dispatcher_v);
    let mut dispatchers = dispatcher_p;
    let ending_state = match forced_challenge {
        ForcedChallenges::ReadValue(..) | ForcedChallenges::CorrectHash(..) => CHALLENGE_READ,
        _ => EXECUTE,
    };

    loop {
        process_dispatcher(&mut dispatchers, &mut instances)?;
        let msgs = mine_and_wait(&bitcoin_client, &channels, &mut instances, &wallet)?;
        let tx = msgs[0].transaction();
        if tx.is_some() {
            let (_uuid, _txid, name) = tx.unwrap();
            if name.as_ref().unwrap() == ending_state {
                info!("Prover executed the program");
                break;
            }
            if name.as_deref() == last_tx_to_dispatch {
                info!("Stopping dispatch loop");
                break;
            }
            if name.unwrap() == timeout_tx(EXECUTE) {
                info!("Verifier wins by timeout");
                return Ok(());
            }
        }
    }

    if ending_state == EXECUTE && last_tx_to_dispatch.is_none() {
        //process verifier choose challenge
        process_dispatcher(&mut dispatchers, &mut instances)?;
    }

    info!("Wait for TXs");

    //wait for claim start
    let msgs = mine_and_wait_blocks(
        &bitcoin_client,
        &channels,
        &mut instances,
        &wallet,
        30,
        None,
    )?;
    info!(
        "Observed: {:?}",
        style(msgs[0].transaction().unwrap().2).green()
    );
    //success wait
    wallet.mine(10)?;
    let msgs = mine_and_wait_blocks(
        &bitcoin_client,
        &channels,
        &mut instances,
        &wallet,
        30,
        None,
    )?;
    info!(
        "Observed: {:?}",
        style(msgs[0].transaction().unwrap().2).green()
    );
    //action wait
    let msgs = mine_and_wait_blocks(
        &bitcoin_client,
        &channels,
        &mut instances,
        &wallet,
        30,
        None,
    )?;
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

pub fn process_dispatcher_non_blocking(
    dispatchers: &mut Vec<DispatcherHandler<EmulatorJobType>>,
    instances: &mut Vec<BitVMX>,
) -> Result<bool> {
    for dispatcher in dispatchers.iter_mut() {
        if dispatcher.tick()? {
            info!("Dispatcher completed a job");
            return Ok(true);
        }
    }
    for instance in instances.iter_mut() {
        let ret = instance.tick();
        if ret.is_err() {
            error!("Error processing instance: {:?}", ret);
            return Ok(false);
        }
    }
    Ok(false)
}

fn wait_msg_channel(
    name: &str,
    instances: &mut Vec<&mut BitVMX>,
    channels: Vec<DualChannel>,
) -> Result<()> {
    for channel in channels.iter() {
        let msg = wait_message_from_channel(channel, instances, false)?;
        let tx = OutgoingBitVMXApiMessages::from_string(&msg.0)?
            .transaction()
            .unwrap()
            .2
            .unwrap();
        assert_eq!(tx, name);
    }

    Ok(())
}

pub fn get_fail_force_config(fail_force_config: ForcedChallenges) -> ConfigResults {
    //TODO: check all cases after refactor
    match fail_force_config {
        ForcedChallenges::TraceHash(role) => get_config_simple(
            role,
            FailConfiguration::new_fail_hash(100),
            ForceChallenge::TraceHash,
            ForceCondition::ValidInputWrongStepOrHash,
        ),
        ForcedChallenges::TraceHashZero(role) => get_config_simple(
            role,
            FailConfiguration::new_fail_hash(1),
            ForceChallenge::TraceHashZero,
            ForceCondition::ValidInputWrongStepOrHash,
        ),
        ForcedChallenges::EntryPoint(role) => get_config_simple(
            role,
            FailConfiguration::new_fail_pc(0),
            ForceChallenge::EntryPoint,
            ForceCondition::ValidInputWrongStepOrHash,
        ),
        ForcedChallenges::ProgramCounter(role) => get_config_simple(
            role,
            FailConfiguration::new_fail_pc(1),
            ForceChallenge::ProgramCounter,
            ForceCondition::ValidInputWrongStepOrHash,
        ),
        ForcedChallenges::Input(role) => get_config_simple(
            role,
            FailConfiguration::new_fail_reads(FailReads::new(
                None,
                Some(&vec![
                    "1106".to_string(),
                    "0xaa000000".to_string(),
                    "0x11111100".to_string(),
                    "0xaa000000".to_string(),
                    "0xffffffffffffffff".to_string(),
                ]),
            )),
            ForceChallenge::InputData,
            ForceCondition::ValidInputWrongStepOrHash,
        ),
        ForcedChallenges::Opcode(role) => get_config_simple(
            role,
            FailConfiguration::new_fail_opcode(FailOpcode::new(&vec![
                "2".to_string(),
                "0x100073".to_string(),
            ])),
            ForceChallenge::Opcode,
            ForceCondition::ValidInputWrongStepOrHash,
        ),
        ForcedChallenges::ReadSection(role) => {
            let prover_fail = FailConfiguration::new_fail_execute(FailExecute {
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
            });

            let verifier_fail = FailConfiguration::new_fail_reads(FailReads::new(
                None,
                Some(&vec![
                    "1106".to_string(),
                    "0xaa000000".to_string(),
                    "0x11111100".to_string(),
                    "0x00000000".to_string(),
                    "0xffffffffffffffff".to_string(),
                ]),
            ));

            get_config_with_read(
                role,
                prover_fail,
                verifier_fail,
                ForceChallenge::AddressesSections,
                ForceCondition::No,
                ForceCondition::No,
                None,
                ForceChallenge::No,
            )
        }
        ForcedChallenges::WriteSection(role) => {
            let prover_fail = FailConfiguration::new_fail_execute(FailExecute {
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
            });

            let verifier_fail = FailConfiguration::new_fail_write(FailWrite::new(&vec![
                "1106".to_string(),
                "0xaa000000".to_string(),
                "0x11111100".to_string(),
                "0x00000000".to_string(),
            ]));

            get_config_with_read(
                role,
                prover_fail,
                verifier_fail,
                ForceChallenge::AddressesSections,
                ForceCondition::No,
                ForceCondition::ValidInputWrongStepOrHash,
                None,
                ForceChallenge::No,
            )
        }
        ForcedChallenges::ProgramCounterSection(role) => {
            let fail_config = FailConfiguration::new_fail_execute(FailExecute {
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
            });
            get_config_with_read(
                role,
                fail_config.clone(),
                fail_config,
                ForceChallenge::AddressesSections,
                ForceCondition::No,
                ForceCondition::ValidInputWrongStepOrHash,
                None,
                ForceChallenge::No,
            )
        }
        ForcedChallenges::Initialized(role) => {
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
            get_config_simple(
                role,
                FailConfiguration::new_fail_execute(fail_execute),
                ForceChallenge::InitializedData,
                ForceCondition::ValidInputWrongStepOrHash,
            )
        }
        ForcedChallenges::Uninitialized(role) => {
            let fail_config = FailConfiguration::new_fail_reads(FailReads::new(
                None,
                Some(&vec![
                    "9".to_string(),
                    "0xa0001004".to_string(),
                    "0x11111100".to_string(),
                    "0xa0001004".to_string(),
                    "0xffffffffffffffff".to_string(),
                ]),
            ));

            get_config_with_read(
                role,
                fail_config.clone(),
                fail_config,
                ForceChallenge::UninitializedData,
                ForceCondition::Always,
                ForceCondition::ValidInputWrongStepOrHash,
                None,
                ForceChallenge::No,
            )
        }
        ForcedChallenges::FutureRead(role) => {
            let fail_read_args = vec!["1106", "0xf000003c", "0xaa000004", "0xf000003c", "1107"]
                .iter()
                .map(|x| x.to_string())
                .collect::<Vec<String>>();

            let fail_read_1 =
                FailConfiguration::new_fail_reads(FailReads::new(Some(&fail_read_args), None));

            get_config_simple(
                role,
                fail_read_1,
                ForceChallenge::FutureRead,
                ForceCondition::ValidInputWrongStepOrHash,
            )
        }
        ForcedChallenges::CorrectHash(role) => {
            let fail_read_args = vec!["1106", "0xaa000000", "0x11111100", "0xaa000000", "600"]
                .iter()
                .map(|x| x.to_string())
                .collect::<Vec<String>>();

            let fail_read_2 =
                FailConfiguration::new_fail_reads(FailReads::new(None, Some(&fail_read_args)));

            let fail_write_args = vec!["600", "0xaa000000", "0x11111100", "0xaa000000"]
                .iter()
                .map(|x| x.to_string())
                .collect::<Vec<String>>();
            let fail_write = FailConfiguration::new_fail_write(FailWrite::new(&fail_write_args));

            get_config_with_read(
                role,
                fail_read_2.clone(),
                fail_read_2,
                ForceChallenge::ReadValueNArySearch,
                ForceCondition::ValidInputWrongStepOrHash,
                ForceCondition::ValidInputWrongStepOrHash,
                Some(fail_write),
                ForceChallenge::TraceHash,
            )
        }
        ForcedChallenges::ReadValue(role) => {
            let fail_read_args = vec!["1106", "0xaa000000", "0x11111100", "0xaa000000", "600"]
                .iter()
                .map(|x| x.to_string())
                .collect::<Vec<String>>();

            let fail_read_2 =
                FailConfiguration::new_fail_reads(FailReads::new(None, Some(&fail_read_args)));

            get_config_with_read(
                role,
                fail_read_2.clone(),
                fail_read_2,
                ForceChallenge::ReadValueNArySearch,
                ForceCondition::ValidInputWrongStepOrHash,
                ForceCondition::ValidInputWrongStepOrHash,
                None,
                ForceChallenge::ReadValue,
            )
        }
        ForcedChallenges::WitnessDiv(role) => {
            let fail_opcode = FailConfiguration::new_fail_opcode(FailOpcode::new(&vec![
                "2".to_string(),
                "0x100073".to_string(),
            ]));

            get_config_with_read(
                role,
                fail_opcode.clone(),
                fail_opcode,
                ForceChallenge::No,
                ForceCondition::Always,
                ForceCondition::Always,
                None,
                ForceChallenge::No,
            )
        }
        ForcedChallenges::No => ConfigResults::default(),
        // The forced Execution is required for testing because without it, the prover or verifier will not execute directly
        ForcedChallenges::Execution => ConfigResults {
            main: ConfigResult {
                fail_config_prover: None,
                fail_config_verifier: None,
                force_challenge: ForceChallenge::No,
                force_condition: ForceCondition::Always,
            },
            read: ConfigResult::default(),
        },
        ForcedChallenges::Personalized(config) => config,
    }
}

fn get_config_with_read(
    role: ParticipantRole,
    fail_prover: FailConfiguration,
    fail_verifier: FailConfiguration,
    challenge: ForceChallenge,
    cond_prover: ForceCondition,
    cond_verifier: ForceCondition,
    fail_read: Option<FailConfiguration>,
    challenge_read: ForceChallenge,
) -> ConfigResults {
    match role {
        ParticipantRole::Prover => ConfigResults {
            main: ConfigResult {
                fail_config_prover: Some(fail_prover),
                fail_config_verifier: None,
                force_challenge: ForceChallenge::No,
                force_condition: cond_prover,
            },
            read: ConfigResult {
                fail_config_prover: fail_read,
                fail_config_verifier: None,
                force_challenge: ForceChallenge::No,
                force_condition: ForceCondition::No,
            },
        },
        ParticipantRole::Verifier => ConfigResults {
            main: ConfigResult {
                fail_config_prover: None,
                fail_config_verifier: Some(fail_verifier),
                force_challenge: challenge,
                force_condition: cond_verifier,
            },
            read: ConfigResult {
                fail_config_prover: None,
                fail_config_verifier: fail_read,
                force_challenge: challenge_read,
                force_condition: ForceCondition::No,
            },
        },
    }
}

fn get_config_simple(
    role: ParticipantRole,
    fail: FailConfiguration,
    challenge: ForceChallenge,
    cond: ForceCondition,
) -> ConfigResults {
    get_config_with_read(
        role,
        fail.clone(),
        fail,
        challenge,
        cond.clone(),
        cond,
        None,
        ForceChallenge::No,
    )
}
