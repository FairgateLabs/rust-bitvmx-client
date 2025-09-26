use bitcoin::Txid;
use bitcoin_coordinator::{coordinator::BitcoinCoordinatorApi, TransactionStatus};
use bitvmx_cpu_definitions::{memory::MemoryWitness, trace::*};
use bitvmx_job_dispatcher::dispatcher_job::DispatcherJob;
use bitvmx_job_dispatcher_types::emulator_messages::EmulatorJobType;
use console::style;
use emulator::decision::challenge::{ForceChallenge, ForceCondition};
use tracing::info;

use crate::{
    bitvmx::Context,
    errors::BitVMXError,
    program::{
        participant::ParticipantRole,
        protocols::{
            claim::ClaimGate,
            dispute::{
                input_handler::{get_txs_configuration, unify_inputs, unify_witnesses},
                DisputeResolutionProtocol, ACTION_PROVER_WINS, CHALLENGE, COMMITMENT, EXECUTE,
                INPUT_TX, PROVER_WINS, TRACE_VARS,
            },
            protocol_handler::ProtocolHandler,
        },
        variables::VariableTypes,
    },
    types::ProgramContext,
};

pub fn handle_tx_news(
    drp: &DisputeResolutionProtocol,
    tx_id: Txid,
    vout: Option<u32>,
    tx_status: TransactionStatus,
    program_context: &ProgramContext,
) -> Result<(), BitVMXError> {
    let name = drp.get_transaction_name_by_id(tx_id)?;
    info!(
        "Program {}: Transaction name: {}  id: {}:{:?} has been seen on-chain {}",
        drp.ctx.id,
        style(&name).blue(),
        style(&tx_id).green(),
        style(&vout).yellow(),
        drp.role()
    );

    let (fail_config_prover, fail_config_verifier, force, force_condition) = program_context
        .globals
        .get_var(&drp.ctx.id, "fail_force_config")?
        .unwrap_or(VariableTypes::FailConfiguration(
            None,
            None,
            ForceChallenge::No,
            ForceCondition::No,
        ))
        .fail_configuration()?;

    if name.starts_with(INPUT_TX) && vout.is_some() {
        let idx = name.strip_prefix(INPUT_TX).unwrap().parse::<u32>()?;

        let (input_txs, _input_txs_sizes, _input_txs_offsets, last_tx_id) =
            get_txs_configuration(&drp.ctx.id, program_context)?;

        let owner = input_txs[idx as usize].as_str();

        if owner == drp.role().to_string() {
            //if I'm the prover and it's the last input
            if drp.role() == ParticipantRole::Prover && idx == last_tx_id {
                let (def, program_definition) = drp.get_program_definition(program_context)?;
                let full_input = unify_inputs(&drp.ctx.id, program_context, &def)?;

                let execution_path = drp.get_execution_path()?;
                let msg = serde_json::to_string(&DispatcherJob {
                    job_id: drp.ctx.id.to_string(),
                    job_type: EmulatorJobType::ProverExecute(
                        program_definition,
                        full_input,
                        execution_path.clone(),
                        format!("{}/{}", execution_path, "execution.json").to_string(),
                        fail_config_prover.clone(),
                    ),
                })?;
                program_context
                    .broker_channel
                    .send(&program_context.components_config.emulator, msg)?;
            }
        } else {
            //if it's not my input, decode the witness
            drp.decode_witness_from_speedup(
                tx_id,
                vout.unwrap(),
                &name,
                program_context,
                &tx_status.tx,
                None,
            )?;

            unify_witnesses(&drp.ctx.id, program_context, idx as usize)?;
        }
    }

    if name == COMMITMENT && drp.role() == ParticipantRole::Verifier && vout.is_some() {
        drp.decode_witness_from_speedup(
            tx_id,
            vout.unwrap(),
            &name,
            program_context,
            &tx_status.tx,
            None,
        )?;

        let execution_path = drp.get_execution_path()?;

        let (def, program_definition) = drp.get_program_definition(program_context)?;
        let input_program = unify_inputs(&drp.ctx.id, program_context, &def)?;

        let last_hash = program_context
            .witness
            .get_witness(&drp.ctx.id, "prover_last_hash")?
            .unwrap()
            .winternitz()?
            .message_bytes();

        let last_step = program_context
            .witness
            .get_witness(&drp.ctx.id, "prover_last_step")?
            .unwrap()
            .winternitz()?
            .message_bytes();
        let last_step = u64::from_be_bytes(last_step.try_into().unwrap());

        let msg = serde_json::to_string(&DispatcherJob {
            job_id: drp.ctx.id.to_string(),
            job_type: EmulatorJobType::VerifierCheckExecution(
                program_definition,
                input_program,
                execution_path.clone(),
                last_step,
                hex::encode(last_hash),
                format!("{}/{}", execution_path, "execution.json").to_string(),
                force_condition,
                fail_config_verifier.clone(),
            ),
        })?;

        program_context
            .broker_channel
            .send(&program_context.components_config.emulator, msg)?;
    }

    if (name == COMMITMENT || name.starts_with("NARY_VERIFIER")) && vout.is_some() {
        let mut round = name
            .strip_prefix("NARY_VERIFIER_")
            .unwrap_or("0")
            .parse::<u32>()
            .unwrap();

        let (program_definition, pdf) = drp.get_program_definition(program_context)?;
        let nary = program_definition.nary_def();

        if drp.role() == ParticipantRole::Prover {
            let decision = if name == COMMITMENT {
                0
            } else {
                drp.decode_witness_from_speedup(
                    tx_id,
                    vout.unwrap(),
                    &name,
                    program_context,
                    &tx_status.tx,
                    None,
                )?;

                let bits = program_context
                    .witness
                    .get_witness(&drp.ctx.id, &format!("selection_bits_{}", round))?
                    .unwrap()
                    .winternitz()?
                    .message_bytes();
                let bits = bits[0];
                bits
            };

            round += 1;

            //TODO: make this value return from execution
            program_context.globals.set_var(
                &drp.ctx.id,
                "current_round",
                VariableTypes::Number(round as u32),
            )?;

            let execution_path = drp.get_execution_path()?;
            if round <= nary.total_rounds() as u32 {
                let msg = serde_json::to_string(&DispatcherJob {
                    job_id: drp.ctx.id.to_string(),
                    job_type: EmulatorJobType::ProverGetHashesForRound(
                        pdf,
                        execution_path.clone(),
                        round as u8,
                        decision as u32,
                        format!("{}/{}", execution_path, "execution.json").to_string(),
                        fail_config_prover.clone(),
                    ),
                })?;
                program_context
                    .broker_channel
                    .send(&program_context.components_config.emulator, msg)?;
            } else {
                let msg = serde_json::to_string(&DispatcherJob {
                    job_id: drp.ctx.id.to_string(),
                    job_type: EmulatorJobType::ProverFinalTrace(
                        pdf,
                        execution_path.clone(),
                        (decision + 1) as u32,
                        format!("{}/{}", execution_path, "execution.json").to_string(),
                        fail_config_prover.clone(),
                    ),
                })?;
                program_context
                    .broker_channel
                    .send(&program_context.components_config.emulator, msg)?;
            }
        } else {
            if round == nary.total_rounds() as u32 {
                info!(
                    "Current block: {}",
                    tx_status.block_info.as_ref().unwrap().height
                );
                /*program_context.bitcoin_coordinator.dispatch(
                    drp.get_signed_tx(program_context, "EXECUTE_TO", 0, 1, true)?,
                    Context::ProgramId(drp.ctx.id).to_string()?,
                    Some(
                        tx_status.block_info.as_ref().unwrap().block_height
                            + TIMELOCK_BLOCKS as u32,
                    ),
                )?;*/
            }
        }
    }

    if (name.starts_with("NARY_PROVER"))
        && drp.role() == ParticipantRole::Verifier
        && vout.is_some()
    {
        drp.decode_witness_from_speedup(
            tx_id,
            vout.unwrap(),
            &name,
            program_context,
            &tx_status.tx,
            None,
        )?;

        let round = name
            .strip_prefix("NARY_PROVER_")
            .unwrap()
            .parse::<u32>()
            .unwrap();

        //TODO: make this value return from execution
        program_context.globals.set_var(
            &drp.ctx.id,
            "current_round",
            VariableTypes::Number(round as u32),
        )?;

        let (program_definition, pdf) = drp.get_program_definition(program_context)?;
        let nary = program_definition.nary_def();
        let hashes_count = nary.hashes_for_round(round as u8);

        let hashes: Vec<String> = (0..hashes_count)
            .map(|h| {
                hex::encode(
                    program_context
                        .witness
                        .get_witness(&drp.ctx.id, &format!("prover_hash_{}_{}", round, h))
                        .unwrap()
                        .unwrap()
                        .winternitz()
                        .unwrap()
                        .message_bytes(),
                )
            })
            .collect();

        let execution_path = drp.get_execution_path()?;
        let msg = serde_json::to_string(&DispatcherJob {
            job_id: drp.ctx.id.to_string(),
            job_type: EmulatorJobType::VerifierChooseSegment(
                pdf,
                execution_path.clone(),
                round as u8,
                hashes,
                format!("{}/{}", execution_path, "execution.json").to_string(),
                fail_config_verifier.clone(),
            ),
        })?;

        if round > 1 {
            program_context
                .broker_channel
                .send(&program_context.components_config.emulator, msg)?;
        } else {
            if let Some(_ready) = program_context
                .globals
                .get_var(&drp.ctx.id, "execution-check-ready")?
            {
                info!("The execution is ready. Sending the choose segment message");
                program_context
                    .broker_channel
                    .send(&program_context.components_config.emulator, msg)?;
            } else {
                info!("The execution is not ready. Saving the message.");
                program_context.globals.set_var(
                    &drp.ctx.id,
                    "choose-segment-msg",
                    VariableTypes::String(msg),
                )?;
            }
        }
    }

    if name == EXECUTE && drp.role() == ParticipantRole::Verifier && vout.is_some() {
        drp.decode_witness_from_speedup(
            tx_id,
            vout.unwrap(),
            &name,
            program_context,
            &tx_status.tx,
            None,
        )?;
        let (_program_definition, pdf) = drp.get_program_definition(program_context)?;
        let execution_path = drp.get_execution_path()?;

        let mut values = std::collections::HashMap::new();

        for (name, _) in TRACE_VARS.iter() {
            if *name == "prover_witness" {
                continue;
            }
            if let Some(value) = program_context.witness.get_witness(&drp.ctx.id, name)? {
                values.insert(*name, value.winternitz().unwrap().message_bytes());
            } else {
                return Err(BitVMXError::VariableNotFound(drp.ctx.id, name.to_string()));
            }
        }
        fn to_u8(bytes: &[u8]) -> u8 {
            u8::from_be_bytes(bytes.try_into().expect("Expected 1 byte for u8"))
        }
        fn to_u32(bytes: &[u8]) -> u32 {
            u32::from_be_bytes(bytes.try_into().expect("Expected 4 bytes for u32"))
        }
        fn to_u64(bytes: &[u8]) -> u64 {
            u64::from_be_bytes(bytes.try_into().expect("Expected 8 bytes for u64"))
        }

        let step_number = to_u64(&values["prover_step_number"]);
        let trace_read1 = TraceRead::new(
            to_u32(&values["prover_read_1_address"]),
            to_u32(&values["prover_read_1_value"]),
            to_u64(&values["prover_read_1_last_step"]),
        );
        let trace_read2 = TraceRead::new(
            to_u32(&values["prover_read_2_address"]),
            to_u32(&values["prover_read_2_value"]),
            to_u64(&values["prover_read_2_last_step"]),
        );
        let program_counter = ProgramCounter::new(
            to_u32(&values["prover_read_pc_address"]),
            to_u8(&values["prover_read_pc_micro"]),
        );
        let read_pc = TraceReadPC::new(program_counter, to_u32(&values["prover_read_pc_opcode"]));
        let trace_write = TraceWrite::new(
            to_u32(&values["prover_write_address"]),
            to_u32(&values["prover_write_value"]),
        );
        let program_counter = ProgramCounter::new(
            to_u32(&values["prover_write_pc"]),
            to_u8(&values["prover_write_micro"]),
        );
        let trace_step = TraceStep::new(trace_write, program_counter);
        let witness = None; //TODO: get the witness from the context?
        let mem_witness = MemoryWitness::from_byte(to_u8(&values["prover_mem_witness"]));

        let final_trace = TraceRWStep::new(
            step_number,
            trace_read1,
            trace_read2,
            read_pc,
            trace_step,
            witness,
            mem_witness,
        );
        let msg = serde_json::to_string(&DispatcherJob {
            job_id: drp.ctx.id.to_string(),
            job_type: EmulatorJobType::VerifierChooseChallenge(
                pdf,
                execution_path.clone(),
                final_trace,
                format!("{}/{}", execution_path, "execution.json").to_string(),
                fail_config_verifier.clone(),
                force,
            ),
        })?;
        program_context
            .broker_channel
            .send(&program_context.components_config.emulator, msg)?;
    }

    if name == EXECUTE && drp.role() == ParticipantRole::Prover && vout.is_some() {
        let tx = drp.get_signed_tx(
            program_context,
            &ClaimGate::tx_start(PROVER_WINS),
            0,
            0,
            false,
            0,
        )?;
        info!("PROVER_WINS_TX: {:?}", tx);
        let speedup_data = drp.get_speedup_data_from_tx(&tx, program_context, None)?;
        program_context.bitcoin_coordinator.dispatch(
            tx,
            Some(speedup_data),
            //prover-win-start is input 1
            Context::ProgramId(drp.ctx.id).to_string()?,
            None,
        )?;
    }

    if name == ClaimGate::tx_start(PROVER_WINS) && drp.role() == ParticipantRole::Prover {
        info!("Prover wins SUCCESS dispatch");
        let timelock_blocks = program_context
            .globals
            .get_var(&drp.ctx.id, "TIMELOCK_BLOCKS")?
            .unwrap()
            .number()?;

        let prover_wins_tx = drp.get_signed_tx(
            program_context,
            &ClaimGate::tx_success(PROVER_WINS),
            0,
            1,
            false,
            0,
        )?;
        let speedup_data = drp.get_speedup_data_from_tx(&prover_wins_tx, program_context, None)?;
        program_context.bitcoin_coordinator.dispatch(
            prover_wins_tx,
            Some(speedup_data),
            Context::ProgramId(drp.ctx.id).to_string()?,
            Some(tx_status.block_info.as_ref().unwrap().height + timelock_blocks),
        )?;
    }

    if name == ClaimGate::tx_success(PROVER_WINS) && drp.role() == ParticipantRole::Prover {
        //Execute actions.
        //Could execute more than one
        info!("Prover. Execute Action");
        let prover_wins_action_tx =
            drp.get_signed_tx(program_context, ACTION_PROVER_WINS, 0, 0, false, 1)?;
        let speedup_data =
            drp.get_speedup_data_from_tx(&prover_wins_action_tx, program_context, None)?;

        program_context.bitcoin_coordinator.dispatch(
            prover_wins_action_tx,
            Some(speedup_data),
            Context::ProgramId(drp.ctx.id).to_string()?,
            None,
        )?;
    }

    if name == CHALLENGE && drp.role() == ParticipantRole::Prover && vout.is_some() {
        drp.decode_witness_from_speedup(
            tx_id,
            vout.unwrap(),
            &name,
            program_context,
            &tx_status.tx,
            None,
        )?;
        //TODO: if the verifier is able to execute the challenge, the prover can react only to the read challenge nary search
    }

    Ok(())
}
