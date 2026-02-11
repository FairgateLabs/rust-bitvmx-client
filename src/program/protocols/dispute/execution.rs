use bitcoin_coordinator::coordinator::BitcoinCoordinatorApi;
use bitcoin_script_riscv::riscv::instruction_mapping::{
    create_verification_script_mapping, get_key_from_opcode,
};
use bitvmx_cpu_definitions::challenge::{
    ChallengeType, EmulatorResultType, ProverFinalTraceType, ProverHashesAndStepType,
};
use emulator::constants::REGISTERS_BASE_ADDRESS;
use tracing::{error, info};
use uuid::Uuid;

use crate::{
    bitvmx::Context,
    errors::BitVMXError,
    program::{
        protocols::{
            dispute::{
                challenge::get_challenge_leaf, input_handler::*, tx_news::dispatch,
                DisputeResolutionProtocol, CHALLENGE, CHALLENGE_READ, COMMITMENT, EXECUTE,
                GET_HASHES_AND_STEP,
            },
            protocol_handler::ProtocolHandler,
        },
        variables::VariableTypes,
    },
    types::ProgramContext,
};

pub fn execution_result(
    id: &Uuid,
    drp: &DisputeResolutionProtocol,
    result: &EmulatorResultType,
    context: &ProgramContext,
) -> Result<(), BitVMXError> {
    match result {
        EmulatorResultType::ProverExecuteResult {
            last_step,
            last_hash,
            halt,
        } => {
            info!("Last step: {:?}", last_step);
            info!("Last hash: {:?}", last_hash);
            info!("halt: {:?}", halt);
            //TODO: chef if it's halt 0 before commiting the transaction
            set_inputs(
                id,
                context,
                vec![
                    ("prover_last_step", *last_step).into(),
                    ("prover_last_hash", last_hash.clone()).into(),
                ],
            )?;

            let (tx, sp) = drp.get_tx_with_speedup_data(context, COMMITMENT, 0, 0, true)?;
            dispatch(context, drp, tx, Some(sp), None)?;
        }
        EmulatorResultType::VerifierCheckExecutionResult { step } => {
            info!("Verifier execution result: Step: {:?}", step);
            context
                .globals
                .set_var(id, "execution-check-ready", VariableTypes::Number(1))?;
            if let Some(msg) = context.globals.get_var(id, "choose-segment-msg")? {
                info!("The msg to choose segment was ready. Sending it");
                context
                    .broker_channel
                    .send(&context.components_config.emulator, msg.string()?)?;
            } else {
                info!("The msg to choose segment was not ready");
            }
        }
        EmulatorResultType::ProverGetHashesForRoundResult { hashes, round } => {
            let save_round = context
                .globals
                .get_var(id, "current_round2")? // 2nd n-ary search
                .unwrap_or(context.globals.get_var_or_err(id, "current_round")?) // 1st n-ary search
                .number()? as u8;

            let is_second_nary_search = context.globals.get_var(id, "current_round2")?.is_some();

            let (nary_prover, prover_hash) = if is_second_nary_search {
                ("NARY2_PROVER", "prover_hash2") // 2nd n-ary search
            } else {
                ("NARY_PROVER", "prover_hash") // 1st n-ary search
            };

            if save_round != *round {
                return Err(BitVMXError::InvalidState(format!(
                    "Saved round {} does not match the expected round {}",
                    save_round, round
                )));
            }
            for (i, h) in hashes.iter().enumerate() {
                set_input_hex(
                    id,
                    context,
                    &format!("{}_{}_{}", prover_hash, round, i + 1),
                    h,
                )?;
            }

            let tx_with_speedup = drp.get_tx_with_speedup_data(
                context,
                &format!("{}_{}", nary_prover, round),
                0,
                0,
                true,
            );

            if is_second_nary_search
                && *round == 2 // second nary search starts at the second round for the prover, since the first hashes are shared with the first nary search
                && matches!(tx_with_speedup, Err(BitVMXError::KeysNotFound(_)))
            {
                error!("Could not start second nary search, this is expected if the verifier didn't select the ReadNAryValue Challenge since we don't have the required signature for verifier_selection_bits2_1 to continue");
                return Ok(());
            }

            let (tx, sp) = tx_with_speedup?;

            info!("Dispatching tx {:?}", tx);

            dispatch(context, drp, tx, Some(sp), None)?;
        }
        EmulatorResultType::VerifierChooseSegmentResult { v_decision, round } => {
            let save_round = context
                .globals
                .get_var(id, "current_round2")? // 2nd n-ary search
                .unwrap_or(context.globals.get_var_or_err(id, "current_round")?) // 1st n-ary search
                .number()? as u8;

            if save_round != *round {
                return Err(BitVMXError::InvalidState(format!(
                    "Saved round {} does not match the expected round {}",
                    save_round, round
                )));
            }

            let (nary_verifier, selection_bits) =
                if context.globals.get_var(id, "current_round2")?.is_some() {
                    ("NARY2_VERIFIER", "verifier_selection_bits2") // 2nd n-ary search
                } else {
                    ("NARY_VERIFIER", "verifier_selection_bits") // 1st n-ary search
                };

            set_input_u8(
                id,
                context,
                &format!("{}_{}", selection_bits, round),
                *v_decision as u8,
            )?;

            let (tx, sp) = drp.get_tx_with_speedup_data(
                context,
                &format!("{}_{}", nary_verifier, round),
                0,
                0,
                true,
            )?;

            dispatch(context, drp, tx, Some(sp), None)?;
        }
        EmulatorResultType::ProverFinalTraceResult { prover_final_trace } => {
            info!("Final trace: {:?}", prover_final_trace);
            if let ProverFinalTraceType::ChallengeStep = prover_final_trace {
                info!("Prover will challenge the selected step");
                let (tx, sp) = drp.get_tx_with_speedup_data(context, EXECUTE, 0, 0, true)?;

                dispatch(context, drp, tx, Some(sp), None)?;
            } else {
                let (trace, resigned_step_hash, resigned_next_hash, conflict_step) =
                    prover_final_trace.as_final_trace_with_hashes_and_step()?;
                let mut inputs: Vec<InputPair> = vec![
                    ("prover_write_address", trace.trace_step.get_write().address).into(),
                    ("prover_write_value", trace.trace_step.get_write().value).into(),
                    ("prover_write_pc", trace.trace_step.get_pc().get_address()).into(),
                    ("prover_write_micro", trace.trace_step.get_pc().get_micro()).into(),
                    ("prover_mem_witness", trace.mem_witness.byte()).into(),
                    ("prover_read_1_address", trace.read_1.address).into(),
                    ("prover_read_1_value", trace.read_1.value).into(),
                    ("prover_read_1_last_step", trace.read_1.last_step).into(),
                    ("prover_read_2_address", trace.read_2.address).into(),
                    ("prover_read_2_value", trace.read_2.value).into(),
                    ("prover_read_2_last_step", trace.read_2.last_step).into(),
                    ("prover_read_pc_address", trace.read_pc.pc.get_address()).into(),
                    ("prover_read_pc_micro", trace.read_pc.pc.get_micro()).into(),
                    ("prover_read_pc_opcode", trace.read_pc.opcode).into(),
                    ("prover_step_number", trace.step_number).into(),
                ];
                if let Some(witness) = trace.witness {
                    inputs.push(("prover_witness", witness).into());
                }
                inputs.extend([
                    ("prover_step_hash_tk", resigned_step_hash.clone()).into(),
                    ("prover_next_hash_tk", resigned_next_hash.clone()).into(),
                    ("prover_conflict_step_tk", conflict_step).into(),
                ]);
                set_inputs(id, context, inputs)?;
                let instruction =
                    get_key_from_opcode(trace.read_pc.opcode, trace.read_pc.pc.get_micro())
                        .ok_or_else(|| {
                            BitVMXError::InstructionNotFound(format!(
                                "{}_{}",
                                trace.read_pc.opcode,
                                trace.read_pc.pc.get_micro()
                            ))
                        })?;
                let mapping = create_verification_script_mapping(REGISTERS_BASE_ADDRESS);
                let mut instruction_names: Vec<_> = mapping.keys().cloned().collect();
                instruction_names.sort();
                let index = instruction_names
                    .iter()
                    .position(|i| i == &instruction)
                    .ok_or_else(|| BitVMXError::InstructionNotFound(instruction.to_string()))?;
                // first index leaf is the challenge_step, we have to skip it
                let (tx, sp) =
                    drp.get_tx_with_speedup_data(context, EXECUTE, 0, (index + 1) as u32, true)?;

                dispatch(context, drp, tx, Some(sp), None)?;
            }
        }
        EmulatorResultType::VerifierChooseChallengeResult { challenge } => {
            info!("Verifier choose challenge result: {:?}", challenge);

            let program_definitions = drp.get_program_definition(context)?;
            let Some(leaf) = get_challenge_leaf(id, context, &program_definitions.0, challenge)?
            else {
                return Ok(());
            };

            // Check if it's the second n-ary search to set next tx name
            let second_nary_search = context
                .globals
                .get_var(id, "second-nary-search-started")?
                .and_then(|v| v.bool().ok())
                .unwrap_or(false);
            if let ChallengeType::ReadValueNArySearch { .. } = challenge {
                context.globals.set_var(
                    id,
                    "second-nary-search-started",
                    VariableTypes::Bool(true),
                )?;
            }
            let name = if second_nary_search {
                CHALLENGE_READ
            } else {
                CHALLENGE
            };

            let (tx, sp) = drp.get_tx_with_speedup_data(context, name, 0, leaf as u32, true)?;
            dispatch(context, drp, tx, Some(sp), None)?;
        }
        EmulatorResultType::ProverGetHashesAndStepResult {
            prover_hashes_and_step,
        } => {
            if let ProverHashesAndStepType::ChallengeStep = prover_hashes_and_step {
                info!("Prover will challenge step of second nary search");
                let (tx, sp) =
                    drp.get_tx_with_speedup_data(context, GET_HASHES_AND_STEP, 0, 0, true)?;

                context.bitcoin_coordinator.dispatch(
                    tx,
                    Some(sp),
                    Context::ProgramId(*id).to_string()?,
                    None,
                    drp.requested_confirmations(context),
                )?;
            } else {
                let (resigned_step_hash, resigned_next_hash, write_step) =
                    prover_hashes_and_step.as_hashes_with_step()?;

                info!(
                    "Prover got hashes and step result: {:?}, {:?}, {:?}",
                    resigned_step_hash, resigned_next_hash, write_step
                );

                set_inputs(
                    id,
                    context,
                    vec![
                        ("prover_step_hash_tk2", resigned_step_hash.clone()).into(),
                        ("prover_next_hash_tk2", resigned_next_hash.clone()).into(),
                        ("prover_write_step_tk2", write_step).into(),
                    ],
                )?;
                let (tx, sp) =
                    drp.get_tx_with_speedup_data(context, GET_HASHES_AND_STEP, 0, 1, true)?;

                dispatch(context, drp, tx, Some(sp), None)?;
            }
        }
    }
    Ok(())
}
