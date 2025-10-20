use bitcoin_coordinator::coordinator::BitcoinCoordinatorApi;
use bitcoin_script_riscv::riscv::instruction_mapping::{
    create_verification_script_mapping, get_key_from_opcode,
};
use bitvmx_cpu_definitions::challenge::{ChallengeType, EmulatorResultType};
use emulator::constants::REGISTERS_BASE_ADDRESS;
use tracing::info;
use uuid::Uuid;

use crate::{
    bitvmx::Context,
    errors::BitVMXError,
    program::{
        protocols::dispute::{
            challenge::get_challenge_leaf, input_handler::*, DisputeResolutionProtocol, CHALLENGE,
            CHALLENGE_READ, COMMITMENT, EXECUTE,
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
            set_input_u64(id, context, "prover_last_step", *last_step)?;

            set_input_hex(id, context, "prover_last_hash", last_hash)?;

            let (tx, sp) = drp.get_tx_with_speedup_data(context, COMMITMENT, 0, 0, true)?;
            context.bitcoin_coordinator.dispatch(
                tx,
                Some(sp),
                Context::ProgramId(*id).to_string()?,
                None,
            )?;
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
                .unwrap_or(context.globals.get_var(id, "current_round")?.unwrap()) // 1st n-ary search
                .number()? as u8;

            let (nary_prover, prover_hash) =
                if context.globals.get_var(id, "current_round2")?.is_some() {
                    ("NARY2_PROVER", "prover_hash2") // 2nd n-ary search
                } else {
                    ("NARY_PROVER", "prover_hash") // 1st n-ary search
                };

            assert_eq!(save_round, *round);
            for (i, h) in hashes.iter().enumerate() {
                set_input_hex(id, context, &format!("{}_{}_{}", prover_hash, round, i), h)?;
            }
            let (tx, sp) = drp.get_tx_with_speedup_data(
                context,
                &format!("{}_{}", nary_prover, round),
                0,
                0,
                true,
            )?;
            info!("Dispatching tx {:?}", tx);
            context.bitcoin_coordinator.dispatch(
                tx,
                Some(sp),
                Context::ProgramId(*id).to_string()?,
                None,
            )?;
        }
        EmulatorResultType::VerifierChooseSegmentResult { v_decision, round } => {
            let save_round = context
                .globals
                .get_var(id, "current_round2")? // 2nd n-ary search
                .unwrap_or(context.globals.get_var(id, "current_round")?.unwrap()) // 1st n-ary search
                .number()? as u8;

            assert_eq!(save_round, *round);

            let (nary_verifier, selection_bits) =
                if context.globals.get_var(id, "current_round2")?.is_some() {
                    ("NARY2_VERIFIER", "selection_bits2") // 2nd n-ary search
                } else {
                    ("NARY_VERIFIER", "selection_bits") // 1st n-ary search
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
            context.bitcoin_coordinator.dispatch(
                tx,
                Some(sp),
                Context::ProgramId(*id).to_string()?,
                None,
            )?;
        }
        EmulatorResultType::ProverFinalTraceResult { final_trace } => {
            info!("Final trace: {:?}", final_trace);

            set_input_u32(
                id,
                context,
                "prover_write_address",
                final_trace.trace_step.get_write().address,
            )?;
            set_input_u32(
                id,
                context,
                "prover_write_value",
                final_trace.trace_step.get_write().value,
            )?;
            set_input_u32(
                id,
                context,
                "prover_write_pc",
                final_trace.trace_step.get_pc().get_address(),
            )?;
            set_input_u8(
                id,
                context,
                "prover_write_micro",
                final_trace.trace_step.get_pc().get_micro(),
            )?;

            set_input_u8(
                id,
                context,
                "prover_mem_witness",
                final_trace.mem_witness.byte(),
            )?;

            set_input_u32(
                id,
                context,
                "prover_read_1_address",
                final_trace.read_1.address,
            )?;
            set_input_u32(id, context, "prover_read_1_value", final_trace.read_1.value)?;
            set_input_u64(
                id,
                context,
                "prover_read_1_last_step",
                final_trace.read_1.last_step,
            )?;
            set_input_u32(
                id,
                context,
                "prover_read_2_address",
                final_trace.read_2.address,
            )?;
            set_input_u32(id, context, "prover_read_2_value", final_trace.read_2.value)?;
            set_input_u64(
                id,
                context,
                "prover_read_2_last_step",
                final_trace.read_2.last_step,
            )?;

            set_input_u32(
                id,
                context,
                "prover_read_pc_address",
                final_trace.read_pc.pc.get_address(),
            )?;
            set_input_u8(
                id,
                context,
                "prover_read_pc_micro",
                final_trace.read_pc.pc.get_micro(),
            )?;
            set_input_u32(
                id,
                context,
                "prover_read_pc_opcode",
                final_trace.read_pc.opcode,
            )?;
            set_input_u64(id, context, "prover_step_number", final_trace.step_number)?;
            if let Some(witness) = final_trace.witness {
                set_input_u32(id, context, "prover_witness", witness)?;
            }

            //ASK: ok?
            // set_input_hex(id, context, "prover_prev_hash_tk", &final_trace.prev_hash)?;
            // set_input_hex(id, context, "prover_step_hash_tk", &final_trace.step_hash_tk)?;
            // set_input_hex(id, context, "prover_next_hash_tk", &final_trace.next_hash_tk)?;
            // set_input_u64(id, context, "prover_write_step_tk", final_trace.write_step_tk)?;
            // set_input_u64(id, context, "prover_conflict_step_tk", final_trace.conflict_step_tk)?;
            // set_input_hex(id, context, "prover_hash_tk", &final_trace.hash_tk)?;

            let instruction = get_key_from_opcode(
                final_trace.read_pc.opcode,
                final_trace.read_pc.pc.get_micro(),
            )
            .ok_or_else(|| {
                BitVMXError::InstructionNotFound(format!(
                    "{}_{}",
                    final_trace.read_pc.opcode,
                    final_trace.read_pc.pc.get_micro()
                ))
            })?;
            let mapping = create_verification_script_mapping(REGISTERS_BASE_ADDRESS);
            let mut instruction_names: Vec<_> = mapping.keys().cloned().collect();
            instruction_names.sort();
            let index = instruction_names
                .iter()
                .position(|i| i == &instruction)
                .ok_or_else(|| BitVMXError::InstructionNotFound(instruction.to_string()))?;

            let (tx, sp) = drp.get_tx_with_speedup_data(context, EXECUTE, 0, index as u32, true)?;

            context.bitcoin_coordinator.dispatch(
                tx,
                Some(sp),
                Context::ProgramId(*id).to_string()?,
                None,
            )?;
        }
        EmulatorResultType::VerifierChooseChallengeResult { challenge } => {
            info!("Verifier choose challenge result: {:?}", challenge);

            let program_definitions = drp.get_program_definition(context)?;
            let leaf = get_challenge_leaf(id, context, &program_definitions.0, challenge)?;
            if leaf.is_none() {
                return Ok(());
            }

            let name = match challenge {
                ChallengeType::ReadValue { .. } | ChallengeType::CorrectHash { .. } => {
                    CHALLENGE_READ
                }
                _ => CHALLENGE,
            };
            let (tx, sp) =
                drp.get_tx_with_speedup_data(context, name, 0, leaf.unwrap() as u32, true)?;
            context.bitcoin_coordinator.dispatch(
                tx,
                Some(sp),
                Context::ProgramId(*id).to_string()?,
                None,
            )?;
        }
    }
    Ok(())
}
