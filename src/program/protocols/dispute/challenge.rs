use std::collections::HashMap;

use bitcoin::{PublicKey, ScriptBuf};
use bitcoin_script_riscv::riscv::challenges::*;
use bitcoin_script_stack::stack::StackTracker;
use bitvmx_cpu_definitions::{
    challenge::{ChallengeType, EquivocationKind},
    constants::CHUNK_SIZE,
};
use emulator::{
    decision::nary_search::NArySearchType, loader::program_definition::ProgramDefinition,
};
use protocol_builder::scripts::{self, ProtocolScript, SignMode};
use tracing::info;
use uuid::Uuid;

use crate::{
    errors::BitVMXError,
    program::{
        participant::{ParticipantKeys, ParticipantRole},
        protocols::dispute::{
            input_handler::{
                generate_input_owner_list, set_input_hex, set_input_u32, set_input_u8,
                ProgramInputType,
            },
            program_input_prev_prefix, program_input_prev_protocol, program_input_word,
            DisputeResolutionProtocol,
        },
        variables::VariableTypes,
    },
    types::ProgramContext,
};

// 1st n-ary search challenges
pub const ENTRY_POINT_CHALLENGE: [(&str, usize); 3] = [
    ("prover_read_pc_address", 4),
    ("prover_read_pc_micro", 1),
    ("prover_conflict_step_tk", 8),
];
pub const PROGRAM_COUNTER_CHALLENGE: [(&str, usize); 8] = [
    ("verifier_prev_hash", 20), //TODO: These could be unsinged
    ("verifier_prev_write_add", 4),
    ("verifier_prev_write_data", 4),
    ("verifier_prev_write_pc", 4),
    ("verifier_prev_write_micro", 1),
    ("prover_read_pc_address", 4),
    ("prover_read_pc_micro", 1),
    ("prover_step_hash_tk", 20),
];
pub const HALT_CHALLENGE: [(&str, usize); 7] = [
    ("prover_last_step", 8),
    ("prover_conflict_step_tk", 8),
    ("prover_read_1_value", 4),
    ("prover_read_2_value", 4),
    ("prover_read_pc_opcode", 4),
    ("prover_next_hash_tk", 20),
    ("prover_last_hash", 20),
];
pub const TRACE_HASH_CHALLENGE: [(&str, usize); 6] = [
    ("prover_step_hash_tk", 20),
    ("prover_write_address", 4),
    ("prover_write_value", 4),
    ("prover_write_pc", 4),
    ("prover_write_micro", 1),
    ("prover_next_hash_tk", 20),
];
pub const TRACE_HASH_ZERO_CHALLENGE: [(&str, usize); 6] = [
    ("prover_write_address", 4),
    ("prover_write_value", 4),
    ("prover_write_pc", 4),
    ("prover_write_micro", 1),
    ("prover_next_hash_tk", 20),
    ("prover_conflict_step_tk", 8),
];
pub const INPUT_CHALLENGE: [(&str, usize); 7] = [
    ("prover_program_input", 4),
    ("prover_read_1_address", 4),
    ("prover_read_1_value", 4),
    ("prover_read_1_last_step", 8),
    ("prover_read_2_address", 4),
    ("prover_read_2_value", 4),
    ("prover_read_2_last_step", 8),
];
pub const OPCODE_CHALLENGE: [(&str, usize); 2] =
    [("prover_read_pc_address", 4), ("prover_read_pc_opcode", 4)];
pub const ADDRESSES_SECTIONS_CHALLENGE: [(&str, usize); 5] = [
    ("prover_read_1_address", 4),
    ("prover_read_2_address", 4),
    ("prover_write_address", 4),
    ("prover_mem_witness", 1),
    ("prover_read_pc_address", 4),
];
pub const ROM_CHALLENGE: [(&str, usize); 6] = [
    ("prover_read_1_address", 4),
    ("prover_read_1_value", 4),
    ("prover_read_1_last_step", 8),
    ("prover_read_2_address", 4),
    ("prover_read_2_value", 4),
    ("prover_read_2_last_step", 8),
];
pub const INITIALIZED_CHALLENGE: [(&str, usize); 7] = [
    ("prover_read_1_address", 4),
    ("prover_read_1_value", 4),
    ("prover_read_1_last_step", 8),
    ("prover_read_2_address", 4),
    ("prover_read_2_value", 4),
    ("prover_read_2_last_step", 8),
    ("verifier_read_selector", 1),
];
pub const UNINITIALIZED_CHALLENGE: [(&str, usize); 7] = [
    ("prover_read_1_address", 4),
    ("prover_read_1_value", 4),
    ("prover_read_1_last_step", 8),
    ("prover_read_2_address", 4),
    ("prover_read_2_value", 4),
    ("prover_read_2_last_step", 8),
    ("verifier_read_selector", 1),
];
pub const FUTURE_READ_CHALLENGE: [(&str, usize); 4] = [
    ("prover_conflict_step_tk", 8),
    ("prover_read_1_last_step", 8),
    ("prover_read_2_last_step", 8),
    ("verifier_read_selector", 1),
];
pub const READ_VALUE_NARY_SEARCH_CHALLENGE: [(&str, usize); 1] =
    [("verifier_selection_bits2_1", 1)];

// 2nd n-ary search challenges
pub const READ_VALUE_CHALLENGE: [(&str, usize); 15] = [
    ("prover_read_1_address", 4),
    ("prover_read_1_value", 4),
    ("prover_read_1_last_step", 8),
    ("prover_read_2_address", 4),
    ("prover_read_2_value", 4),
    ("prover_read_2_last_step", 8),
    ("verifier_read_selector", 1),
    ("prover_step_hash_tk2", 20),
    ("verifier_write_addr", 4),
    ("verifier_write_value", 4),
    ("verifier_write_pc", 4),
    ("verifier_write_micro", 1),
    ("prover_next_hash_tk2", 20),
    ("prover_write_step_tk2", 8),
    ("prover_conflict_step_tk", 8),
];
pub const CORRECT_HASH_CHALLENGE: [(&str, usize); 7] = [
    ("prover_step_hash_tk2", 20),
    ("verifier_hash", 20),
    ("verifier_write_addr", 4),
    ("verifier_write_value", 4),
    ("verifier_write_pc", 4),
    ("verifier_write_micro", 1),
    ("prover_next_hash_tk2", 20),
];
pub const EQUIVOCATION_HASH_CHALLENGE: [(&str, usize); 4] = [
    ("prover_step_hash_tk", 20),
    ("prover_step_hash_tk2", 20),
    ("prover_write_step_tk2", 8),
    ("prover_conflict_step_tk", 8),
];
// All variants of the equivocation–resign challenge, covering both step and next hashes as well as both n-ary searches.
pub const EQUIVOCATION_RESIGN_CHALLENGE: [(&str, usize); 3] = [
    ("prover_step_hash_tk", 20), // This is a placeholder where the specific prover hash key will be inserted later
    ("prover_step_hash_tk", 20), // This will also be replaced with prover_next_hash_tk for some leaves
    ("prover_conflict_step_tk", 8),
];
pub const EQUIVOCATION_RESIGN_CHALLENGE2: [(&str, usize); 3] = [
    ("prover_step_hash_tk2", 20), // This is a placeholder where the specific prover hash key will be inserted later
    ("prover_step_hash_tk2", 20), // This will also be replaced with prover_next_hash_tk2 for some leaves
    ("prover_write_step_tk2", 8),
];

pub const CHALLENGES: [(&str, &'static [(&str, usize)]); 14] = [
    ("entry_point", &ENTRY_POINT_CHALLENGE),
    ("program_counter", &PROGRAM_COUNTER_CHALLENGE),
    ("halt", &HALT_CHALLENGE),
    ("trace_hash", &TRACE_HASH_CHALLENGE),
    ("trace_hash_zero", &TRACE_HASH_ZERO_CHALLENGE),
    ("addresses_sections", &ADDRESSES_SECTIONS_CHALLENGE),
    ("input", &INPUT_CHALLENGE),
    ("opcode", &OPCODE_CHALLENGE),
    ("rom", &ROM_CHALLENGE),
    ("initialized", &INITIALIZED_CHALLENGE),
    ("uninitialized", &UNINITIALIZED_CHALLENGE),
    ("future_read", &FUTURE_READ_CHALLENGE),
    ("read_value_nary_search", &READ_VALUE_NARY_SEARCH_CHALLENGE),
    ("equivocation_resign", &EQUIVOCATION_RESIGN_CHALLENGE),
];

pub const READ_CHALLENGES: [(&str, &'static [(&str, usize)]); 4] = [
    ("read_value", &READ_VALUE_CHALLENGE),
    ("correct_hash", &CORRECT_HASH_CHALLENGE),
    ("equivocation_hash", &EQUIVOCATION_HASH_CHALLENGE),
    ("equivocation_resign2", &EQUIVOCATION_RESIGN_CHALLENGE2),
];

pub fn get_verifier_keys() -> Vec<(String, usize)> {
    let mut keys = Vec::new();
    for (name, size) in CHALLENGES
        .iter()
        .flat_map(|(_, challenge)| challenge.iter())
    {
        if name.starts_with("verifier") {
            keys.push((name.to_string(), *size));
        }
    }
    for (name, size) in READ_CHALLENGES
        .iter()
        .flat_map(|(_, challenge)| challenge.iter())
    {
        if name.starts_with("verifier") {
            keys.push((name.to_string(), *size));
        }
    }
    keys
}

pub fn challenge_scripts(
    id: &Uuid,
    role: ParticipantRole,
    program_definitions: &ProgramDefinition,
    context: &ProgramContext,
    aggregated: &PublicKey,
    sign_mode: SignMode,
    keys: &Vec<ParticipantKeys>,
    nary_search_type: NArySearchType,
) -> Result<Vec<ProtocolScript>, BitVMXError> {
    let program = program_definitions.load_program()?;

    let mut challenge_leaf_script = vec![];

    let mut challenge_current_leaf = 0;

    let nary_def = program_definitions.nary_def();
    let rounds = nary_def.total_rounds();
    let nary = nary_def.nary;
    let nary_last_round = nary_def.nary_last_round;

    match nary_search_type {
        NArySearchType::ConflictStep => {
            for (challenge_name, subnames) in CHALLENGES.iter() {
                let mut subnames: Vec<(&str, usize)> = subnames.to_vec();
                // The verifier to challenge needs this variable from the prover so we add it to every challenge
                // we then drop it in the reverse script
                subnames.push(("prover_continue", 1));

                let total_len = subnames.iter().map(|(_, size)| *size).sum::<usize>() as u32 * 2;

                let (names_and_keys, alternate_reverse) = if *challenge_name == "input" {
                    //for constant inputs we don't need the input var
                    let mut stack = StackTracker::new();
                    let total_len = total_len - INPUT_CHALLENGE[0].1 as u32 * 2;
                    let all = stack.define(total_len, "all");
                    for i in 1..total_len {
                        stack.move_var_sub_n(all, total_len - i - 1);
                    }
                    stack.op_2drop(); // drop prover_continue
                    let reverse_script = stack.get_script();
                    (vec![], Some(reverse_script))
                } else {
                    (
                        subnames
                            .iter()
                            .map(|(var_name, _)| {
                                let idx = if var_name.starts_with("prover") { 0 } else { 1 };
                                let key = keys[idx].get_winternitz(var_name)?;
                                Ok((var_name, key))
                            })
                            .collect::<Result<Vec<_>, BitVMXError>>()?,
                        None,
                    )
                };

                //TODO: This is a workaround to reverse the order of the stack
                let mut stack = StackTracker::new();
                let all = stack.define(total_len, "all");
                for i in 1..total_len {
                    stack.move_var_sub_n(all, total_len - i - 1);
                }
                stack.op_2drop(); // drop prover_continue
                let reverse_script = stack.get_script();

                context.globals.set_var(
                    id,
                    &format!("challenge_leaf_start_{}", challenge_name),
                    VariableTypes::Number(challenge_current_leaf),
                )?;

                match *challenge_name {
                    "opcode" => {
                        let chunks = program.get_code_chunks(CHUNK_SIZE);
                        for opcodes_chunk in chunks.iter() {
                            let mut scripts = vec![reverse_script.clone()];
                            stack = StackTracker::new();
                            opcode_challenge(&mut stack, opcodes_chunk);
                            scripts.push(stack.get_script());
                            let winternitz_check = scripts::verify_winternitz_signatures_aux(
                                aggregated,
                                &names_and_keys,
                                sign_mode,
                                true,
                                Some(scripts),
                            )?;
                            challenge_leaf_script.push(winternitz_check);
                        }
                        challenge_current_leaf += chunks.len() as u32;
                    }
                    "input" => {
                        let base_addr = program
                            .find_section_by_name(&program_definitions.input_section_name)
                            .ok_or_else(|| {
                                BitVMXError::SectionNotFound(
                                    program_definitions.input_section_name.clone(),
                                )
                            })?
                            .start;

                        let (inputs, _) = generate_input_owner_list(&program_definitions)?;
                        let const_names_and_keys = subnames
                            .iter()
                            .skip(1)
                            .map(|(var_name, _)| {
                                let idx = if var_name.starts_with("prover") { 0 } else { 1 };
                                Ok::<_, BitVMXError>((
                                    *var_name,
                                    keys[idx].get_winternitz(var_name)?,
                                ))
                            })
                            .collect::<Result<Vec<_>, _>>()?;

                        for (idx, input) in inputs.iter().enumerate() {
                            match input {
                                ProgramInputType::Verifier(words, offset)
                                | ProgramInputType::Prover(words, offset) => {
                                    for j in *offset..*offset + *words {
                                        let names_and_keys = subnames
                                            .iter()
                                            .map(|(var_name, _)| {
                                                let var_name =
                                                    if *var_name == "prover_program_input" {
                                                        format!("{}_{}", var_name, j)
                                                    } else {
                                                        var_name.to_string()
                                                    };
                                                let idx = if var_name.starts_with("prover") {
                                                    0
                                                } else {
                                                    1
                                                };

                                                Ok::<_, BitVMXError>((
                                                    var_name.clone(),
                                                    keys[idx].get_winternitz(&var_name)?,
                                                ))
                                            })
                                            .collect::<Result<Vec<_>, _>>()?;

                                        let address = base_addr + j * 4;
                                        let mut scripts = vec![reverse_script.clone()];
                                        stack = StackTracker::new();
                                        input_challenge(&mut stack, address);
                                        scripts.push(stack.get_script());
                                        let winternitz_check =
                                            scripts::verify_winternitz_signatures_aux(
                                                aggregated,
                                                &names_and_keys,
                                                sign_mode,
                                                true,
                                                Some(scripts),
                                            )?;
                                        challenge_leaf_script.push(winternitz_check);
                                    }
                                    challenge_current_leaf += *words as u32;
                                }

                                ProgramInputType::ProverPrev(words, offset) => {
                                    let previous_protocol = context
                                        .globals
                                        .get_var_or_err(
                                            id,
                                            &program_input_prev_protocol(idx as u32),
                                        )?
                                        .uuid()?;
                                    let previous_prefix = context
                                        .globals
                                        .get_var_or_err(id, &program_input_prev_prefix(idx as u32))?
                                        .string()?;

                                    for j in 0..*words {
                                        let mut temp_keys = vec![];
                                        let mut names_and_keys = vec![];
                                        let key = format!("{}{}", previous_prefix, j);
                                        info!(
                                            "Getting wots_pubkeys from protocol {} and key: {}",
                                            previous_protocol, key
                                        );
                                        let pubkey = context
                                            .globals
                                            .get_var_or_err(&previous_protocol, &key)?
                                            .wots_pubkey()?;
                                        //we copy the var so the prover is able to decode it when it sees the challenge tx
                                        if role == ParticipantRole::Prover {
                                            context.globals.copy_var(
                                                &previous_protocol,
                                                id,
                                                &key,
                                            )?;
                                        }
                                        temp_keys.push(pubkey.clone());
                                        let temp_key = &temp_keys[temp_keys.len() - 1];
                                        names_and_keys.push((key.as_str(), temp_key));
                                        names_and_keys
                                            .extend_from_slice(const_names_and_keys.as_slice());

                                        let address = base_addr + (j + offset) * 4;
                                        let mut scripts = vec![reverse_script.clone()];
                                        stack = StackTracker::new();
                                        input_challenge(&mut stack, address);
                                        scripts.push(stack.get_script());
                                        let winternitz_check =
                                            scripts::verify_winternitz_signatures_aux(
                                                aggregated,
                                                &names_and_keys,
                                                sign_mode,
                                                true,
                                                Some(scripts),
                                            )?;
                                        challenge_leaf_script.push(winternitz_check);
                                    }
                                    challenge_current_leaf += *words as u32;
                                }
                                ProgramInputType::Const(words, offset) => {
                                    for j in *offset..*offset + *words {
                                        let address = base_addr + j * 4;
                                        let mut scripts = vec![alternate_reverse
                                            .as_ref()
                                            .ok_or_else(|| BitVMXError::ScriptNotFound(*id))?
                                            .clone()];
                                        stack = StackTracker::new();

                                        let key = program_input_word(idx as u32, j);
                                        let value =
                                            context.globals.get_var_or_err(id, &key)?.input()?;

                                        let value =
                                            u32::from_be_bytes(value.as_slice().try_into()?);

                                        rom_challenge(&mut stack, address, value);
                                        scripts.push(stack.get_script());
                                        let winternitz_check =
                                            scripts::verify_winternitz_signatures_aux(
                                                aggregated,
                                                &const_names_and_keys,
                                                sign_mode,
                                                true,
                                                Some(scripts),
                                            )?;
                                        challenge_leaf_script.push(winternitz_check);
                                    }
                                    challenge_current_leaf += *words as u32;
                                }
                            }
                        }
                    }
                    "rom" => {
                        if let Some(rodata) = program.find_section_by_name(".rodata") {
                            let rodata_words = rodata.data.len() as u32;
                            let base_addr = rodata.start;
                            let step = 4; //TODO: make this configurable
                            for i in (0..rodata_words).step_by(step) {
                                let address = base_addr + i;
                                let value = program.read_mem(address, false)?;
                                let mut scripts = vec![reverse_script.clone()];
                                stack = StackTracker::new();
                                rom_challenge(&mut stack, address, value);
                                scripts.push(stack.get_script());
                                let winternitz_check = scripts::verify_winternitz_signatures_aux(
                                    aggregated,
                                    &names_and_keys,
                                    sign_mode,
                                    true,
                                    Some(scripts),
                                )?;
                                challenge_leaf_script.push(winternitz_check);
                            }
                            challenge_current_leaf += rodata_words / step as u32 + 1;
                        }
                    }
                    "initialized" => {
                        let chunks = program.get_initialized_chunks(CHUNK_SIZE);
                        for initialized_chunk in chunks.iter() {
                            let mut scripts = vec![reverse_script.clone()];
                            stack = StackTracker::new();
                            extract_nibble(
                                &mut stack,
                                &mut scripts,
                                "initialized",
                                "verifier_read_selector",
                            )?;
                            stack = StackTracker::new();
                            initialized_challenge(&mut stack, initialized_chunk);

                            scripts.push(stack.get_script());
                            let winternitz_check = scripts::verify_winternitz_signatures_aux(
                                aggregated,
                                &names_and_keys,
                                sign_mode,
                                true,
                                Some(scripts),
                            )?;
                            challenge_leaf_script.push(winternitz_check);
                        }
                        challenge_current_leaf += chunks.len() as u32;
                    }
                    "equivocation_resign" => {
                        for kind in [EquivocationKind::StepHash, EquivocationKind::NextHash] {
                            for round in 1..rounds + 1 {
                                let hashes = program_definitions.nary_def().hashes_for_round(round);
                                for h in 1..hashes + 1 {
                                    let mut scripts = vec![reverse_script.clone()];
                                    stack = StackTracker::new();
                                    equivocation_resign_challenge(
                                        &mut stack,
                                        kind.clone(),
                                        round,
                                        h,
                                        rounds,
                                        nary,
                                        nary_last_round,
                                    );
                                    scripts.push(stack.get_script());

                                    let mut names_and_keys_copy = names_and_keys.clone();
                                    let key_name = format!("prover_hash_{}_{}", round, h);
                                    let key_name_ref: &str = key_name.as_str();
                                    let winternitz_key = keys[0].get_winternitz(&key_name)?;
                                    names_and_keys_copy[0] = (&key_name_ref, winternitz_key);

                                    names_and_keys_copy[1] = if kind == EquivocationKind::StepHash {
                                        (
                                            &"prover_step_hash_tk",
                                            keys[0].get_winternitz("prover_step_hash_tk")?,
                                        )
                                    } else {
                                        (
                                            &"prover_next_hash_tk",
                                            keys[0].get_winternitz("prover_next_hash_tk")?,
                                        )
                                    };
                                    let winternitz_check =
                                        scripts::verify_winternitz_signatures_aux(
                                            aggregated,
                                            &names_and_keys_copy,
                                            sign_mode,
                                            true,
                                            Some(scripts),
                                        )?;
                                    challenge_leaf_script.push(winternitz_check);

                                    challenge_current_leaf += 1;
                                }
                            }
                        }
                    }
                    _ => {
                        challenge_current_leaf += 1;
                        let mut scripts = vec![reverse_script.clone()];
                        stack = StackTracker::new();

                        match *challenge_name {
                            "entry_point" => {
                                let entry_point = program.pc.get_address();
                                entry_point_challenge(&mut stack, entry_point)
                            }
                            "program_counter" => program_counter_challenge(&mut stack),
                            "halt" => halt_challenge(&mut stack),
                            "trace_hash" => trace_hash_challenge(&mut stack),
                            "trace_hash_zero" => trace_hash_zero_challenge(&mut stack),
                            "addresses_sections" => {
                                let read_write_sections = &program.read_write_sections;
                                let read_only_sections = &program.read_only_sections;
                                let register_sections = &program.register_sections;
                                let code_sections = &program.code_sections;

                                addresses_sections_challenge(
                                    &mut stack,
                                    read_write_sections,
                                    read_only_sections,
                                    register_sections,
                                    code_sections,
                                );
                            }
                            "uninitialized" => {
                                extract_nibble(
                                    &mut stack,
                                    &mut scripts,
                                    "uninitialized",
                                    "verifier_read_selector",
                                )?;
                                stack = StackTracker::new();
                                let ranges = program.get_uninitialized_ranges(program_definitions);
                                uninitialized_challenge(&mut stack, &ranges);
                            }
                            "future_read" => {
                                extract_nibble(
                                    &mut stack,
                                    &mut scripts,
                                    "future_read",
                                    "verifier_read_selector",
                                )?;
                                stack = StackTracker::new();
                                future_read_challenge(&mut stack);
                            }
                            "read_value_nary_search" => {
                                let bits = stack.define(2, "bits");
                                // the reverse script was used, but the function that verifies the bits doesn't expect the reverse
                                stack.move_var_sub_n(bits, 0);
                                let bits = nary_def.bits_for_round(1);
                                let verification_script =
                                    DisputeResolutionProtocol::get_validate_selection_bits_script(
                                        (1 << bits) - 1,
                                    );
                                stack.custom(verification_script, 1, false, 0, "");
                            }
                            _ => {
                                return Err(BitVMXError::ChallengeNotFound(
                                    challenge_name.to_string(),
                                ))
                            }
                        };
                        scripts.push(stack.get_script());
                        let winternitz_check = scripts::verify_winternitz_signatures_aux(
                            aggregated,
                            &names_and_keys,
                            sign_mode,
                            true,
                            Some(scripts),
                        )?;

                        challenge_leaf_script.push(winternitz_check);
                    }
                }
            }
        }
        NArySearchType::ReadValueChallenge => {
            for (challenge_name, subnames) in READ_CHALLENGES.iter() {
                let mut subnames: Vec<(&str, usize)> = subnames.to_vec();
                subnames.push(("prover_continue2", 1));

                let total_len = subnames.iter().map(|(_, size)| *size).sum::<usize>() as u32 * 2;

                let names_and_keys = subnames
                    .iter()
                    .map(|(var_name, _)| {
                        let idx = if var_name.starts_with("prover") { 0 } else { 1 };
                        let key = keys[idx].get_winternitz(var_name)?;
                        Ok((var_name, key))
                    })
                    .collect::<Result<Vec<_>, BitVMXError>>()?;

                //TODO: This is a workaround to reverse the order of the stack
                let mut stack = StackTracker::new();
                let all = stack.define(total_len, "all");
                for i in 1..total_len {
                    stack.move_var_sub_n(all, total_len - i - 1);
                }
                stack.op_2drop(); // drop prover_continue2
                let reverse_script = stack.get_script();

                context.globals.set_var(
                    id,
                    &format!("challenge_leaf_start_{}", challenge_name),
                    VariableTypes::Number(challenge_current_leaf),
                )?;

                match *challenge_name {
                    "equivocation_resign2" => {
                        for kind in [EquivocationKind::StepHash, EquivocationKind::NextHash] {
                            for round in 1..rounds + 1 {
                                let hashes = program_definitions.nary_def().hashes_for_round(round);
                                for h in 1..hashes + 1 {
                                    let mut scripts = vec![reverse_script.clone()];
                                    stack = StackTracker::new();
                                    equivocation_resign_challenge(
                                        &mut stack,
                                        kind.clone(),
                                        round,
                                        h,
                                        rounds,
                                        nary,
                                        nary_last_round,
                                    );
                                    scripts.push(stack.get_script());

                                    let mut names_and_keys_copy = names_and_keys.clone();
                                    let key_name = if round == 1 {
                                        format!("prover_hash_{}_{}", round, h) // Hashes from round 1 are the same from the first n-ary search
                                    } else {
                                        format!("prover_hash2_{}_{}", round, h)
                                    };
                                    let key_name_ref: &str = key_name.as_str();
                                    let winternitz_key = keys[0].get_winternitz(&key_name)?;
                                    names_and_keys_copy[0] = (&key_name_ref, winternitz_key);

                                    names_and_keys_copy[1] = if kind == EquivocationKind::StepHash {
                                        (
                                            &"prover_step_hash_tk2",
                                            keys[0].get_winternitz("prover_step_hash_tk2")?,
                                        )
                                    } else {
                                        (
                                            &"prover_next_hash_tk2",
                                            keys[0].get_winternitz("prover_next_hash_tk2")?,
                                        )
                                    };
                                    let winternitz_check =
                                        scripts::verify_winternitz_signatures_aux(
                                            aggregated,
                                            &names_and_keys_copy,
                                            sign_mode,
                                            true,
                                            Some(scripts),
                                        )?;
                                    challenge_leaf_script.push(winternitz_check);

                                    challenge_current_leaf += 1;
                                }
                            }
                        }
                    }
                    _ => {
                        challenge_current_leaf += 1;
                        let mut scripts = vec![reverse_script.clone()];
                        stack = StackTracker::new();
                        match *challenge_name {
                            "read_value" => {
                                extract_nibble(
                                    &mut stack,
                                    &mut scripts,
                                    "read_value",
                                    "verifier_read_selector",
                                )?;
                                stack = StackTracker::new();
                                read_value_challenge(&mut stack);
                            }
                            "correct_hash" => {
                                correct_hash_challenge(&mut stack);
                            }
                            "equivocation_hash" => {
                                equivocation_hash_challenge(&mut stack);
                            }
                            _ => {
                                return Err(BitVMXError::ChallengeNotFound(
                                    challenge_name.to_string(),
                                ))
                            }
                        }
                        scripts.push(stack.get_script());
                        let winternitz_check = scripts::verify_winternitz_signatures_aux(
                            aggregated,
                            &names_and_keys,
                            sign_mode,
                            true,
                            Some(scripts),
                        )?;

                        challenge_leaf_script.push(winternitz_check);
                    }
                }
            }
        }
    }
    Ok(challenge_leaf_script)
}

pub fn get_challenge_leaf(
    id: &Uuid,
    context: &ProgramContext,
    program_definitions: &ProgramDefinition,
    challenge: &ChallengeType,
) -> Result<Option<u32>, BitVMXError> {
    let program = program_definitions.load_program()?;
    let name: &str;
    let mut dynamic_offset: u32 = 0; // For offset inside a specific challenge

    match challenge {
        ChallengeType::EntryPoint {
            prover_read_pc: _,
            real_entry_point: _,
            prover_conflict_step_tk: _,
        } => {
            name = "entry_point";
            info!("Verifier chose {name} challenge");
        }
        ChallengeType::ProgramCounter {
            pre_hash,
            trace,
            prover_step_hash: _,
            prover_pc_read: _,
        } => {
            name = "program_counter";
            info!("Verifier chose {name} challenge");

            set_input_hex(id, context, "verifier_prev_hash", &pre_hash)?;
            set_input_u32(
                id,
                context,
                "verifier_prev_write_add",
                trace.get_write().address,
            )?;
            set_input_u32(
                id,
                context,
                "verifier_prev_write_data",
                trace.get_write().value,
            )?;
            set_input_u32(
                id,
                context,
                "verifier_prev_write_pc",
                trace.get_pc().get_address(),
            )?;
            set_input_u8(
                id,
                context,
                "verifier_prev_write_micro",
                trace.get_pc().get_micro(),
            )?;
        }
        ChallengeType::TraceHash {
            prover_step_hash: _,
            prover_trace: _,
            prover_next_hash: _,
        } => {
            name = "trace_hash";
            info!("Verifier chose {name} challenge");
        }
        ChallengeType::TraceHashZero {
            prover_trace: _,
            prover_next_hash: _,
            prover_conflict_step_tk: _,
        } => {
            name = "trace_hash_zero";
            info!("Verifier chose {name} challenge");
        }
        ChallengeType::InputData {
            prover_read_1: _,
            prover_read_2: _,
            address,
            input_for_address: _,
        } => {
            name = "input";
            info!("Verifier chose {name} challenge");

            let base_addr = program
                .find_section_by_name(&program_definitions.input_section_name)
                .ok_or_else(|| {
                    BitVMXError::SectionNotFound(program_definitions.input_section_name.clone())
                })?
                .start;
            dynamic_offset = (address - base_addr) / 4;
        }
        ChallengeType::Opcode {
            prover_pc_read: _,
            chunk_index,
            chunk: _,
        } => {
            name = "opcode";
            info!("Verifier chose {name} challenge");

            dynamic_offset = *chunk_index;
        }
        ChallengeType::AddressesSections {
            prover_read_1: _,
            prover_read_2: _,
            prover_write: _,
            prover_witness: _,
            prover_pc: _,
            read_write_sections: _,
            read_only_sections: _,
            register_sections: _,
            code_sections: _,
        } => {
            name = "addresses_sections";
            info!("Verifier chose {name} challenge");
        }
        ChallengeType::RomData {
            prover_read_1: _,
            prover_read_2: _,
            address,
            input_for_address: _,
        } => {
            name = "rom";
            info!("Verifier chose {name} challenge");

            let base_addr = program
                .find_section_by_name(".rodata")
                .ok_or_else(|| BitVMXError::SectionNotFound(".rodata".to_string()))?
                .start;
            dynamic_offset = address - base_addr;
        }
        ChallengeType::InitializedData {
            prover_read_1: _,
            prover_read_2: _,
            read_selector,
            chunk_index,
            chunk: _,
        } => {
            name = "initialized";
            info!("Verifier chose {name} challenge");

            set_input_u8(id, context, "verifier_read_selector", *read_selector as u8)?;
            dynamic_offset = *chunk_index;
        }
        ChallengeType::UninitializedData {
            prover_read_1: _,
            prover_read_2: _,
            read_selector,
            sections: _,
        } => {
            name = "uninitialized";
            info!("Verifier chose {name} challenge");

            set_input_u8(id, context, "verifier_read_selector", *read_selector as u8)?;
        }
        ChallengeType::FutureRead {
            prover_read_step_1: _,
            prover_read_step_2: _,
            read_selector,
            prover_conflict_step_tk: _,
        } => {
            name = "future_read";
            info!("Verifier chose {name} challenge");

            set_input_u8(id, context, "verifier_read_selector", *read_selector as u8)?;
        }
        ChallengeType::EquivocationResign {
            prover_true_hash: _,
            prover_wrong_hash: _,
            prover_challenge_step_tk: _,
            kind,
            expected_round,
            expected_index,
            rounds: _,
            nary: _,
            nary_last_round: _,
        } => {
            let second_nary_search = context
                .globals
                .get_var(id, "second-nary-search-started")?
                .and_then(|v| v.bool().ok())
                .unwrap_or(false);
            if second_nary_search {
                name = "equivocation_resign2";
            } else {
                name = "equivocation_resign";
            }
            info!("Verifier chose {name} challenge");

            if let EquivocationKind::NextHash = kind {
                // Adjust for step hashes, which come first
                for round in 1..program_definitions.nary_def().total_rounds() + 1 {
                    let hashes = program_definitions.nary_def().hashes_for_round(round);
                    dynamic_offset += hashes as u32;
                }
            }

            for round in 1..*expected_round {
                let hashes = program_definitions.nary_def().hashes_for_round(round);
                dynamic_offset += hashes as u32;
            }
            dynamic_offset += *expected_index as u32 - 1;
        }
        ChallengeType::Halt {
            prover_last_step: _,
            prover_conflict_step_tk: _,
            prover_trace: _,
            prover_next_hash: _,
            prover_last_hash: _,
        } => {
            name = "halt";
            info!("Verifier chose {name} challenge");
        }
        ChallengeType::ReadValueNArySearch { bits } => {
            name = "read_value_nary_search";
            info!("Verifier chose {name} challenge");

            set_input_u8(
                id,
                context,
                "verifier_selection_bits2_1",
                *bits as u8, // Already checked in CPU
            )?;
        }

        // 2nd N-ary search challenges
        ChallengeType::ReadValue {
            prover_read_1: _,
            prover_read_2: _,
            read_selector,
            prover_hash: _,
            trace,
            prover_next_hash: _,
            prover_write_step_tk: _,
            prover_conflict_step_tk: _,
        } => {
            name = "read_value";
            info!("Verifier chose {name} challenge");

            set_input_u8(id, context, "verifier_read_selector", *read_selector as u8)?;
            set_input_u32(
                id,
                context,
                "verifier_write_addr",
                trace.get_write().address,
            )?;
            set_input_u32(id, context, "verifier_write_value", trace.get_write().value)?;
            set_input_u32(
                id,
                context,
                "verifier_write_pc",
                trace.get_pc().get_address(),
            )?;
            set_input_u8(
                id,
                context,
                "verifier_write_micro",
                trace.get_pc().get_micro(),
            )?;
        }
        ChallengeType::CorrectHash {
            prover_step_hash: _,
            verifier_hash,
            trace,
            prover_next_hash: _,
        } => {
            name = "correct_hash";
            info!("Verifier chose {name} challenge");
            set_input_hex(id, context, "verifier_hash", &verifier_hash)?;
            set_input_u32(
                id,
                context,
                "verifier_write_addr",
                trace.get_write().address,
            )?;
            set_input_u32(id, context, "verifier_write_value", trace.get_write().value)?;
            set_input_u32(
                id,
                context,
                "verifier_write_pc",
                trace.get_pc().get_address(),
            )?;
            set_input_u8(
                id,
                context,
                "verifier_write_micro",
                trace.get_pc().get_micro(),
            )?;
        }
        ChallengeType::EquivocationHash {
            prover_step_hash1: _,
            prover_step_hash2: _,
            prover_write_step_tk: _,
            prover_conflict_step_tk: _,
        } => {
            name = "equivocation_hash";
            info!("Verifier chose {name} challenge");
        }
        ChallengeType::No => {
            name = "";
        }
    }

    if name.is_empty() {
        info!("Verifier chose no challenge");
        return Ok(None);
    }

    let leaf_start_var = format!("challenge_leaf_start_{}", name);
    let leaf_start = context
        .globals
        .get_var_or_err(id, &leaf_start_var)?
        .number()? as u32;

    info!(
        "Leaf start: {}, leaf offset: {}",
        leaf_start, dynamic_offset
    );
    Ok(Some(leaf_start + dynamic_offset))
}

pub fn extract_nibble(
    stack: &mut StackTracker,
    scripts: &mut Vec<ScriptBuf>,
    challenge_type: &str,
    var_name: &str,
) -> Result<(), BitVMXError> {
    let challenge = CHALLENGES
        .iter()
        .chain(READ_CHALLENGES.iter())
        .find(|(name, _)| *name == challenge_type)
        .map(|(_, vars)| *vars)
        .ok_or_else(|| BitVMXError::ChallengeNotFound(challenge_type.to_string()))?;
    let mut stackvars = HashMap::new();
    for (name, size) in challenge.iter() {
        stackvars.insert(*name, stack.define((size * 2) as u32, name));
    }
    let read_selector = stack.move_var_sub_n(stackvars[var_name], 0);
    stack.drop(read_selector);
    scripts.push(stack.get_script());
    Ok(())
}
