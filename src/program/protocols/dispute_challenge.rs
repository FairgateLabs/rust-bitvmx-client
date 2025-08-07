use bitcoin::PublicKey;
use bitcoin_script_riscv::riscv::challenges::*;
use bitcoin_script_stack::stack::StackTracker;
use bitvmx_cpu_definitions::{challenge::ChallengeType, constants::CODE_CHUNK_SIZE};
use emulator::loader::program_definition::ProgramDefinition;
use protocol_builder::scripts::{self, ProtocolScript, SignMode};
use tracing::info;
use uuid::Uuid;

use crate::{
    errors::BitVMXError,
    program::{
        participant::{ParticipantKeys, ParticipantRole},
        protocols::{
            dispute::{program_input_prev_prefix, program_input_prev_protocol, program_input_word},
            dispute_input_handler::{
                generate_input_owner_list, set_input_hex, set_input_u32, set_input_u8,
                ProgramInputType,
            },
        },
        variables::VariableTypes,
    },
    types::ProgramContext,
};

pub const ENTRY_POINT_CHALLENGE: [(&str, usize); 3] = [
    ("prover_read_pc_address", 4),
    ("prover_read_pc_micro", 1),
    ("prover_step_number", 8),
];
pub const PROGRAM_COUNTER_CHALLENGE: [(&str, usize); 8] = [
    ("verifier_prev_prev_hash", 20), //TODO: These could be unsinged
    ("verifier_prev_write_add", 4),
    ("verifier_prev_write_data", 4),
    ("verifier_prev_write_pc", 4),
    ("verifier_prev_write_micro", 1),
    ("prover_read_pc_address", 4),
    ("prover_read_pc_micro", 1),
    ("verifier_prev_hash", 20), //TODO: Fix, this hash is from prover translation keys
];
pub const HALT_CHALLENGE: [(&str, usize); 5] = [
    ("prover_last_step", 8),
    ("prover_step_number", 8),
    ("prover_read_1_value", 4),
    ("prover_read_2_value", 4),
    ("prover_read_pc_opcode", 4),
];
pub const TRACE_HASH_CHALLENGE: [(&str, usize); 6] = [
    ("verifier_prev_hash", 20), //TODO: this should be from prover translation keys
    ("prover_write_address", 4),
    ("prover_write_value", 4),
    ("prover_write_pc", 4),
    ("prover_write_micro", 1),
    ("prover_last_hash", 20),
];
pub const TRACE_HASH_ZERO_CHALLENGE: [(&str, usize); 5] = [
    ("prover_write_address", 4),
    ("prover_write_value", 4),
    ("prover_write_pc", 4),
    ("prover_write_micro", 1),
    ("verifier_step_hash", 20), //TODO: this should be from prover translation keys
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

pub const CHALLENGES: [(&str, &'static [(&str, usize)]); 9] = [
    ("entry_point", &ENTRY_POINT_CHALLENGE),
    ("program_counter", &PROGRAM_COUNTER_CHALLENGE),
    ("halt", &HALT_CHALLENGE),
    ("trace_hash", &TRACE_HASH_CHALLENGE),
    ("trace_hash_zero", &TRACE_HASH_ZERO_CHALLENGE),
    ("addresses_sections", &ADDRESSES_SECTIONS_CHALLENGE),
    ("input", &INPUT_CHALLENGE),
    ("opcode", &OPCODE_CHALLENGE),
    ("rom", &ROM_CHALLENGE),
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
) -> Result<Vec<ProtocolScript>, BitVMXError> {
    let mut program = program_definitions.load_program()?;

    let mut challenge_leaf_script = vec![];

    let mut challenge_current_leaf = 0;

    for (challenge_name, subnames) in CHALLENGES.iter() {
        let total_len = subnames.iter().map(|(_, size)| *size).sum::<usize>() as u32 * 2;

        let (names_and_keys, alternate_reverse) = if *challenge_name == "input" {
            //for constant inputs we don't need the input var
            let mut stack = StackTracker::new();
            let total_len = total_len - INPUT_CHALLENGE[0].1 as u32 * 2;
            let all = stack.define(total_len, "all");
            for i in 1..total_len {
                stack.move_var_sub_n(all, total_len - i - 1);
            }
            let reverse_script = stack.get_script();
            (vec![], Some(reverse_script))
        } else {
            (
                subnames
                    .iter()
                    .map(|(var_name, _)| {
                        let idx = if var_name.starts_with("prover") { 0 } else { 1 };
                        (var_name, keys[idx].get_winternitz(var_name).unwrap())
                    })
                    .collect::<Vec<_>>(),
                None,
            )
        };

        //TODO: This is a workaround to reverse the order of the stack
        let mut stack = StackTracker::new();
        let all = stack.define(total_len, "all");
        for i in 1..total_len {
            stack.move_var_sub_n(all, total_len - i - 1);
        }
        let reverse_script = stack.get_script();

        context.globals.set_var(
            id,
            &format!("challenge_leaf_start_{}", challenge_name),
            VariableTypes::Number(challenge_current_leaf),
        )?;

        match *challenge_name {
            "opcode" => {
                let chunks = program.get_chunks(CODE_CHUNK_SIZE);
                for (chunk_base, opcodes_chunk) in chunks.iter() {
                    let mut scripts = vec![reverse_script.clone()];
                    stack = StackTracker::new();
                    opcode_challenge(&mut stack, *chunk_base, &opcodes_chunk);
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
                    .unwrap()
                    .start;

                let (inputs, _) = generate_input_owner_list(&program_definitions)?;
                let const_names_and_keys = subnames
                    .iter()
                    .skip(1)
                    .map(|(var_name, _)| {
                        let idx = if var_name.starts_with("prover") { 0 } else { 1 };
                        (*var_name, keys[idx].get_winternitz(&var_name).unwrap())
                    })
                    .collect::<Vec<_>>();

                for (idx, input) in inputs.iter().enumerate() {
                    match input {
                        //ProgramInputType::Verifier(words, offset)
                        ProgramInputType::Prover(words, offset) => {
                            for j in *offset..*offset + *words {
                                let names_and_keys = subnames
                                    .iter()
                                    .map(|(var_name, _)| {
                                        let var_name = if *var_name == "prover_program_input" {
                                            format!("{}_{}", var_name, j)
                                        } else {
                                            var_name.to_string()
                                        };
                                        let idx =
                                            if var_name.starts_with("prover") { 0 } else { 1 };
                                        (
                                            var_name.clone(),
                                            keys[idx].get_winternitz(&var_name).unwrap(),
                                        )
                                    })
                                    .collect::<Vec<_>>();

                                let address = base_addr + j * 4;
                                let mut scripts = vec![reverse_script.clone()];
                                stack = StackTracker::new();
                                input_challenge(&mut stack, address);
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
                            challenge_current_leaf += *words as u32;
                        }

                        ProgramInputType::ProverPrev(words, offset) => {
                            let previous_protocol = context
                                .globals
                                .get_var(id, &program_input_prev_protocol(idx as u32))?
                                .unwrap()
                                .uuid()?;
                            let previous_prefix = context
                                .globals
                                .get_var(id, &program_input_prev_prefix(idx as u32))?
                                .unwrap()
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
                                    .get_var(&previous_protocol, &key)
                                    .unwrap()
                                    .unwrap()
                                    .wots_pubkey()
                                    .unwrap();
                                //we copy the var so the prover is able to decode it when it sees the challenge tx
                                if role == ParticipantRole::Prover {
                                    context.globals.copy_var(&previous_protocol, id, &key)?;
                                }
                                temp_keys.push(pubkey.clone());
                                let temp_key = &temp_keys[temp_keys.len() - 1];
                                names_and_keys.push((key.as_str(), temp_key));
                                names_and_keys.extend_from_slice(const_names_and_keys.as_slice());

                                let address = base_addr + (j + offset) * 4;
                                let mut scripts = vec![reverse_script.clone()];
                                stack = StackTracker::new();
                                input_challenge(&mut stack, address);
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
                            challenge_current_leaf += *words as u32;
                        }
                        ProgramInputType::Const(words, offset) => {
                            for j in *offset..*offset + *words {
                                let address = base_addr + j * 4;
                                let mut scripts = vec![alternate_reverse.as_ref().unwrap().clone()];
                                stack = StackTracker::new();

                                let key = program_input_word(idx as u32, j);
                                let value = context.globals.get_var(id, &key)?.unwrap().input()?;
                                let value =
                                    u32::from_be_bytes(value.as_slice().try_into().unwrap());

                                rom_challenge(&mut stack, address, value);
                                scripts.push(stack.get_script());
                                let winternitz_check = scripts::verify_winternitz_signatures_aux(
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
                    for i in 0..rodata_words {
                        let address = base_addr + i;
                        let value = program.read_mem(address).unwrap();
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
                    challenge_current_leaf += rodata_words;
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
                    _ => panic!("Unknown challenge name: {}", challenge_name),
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
    Ok(challenge_leaf_script)
}

pub fn get_challenge_leaf(
    id: &Uuid,
    context: &ProgramContext,
    program_definitions: &ProgramDefinition,
    challenge: &ChallengeType,
) -> Result<Option<u32>, BitVMXError> {
    let mut program = program_definitions.load_program()?;
    let name: &str;
    let mut dynamic_offset: u32 = 0; // For offset inside a specific challenge

    match challenge {
        ChallengeType::EntryPoint(_trace_read_pc, _prover_trace_step, _entrypoint) => {
            name = "entry_point";
            info!("Verifier chose {name} challenge");
        }

        ChallengeType::ProgramCounter(
            pre_pre_hash,
            pre_step,
            prover_step_hash,
            _prover_pc_read,
        ) => {
            name = "program_counter";
            info!("Verifier chose {name} challenge");

            set_input_hex(
                id,
                context,
                &format!("verifier_prev_prev_hash"),
                &pre_pre_hash,
            )?;
            set_input_u32(
                id,
                context,
                &format!("verifier_prev_write_add"),
                pre_step.get_write().address,
            )?;
            set_input_u32(
                id,
                context,
                &format!("verifier_prev_write_data"),
                pre_step.get_write().value,
            )?;
            set_input_u32(
                id,
                context,
                &format!("verifier_prev_write_pc"),
                pre_step.get_pc().get_address(),
            )?;
            set_input_u8(
                id,
                context,
                &format!("verifier_prev_write_micro"),
                pre_step.get_pc().get_micro(),
            )?;
            set_input_hex(
                id,
                context,
                &format!("verifier_prev_hash"), //TODO: fix
                &prover_step_hash,
            )?;
        }

        ChallengeType::TraceHash(prover_prev_hash, _prover_trace_step, _prover_step_hash) => {
            name = "trace_hash";
            info!("Verifier chose {name} challenge");

            //TODO: fix
            set_input_hex(id, context, "verifier_prev_hash", &prover_prev_hash)?;
        }

        ChallengeType::TraceHashZero(_prover_trace_step, prover_step_hash) => {
            name = "trace_hash_zero";
            info!("Verifier chose {name} challenge");
            set_input_hex(id, context, "verifier_step_hash", &prover_step_hash)?;
        }

        ChallengeType::InputData(_read_1, _read_2, address, _input_for_address) => {
            name = "input";
            info!("Verifier chose {name} challenge");

            let base_addr = program
                .find_section_by_name(&program_definitions.input_section_name)
                .unwrap()
                .start;
            dynamic_offset = (address - base_addr) / 4;
        }

        ChallengeType::Opcode(_pc_read, chunk_index, _chunk_base, _opcodes_chunk) => {
            name = "opcode";
            info!("Verifier chose {name} challenge");

            dynamic_offset = *chunk_index;
        }

        ChallengeType::AddressesSections(
            _read_1,
            _read_2,
            _write,
            _memory_witness,
            _program_counter,
            _,
            _,
            _,
            _,
        ) => {
            name = "addresses_sections";
            info!("Verifier chose {name} challenge");
        }

        ChallengeType::RomData(_read_1, _read_2, address, _input_for_address) => {
            name = "rom";
            info!("Verifier chose {name} challenge");

            let base_addr = program.find_section_by_name(".rodata").unwrap().start;
            dynamic_offset = address - base_addr;
        }
        ChallengeType::No => {
            name = "";
        }
    }

    if name.is_empty() {
        info!("Verifier chose no challenge");
        return Ok(None);
    }

    let leaf_start = context
        .globals
        .get_var(id, &format!("challenge_leaf_start_{}", name))?
        .unwrap()
        .number()? as u32;

    info!(
        "Leaf start: {}, leaf offset: {}",
        leaf_start, dynamic_offset
    );
    Ok(Some(leaf_start + dynamic_offset))
}
