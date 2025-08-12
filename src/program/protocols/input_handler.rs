use emulator::loader::program_definition::ProgramDefinition;
use tracing::info;
use uuid::Uuid;

use crate::{
    errors::BitVMXError,
    program::{
        participant::ParticipantRole,
        protocols::dispute::{
            program_input, program_input_prev_prefix, program_input_prev_protocol,
            program_input_word,
        },
        variables::VariableTypes,
    },
    types::ProgramContext,
};

pub enum ProgramInputType {
    Prover(u32, u32),
    //Verifier(u32, u32), // Not yet supported
    ProverPrev(u32, u32),
    //VerifierPrev(u32, u32), // Not yet supported
    Const(u32, u32),
}

pub fn generate_input_owner_list(
    program_def: &ProgramDefinition,
) -> Result<(Vec<ProgramInputType>, u32), BitVMXError> {
    let mut input_mapping = Vec::new();
    let mut total_words = 0;
    for input in program_def.inputs.iter() {
        if input.size == 0 || input.size % 4 != 0 {
            return Err(BitVMXError::DisputeResolutionProtocolSetup(
                "Input size cannot be zero and need to be a multiple of 4".to_string(),
            ));
        }
        assert!(input.size % 4 == 0, "Input size must be a multiple of 4");
        let words = (input.size / 4) as u32;

        match input.owner.as_str() {
            "prover" => {
                input_mapping.push(ProgramInputType::Prover(words, total_words));
            }
            /*"verifier" => {
                input_mapping.push(ProgramInputType::Verifier(words, total_words));
            }*/
            "prover_prev" => {
                input_mapping.push(ProgramInputType::ProverPrev(words, total_words));
            }
            "const" => {
                input_mapping.push(ProgramInputType::Const(words, total_words));
            }
            _ => {
                return Err(BitVMXError::DisputeResolutionProtocolSetup(format!(
                    "Unknown input owner: {}",
                    input.owner
                )));
            }
        }
        total_words += words;
    }
    Ok((input_mapping, total_words))
}

pub fn get_required_keys(
    id: &Uuid,
    program_def: &ProgramDefinition,
    program_context: &ProgramContext,
    participant_role: &ParticipantRole,
) -> Result<Vec<String>, BitVMXError> {
    let mut required_keys = Vec::new();

    let (input_mapping, total_words) = generate_input_owner_list(program_def)?;
    program_context
        .globals
        .set_var(id, "input_words", VariableTypes::Number(total_words))?;

    let mut input_txs = vec![];
    let mut input_txs_sizes = vec![];
    let mut input_txs_offsets = vec![];
    //let mut drp_txs = 0;

    let mut last_tx_id = 0;

    for (idx, input) in input_mapping.iter().enumerate() {
        match input {
            // if the input is owned by the prover it's the only one that needs to be set
            ProgramInputType::Prover(words, offset) => {
                input_txs.push("prover".to_string());
                input_txs_sizes.push(*words);
                input_txs_offsets.push(*offset);
                if participant_role.is_prover() {
                    for i in 0..*words {
                        required_keys.push(format!("prover_program_input_{}", offset + i));
                    }
                }
                last_tx_id = input_txs.len();
            }
            // if the input is owned by the verifier then the prover needs to cosign it
            /*ProgramInputType::Verifier(words, offset) => {
                input_txs.push("verifier".to_string());
                input_txs.push("prover_cosign".to_string());
                input_txs_sizes.push(*words);
                input_txs_sizes.push(*words);
                input_txs_offsets.push(*offset);
                input_txs_offsets.push(*offset);
                for i in 0..*words {
                    required_keys.push(format!(
                        "{}_program_input_{}",
                        participant_role.to_string(),
                        offset + i
                    ));
                }
                last_tx_id = input_txs.len();
            }*/
            ProgramInputType::Const(words, offset) => {
                //similar to split_input
                let full_input = program_context
                    .globals
                    .get_var(id, &program_input(idx as u32))?
                    .unwrap()
                    .input()?;

                for i in 0..*words {
                    let partial_input = full_input
                        .get((i * 4) as usize..((i + 1) * 4) as usize)
                        .unwrap();
                    program_context.globals.set_var(
                        id,
                        &program_input_word(idx as u32, i + offset),
                        VariableTypes::Input(partial_input.to_vec()),
                    )?;
                }
                input_txs.push("skip".to_string());
                input_txs_sizes.push(*words);
                input_txs_offsets.push(*offset);
            }

            ProgramInputType::ProverPrev(words, offset) => {
                input_txs.push("prover_prev".to_string());
                input_txs_sizes.push(*words);
                input_txs_offsets.push(*offset);
            }
        }
    }

    info!("Input txs: {:?}", input_txs);
    info!("Input txs sizes: {:?}", input_txs_sizes);
    info!("Input txs offsets: {:?}", input_txs_offsets);
    info!("Required keys: {:?}", required_keys);
    info!("Total words: {}", total_words);

    program_context.globals.set_var(
        id,
        "last_tx_id",
        VariableTypes::Number(last_tx_id as u32 - 1),
    )?;
    program_context
        .globals
        .set_var(id, "input_txs", VariableTypes::VecStr(input_txs))?;
    program_context.globals.set_var(
        id,
        "input_txs_sizes",
        VariableTypes::VecNumber(input_txs_sizes),
    )?;
    program_context.globals.set_var(
        id,
        "input_txs_offsets",
        VariableTypes::VecNumber(input_txs_offsets),
    )?;

    Ok(required_keys)
}

pub fn split_input(
    id: &Uuid,
    idx: u32,
    program_context: &ProgramContext,
) -> Result<(), BitVMXError> {
    let (input_txs, input_txs_sizes, input_txs_offsets, _) =
        get_txs_configuration(id, program_context)?;

    let full_input = program_context
        .globals
        .get_var(id, &program_input(idx))?
        .unwrap()
        .input()?;
    let words = input_txs_sizes[idx as usize];
    let owner = input_txs[idx as usize].as_str();
    let offset = input_txs_offsets[idx as usize];

    for i in 0..words {
        let partial_input = full_input
            .get((i * 4) as usize..((i + 1) * 4) as usize)
            .unwrap();
        program_context.globals.set_var(
            id,
            &format!("{}_program_input_{}", owner, i + offset),
            VariableTypes::Input(partial_input.to_vec()),
        )?;
    }
    Ok(())
}

pub fn get_txs_configuration(
    id: &Uuid,
    program_context: &ProgramContext,
) -> Result<(Vec<String>, Vec<u32>, Vec<u32>, u32), BitVMXError> {
    let input_txs = program_context
        .globals
        .get_var(id, "input_txs")?
        .unwrap()
        .vec_string()?;
    let input_txs_sizes = program_context
        .globals
        .get_var(id, "input_txs_sizes")?
        .unwrap()
        .vec_number()?;
    let input_txs_offsets = program_context
        .globals
        .get_var(id, "input_txs_offsets")?
        .unwrap()
        .vec_number()?;
    let last_tx_id = program_context
        .globals
        .get_var(id, "last_tx_id")?
        .unwrap()
        .number()?;

    if input_txs.len() != input_txs_sizes.len() || input_txs.len() != input_txs_offsets.len() {
        return Err(BitVMXError::DisputeResolutionProtocolSetup(
            "Input txs configuration is not valid".to_string(),
        ));
    }
    Ok((input_txs, input_txs_sizes, input_txs_offsets, last_tx_id))
}

pub fn unify_witnesses(
    id: &Uuid,
    program_context: &ProgramContext,
    idx: usize,
) -> Result<(), BitVMXError> {
    let (input_txs, input_txs_sizes, input_txs_offsets, _) =
        get_txs_configuration(&id, program_context)?;
    let owner = &input_txs[idx];
    let offset = input_txs_offsets[idx];
    let size = input_txs_sizes[idx];

    let mut input_for_tx = vec![];
    for i in 0..size {
        let key = format!("{}_program_input_{}", owner, offset + i);
        let input = program_context
            .witness
            .get_witness(id, &key)?
            .unwrap()
            .winternitz()?
            .message_bytes();
        info!("Unifying input for tx {}: {}", idx, hex::encode(&input));
        input_for_tx.extend_from_slice(&input);
    }
    program_context.globals.set_var(
        id,
        &program_input(idx as u32),
        VariableTypes::Input(input_for_tx),
    )?;

    Ok(())
}

pub fn unify_inputs(
    id: &Uuid,
    program_context: &ProgramContext,
    program_def: &ProgramDefinition,
) -> Result<Vec<u8>, BitVMXError> {
    let (input_txs, input_txs_sizes, _, _) = get_txs_configuration(&id, program_context)?;

    let mut full_input = vec![];
    for idx in 0..program_def.inputs.len() {
        if input_txs[idx] == "prover_prev" {
            let previous_protocol = program_context
                .globals
                .get_var(id, &program_input_prev_protocol(idx as u32))?
                .unwrap()
                .uuid()?;
            let previous_prefix = program_context
                .globals
                .get_var(id, &program_input_prev_prefix(idx as u32))?
                .unwrap()
                .string()?;

            info!(
                "Will get previous input from protocol {} and prefix: {}",
                previous_protocol, previous_prefix
            );

            for word in 0..input_txs_sizes[idx] {
                let key = format!("{}{}", previous_prefix, word);
                info!(
                    "Getting witness from protocol {} and key: {}",
                    previous_protocol, key
                );
                let signature = &program_context
                    .witness
                    .get_witness(&previous_protocol, &key)?
                    .unwrap()
                    .winternitz()?;
                //copy the witness to the current program so the when needed it can be used to sign txs
                program_context
                    .witness
                    .copy_witness(&previous_protocol, &id, &key)?;
                full_input.extend_from_slice(&signature.message_bytes());
            }
            continue;
        }

        let key = &program_input(idx as u32);
        full_input.extend_from_slice(&program_context.globals.get_var(id, key)?.unwrap().input()?);
        info!(
            "Unifying input from tx {}: {}",
            key,
            hex::encode(&full_input)
        );
    }

    Ok(full_input)
}
