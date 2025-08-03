use emulator::loader::program_definition::ProgramDefinition;
use uuid::Uuid;

use crate::{
    errors::BitVMXError,
    program::{participant::ParticipantRole, variables::VariableTypes},
    types::ProgramContext,
};

pub enum ProgramInputType {
    Prover(u32, u32),
    Verifier(u32, u32),
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
            "verifier" => {
                input_mapping.push(ProgramInputType::Verifier(words, total_words));
            }
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

    for input in input_mapping.iter() {
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
            }
            // if the input is owned by the verifier then the prover needs to cosign it
            ProgramInputType::Verifier(words, offset) => {
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
            }
            _ => {}
        }
    }

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

pub fn get_txs_configuration(
    id: &Uuid,
    program_context: &ProgramContext,
) -> Result<(Vec<String>, Vec<u32>, Vec<u32>), BitVMXError> {
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

    if input_txs.len() != input_txs_sizes.len() || input_txs.len() != input_txs_offsets.len() {
        return Err(BitVMXError::DisputeResolutionProtocolSetup(
            "Input txs configuration is not valid".to_string(),
        ));
    }
    Ok((input_txs, input_txs_sizes, input_txs_offsets))
}
