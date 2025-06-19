use std::collections::HashMap;

use bitcoin::{PublicKey, Transaction, Txid};
use bitcoin_coordinator::{coordinator::BitcoinCoordinatorApi, TransactionStatus};
use bitcoin_script_riscv::riscv::{
    challenges::{
        entry_point_challenge, halt_challenge, program_counter_challenge, trace_hash_challenge,
        trace_hash_zero_challenge,
    },
    instruction_mapping::{create_verification_script_mapping, get_key_from_opcode},
};
use bitcoin_script_stack::stack::StackTracker;
use bitvmx_cpu_definitions::{
    challenge::{ChallengeType, EmulatorResultType},
    memory::MemoryWitness,
    trace::{ProgramCounter, TraceRWStep, TraceRead, TraceReadPC, TraceStep, TraceWrite},
};
use bitvmx_job_dispatcher::dispatcher_job::DispatcherJob;
use bitvmx_job_dispatcher_types::emulator_messages::EmulatorJobType;
use emulator::{constants::REGISTERS_BASE_ADDRESS, loader::program_definition::ProgramDefinition};
use key_manager::winternitz::WinternitzPublicKey;
use protocol_builder::{
    builder::{Protocol, ProtocolBuilder},
    scripts::{self, SignMode},
    types::{
        connection::{InputSpec, OutputSpec},
        input::{SighashType, SpendMode},
        OutputType,
    },
};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::{
    bitvmx::Context,
    errors::BitVMXError,
    program::{
        participant::ParticipantRole, protocols::claim::ClaimGate, variables::VariableTypes,
    },
    types::{ProgramContext, EMULATOR_ID},
};

use super::{
    super::participant::ParticipantKeys,
    protocol_handler::{ProtocolContext, ProtocolHandler},
};

pub const EXTERNAL_START: &str = "EXTERNAL_START";
pub const EXTERNAL_ACTION: &str = "EXTERNAL_ACTION";
pub const START_CH: &str = "START_CHALLENGE";
pub const INPUT_1: &str = "INPUT_1";
pub const COMMITMENT: &str = "COMMITMENT";
pub const EXECUTE: &str = "EXECUTE";
pub const TIMELOCK_BLOCKS: u16 = 1;
pub const PROVER_WINS: &str = "PROVER_WINS";
pub const VERIFIER_WINS: &str = "VERIFIER_WINS";
pub const ACTION_PROVER_WINS: &str = "ACTION_PROVER_WINS";
pub const CHALLENGE: &str = "CHALLENGE";

pub const TRACE_VARS: [(&str, usize); 16] = [
    ("write_address", 4 as usize),
    ("write_value", 4),
    ("write_pc", 4),
    ("write_micro", 1),
    ("mem_witness", 1),
    ("read_1_address", 4),
    ("read_1_value", 4),
    ("read_1_last_step", 8),
    ("read_2_address", 4),
    ("read_2_value", 4),
    ("read_2_last_step", 8),
    ("read_pc_address", 4),
    ("read_pc_micro", 1),
    ("read_pc_opcode", 4),
    ("step_number", 8),
    ("witness", 4),
];

pub const ENTRY_POINT_CHALLENGE: [(&str, usize); 3] = [
    ("provided_pc", 4),
    ("provided_micro", 1),
    ("provided_step", 8),
];
pub const PROGRAM_COUNTER_CHALLENGE: [(&str, usize); 8] = [
    ("prev_prev_hash", 20),
    ("prev_write_add", 4),
    ("prev_write_data", 4),
    ("prev_write_pc", 4),
    ("prev_write_micro", 1),
    ("prover_read_pc", 4),
    ("prover_read_micro", 1),
    ("prover_prev_hash", 20),
];
pub const HALT_CHALLENGE: [(&str, usize); 5] = [
    ("final_step", 8),
    ("trace_step", 8),
    ("read_value_1", 4),
    ("read_value_2", 4),
    ("opcode", 4),
];
pub const TRACE_HASH_CHALLENGE: [(&str, usize); 6] = [
    ("prev_hash", 20),
    ("write_add", 4),
    ("write_data", 4),
    ("write_pc", 4),
    ("write_micro", 1),
    ("hash", 20),
];
pub const TRACE_HASH_ZERO_CHALLENGE: [(&str, usize); 5] = [
    ("write_add", 4),
    ("write_data", 4),
    ("write_pc", 4),
    ("write_micro", 1),
    ("hash", 20),
];
pub const CHALLENGES: [(&str, &'static [(&str, usize)]); 5] = [
    ("entry_point", &ENTRY_POINT_CHALLENGE),
    ("program_counter", &PROGRAM_COUNTER_CHALLENGE),
    ("halt", &HALT_CHALLENGE),
    ("trace_hash", &TRACE_HASH_CHALLENGE),
    ("trace_hash_zero", &TRACE_HASH_ZERO_CHALLENGE),
];

#[derive(Clone, Serialize, Deserialize)]
pub struct DisputeResolutionProtocol {
    ctx: ProtocolContext,
}

fn get_role(my_idx: usize) -> ParticipantRole {
    if my_idx == 0 {
        ParticipantRole::Prover
    } else {
        ParticipantRole::Verifier
    }
}

impl ProtocolHandler for DisputeResolutionProtocol {
    fn context(&self) -> &ProtocolContext {
        &self.ctx
    }

    fn context_mut(&mut self) -> &mut ProtocolContext {
        &mut self.ctx
    }

    fn get_pregenerated_aggregated_keys(
        &self,
        context: &ProgramContext,
    ) -> Result<Vec<(String, PublicKey)>, BitVMXError> {
        Ok(vec![(
            "pregenerated".to_string(),
            context
                .globals
                .get_var(&self.ctx.id, "aggregated")?
                .unwrap()
                .pubkey()?,
        )])
    }

    fn generate_keys(
        &self,
        program_context: &mut ProgramContext,
    ) -> Result<ParticipantKeys, BitVMXError> {
        let program_def = self.get_program_definition(&program_context)?.0;
        let key_chain = &mut program_context.key_chain;

        let aggregated_1 = key_chain.derive_keypair()?;

        let speedup = key_chain.derive_keypair()?;
        let timelock = key_chain.derive_keypair()?;

        let mut keys = vec![
            ("aggregated_1".to_string(), aggregated_1.into()),
            ("speedup".to_string(), speedup.into()),
            ("timelock".to_string(), timelock.into()),
        ];

        for inputs in program_def.inputs.iter() {
            //TODO: handle more inputs, owners and counter-sign
            assert!(inputs.size % 4 == 0);
            let words_needed = inputs.size / 4;
            if self.role() == ParticipantRole::Prover {
                for i in 0..words_needed {
                    let key = key_chain.derive_winternitz_hash160(4)?;
                    keys.push((format!("program_input_{}", i), key.into()));
                }
            }
            program_context.globals.set_var(
                &self.ctx.id,
                "input_words",
                VariableTypes::Number(words_needed as u32),
            )?;
        }

        if self.role() == ParticipantRole::Prover {
            let last_step = key_chain.derive_winternitz_hash160(8)?;
            keys.push(("last_step".to_string(), last_step.into()));

            let last_hash = key_chain.derive_winternitz_hash160(20)?;
            keys.push(("last_hash".to_string(), last_hash.into()));

            for (name, size) in TRACE_VARS {
                let key = key_chain.derive_winternitz_hash160(size)?;
                keys.push((name.to_string(), key.into()));
            }
        } else {
            for (challenge_name, challenge) in CHALLENGES.iter() {
                for (name, size) in challenge.iter() {
                    let key = key_chain.derive_winternitz_hash160(*size)?;
                    keys.push((format!("{}_{}", challenge_name, name), key.into()));
                }
            }
        }

        //generate keys for the nary search
        let nary_def = program_def.nary_def();
        info!("Nary def: {:?}", nary_def);
        for i in 1..nary_def.total_rounds() + 1 {
            if self.role() == ParticipantRole::Prover {
                let hashes = nary_def.hashes_for_round(i);
                for h in 0..hashes {
                    let key = key_chain.derive_winternitz_hash160(20)?;
                    keys.push((format!("prover_hash_{}_{}", i, h), key.into()));
                }
            } else {
                let _bits = nary_def.bits_for_round(i);
                let key = key_chain.derive_winternitz_hash160(1)?;
                //TODO: assuming bits fits in one byte. We should also enforce in the script that the revealed are in range
                keys.push((format!("selection_bits_{}", i), key.into()));
            }
        }

        Ok(ParticipantKeys::new(keys, vec!["aggregated_1".to_string()]))
    }

    fn get_transaction_name(
        &self,
        name: &str,
        context: &ProgramContext,
    ) -> Result<Transaction, BitVMXError> {
        match name {
            START_CH => Ok(self.start_challenge(context)?),
            INPUT_1 => Ok(self.input_1_tx(context)?),
            _ => Err(BitVMXError::InvalidTransactionName(name.to_string())),
        }
    }

    fn notify_news(
        &self,
        tx_id: Txid,
        _vout: Option<u32>,
        tx_status: TransactionStatus,
        _context: String,
        program_context: &ProgramContext,
        participant_keys: Vec<&ParticipantKeys>,
    ) -> Result<(), BitVMXError> {
        let name = self.get_transaction_name_by_id(tx_id)?;
        info!(
            "Program {}: Transaction {} has been seen on-chain {}",
            self.ctx.id,
            name,
            self.role()
        );

        let (fail_config_prover, fail_config_verifier, force, force_condition) = program_context
            .globals
            .get_var(&self.ctx.id, "fail_force_config")?
            .unwrap()
            .fail_configuration()?;

        if name == INPUT_1 && self.role() == ParticipantRole::Prover {
            if program_context
                .globals
                .get_var(&self.ctx.id, "FAKE_RUN")?
                .is_some()
            {
                //Execute actions.
                //Could execute more than one
                info!("Prover. Execute Action");
                program_context.bitcoin_coordinator.dispatch(
                    self.get_signed_tx(program_context, ACTION_PROVER_WINS, 0, 1, false, 0)?,
                    None,
                    Context::ProgramId(self.ctx.id).to_string()?,
                    None,
                )?;
                return Ok(());
            }
        }
        //TODO: generalize decoding
        if name == INPUT_1 && self.role() == ParticipantRole::Prover {
            //TODO: Check if the last input
            //only then execute the program.

            let program_definition = program_context
                .globals
                .get_var(&self.ctx.id, "program_definition")?
                .unwrap()
                .string()?;

            let input_program = program_context
                .globals
                .get_var(&self.ctx.id, "program_input")?
                .unwrap()
                .input()?;

            let execution_path = self.get_execution_path()?;
            let msg = serde_json::to_string(&DispatcherJob {
                job_id: self.ctx.id.to_string(),
                job_type: EmulatorJobType::ProverExecute(
                    program_definition,
                    input_program,
                    execution_path.clone(),
                    format!("{}/{}", execution_path, "execution.json").to_string(),
                    fail_config_prover.clone(),
                ),
            })?;
            program_context.broker_channel.send(EMULATOR_ID, msg)?;
        }
        if name == INPUT_1 && self.role() == ParticipantRole::Verifier {
            self.decode_witness_for_tx(
                &name,
                0,
                program_context,
                &participant_keys[0],
                &tx_status.tx,
                None,
            )?;
        }

        if name == COMMITMENT && self.role() == ParticipantRole::Verifier {
            self.decode_witness_for_tx(
                &name,
                0,
                program_context,
                &participant_keys[0],
                &tx_status.tx,
                None,
            )?;

            let program_definition = program_context
                .globals
                .get_var(&self.ctx.id, "program_definition")?
                .unwrap()
                .string()?;

            let execution_path = self.get_execution_path()?;
            let words = program_context
                .globals
                .get_var(&self.ctx.id, "input_words")?
                .unwrap()
                .number()?;

            let mut input_program = Vec::new();

            for i in 0..words {
                let input = program_context
                    .witness
                    .get_witness(&self.ctx.id, &format!("program_input_{}", i))?
                    .unwrap()
                    .winternitz()?
                    .message_bytes();
                input_program.extend_from_slice(&input);
            }

            let last_hash = program_context
                .witness
                .get_witness(&self.ctx.id, "last_hash")?
                .unwrap()
                .winternitz()?
                .message_bytes();

            let last_step = program_context
                .witness
                .get_witness(&self.ctx.id, "last_step")?
                .unwrap()
                .winternitz()?
                .message_bytes();
            let last_step = u64::from_be_bytes(last_step.try_into().unwrap());

            let msg = serde_json::to_string(&DispatcherJob {
                job_id: self.ctx.id.to_string(),
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

            program_context.broker_channel.send(EMULATOR_ID, msg)?;
        }

        if name == COMMITMENT || name.starts_with("NARY_VERIFIER") {
            let mut round = name
                .strip_prefix("NARY_VERIFIER_")
                .unwrap_or("0")
                .parse::<u32>()
                .unwrap();

            let (program_definition, pdf) = self.get_program_definition(program_context)?;
            let nary = program_definition.nary_def();

            if self.role() == ParticipantRole::Prover {
                let decision = if name == COMMITMENT {
                    0
                } else {
                    self.decode_witness_for_tx(
                        &name,
                        0,
                        program_context,
                        &participant_keys[1],
                        &tx_status.tx,
                        None,
                    )?;

                    let bits = program_context
                        .witness
                        .get_witness(&self.ctx.id, &format!("selection_bits_{}", round))?
                        .unwrap()
                        .winternitz()?
                        .message_bytes();
                    let bits = bits[0];
                    bits
                };

                round += 1;

                //TODO: make this value return from execution
                program_context.globals.set_var(
                    &self.ctx.id,
                    "current_round",
                    VariableTypes::Number(round as u32),
                )?;

                let execution_path = self.get_execution_path()?;
                if round <= nary.total_rounds() as u32 {
                    let msg = serde_json::to_string(&DispatcherJob {
                        job_id: self.ctx.id.to_string(),
                        job_type: EmulatorJobType::ProverGetHashesForRound(
                            pdf,
                            execution_path.clone(),
                            round as u8,
                            decision as u32,
                            format!("{}/{}", execution_path, "execution.json").to_string(),
                            fail_config_prover.clone(),
                        ),
                    })?;
                    program_context.broker_channel.send(EMULATOR_ID, msg)?;
                } else {
                    let msg = serde_json::to_string(&DispatcherJob {
                        job_id: self.ctx.id.to_string(),
                        job_type: EmulatorJobType::ProverFinalTrace(
                            pdf,
                            execution_path.clone(),
                            (decision + 1) as u32,
                            format!("{}/{}", execution_path, "execution.json").to_string(),
                            fail_config_prover.clone(),
                        ),
                    })?;
                    program_context.broker_channel.send(EMULATOR_ID, msg)?;
                }
            } else {
                if round == nary.total_rounds() as u32 {
                    info!("Current block: {}", tx_status.block_info.height);
                    /*program_context.bitcoin_coordinator.dispatch(
                        self.get_signed_tx(program_context, "EXECUTE_TO", 0, 1, true)?,
                        Context::ProgramId(self.ctx.id).to_string()?,
                        Some(
                            tx_status.block_info.as_ref().unwrap().block_height
                                + TIMELOCK_BLOCKS as u32,
                        ),
                    )?;*/
                }
            }
        }

        if (name.starts_with("NARY_PROVER")) && self.role() == ParticipantRole::Verifier {
            self.decode_witness_for_tx(
                &name,
                0,
                program_context,
                &participant_keys[0],
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
                &self.ctx.id,
                "current_round",
                VariableTypes::Number(round as u32),
            )?;

            let (program_definition, pdf) = self.get_program_definition(program_context)?;
            let nary = program_definition.nary_def();
            let hashes_count = nary.hashes_for_round(round as u8);

            let hashes: Vec<String> = (0..hashes_count)
                .map(|h| {
                    hex::encode(
                        program_context
                            .witness
                            .get_witness(&self.ctx.id, &format!("prover_hash_{}_{}", round, h))
                            .unwrap()
                            .unwrap()
                            .winternitz()
                            .unwrap()
                            .message_bytes(),
                    )
                })
                .collect();

            let execution_path = self.get_execution_path()?;
            let msg = serde_json::to_string(&DispatcherJob {
                job_id: self.ctx.id.to_string(),
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
                program_context.broker_channel.send(EMULATOR_ID, msg)?;
            } else {
                if let Some(_ready) = program_context
                    .globals
                    .get_var(&self.ctx.id, "execution-check-ready")?
                {
                    info!("The execution is ready. Sending the choose segment message");
                    program_context.broker_channel.send(EMULATOR_ID, msg)?;
                } else {
                    info!("The execution is not ready. Saving the message.");
                    program_context.globals.set_var(
                        &self.ctx.id,
                        "choose-segment-msg",
                        VariableTypes::String(msg),
                    )?;
                }
            }
        }

        if name == EXECUTE && self.role() == ParticipantRole::Verifier {
            self.decode_witness_for_tx(
                &name,
                0,
                program_context,
                &participant_keys[0],
                &tx_status.tx,
                None,
            )?;
            let (_program_definition, pdf) = self.get_program_definition(program_context)?;
            let execution_path = self.get_execution_path()?;

            let mut values = std::collections::HashMap::new();

            for (name, _) in TRACE_VARS.iter() {
                if *name == "witness" {
                    continue;
                }

                let value = program_context
                    .witness
                    .get_witness(&self.ctx.id, name)
                    .unwrap()
                    .unwrap()
                    .winternitz()
                    .unwrap()
                    .message_bytes();
                values.insert(*name, value);
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

            let step_number = to_u64(&values["step_number"]);
            let trace_read1 = TraceRead::new(
                to_u32(&values["read_1_address"]),
                to_u32(&values["read_1_value"]),
                to_u64(&values["read_1_last_step"]),
            );
            let trace_read2 = TraceRead::new(
                to_u32(&values["read_2_address"]),
                to_u32(&values["read_2_value"]),
                to_u64(&values["read_2_last_step"]),
            );
            let program_counter = ProgramCounter::new(
                to_u32(&values["read_pc_address"]),
                to_u8(&values["read_pc_micro"]),
            );
            let read_pc = TraceReadPC::new(program_counter, to_u32(&values["read_pc_opcode"]));
            let trace_write = TraceWrite::new(
                to_u32(&values["write_address"]),
                to_u32(&values["write_value"]),
            );
            let program_counter =
                ProgramCounter::new(to_u32(&values["write_pc"]), to_u8(&values["write_micro"]));
            let trace_step = TraceStep::new(trace_write, program_counter);
            let witness = None; //TODO: get the witness from the context?
            let mem_witness = MemoryWitness::from_byte(to_u8(&values["mem_witness"]));

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
                job_id: self.ctx.id.to_string(),
                job_type: EmulatorJobType::VerifierChooseChallenge(
                    pdf,
                    execution_path.clone(),
                    final_trace,
                    format!("{}/{}", execution_path, "execution.json").to_string(),
                    fail_config_verifier.clone(),
                    force,
                ),
            })?;
            program_context.broker_channel.send(EMULATOR_ID, msg)?;
        }

        if name == EXECUTE && self.role() == ParticipantRole::Prover {
            let tx = self.get_signed_tx(
                program_context,
                &ClaimGate::tx_start(PROVER_WINS),
                0,
                0,
                false,
                0,
            )?;
            info!("PROVER_WINS_TX: {:?}", tx);
            program_context.bitcoin_coordinator.dispatch(
                tx,
                None,
                //prover-win-start is input 1
                Context::ProgramId(self.ctx.id).to_string()?,
                None,
            )?;
        }

        if name == ClaimGate::tx_start(PROVER_WINS) && self.role() == ParticipantRole::Prover {
            info!("Prover wins SUCCESS dispatch");
            program_context.bitcoin_coordinator.dispatch(
                self.get_signed_tx(
                    program_context,
                    &ClaimGate::tx_success(PROVER_WINS),
                    0,
                    0,
                    false,
                    0,
                )?,
                None,
                Context::ProgramId(self.ctx.id).to_string()?,
                Some(tx_status.block_info.height + TIMELOCK_BLOCKS as u32),
            )?;
        }

        if name == ClaimGate::tx_success(PROVER_WINS) && self.role() == ParticipantRole::Prover {
            //Execute actions.
            //Could execute more than one
            info!("Prover. Execute Action");
            program_context.bitcoin_coordinator.dispatch(
                self.get_signed_tx(program_context, ACTION_PROVER_WINS, 0, 0, false, 1)?,
                None,
                Context::ProgramId(self.ctx.id).to_string()?,
                None,
            )?;
        }

        if name == CHALLENGE && self.role() == ParticipantRole::Prover {
            let input_index = 0;
            self.decode_witness_for_tx(
                &name,
                input_index,
                program_context,
                &participant_keys[1],
                &tx_status.tx,
                None,
            )?;
            // let (_program_definition, pdf) = self.get_program_definition(program_context)?;
            // let execution_path = self.get_execution_path()?;

            let challenge_idx = program_context
                .globals
                .get_var(
                    &self.ctx.id,
                    &format!("CHALLENGE_{}_leaf_index", input_index),
                )?
                .unwrap()
                .number()?;

            let (challenge_name, subchallenges) = CHALLENGES
                .get(challenge_idx as usize)
                .ok_or(BitVMXError::ChallengeIdxNotFound(challenge_idx))?;

            let mut values = HashMap::with_capacity(subchallenges.len());

            for (subname, _) in *subchallenges {
                let full_name = format!("{}_{}", challenge_name, subname);
                let value = program_context
                    .witness
                    .get_witness(&self.ctx.id, &full_name)?
                    .unwrap()
                    .winternitz()?
                    .message_bytes();
                values.insert(full_name, value);
            }
            info!(
                "Prover decoded challenge {} with values: {:?}",
                challenge_name, values
            );
            //TODO: continue challenge for some challenges
        }

        Ok(())
    }

    fn build(
        &self,
        keys: Vec<ParticipantKeys>,
        computed_aggregated: HashMap<String, PublicKey>,
        context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        // TODO get this from config, all values expressed in satoshis
        let fee = context
            .globals
            .get_var(&self.ctx.id, "FEE")?
            .unwrap()
            .number()? as u64;
        let speedup_dust = 500;

        let utxo = context
            .globals
            .get_var(&self.ctx.id, "utxo")?
            .unwrap()
            .utxo()?;

        let utxo_prover_win_action = context
            .globals
            .get_var(&self.ctx.id, "utxo_prover_win_action")?
            .unwrap()
            .utxo()?;

        let program_def = self.get_program_definition(context)?;

        let mut protocol = self.load_or_create_protocol();

        let mut amount = utxo.2.unwrap();
        info!("Protocol amount: {}", amount);
        let output_type = utxo.3.unwrap();

        protocol.add_external_transaction(EXTERNAL_START)?;
        protocol.add_unkwnoun_outputs(EXTERNAL_START, utxo.1)?;
        protocol.add_transaction_output(EXTERNAL_START, &output_type)?;

        protocol.add_connection(
            &format!("{}_{}", EXTERNAL_START, START_CH),
            EXTERNAL_START,
            (utxo.1 as usize).into(),
            START_CH,
            InputSpec::Auto(SighashType::taproot_all(), SpendMode::Script { leaf: 1 }),
            None,
            Some(utxo.0),
        )?;

        let aggregated = computed_aggregated.get("aggregated_1").unwrap();
        amount = self.checked_sub(amount, fee)?;

        let words = context
            .globals
            .get_var(&self.ctx.id, "input_words")?
            .unwrap()
            .number()?;

        let input_vars = (0..words)
            .map(|i| format!("program_input_{}", i))
            .collect::<Vec<_>>();
        let input_vars_slice = input_vars.iter().map(|s| s.as_str()).collect::<Vec<&str>>();

        amount = self.checked_sub(amount, ClaimGate::cost(fee, speedup_dust, 1, 1))?;
        amount = self.checked_sub(amount, ClaimGate::cost(fee, speedup_dust, 1, 1))?;

        self.add_winternitz_check(
            aggregated,
            &mut protocol,
            TIMELOCK_BLOCKS,
            &keys[0],
            amount,
            speedup_dust,
            &input_vars_slice,
            START_CH,
            INPUT_1,
            None,
        )?;
        amount = self.checked_sub(amount, fee)?;
        amount = self.checked_sub(amount, speedup_dust)?;

        let claim_prover = ClaimGate::new(
            &mut protocol,
            START_CH,
            PROVER_WINS,
            aggregated,
            fee,
            speedup_dust,
            1,
            None,
            TIMELOCK_BLOCKS,
            vec![aggregated],
        )?;

        protocol.add_transaction(ACTION_PROVER_WINS)?;

        if context.globals.get_var(&self.ctx.id, "FAKE_RUN")?.is_none() {
            protocol.add_connection(
                "PROVER_ACTION_1",
                &ClaimGate::tx_success(PROVER_WINS),
                0.into(),
                ACTION_PROVER_WINS,
                InputSpec::Auto(
                    SighashType::taproot_all(),
                    SpendMode::All {
                        key_path_sign: SignMode::Aggregate,
                    },
                ),
                None,
                None,
            )?;
        }

        //let prover_win_amount = utxo_prover_win_action.2.unwrap();
        let output_type = utxo_prover_win_action.3.unwrap();
        protocol.add_external_transaction(EXTERNAL_ACTION)?;
        protocol.add_unkwnoun_outputs(EXTERNAL_ACTION, utxo_prover_win_action.1)?;
        protocol.add_transaction_output(EXTERNAL_ACTION, &output_type)?;
        protocol.add_connection(
            "EXTERNAL_ACTION__PROVER_WINS",
            EXTERNAL_ACTION,
            (utxo_prover_win_action.1 as usize).into(),
            ACTION_PROVER_WINS,
            InputSpec::Auto(
                SighashType::taproot_all(),
                SpendMode::Script { leaf: 1 }, //the alternate key is on leaf 1
            ),
            None,
            Some(utxo_prover_win_action.0),
        )?;

        let pb = ProtocolBuilder {};
        pb.add_speedup_output(&mut protocol, ACTION_PROVER_WINS, speedup_dust, aggregated)?;

        let claim_verifier = ClaimGate::new(
            &mut protocol,
            START_CH,
            VERIFIER_WINS,
            aggregated,
            fee,
            speedup_dust,
            1,
            None,
            TIMELOCK_BLOCKS,
            vec![aggregated],
        )?;

        self.add_winternitz_check(
            aggregated,
            &mut protocol,
            TIMELOCK_BLOCKS,
            &keys[0],
            amount,
            speedup_dust,
            &vec!["last_step", "last_hash"],
            INPUT_1,
            COMMITMENT,
            Some(&claim_verifier),
        )?;
        amount = self.checked_sub(amount, fee)?;
        amount = self.checked_sub(amount, speedup_dust)?;

        let nary_def = program_def.0.nary_def();
        let mut prev = COMMITMENT.to_string();
        for i in 1..nary_def.total_rounds() + 1 {
            let next = format!("NARY_PROVER_{}", i);
            let hashes = nary_def.hashes_for_round(i);
            let vars = (0..hashes)
                .map(|h| format!("prover_hash_{}_{}", i, h))
                .collect::<Vec<_>>();

            self.add_winternitz_check(
                aggregated,
                &mut protocol,
                TIMELOCK_BLOCKS,
                &keys[0],
                amount,
                speedup_dust,
                &vars.iter().map(|s| s.as_str()).collect::<Vec<&str>>(),
                &prev,
                &next,
                Some(&claim_verifier),
            )?;
            amount = self.checked_sub(amount, fee)?;
            amount = self.checked_sub(amount, speedup_dust)?;

            prev = next;
            let next = format!("NARY_VERIFIER_{}", i);
            //TODO: Add a lower than value check
            let _bits = nary_def.bits_for_round(i);

            self.add_winternitz_check(
                aggregated,
                &mut protocol,
                TIMELOCK_BLOCKS,
                &keys[1],
                amount,
                speedup_dust,
                &vec![&format!("selection_bits_{}", i)],
                &prev,
                &next,
                Some(&claim_prover),
            )?;
            amount = self.checked_sub(amount, fee)?;
            amount = self.checked_sub(amount, speedup_dust)?;
            prev = next;
        }

        // amount -= fee;
        // amount -= speedup_dust;

        //Simple execution check
        let vars = TRACE_VARS
            .iter()
            .take(TRACE_VARS.len() - 1) // Skip the witness (except is needed)
            //.rev() //reverse to get the proper order on the stack
            .map(|(name, _)| *name)
            .collect::<Vec<&str>>();

        self.add_winternitz_and_script(
            context,
            aggregated,
            &mut protocol,
            TIMELOCK_BLOCKS,
            &keys[0],
            amount,
            speedup_dust,
            &vars,
            &prev,
            EXECUTE,
            Some(&claim_verifier),
        )?;

        //Add this as if it were the final tx execution
        claim_prover.add_claimer_win_connection(&mut protocol, EXECUTE)?;

        info!(
            "Amount {}, fee {}, speedup_dust {}",
            amount, fee, speedup_dust
        );
        amount -= fee;
        amount -= speedup_dust;

        self.add_winternitz_and_challenge(
            context,
            aggregated,
            &mut protocol,
            TIMELOCK_BLOCKS,
            &keys[1],
            amount,
            speedup_dust,
            EXECUTE,
            CHALLENGE,
            Some(&claim_prover),
        )?;

        protocol.build(&context.key_chain.key_manager, &self.ctx.protocol_name)?;
        info!("{}", protocol.visualize()?);
        self.save_protocol(protocol)?;

        Ok(())
    }
}

impl DisputeResolutionProtocol {
    pub fn new(context: ProtocolContext) -> Self {
        Self { ctx: context }
    }

    pub fn role(&self) -> ParticipantRole {
        get_role(self.ctx.my_idx)
    }

    pub fn start_challenge(&self, context: &ProgramContext) -> Result<Transaction, BitVMXError> {
        /*let signature = self
            .load_protocol()?
            .input_taproot_key_spend_signature(START_CH, 0)?
            .unwrap();
        let mut taproot_arg = InputArgs::new_taproot_key_args();
        taproot_arg.push_taproot_signature(signature)?;*/

        self.get_signed_tx(context, START_CH, 0, 1, false, 0)

        /*self.load_protocol()?
        .transaction_to_send(START_CH, &[taproot_arg])*/
    }

    pub fn input_1_tx(&self, context: &ProgramContext) -> Result<Transaction, BitVMXError> {
        //TODO: concatenate all inputs
        let words = context
            .globals
            .get_var(&self.ctx.id, "input_words")?
            .unwrap()
            .number()?;

        let full_input = context
            .globals
            .get_var(&self.ctx.id, "program_input")?
            .unwrap()
            .input()?;

        for i in 0..words {
            let partial_input = full_input
                .get((i * 4) as usize..((i + 1) * 4) as usize)
                .unwrap();
            context.globals.set_var(
                &self.ctx.id,
                &format!("program_input_{}", i),
                VariableTypes::Input(partial_input.to_vec()),
            )?;
        }

        self.get_signed_tx(context, INPUT_1, 0, 0, true, 0)
    }

    pub fn add_winternitz_check(
        &self,
        aggregated: &PublicKey,
        protocol: &mut Protocol,
        timelock_blocks: u16,
        keys: &ParticipantKeys,
        amount: u64,
        amount_speedup: u64,
        var_names: &Vec<&str>,
        from: &str,
        to: &str,
        claim_gate: Option<&ClaimGate>,
    ) -> Result<(), BitVMXError> {
        //TODO:
        // - Support multiple inputs
        // - check if input is prover of verifier and use proper keys[n]
        // - the prover needs to re-sign any verifier provided input (so the equivocation is possible on reads)
        info!("Adding winternitz check for {} to {}", from, to);
        info!("Amount: {}", amount);
        info!("Speedup: {}", amount_speedup);
        let names_and_keys = var_names
            .iter()
            .map(|v| (*v, keys.get_winternitz(v).unwrap()))
            .collect();

        let winternitz_check = scripts::verify_winternitz_signatures(
            aggregated,
            &names_and_keys,
            SignMode::Aggregate,
        )?;

        let timeout = scripts::timelock(timelock_blocks, &aggregated, SignMode::Aggregate);

        let mut leaves = [winternitz_check, timeout];
        for (pos, leave) in leaves.iter_mut().enumerate() {
            leave.set_assert_leaf_id(pos as u32);
        }

        let output_type = OutputType::taproot(amount, aggregated, &leaves)?;

        protocol.add_connection(
            &format!("{}__{}", from, to),
            from,
            output_type.clone().into(),
            to,
            InputSpec::Auto(SighashType::taproot_all(), SpendMode::Script { leaf: 0 }),
            None,
            None,
        )?;

        protocol.add_connection(
            &format!("{}__{}_TO", from, to),
            from,
            OutputSpec::Last,
            &format!("{}_TO", to),
            InputSpec::Auto(SighashType::taproot_all(), SpendMode::Script { leaf: 1 }),
            Some(timelock_blocks),
            None,
        )?;

        if let Some(claim_gate) = claim_gate {
            claim_gate.add_claimer_win_connection(protocol, &format!("{}_TO", to))?;
        }

        let pb = ProtocolBuilder {};
        //put the amount here as there is no output yet
        pb.add_speedup_output(protocol, to, amount_speedup, aggregated)?;
        pb.add_speedup_output(protocol, &format!("{}_TO", to), amount_speedup, aggregated)?;

        Ok(())
    }

    pub fn add_winternitz_and_script(
        &self,
        context: &ProgramContext,
        aggregated: &PublicKey,
        protocol: &mut Protocol,
        timelock_blocks: u16,
        keys: &ParticipantKeys,
        amount: u64,
        amount_speedup: u64,
        var_names: &Vec<&str>,
        from: &str,
        to: &str,
        claim_gate: Option<&ClaimGate>,
    ) -> Result<(), BitVMXError> {
        info!("Adding winternitz check for {} to {}", from, to);
        info!("Amount: {}", amount);
        info!("Speedup: {}", amount_speedup);
        let names_and_keys = var_names
            .iter()
            .map(|v| (*v, keys.get_winternitz(v).unwrap()))
            .collect();

        let mapping = create_verification_script_mapping(REGISTERS_BASE_ADDRESS);
        let mut instruction_names: Vec<_> = mapping.keys().cloned().collect();
        instruction_names.sort();

        //TODO: This is a workacround to inverse the order of the stack
        let mut stack = StackTracker::new();
        let all = stack.define(126, "all");
        for i in 1..126 {
            stack.move_var_sub_n(all, 126 - i - 1);
        }
        let reverse_script = stack.get_script();

        //TODO: This is a workaround to remove one nibble from the micro instructions
        //and drop the last steps. (this can be avoided)
        let mut stack = StackTracker::new();
        let mut stackvars = HashMap::new();
        for (name, size) in TRACE_VARS.iter().take(TRACE_VARS.len() - 1) {
            stackvars.insert(*name, stack.define((size * 2) as u32, name));
        }
        let step_n = stack.move_var(stackvars["step_number"]);
        stack.drop(step_n);
        let stripped = stack.move_var_sub_n(stackvars["write_micro"], 0);
        stack.drop(stripped);
        let stripped = stack.move_var_sub_n(stackvars["read_pc_micro"], 0);
        stack.drop(stripped);
        let last_step_1 = stack.move_var(stackvars["read_1_last_step"]);
        stack.drop(last_step_1);
        let last_step_2 = stack.move_var(stackvars["read_2_last_step"]);
        stack.drop(last_step_2);
        let strip_script = stack.get_script();

        let mut winternitz_check_list = vec![];

        if context
            .globals
            .get_var(&self.ctx.id, "FAKE_INSTRUCTION")?
            .is_some()
        {
            instruction_names = vec!["ecall".to_string()];
        }
        for (_, name) in instruction_names.iter().enumerate() {
            let script = mapping[name].0.clone();
            let winternitz_check = scripts::verify_winternitz_signatures_aux(
                aggregated,
                &names_and_keys,
                SignMode::Aggregate,
                true,
                Some(vec![
                    reverse_script.clone(),
                    strip_script.clone(),
                    script.clone(),
                ]),
            )?;
            winternitz_check_list.push(winternitz_check);
        }

        let timeout = scripts::timelock(timelock_blocks, &aggregated, SignMode::Aggregate);
        winternitz_check_list.push(timeout.clone());

        for (pos, leave) in winternitz_check_list.iter_mut().enumerate() {
            leave.set_assert_leaf_id(pos as u32);
        }

        let output_type = OutputType::taproot(amount, aggregated, &winternitz_check_list)?;

        protocol.add_connection(
            &format!("{}__{}", from, to),
            from,
            output_type.clone().into(),
            to,
            InputSpec::Auto(
                SighashType::taproot_all(),
                SpendMode::All {
                    //TODO: fix proper leaf set
                    key_path_sign: SignMode::Aggregate,
                },
            ),
            None,
            None,
        )?;

        protocol.add_connection(
            &format!("{}__{}_TO", from, to),
            from,
            OutputSpec::Last,
            &format!("{}_TO", to),
            InputSpec::Auto(
                SighashType::taproot_all(),
                SpendMode::All {
                    //TODO: sign only timelock
                    key_path_sign: SignMode::Aggregate,
                },
            ),
            Some(timelock_blocks),
            None,
        )?;

        if let Some(claim_gate) = claim_gate {
            claim_gate.add_claimer_win_connection(protocol, &format!("{}_TO", to))?;
        }

        let pb = ProtocolBuilder {};
        //put the amount here as there is no output yet
        pb.add_speedup_output(protocol, to, amount_speedup, aggregated)?;
        pb.add_speedup_output(protocol, &format!("{}_TO", to), amount_speedup, aggregated)?;
        Ok(())
    }

    pub fn add_winternitz_and_challenge(
        &self,
        context: &ProgramContext,
        aggregated: &PublicKey,
        protocol: &mut Protocol,
        timelock_blocks: u16,
        keys: &ParticipantKeys,
        amount: u64,
        amount_speedup: u64,
        from: &str,
        to: &str,
        claim_gate: Option<&ClaimGate>,
    ) -> Result<(), BitVMXError> {
        info!("Adding winternitz check for {} to {}", from, to);
        info!("Amount: {}", amount);
        info!("Speedup: {}", amount_speedup);

        let mut names_and_keys: HashMap<&str, Vec<(&'static str, &WinternitzPublicKey)>> =
            HashMap::new();

        for (challenge_name, subnames) in CHALLENGES.iter() {
            let group: Vec<(&'static str, &WinternitzPublicKey)> = subnames
                .iter()
                .map(|(subname, _)| {
                    let var_name: &'static str =
                        Box::leak(format!("{}_{}", challenge_name, subname).into_boxed_str());
                    let key = keys.get_winternitz(var_name).unwrap();
                    (var_name, key)
                })
                .collect();

            names_and_keys.insert(challenge_name, group);
        }

        let mut winternitz_check_list = vec![];

        for (challenge_name, subnames) in CHALLENGES.iter() {
            let total_len = subnames.iter().map(|(_, size)| *size).sum::<usize>() as u32 * 2;

            let mut stack = StackTracker::new();
            let all = stack.define(total_len, "all");
            //TODO: This is a workaround to remove one nibble from the micro instructions
            for i in 1..total_len {
                stack.move_var_sub_n(all, total_len - i - 1);
            }
            let reverse_script = stack.get_script();
            let mut scripts = vec![reverse_script.clone()];

            stack = StackTracker::new();

            match *challenge_name {
                "entry_point" => {
                    let program = self.get_program_definition(context)?;
                    let entry_point = program.0.load_program()?.pc.get_address();
                    entry_point_challenge(&mut stack, entry_point)
                }
                "program_counter" => program_counter_challenge(&mut stack),
                "halt" => halt_challenge(&mut stack),
                "trace_hash" => trace_hash_challenge(&mut stack),
                "trace_hash_zero" => trace_hash_zero_challenge(&mut stack),
                _ => panic!("Unknown challenge name: {}", challenge_name),
            }

            scripts.push(stack.get_script());
            let winternitz_check = scripts::verify_winternitz_signatures_aux(
                aggregated,
                &names_and_keys[challenge_name],
                SignMode::Aggregate,
                true,
                Some(scripts),
            )?;

            winternitz_check_list.push(winternitz_check);
        }

        let timeout = scripts::timelock(timelock_blocks, &aggregated, SignMode::Aggregate);
        winternitz_check_list.push(timeout.clone());

        for (pos, leave) in winternitz_check_list.iter_mut().enumerate() {
            leave.set_assert_leaf_id(pos as u32);
        }

        let output_type = OutputType::taproot(amount, aggregated, &winternitz_check_list)?;

        protocol.add_connection(
            &format!("{}__{}", from, to),
            from,
            output_type.clone().into(),
            to,
            InputSpec::Auto(
                SighashType::taproot_all(),
                SpendMode::All {
                    //TODO: fix proper leaf set
                    key_path_sign: SignMode::Aggregate,
                },
            ),
            None,
            None,
        )?;

        protocol.add_connection(
            &format!("{}__{}_TO", from, to),
            from,
            OutputSpec::Last,
            &format!("{}_TO", to),
            InputSpec::Auto(
                SighashType::taproot_all(),
                SpendMode::All {
                    //TODO: sign only timelock
                    key_path_sign: SignMode::Aggregate,
                },
            ),
            Some(timelock_blocks),
            None,
        )?;

        if let Some(claim_gate) = claim_gate {
            claim_gate.add_claimer_win_connection(protocol, &format!("{}_TO", to))?;
        }

        let pb = ProtocolBuilder {};
        //put the amount here as there is no output yet
        pb.add_speedup_output(protocol, to, amount_speedup, aggregated)?;
        pb.add_speedup_output(protocol, &format!("{}_TO", to), amount_speedup, aggregated)?;
        Ok(())
    }

    pub fn execution_result(
        &self,
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
                self.set_input_u64(context, "last_step", *last_step)?;

                self.set_input_hex(context, "last_hash", last_hash)?;

                context.bitcoin_coordinator.dispatch(
                    self.get_signed_tx(context, COMMITMENT, 0, 0, true, 0)?,
                    None,
                    Context::ProgramId(self.ctx.id).to_string()?,
                    None,
                )?;
            }
            EmulatorResultType::VerifierCheckExecutionResult { step } => {
                info!("Verifier execution result: Step: {:?}", step);
                context.globals.set_var(
                    &self.ctx.id,
                    "execution-check-ready",
                    VariableTypes::Number(1),
                )?;
                if let Some(msg) = context
                    .globals
                    .get_var(&self.ctx.id, "choose-segment-msg")?
                {
                    info!("The msg to choose segment was ready. Sending it");
                    context.broker_channel.send(EMULATOR_ID, msg.string()?)?;
                } else {
                    info!("The msg to choose segment was not ready");
                }
            }
            EmulatorResultType::ProverGetHashesForRoundResult { hashes, round } => {
                let save_round = context
                    .globals
                    .get_var(&self.ctx.id, "current_round")?
                    .unwrap()
                    .number()? as u8;
                assert_eq!(save_round, *round);
                for (i, h) in hashes.iter().enumerate() {
                    self.set_input_hex(context, &format!("prover_hash_{}_{}", round, i), h)?;
                }
                context.bitcoin_coordinator.dispatch(
                    self.get_signed_tx(context, &format!("NARY_PROVER_{}", round), 0, 0, true, 0)?,
                    None,
                    Context::ProgramId(self.ctx.id).to_string()?,
                    None,
                )?;
            }
            EmulatorResultType::VerifierChooseSegmentResult { v_decision, round } => {
                let save_round = context
                    .globals
                    .get_var(&self.ctx.id, "current_round")?
                    .unwrap()
                    .number()? as u8;
                assert_eq!(save_round, *round);

                self.set_input_u8(
                    context,
                    &format!("selection_bits_{}", round),
                    *v_decision as u8,
                )?;

                context.bitcoin_coordinator.dispatch(
                    self.get_signed_tx(
                        context,
                        &format!("NARY_VERIFIER_{}", round),
                        0,
                        0,
                        true,
                        0,
                    )?,
                    None,
                    Context::ProgramId(self.ctx.id).to_string()?,
                    None,
                )?;
            }
            EmulatorResultType::ProverFinalTraceResult { final_trace } => {
                info!("Final trace: {:?}", final_trace);

                self.set_input_u32(
                    context,
                    "write_address",
                    final_trace.trace_step.get_write().address,
                )?;
                self.set_input_u32(
                    context,
                    "write_value",
                    final_trace.trace_step.get_write().value,
                )?;
                self.set_input_u32(
                    context,
                    "write_pc",
                    final_trace.trace_step.get_pc().get_address(),
                )?;
                self.set_input_u8(
                    context,
                    "write_micro",
                    final_trace.trace_step.get_pc().get_micro(),
                )?;

                self.set_input_u8(context, "mem_witness", final_trace.mem_witness.byte())?;

                self.set_input_u32(context, "read_1_address", final_trace.read_1.address)?;
                self.set_input_u32(context, "read_1_value", final_trace.read_1.value)?;
                self.set_input_u64(context, "read_1_last_step", final_trace.read_1.last_step)?;
                self.set_input_u32(context, "read_2_address", final_trace.read_2.address)?;
                self.set_input_u32(context, "read_2_value", final_trace.read_2.value)?;
                self.set_input_u64(context, "read_2_last_step", final_trace.read_2.last_step)?;

                self.set_input_u32(
                    context,
                    "read_pc_address",
                    final_trace.read_pc.pc.get_address(),
                )?;
                self.set_input_u8(context, "read_pc_micro", final_trace.read_pc.pc.get_micro())?;
                self.set_input_u32(context, "read_pc_opcode", final_trace.read_pc.opcode)?;
                self.set_input_u64(context, "step_number", final_trace.step_number)?;
                if let Some(witness) = final_trace.witness {
                    self.set_input_u32(context, "witness", witness)?;
                }
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
                let mut index = instruction_names
                    .iter()
                    .position(|i| i == &instruction)
                    .ok_or_else(|| BitVMXError::InstructionNotFound(instruction.to_string()))?;

                if context
                    .globals
                    .get_var(&self.ctx.id, "FAKE_INSTRUCTION")?
                    .is_some()
                {
                    index = 0;
                }

                context.bitcoin_coordinator.dispatch(
                    self.get_signed_tx(context, EXECUTE, 0, index as u32, true, 0)?,
                    None,
                    Context::ProgramId(self.ctx.id).to_string()?,
                    None,
                )?;
            }
            EmulatorResultType::VerifierChooseChallengeResult { challenge } => {
                info!("Verifier choose challenge result: {:?}", challenge);
                let leaf_index: u32;
                let name: &str;

                match challenge {
                    ChallengeType::EntryPoint(trace_read_pc, prover_trace_step, _entrypoint) => {
                        name = "entry_point";
                        info!("Verifier chose {name} challenge");

                        self.set_input_u32(
                            context,
                            &format!("{name}_provided_pc"),
                            trace_read_pc.pc.get_address(),
                        )?;
                        self.set_input_u8(
                            context,
                            &format!("{name}_provided_micro"),
                            trace_read_pc.pc.get_micro(),
                        )?;
                        self.set_input_u64(
                            context,
                            &format!("{name}_provided_step"),
                            *prover_trace_step,
                        )?;
                    }
                    ChallengeType::ProgramCounter(
                        pre_pre_hash,
                        pre_step,
                        prover_step_hash,
                        prover_pc_read,
                    ) => {
                        name = "program_counter";
                        info!("Verifier chose {name} challenge");

                        self.set_input_hex(
                            context,
                            &format!("{name}_prev_prev_hash"),
                            &pre_pre_hash,
                        )?;
                        self.set_input_u32(
                            context,
                            &format!("{name}_prev_write_add"),
                            pre_step.get_write().address,
                        )?;
                        self.set_input_u32(
                            context,
                            &format!("{name}_prev_write_data"),
                            pre_step.get_write().value,
                        )?;
                        self.set_input_u32(
                            context,
                            &format!("{name}_prev_write_pc"),
                            pre_step.get_pc().get_address(),
                        )?;
                        self.set_input_u8(
                            context,
                            &format!("{name}_prev_write_micro"),
                            pre_step.get_pc().get_micro(),
                        )?;
                        self.set_input_u32(
                            context,
                            &format!("{name}_prover_read_pc"),
                            prover_pc_read.pc.get_address(),
                        )?;
                        self.set_input_u8(
                            context,
                            &format!("{name}_prover_read_micro"),
                            prover_pc_read.pc.get_micro(),
                        )?;
                        self.set_input_hex(
                            context,
                            &format!("{name}_prover_prev_hash"),
                            &prover_step_hash,
                        )?;
                    }
                    ChallengeType::TraceHash(
                        prover_prev_hash,
                        prover_trace_step,
                        prover_step_hash,
                    ) => {
                        name = "trace_hash";
                        info!("Verifier chose {name} challenge");

                        self.set_input_hex(context, &format!("{name}_hash"), &prover_step_hash)?;
                        self.set_input_u8(
                            context,
                            &format!("{name}_write_micro"),
                            prover_trace_step.get_pc().get_micro(),
                        )?;
                        self.set_input_u32(
                            context,
                            &format!("{name}_write_pc"),
                            prover_trace_step.get_pc().get_address(),
                        )?;
                        self.set_input_u32(
                            context,
                            &format!("{name}_write_data"),
                            prover_trace_step.get_write().value,
                        )?;
                        self.set_input_u32(
                            context,
                            &format!("{name}_write_add"),
                            prover_trace_step.get_write().address,
                        )?;
                        self.set_input_hex(
                            context,
                            &format!("{name}_prev_hash"),
                            &prover_prev_hash,
                        )?;
                    }
                    ChallengeType::TraceHashZero(prover_trace_step, prover_step_hash) => {
                        name = "trace_hash_zero";
                        info!("Verifier chose {name} challenge");

                        self.set_input_u32(
                            context,
                            &format!("{name}_write_add"),
                            prover_trace_step.get_write().address,
                        )?;
                        self.set_input_u32(
                            context,
                            &format!("{name}_write_data"),
                            prover_trace_step.get_write().value,
                        )?;
                        self.set_input_u8(
                            context,
                            &format!("{name}_write_micro"),
                            prover_trace_step.get_pc().get_micro(),
                        )?;
                        self.set_input_u32(
                            context,
                            &format!("{name}_write_pc"),
                            prover_trace_step.get_pc().get_address(),
                        )?;
                        self.set_input_hex(context, &format!("{name}_hash"), &prover_step_hash)?;
                    }

                    _ => todo!(),
                }

                leaf_index = CHALLENGES
                    .iter()
                    .position(|(n, _)| *n == name)
                    .ok_or_else(|| BitVMXError::ChallengeNotFound(name.to_string()))?
                    as u32;
                info!("Leaf index: {}", leaf_index);
                context.bitcoin_coordinator.dispatch(
                    self.get_signed_tx(context, CHALLENGE, 0, leaf_index, true, 0)?,
                    None,
                    Context::ProgramId(self.ctx.id).to_string()?,
                    None,
                )?;
            }
        }
        Ok(())
    }

    fn get_execution_path(&self) -> Result<String, BitVMXError> {
        let execution_path = format!("runs/{}/{}/", self.role(), self.ctx.id);
        let _ = std::fs::create_dir_all(&execution_path);
        Ok(execution_path)
    }

    fn get_program_definition(
        &self,
        context: &ProgramContext,
    ) -> Result<(ProgramDefinition, String), BitVMXError> {
        let program_definition = context
            .globals
            .get_var(&self.ctx.id, "program_definition")?
            .unwrap()
            .string()?;
        Ok((
            ProgramDefinition::from_config(&program_definition)?,
            program_definition,
        ))
    }

    fn set_input_u8(
        &self,
        context: &ProgramContext,
        name: &str,
        value: u8,
    ) -> Result<(), BitVMXError> {
        self.set_input(context, name, vec![value])
    }

    fn set_input_u32(
        &self,
        context: &ProgramContext,
        name: &str,
        value: u32,
    ) -> Result<(), BitVMXError> {
        self.set_input(context, name, value.to_be_bytes().to_vec())
    }

    fn set_input_u64(
        &self,
        context: &ProgramContext,
        name: &str,
        value: u64,
    ) -> Result<(), BitVMXError> {
        self.set_input(context, name, value.to_be_bytes().to_vec())
    }

    fn set_input_hex(
        &self,
        context: &ProgramContext,
        name: &str,
        value: &str,
    ) -> Result<(), BitVMXError> {
        self.set_input(context, name, hex::decode(value)?)
    }

    fn set_input(
        &self,
        context: &ProgramContext,
        name: &str,
        value: Vec<u8>,
    ) -> Result<(), BitVMXError> {
        context
            .globals
            .set_var(&self.ctx.id, name, VariableTypes::Input(value))?;
        Ok(())
    }
}
