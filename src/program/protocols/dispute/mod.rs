pub mod challenge;
pub mod execution;
pub mod input_handler;
use std::{collections::HashMap, vec};

use bitcoin::{PublicKey, Transaction, Txid};
use bitcoin_coordinator::{coordinator::BitcoinCoordinatorApi, TransactionStatus};
use bitcoin_script_riscv::riscv::instruction_mapping::create_verification_script_mapping;
use bitcoin_script_stack::stack::StackTracker;
use bitvmx_cpu_definitions::{
    challenge::EmulatorResultType,
    memory::MemoryWitness,
    trace::{ProgramCounter, TraceRWStep, TraceRead, TraceReadPC, TraceStep, TraceWrite},
};
use bitvmx_job_dispatcher::dispatcher_job::DispatcherJob;
use bitvmx_job_dispatcher_types::emulator_messages::EmulatorJobType;
use console::style;
use emulator::{
    constants::REGISTERS_BASE_ADDRESS,
    decision::challenge::{ForceChallenge, ForceCondition},
    loader::program_definition::ProgramDefinition,
};
use protocol_builder::{
    builder::{Protocol, ProtocolBuilder},
    graph::graph::GraphOptions,
    scripts::{self, ProtocolScript, SignMode},
    types::{
        connection::{InputSpec, OutputSpec},
        input::{SighashType, SpendMode},
        output::SpeedupData,
        OutputType, Utxo,
    },
};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::{
    bitvmx::Context,
    errors::BitVMXError,
    program::{
        participant::{ParticipantKeys, ParticipantRole, PublicKeyType},
        protocols::{
            claim::ClaimGate,
            dispute::{
                challenge::{challenge_scripts, get_verifier_keys},
                execution::execution_result,
                input_handler::{
                    get_required_keys, get_txs_configuration, split_input, unify_inputs,
                    unify_witnesses,
                },
            },
            protocol_handler::{ProtocolContext, ProtocolHandler},
        },
        variables::VariableTypes,
    },
    types::{ProgramContext, EMULATOR_ID},
};

pub const EXTERNAL_START: &str = "EXTERNAL_START";
pub const EXTERNAL_ACTION: &str = "EXTERNAL_ACTION";
pub const START_CH: &str = "START_CHALLENGE";
pub const INPUT_TX: &str = "INPUT_";
pub const COMMITMENT: &str = "COMMITMENT";
pub const EXECUTE: &str = "EXECUTE";
pub const TIMELOCK_BLOCKS: u16 = 1;
pub const PROVER_WINS: &str = "PROVER_WINS";
pub const VERIFIER_WINS: &str = "VERIFIER_WINS";
pub const ACTION_PROVER_WINS: &str = "ACTION_PROVER_WINS";
pub const CHALLENGE: &str = "CHALLENGE";
pub const TIMELOCK_BLOCKS_KEY: &str = "TIMELOCK_BLOCKS";

pub const TRACE_VARS: [(&str, usize); 16] = [
    ("prover_write_address", 4 as usize),
    ("prover_write_value", 4),
    ("prover_write_pc", 4),
    ("prover_write_micro", 1),
    ("prover_mem_witness", 1),
    ("prover_read_1_address", 4),
    ("prover_read_1_value", 4),
    ("prover_read_1_last_step", 8),
    ("prover_read_2_address", 4),
    ("prover_read_2_value", 4),
    ("prover_read_2_last_step", 8),
    ("prover_read_pc_address", 4),
    ("prover_read_pc_micro", 1),
    ("prover_read_pc_opcode", 4),
    ("prover_step_number", 8),
    ("prover_witness", 4),
];

#[derive(Clone, Serialize, Deserialize)]
pub struct DisputeResolutionProtocol {
    ctx: ProtocolContext,
}

const MIN_RELAY_FEE: u64 = 1;
const DUST: u64 = 500 * MIN_RELAY_FEE;

pub fn protocol_cost() -> u64 {
    32_000 // This is a placeholder value, adjust as needed
}

fn get_role(my_idx: usize) -> ParticipantRole {
    if my_idx == 0 {
        ParticipantRole::Prover
    } else {
        ParticipantRole::Verifier
    }
}

pub fn input_tx_name(index: u32) -> String {
    format!("INPUT_{}", index)
}
pub fn program_input(index: u32) -> String {
    format!("program_input_{}", index)
}

pub fn program_input_prev_protocol(index: u32) -> String {
    format!("program_input_prev_protocol_{}", index)
}

pub fn program_input_prev_prefix(index: u32) -> String {
    format!("program_input_prev_prefix_{}", index)
}

pub fn program_input_word(index: u32, word: u32) -> String {
    format!("program_input_{}_{}", index, word)
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

        let aggregated_1 = program_context.key_chain.derive_keypair()?;

        let speedup = program_context.key_chain.derive_keypair()?;

        program_context
            .globals
            .set_var(&self.ctx.id, "speedup", VariableTypes::PubKey(speedup))?;

        let mut keys = vec![
            ("aggregated_1".to_string(), aggregated_1.into()),
            ("speedup".to_string(), speedup.into()),
        ];

        for required_input in
            get_required_keys(&self.ctx.id, &program_def, program_context, &self.role())?
        {
            let key = program_context.key_chain.derive_winternitz_hash160(4)?;
            keys.push((required_input, key.into()));
        }

        let key_chain = &mut program_context.key_chain;

        if self.role() == ParticipantRole::Prover {
            let last_step = key_chain.derive_winternitz_hash160(8)?;
            keys.push(("prover_last_step".to_string(), last_step.into()));

            let last_hash = key_chain.derive_winternitz_hash160(20)?;
            keys.push(("prover_last_hash".to_string(), last_hash.into()));

            for (name, size) in TRACE_VARS {
                let key = key_chain.derive_winternitz_hash160(size)?;
                keys.push((name.to_string(), key.into()));
            }
        }

        if self.role() == ParticipantRole::Verifier {
            keys.extend_from_slice(
                get_verifier_keys()
                    .iter()
                    .map(|(name, size)| {
                        let key = key_chain.derive_winternitz_hash160(*size).unwrap();
                        (name.to_string(), PublicKeyType::Winternitz(key))
                    })
                    .collect::<Vec<(String, PublicKeyType)>>()
                    .as_slice(),
            );
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

    fn get_transaction_by_name(
        &self,
        name: &str,
        context: &ProgramContext,
    ) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
        if name.starts_with(INPUT_TX) {
            let index = name.strip_prefix(INPUT_TX).unwrap().parse::<u32>()?;
            return self.input_tx(index, context);
        }

        match name {
            START_CH => Ok(self.add_speedup_data(name, context, self.start_challenge(context)?)?),
            _ => Err(BitVMXError::InvalidTransactionName(name.to_string())),
        }
    }

    fn notify_news(
        &self,
        tx_id: Txid,
        vout: Option<u32>,
        tx_status: TransactionStatus,
        _context: String,
        program_context: &ProgramContext,
        participant_keys: Vec<&ParticipantKeys>,
    ) -> Result<(), BitVMXError> {
        let name = self.get_transaction_name_by_id(tx_id)?;
        info!(
            "Program {}: Transaction name: {}  id: {}:{:?} has been seen on-chain {}",
            self.ctx.id,
            style(&name).blue(),
            style(&tx_id).green(),
            style(&vout).yellow(),
            self.role()
        );

        let (fail_config_prover, fail_config_verifier, force, force_condition) = program_context
            .globals
            .get_var(&self.ctx.id, "fail_force_config")?
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
                get_txs_configuration(&self.ctx.id, program_context)?;

            let owner = input_txs[idx as usize].as_str();

            if owner == self.role().to_string() {
                //if I'm the prover and it's the last input
                if self.role() == ParticipantRole::Prover && idx == last_tx_id {
                    let (def, program_definition) = self.get_program_definition(program_context)?;
                    let full_input = unify_inputs(&self.ctx.id, program_context, &def)?;

                    let execution_path = self.get_execution_path()?;
                    let msg = serde_json::to_string(&DispatcherJob {
                        job_id: self.ctx.id.to_string(),
                        job_type: EmulatorJobType::ProverExecute(
                            program_definition,
                            full_input,
                            execution_path.clone(),
                            format!("{}/{}", execution_path, "execution.json").to_string(),
                            fail_config_prover.clone(),
                        ),
                    })?;
                    program_context.broker_channel.send(EMULATOR_ID, msg)?;
                }
            } else {
                //if it's not my input, decode the witness
                self.decode_witness_from_speedup(
                    tx_id,
                    vout.unwrap(),
                    &name,
                    program_context,
                    &participant_keys,
                    &tx_status.tx,
                    None,
                )?;

                unify_witnesses(&self.ctx.id, program_context, idx as usize)?;
            }
        }

        if name == COMMITMENT && self.role() == ParticipantRole::Verifier && vout.is_some() {
            self.decode_witness_from_speedup(
                tx_id,
                vout.unwrap(),
                &name,
                program_context,
                &participant_keys,
                &tx_status.tx,
                None,
            )?;

            let execution_path = self.get_execution_path()?;

            let (def, program_definition) = self.get_program_definition(program_context)?;
            let input_program = unify_inputs(&self.ctx.id, program_context, &def)?;

            let last_hash = program_context
                .witness
                .get_witness(&self.ctx.id, "prover_last_hash")?
                .unwrap()
                .winternitz()?
                .message_bytes();

            let last_step = program_context
                .witness
                .get_witness(&self.ctx.id, "prover_last_step")?
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

        if name == COMMITMENT || name.starts_with("NARY_VERIFIER") && vout.is_some() {
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
                    self.decode_witness_from_speedup(
                        tx_id,
                        vout.unwrap(),
                        &name,
                        program_context,
                        &participant_keys,
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
                    info!(
                        "Current block: {}",
                        tx_status.block_info.as_ref().unwrap().height
                    );
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

        if (name.starts_with("NARY_PROVER"))
            && self.role() == ParticipantRole::Verifier
            && vout.is_some()
        {
            self.decode_witness_from_speedup(
                tx_id,
                vout.unwrap(),
                &name,
                program_context,
                &participant_keys,
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

        if name == EXECUTE && self.role() == ParticipantRole::Verifier && vout.is_some() {
            self.decode_witness_from_speedup(
                tx_id,
                vout.unwrap(),
                &name,
                program_context,
                &participant_keys,
                &tx_status.tx,
                None,
            )?;
            let (_program_definition, pdf) = self.get_program_definition(program_context)?;
            let execution_path = self.get_execution_path()?;

            let mut values = std::collections::HashMap::new();

            for (name, _) in TRACE_VARS.iter() {
                if *name == "prover_witness" {
                    continue;
                }
                if let Some(value) = program_context.witness.get_witness(&self.ctx.id, name)? {
                    values.insert(*name, value.winternitz().unwrap().message_bytes());
                } else {
                    return Err(BitVMXError::VariableNotFound(self.ctx.id, name.to_string()));
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
            let read_pc =
                TraceReadPC::new(program_counter, to_u32(&values["prover_read_pc_opcode"]));
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

        if name == EXECUTE && self.role() == ParticipantRole::Prover && vout.is_some() {
            let tx = self.get_signed_tx(
                program_context,
                &ClaimGate::tx_start(PROVER_WINS),
                0,
                0,
                false,
                0,
            )?;
            info!("PROVER_WINS_TX: {:?}", tx);
            let speedup_data = self.get_speedup_data_from_tx(&tx, program_context, None)?;
            program_context.bitcoin_coordinator.dispatch(
                tx,
                Some(speedup_data),
                //prover-win-start is input 1
                Context::ProgramId(self.ctx.id).to_string()?,
                None,
            )?;
        }

        if name == ClaimGate::tx_start(PROVER_WINS) && self.role() == ParticipantRole::Prover {
            info!("Prover wins SUCCESS dispatch");
            let timelock_blocks = program_context
                .globals
                .get_var(&self.ctx.id, "TIMELOCK_BLOCKS")?
                .unwrap()
                .number()?;

            let prover_wins_tx = self.get_signed_tx(
                program_context,
                &ClaimGate::tx_success(PROVER_WINS),
                0,
                1,
                false,
                0,
            )?;
            let speedup_data =
                self.get_speedup_data_from_tx(&prover_wins_tx, program_context, None)?;
            program_context.bitcoin_coordinator.dispatch(
                prover_wins_tx,
                Some(speedup_data),
                Context::ProgramId(self.ctx.id).to_string()?,
                Some(tx_status.block_info.as_ref().unwrap().height + timelock_blocks),
            )?;
        }

        if name == ClaimGate::tx_success(PROVER_WINS) && self.role() == ParticipantRole::Prover {
            //Execute actions.
            //Could execute more than one
            info!("Prover. Execute Action");
            let prover_wins_action_tx =
                self.get_signed_tx(program_context, ACTION_PROVER_WINS, 0, 0, false, 1)?;
            let speedup_data =
                self.get_speedup_data_from_tx(&prover_wins_action_tx, program_context, None)?;

            program_context.bitcoin_coordinator.dispatch(
                prover_wins_action_tx,
                Some(speedup_data),
                Context::ProgramId(self.ctx.id).to_string()?,
                None,
            )?;
        }

        if name == CHALLENGE && self.role() == ParticipantRole::Prover && vout.is_some() {
            self.decode_witness_from_speedup(
                tx_id,
                vout.unwrap(),
                &name,
                program_context,
                &participant_keys,
                &tx_status.tx,
                None,
            )?;
            //TODO: if the verifier is able to execute the challenge, the prover can react only to the read challenge nary search
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

        let speedup_dust = DUST;
        let fee = DUST;

        let (prover_signs, verifier_signs) = if self.role() == ParticipantRole::Prover {
            (SignMode::Single, SignMode::Skip)
        } else {
            (SignMode::Skip, SignMode::Single)
        };

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

        let input_in_speedup = true;
        let prover_speedup_pub = keys[0].get_public("speedup")?;
        context.globals.set_var(
            &self.ctx.id,
            "prover_speedup_pub",
            VariableTypes::PubKey(prover_speedup_pub.clone()),
        )?;
        let verifier_speedup_pub = keys[1].get_public("speedup")?;
        context.globals.set_var(
            &self.ctx.id,
            "verifier_speedup_pub",
            VariableTypes::PubKey(verifier_speedup_pub.clone()),
        )?;
        let aggregated = computed_aggregated.get("aggregated_1").unwrap();
        let (agg_or_prover, agg_or_verifier, sign_mode) = if input_in_speedup {
            (prover_speedup_pub, verifier_speedup_pub, SignMode::Single)
        } else {
            (aggregated, aggregated, SignMode::Aggregate)
        };

        let program_def = self.get_program_definition(context)?;

        let mut protocol = self.load_or_create_protocol();

        let mut amount = utxo.2.unwrap();
        info!("Protocol amount: {}", amount);
        let output_type = utxo.3.unwrap();

        protocol.add_external_transaction(EXTERNAL_START)?;
        protocol.add_unknown_outputs(EXTERNAL_START, utxo.1)?;
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

        let pb = ProtocolBuilder {};
        pb.add_speedup_output(&mut protocol, START_CH, speedup_dust, verifier_speedup_pub)?;

        amount = self.checked_sub(amount, speedup_dust)?;

        amount = self.checked_sub(amount, fee)?;

        amount = self.checked_sub(amount, ClaimGate::cost(fee, speedup_dust, 1, 1))?;
        amount = self.checked_sub(amount, ClaimGate::cost(fee, speedup_dust, 1, 1))?;

        let timelock_blocks = context
            .globals
            .get_var(&self.ctx.id, TIMELOCK_BLOCKS_KEY)?
            .unwrap()
            .number()? as u16;

        let mut prev_tx = START_CH.to_string();
        let mut input_tx = String::new();

        let (input_txs, input_txs_sizes, input_txs_offsets, _) =
            get_txs_configuration(&self.ctx.id, context)?;

        //TODO: remove this
        context.globals.set_var(
            &self.ctx.id,
            "input_words",
            VariableTypes::Number(input_txs_sizes[0]),
        )?;
        for (idx, tx_owner) in input_txs.iter().enumerate() {
            if tx_owner == "skip" || tx_owner == "prover_prev" {
                continue;
            }
            input_tx = format!("INPUT_{}", idx);

            let words = input_txs_sizes[idx];
            let offset = input_txs_offsets[idx];

            let owner = if tx_owner == "verifier" {
                "verifier"
            } else {
                "prover"
            };

            let input_vars = (offset..offset + words)
                .map(|i| format!("{}_program_input_{}", owner, i))
                .collect::<Vec<_>>();
            //TODO: Handle prover cosigning (in the script check and automatic reply to news)
            self.add_connection_with_scripts(
                context,
                aggregated,
                &mut protocol,
                timelock_blocks,
                amount,
                speedup_dust,
                &prev_tx,
                &input_tx,
                None,
                Self::winternitz_check(agg_or_prover, sign_mode, &keys[0], &input_vars)?,
                input_in_speedup,
                (&prover_speedup_pub, &verifier_speedup_pub),
            )?;

            amount = self.checked_sub(amount, fee)?;
            amount = self.checked_sub(amount, speedup_dust)?;
            prev_tx = input_tx.clone();
        }

        let claim_prover = ClaimGate::new(
            &mut protocol,
            START_CH,
            PROVER_WINS,
            (prover_speedup_pub, prover_signs),
            aggregated,
            fee,
            speedup_dust,
            vec![verifier_speedup_pub],
            None,
            timelock_blocks,
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
        protocol.add_unknown_outputs(EXTERNAL_ACTION, utxo_prover_win_action.1)?;
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
        pb.add_speedup_output(
            &mut protocol,
            ACTION_PROVER_WINS,
            speedup_dust,
            &prover_speedup_pub,
        )?;

        let claim_verifier = ClaimGate::new(
            &mut protocol,
            START_CH,
            VERIFIER_WINS,
            (verifier_speedup_pub, verifier_signs),
            aggregated,
            fee,
            speedup_dust,
            vec![prover_speedup_pub],
            None,
            timelock_blocks,
            vec![aggregated],
        )?;

        self.add_connection_with_scripts(
            context,
            aggregated,
            &mut protocol,
            timelock_blocks,
            amount,
            speedup_dust,
            &input_tx,
            COMMITMENT,
            Some(&claim_verifier),
            Self::winternitz_check(
                agg_or_prover,
                sign_mode,
                &keys[0],
                &vec!["prover_last_step", "prover_last_hash"],
            )?,
            input_in_speedup,
            (&prover_speedup_pub, &verifier_speedup_pub),
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

            self.add_connection_with_scripts(
                context,
                aggregated,
                &mut protocol,
                timelock_blocks,
                amount,
                speedup_dust,
                &prev,
                &next,
                Some(&claim_verifier),
                Self::winternitz_check(
                    agg_or_prover,
                    sign_mode,
                    &keys[0],
                    &vars.iter().map(|s| s.as_str()).collect::<Vec<&str>>(),
                )?,
                input_in_speedup,
                (&prover_speedup_pub, &verifier_speedup_pub),
            )?;
            amount = self.checked_sub(amount, fee)?;
            amount = self.checked_sub(amount, speedup_dust)?;

            prev = next;
            let next = format!("NARY_VERIFIER_{}", i);
            //TODO: Add a lower than value check
            let _bits = nary_def.bits_for_round(i);

            self.add_connection_with_scripts(
                context,
                aggregated,
                &mut protocol,
                timelock_blocks,
                amount,
                speedup_dust,
                &prev,
                &next,
                Some(&claim_prover),
                Self::winternitz_check(
                    agg_or_verifier,
                    sign_mode,
                    &keys[1],
                    &vec![&format!("selection_bits_{}", i)],
                )?,
                input_in_speedup,
                (&verifier_speedup_pub, &prover_speedup_pub),
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

        self.add_connection_with_scripts(
            context,
            aggregated,
            &mut protocol,
            timelock_blocks,
            amount,
            speedup_dust,
            &prev,
            EXECUTE,
            Some(&claim_verifier),
            self.execute_script(context, agg_or_prover, sign_mode, &keys[0], &vars)?,
            input_in_speedup,
            (&prover_speedup_pub, &verifier_speedup_pub),
        )?;

        //Add this as if it were the final tx execution
        claim_prover.add_claimer_win_connection(&mut protocol, EXECUTE)?;

        info!(
            "Amount {}, fee {}, speedup_dust {}",
            amount, fee, speedup_dust
        );
        amount -= fee;
        amount -= speedup_dust;

        let (program_def, _) = self.get_program_definition(context)?;
        self.add_connection_with_scripts(
            context,
            aggregated,
            &mut protocol,
            timelock_blocks,
            amount,
            speedup_dust,
            EXECUTE,
            CHALLENGE,
            Some(&claim_prover),
            challenge_scripts(
                &self.ctx.id,
                self.role(),
                &program_def,
                context,
                agg_or_verifier,
                sign_mode,
                &keys,
            )?,
            input_in_speedup,
            (&verifier_speedup_pub, &prover_speedup_pub),
        )?;

        protocol.build(&context.key_chain.key_manager, &self.ctx.protocol_name)?;
        info!("\n{}", protocol.visualize(GraphOptions::EdgeArrows)?);
        self.save_protocol(protocol)?;

        Ok(())
    }

    fn setup_complete(&self, _program_context: &ProgramContext) -> Result<(), BitVMXError> {
        // This is called after the protocol is built and ready to be used
        info!(
            "DisputeResolutionProtocol setup complete for program {}",
            self.ctx.id
        );
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

    fn get_speedup_key_for(
        &self,
        context: &ProgramContext,
        role: &str,
    ) -> Result<PublicKey, BitVMXError> {
        Ok(context
            .globals
            .get_var(&self.ctx.id, &format!("{role}_speedup_pub"))?
            .unwrap()
            .pubkey()?)
    }

    fn utxo_from(&self, tx: &Transaction, vout: u32, key: &PublicKey) -> Utxo {
        let txid = tx.compute_txid();
        let amount = tx.output[vout as usize].value.to_sat();
        Utxo::new(txid, vout, amount, key)
    }

    fn partial_utxo_from(&self, tx: &Transaction, vout: u32) -> (Txid, u32, u64) {
        let txid = tx.compute_txid();
        let amount = tx.output[vout as usize].value.to_sat();
        (txid, vout, amount)
    }

    //TODO: unify with the speedup in  protocol_handler
    fn add_speedup_data(
        &self,
        name: &str,
        context: &ProgramContext,
        tx: Transaction,
    ) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
        let (vout, role) = match name {
            START_CH => (0, "verifier"),
            _ => todo!("Speedup data not implemented for transaction: {}", name),
        };

        let speedup_data = self
            .utxo_from(&tx, vout, &self.get_speedup_key_for(context, role)?)
            .into();
        Ok((tx, Some(speedup_data)))
    }

    pub fn start_challenge(&self, context: &ProgramContext) -> Result<Transaction, BitVMXError> {
        self.get_signed_tx(context, START_CH, 0, 1, false, 0)
    }

    pub fn get_tx_with_speedup_data(
        &self,
        context: &ProgramContext,
        name: &str,
        _input_index: u32,
        leaf_index: u32,
        leaf_identification: bool,
    ) -> Result<(Transaction, SpeedupData), BitVMXError> {
        let tx = self.get_signed_tx(context, name, 0, 0, leaf_identification, 0)?;
        let protocol = self.load_protocol()?;
        let (output_type, scripts) = protocol.get_script_from_output(name, 0)?;
        info!("Scripts length: {}", scripts.len());
        let wots_sigs =
            self.get_winternitz_signature_for_script(&scripts[leaf_index as usize], context)?;

        let speedup_data = SpeedupData::new_with_input(
            self.partial_utxo_from(&tx, 0),
            output_type,
            wots_sigs,
            leaf_index as usize,
            true,
        );

        Ok((tx, speedup_data))
    }

    pub fn input_tx(
        &self,
        idx: u32,
        context: &ProgramContext,
    ) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
        split_input(&self.ctx.id, idx, context)?;

        let (tx, sp) = self.get_tx_with_speedup_data(context, &input_tx_name(idx), 0, 0, true)?;

        Ok((tx, Some(sp)))
    }

    fn winternitz_check<T: AsRef<str> + std::fmt::Debug>(
        aggregated: &PublicKey,
        sign_mode: SignMode,
        keys: &ParticipantKeys,
        var_names: &Vec<T>,
    ) -> Result<Vec<ProtocolScript>, BitVMXError> {
        info!("Winternitz check for variables: {:?}", &var_names);
        let names_and_keys = var_names
            .iter()
            .map(|v| (v, keys.get_winternitz(v.as_ref()).unwrap()))
            .collect();

        let winternitz_check =
            scripts::verify_winternitz_signatures(aggregated, &names_and_keys, sign_mode)?;

        Ok(vec![winternitz_check])
    }

    fn execute_script(
        &self,
        context: &ProgramContext,
        aggregated: &PublicKey,
        sign_mode: SignMode,
        keys: &ParticipantKeys,
        var_names: &Vec<&str>,
    ) -> Result<Vec<ProtocolScript>, BitVMXError> {
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
        let step_n = stack.move_var(stackvars["prover_step_number"]);
        stack.drop(step_n);
        let stripped = stack.move_var_sub_n(stackvars["prover_write_micro"], 0);
        stack.drop(stripped);
        let stripped = stack.move_var_sub_n(stackvars["prover_read_pc_micro"], 0);
        stack.drop(stripped);
        let last_step_1 = stack.move_var(stackvars["prover_read_1_last_step"]);
        stack.drop(last_step_1);
        let last_step_2 = stack.move_var(stackvars["prover_read_2_last_step"]);
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
                sign_mode,
                true,
                Some(vec![
                    reverse_script.clone(),
                    strip_script.clone(),
                    script.clone(),
                ]),
            )?;
            winternitz_check_list.push(winternitz_check);
        }

        Ok(winternitz_check_list)
    }

    pub fn add_connection_with_scripts(
        &self,
        context: &ProgramContext,
        aggregated: &PublicKey,
        protocol: &mut Protocol,
        timelock_blocks: u16,
        amount: u64,
        amount_speedup: u64,
        from: &str,
        to: &str,
        claim_gate: Option<&ClaimGate>,
        mut leaves: Vec<ProtocolScript>,
        input_in_speedup: bool,
        speedup_keys: (&PublicKey, &PublicKey),
    ) -> Result<(), BitVMXError> {
        //TODO:
        // - Support multiple inputs
        // - check if input is prover of verifier and use proper keys[n]
        // - the prover needs to re-sign any verifier provided input (so the equivocation is possible on reads)

        info!(
            "Adding winternitz check for {} to {}. Amount: {}. Leaves {}",
            style(from).green(),
            style(to).green(),
            style(amount).green(),
            style(leaves.len()).yellow()
        );

        let (mine_speedup, other_speedup) = speedup_keys;
        let timeout_input = if input_in_speedup {
            scripts::timelock(timelock_blocks, &*other_speedup, SignMode::Aggregate)
        } else {
            scripts::timelock(timelock_blocks, &aggregated, SignMode::Aggregate)
        };

        leaves.push(timeout_input);
        for (pos, leave) in leaves.iter_mut().enumerate() {
            leave.set_assert_leaf_id(pos as u32);
        }

        let (leaves, leaves_speedup) = if input_in_speedup {
            let mut connection_flow = scripts::check_signature(aggregated, SignMode::Aggregate);
            connection_flow.set_assert_leaf_id(0);
            let mut timeout_flow =
                scripts::timelock(timelock_blocks, &aggregated, SignMode::Aggregate);
            timeout_flow.set_assert_leaf_id(1);
            let flow_leaves = vec![connection_flow, timeout_flow];
            (flow_leaves, Some(leaves))
        } else {
            (leaves, None)
        };

        let output_type = OutputType::taproot(amount, &hardcoded_unspendable(), &leaves)?;
        //sign all except the timeout
        let scripts_to_sign = (0..leaves.len() - 2).collect::<Vec<_>>();

        protocol.add_connection(
            &format!("{}__{}", from, to),
            from,
            output_type.clone().into(),
            to,
            InputSpec::Auto(
                SighashType::taproot_all(),
                SpendMode::Scripts {
                    leaves: scripts_to_sign,
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
                SpendMode::Script {
                    //sign timeout only
                    leaf: leaves.len() - 1,
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
        if input_in_speedup {
            let output_type = OutputType::taproot(
                amount_speedup,
                &hardcoded_unspendable(),
                &leaves_speedup.unwrap(),
            )?;
            protocol.add_transaction_output(to, &output_type)?;
            let last = protocol.get_output_count(to)? - 1;
            self.add_vout_to_monitor(context, to, last)?;
        } else {
            pb.add_speedup_output(protocol, to, amount_speedup, mine_speedup)?;
        }

        pb.add_speedup_output(
            protocol,
            &format!("{}_TO", to),
            amount_speedup,
            other_speedup,
        )?;

        Ok(())
    }

    pub fn execution_result(
        &self,
        result: &EmulatorResultType,
        context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        execution_result(&self.ctx.id, &self, result, context)
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
}

pub fn hardcoded_unspendable() -> PublicKey {
    // hardcoded unspendable
    let key_bytes =
        hex::decode("02f286025adef23a29582a429ee1b201ba400a9c57e5856840ca139abb629889ad")
            .expect("Invalid hex input");
    PublicKey::from_slice(&key_bytes).expect("Invalid public key")
}
