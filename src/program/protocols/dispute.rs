use std::collections::HashMap;

use bitcoin::{PublicKey, Transaction, Txid};
use bitcoin_coordinator::{coordinator::BitcoinCoordinatorApi, TransactionStatus};
use bitcoin_script_riscv::riscv::instruction_mapping::create_verification_script_mapping;
use bitcoin_script_stack::stack::StackTracker;
use bitvmx_cpu_definitions::challenge::EmulatorResultType;
use bitvmx_job_dispatcher::dispatcher_job::DispatcherJob;
use bitvmx_job_dispatcher_types::emulator_messages::EmulatorJobType;
use emulator::{constants::REGISTERS_BASE_ADDRESS, loader::program_definition::ProgramDefinition};
use key_manager::winternitz::{message_bytes_length, WinternitzType};
use protocol_builder::{
    builder::{Protocol, ProtocolBuilder},
    errors::ProtocolBuilderError,
    scripts::{self, SignMode},
    types::{
        input::{LeafSpec, SighashType},
        output::SpendMode,
        InputArgs, OutputType,
    },
};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::{
    bitvmx::Context,
    errors::BitVMXError,
    program::{
        participant::ParticipantRole,
        protocols::slot::external_fund_tx,
        variables::{VariableTypes, WitnessTypes},
        witness,
    },
    types::{ProgramContext, EMULATOR_ID},
};

use super::{
    super::participant::ParticipantKeys,
    protocol_handler::{ProtocolContext, ProtocolHandler},
};

pub const START_CH: &str = "START_CHALLENGE";
pub const INPUT_1: &str = "INPUT_1";
pub const COMMITMENT: &str = "COMMITMENT";
pub const EXECUTE: &str = "EXECUTE";

pub const TRACE_VARS: [(&str, usize); 15] = [
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
    ("witness", 4),
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
            START_CH => Ok(self.start_challenge()?),
            INPUT_1 => Ok(self.input_1_tx(context)?),
            _ => Err(BitVMXError::InvalidTransactionName(name.to_string())),
        }
    }

    fn notify_news(
        &self,
        tx_id: Txid,
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

        //TODO: generalize decoding
        if name == INPUT_1 && self.role() == ParticipantRole::Prover {
            //TODO: Check if the last input
            //only then execute the program.

            let program_definition = program_context
                .globals
                .get_var(&self.ctx.id, "program_definition")?
                .string()?;

            let input_program = program_context
                .globals
                .get_var(&self.ctx.id, "program_input")?
                .input()?;

            let execution_path = self.get_execution_path()?;
            let msg = serde_json::to_string(&DispatcherJob {
                job_id: self.ctx.id.to_string(),
                job_type: EmulatorJobType::ProverExecute(
                    program_definition,
                    input_program,
                    execution_path.clone(),
                    format!("{}/{}", execution_path, "execution.json").to_string(),
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
            )?;
        }

        if name == COMMITMENT && self.role() == ParticipantRole::Verifier {
            self.decode_witness_for_tx(
                &name,
                0,
                program_context,
                &participant_keys[0],
                &tx_status.tx,
            )?;

            let program_definition = program_context
                .globals
                .get_var(&self.ctx.id, "program_definition")?
                .string()?;

            let execution_path = self.get_execution_path()?;
            let words = program_context
                .globals
                .get_var(&self.ctx.id, "input_words")?
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
                ),
            })?;

            program_context.broker_channel.send(EMULATOR_ID, msg)?;
        }

        if (name == COMMITMENT || name.starts_with("NARY_VERIFIER"))
            && self.role() == ParticipantRole::Prover
        {
            let mut round = name
                .strip_prefix("NARY_VERIFIER_")
                .unwrap_or("0")
                .parse::<u32>()
                .unwrap();

            let decision = if name == COMMITMENT {
                0
            } else {
                self.decode_witness_for_tx(
                    &name,
                    0,
                    program_context,
                    &participant_keys[1],
                    &tx_status.tx,
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

            let (program_definition, pdf) = self.get_program_definition(program_context)?;
            let nary = program_definition.nary_def();
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
                    ),
                })?;
                program_context.broker_channel.send(EMULATOR_ID, msg)?;
            }
        }

        if (name.starts_with("NARY_PROVER")) && self.role() == ParticipantRole::Verifier {
            self.decode_witness_for_tx(
                &name,
                0,
                program_context,
                &participant_keys[0],
                &tx_status.tx,
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
                ),
            })?;

            if round > 1 {
                program_context.broker_channel.send(EMULATOR_ID, msg)?;
            } else {
                if let Ok(_ready) = program_context
                    .globals
                    .get_var(&self.ctx.id, "execution-check-ready")
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
            )?;
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
        let fee = context.globals.get_var(&self.ctx.id, "FEE")?.number()? as u64;
        let speedup_dust = 500;
        const TIMELOCK_BLOCKS: u16 = 10;

        let utxo = context.globals.get_var(&self.ctx.id, "utxo")?.utxo()?;

        let program_def = self.get_program_definition(context)?;

        let external_aggregated = context
            .globals
            .get_var(&self.ctx.id, "aggregated")?
            .pubkey()?;

        let mut protocol = self.load_or_create_protocol();

        let mut amount = utxo.2.unwrap();
        let output_type = external_fund_tx(&external_aggregated, amount)?;

        protocol.add_external_connection(
            utxo.0,
            utxo.1,
            output_type,
            START_CH,
            &SighashType::taproot_all(),
        )?;

        let aggregated = computed_aggregated.get("aggregated_1").unwrap();
        amount -= fee;

        let words = context
            .globals
            .get_var(&self.ctx.id, "input_words")?
            .number()?;

        let input_vars = (0..words)
            .map(|i| format!("program_input_{}", i))
            .collect::<Vec<_>>();
        let input_vars_slice = input_vars.iter().map(|s| s.as_str()).collect::<Vec<&str>>();

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
        )?;
        amount -= fee;
        amount -= speedup_dust;

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
        )?;
        amount -= fee;
        amount -= speedup_dust;

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
            )?;
            amount -= fee;
            amount -= speedup_dust;

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
            )?;
            amount -= fee;
            amount -= speedup_dust;
            prev = next;
        }

        //Simple execution check
        let vars = TRACE_VARS
            .iter()
            .take(TRACE_VARS.len() - 1) // Skip the witness (except is needed)
            //.rev() //reverse to get the proper order on the stack
            .map(|(name, _)| *name)
            .collect::<Vec<&str>>();

        self.add_winternitz_and_script(
            aggregated,
            &mut protocol,
            TIMELOCK_BLOCKS,
            &keys[0],
            amount,
            amount - fee,
            &vars,
            &prev,
            EXECUTE,
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

    pub fn start_challenge(&self) -> Result<Transaction, ProtocolBuilderError> {
        let signature = self
            .load_protocol()?
            .input_taproot_key_spend_signature(START_CH, 0)?
            .unwrap();
        let mut taproot_arg = InputArgs::new_taproot_key_args();
        taproot_arg.push_taproot_signature(signature)?;

        self.load_protocol()?
            .transaction_to_send(START_CH, &[taproot_arg])
    }

    pub fn input_1_tx(&self, context: &ProgramContext) -> Result<Transaction, BitVMXError> {
        //TODO: concatenate all inputs
        let words = context
            .globals
            .get_var(&self.ctx.id, "input_words")?
            .number()?;

        let full_input = context
            .globals
            .get_var(&self.ctx.id, "program_input")?
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

        self.get_signed_tx(context, INPUT_1, 0, 0)
    }

    pub fn get_signed_tx(
        &self,
        context: &ProgramContext,
        name: &str,
        input_index: u32,
        leaf_index: u32,
    ) -> Result<Transaction, BitVMXError> {
        let protocol = self.load_protocol()?;

        let signature = protocol
            .input_taproot_script_spend_signature(name, input_index as usize, leaf_index as usize)?
            .unwrap();
        let spend = protocol.get_script_to_spend(name, input_index, leaf_index)?;
        let mut spending_args =
            InputArgs::new_taproot_script_args(LeafSpec::Index(leaf_index as usize));

        for k in spend.get_keys().iter().rev() {
            let message = context.globals.get_var(&self.ctx.id, k.name())?.input()?;

            info!("Signigng message: {}", hex::encode(message.clone()));
            info!("With key: {:?}", k);

            let winternitz_signature = context.key_chain.key_manager.sign_winternitz_message(
                &message,
                WinternitzType::HASH160,
                spend.get_key(k.name()).unwrap().derivation_index(),
            )?;

            spending_args.push_winternitz_signature(winternitz_signature);
        }

        spending_args.push_taproot_signature(signature)?;

        Ok(protocol.transaction_to_send(name, &[spending_args])?)
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
    ) -> Result<(), BitVMXError> {
        //TODO:
        // - Define one input for the inputs defined in the program
        // - check a way to use input name "global.var_name" to get inputs from previous defined values
        // - check if input is prover of verifier and use propero keys[n]
        // - use the dame logic in generate keys to define the proper amount of winternitz keys
        // - use proper size from config mapped in 4 bytes word
        // - in timelock use secret to avoid the other part to spend the utxo (but is this needed, why the other part would consume it?)
        // - the prover needs to resingn any verifier provided input (so the equivocation is possible on reads)
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

        let output_type = OutputType::taproot(
            amount,
            aggregated,
            &[winternitz_check, timeout],
            &SpendMode::All {
                key_path_sign: SignMode::Aggregate,
            },
            &vec![],
        )?;

        protocol.add_connection(
            &format!("{}_{}", from, to),
            from,
            to,
            &output_type,
            &SighashType::taproot_all(),
        )?;

        let pb = ProtocolBuilder {};
        //put the amount here as there is no output yet
        pb.add_speedup_output(protocol, to, amount_speedup, aggregated)?;
        Ok(())
    }

    pub fn add_winternitz_and_script(
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
    ) -> Result<(), BitVMXError> {
        info!("Adding winternitz check for {} to {}", from, to);
        info!("Amount: {}", amount);
        info!("Speedup: {}", amount_speedup);
        let names_and_keys = var_names
            .iter()
            .map(|v| (*v, keys.get_winternitz(v).unwrap()))
            .collect();

        //TODO: Create full mapping. Add a check to identify the leaf
        let mapping = create_verification_script_mapping(REGISTERS_BASE_ADDRESS);
        let verification_script = mapping["ecall"].0.clone();

        //TOODO: This is a workacround to inverse the order of the stack
        let mut stack = StackTracker::new();
        let all = stack.define(110, "all");
        for i in 1..110 {
            stack.move_var_sub_n(all, 110 - i - 1);
        }
        let reverse_script = stack.get_script();

        //TODO: This is a workaround to remove one nibble from the micro instructions
        //and drop the last steps. (this can be avoided)
        let mut stack = StackTracker::new();
        let mut stackvars = HashMap::new();
        for (name, size) in TRACE_VARS.iter().take(TRACE_VARS.len() - 1) {
            stackvars.insert(*name, stack.define((size * 2) as u32, name));
        }
        let stripped = stack.move_var_sub_n(stackvars["write_micro"], 0);
        stack.drop(stripped);
        let stripped = stack.move_var_sub_n(stackvars["read_pc_micro"], 0);
        stack.drop(stripped);
        let last_step_1 = stack.move_var(stackvars["read_1_last_step"]);
        stack.drop(last_step_1);
        let last_step_2 = stack.move_var(stackvars["read_2_last_step"]);
        stack.drop(last_step_2);
        let strip_script = stack.get_script();

        let winternitz_check = scripts::verify_winternitz_signatures_aux(
            aggregated,
            &names_and_keys,
            SignMode::Aggregate,
            true,
            Some(vec![reverse_script, strip_script, verification_script]),
        )?;

        let timeout = scripts::timelock(timelock_blocks, &aggregated, SignMode::Aggregate);

        let output_type = OutputType::taproot(
            amount,
            aggregated,
            &[winternitz_check, timeout],
            &SpendMode::All {
                key_path_sign: SignMode::Aggregate,
            },
            &vec![],
        )?;

        protocol.add_connection(
            &format!("{}_{}", from, to),
            from,
            to,
            &output_type,
            &SighashType::taproot_all(),
        )?;

        let pb = ProtocolBuilder {};
        //put the amount here as there is no output yet
        pb.add_speedup_output(protocol, to, amount_speedup, aggregated)?;
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
                    self.get_signed_tx(context, COMMITMENT, 0, 0)?,
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
                if let Ok(msg) = context.globals.get_var(&self.ctx.id, "choose-segment-msg") {
                    info!("The msg to choose segment was ready. Sending it");
                    context.broker_channel.send(EMULATOR_ID, msg.string()?)?;
                } else {
                    info!("The msg to choose segment was not ready");
                }
            }
            EmulatorResultType::ProverGetHashesForRoundResult { hashes } => {
                let round = context
                    .globals
                    .get_var(&self.ctx.id, "current_round")?
                    .number()? as u8;
                for (i, h) in hashes.iter().enumerate() {
                    self.set_input_hex(context, &format!("prover_hash_{}_{}", round, i), h)?;
                }
                context.bitcoin_coordinator.dispatch(
                    self.get_signed_tx(context, &format!("NARY_PROVER_{}", round), 0, 0)?,
                    Context::ProgramId(self.ctx.id).to_string()?,
                    None,
                )?;
            }
            EmulatorResultType::VerifierChooseSegmentResult { v_decision } => {
                let round = context
                    .globals
                    .get_var(&self.ctx.id, "current_round")?
                    .number()? as u8;

                self.set_input_u8(
                    context,
                    &format!("selection_bits_{}", round),
                    *v_decision as u8,
                )?;

                context.bitcoin_coordinator.dispatch(
                    self.get_signed_tx(context, &format!("NARY_VERIFIER_{}", round), 0, 0)?,
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
                if let Some(witness) = final_trace.witness {
                    self.set_input_u32(context, "witness", witness)?;
                }
                let tx = self.get_signed_tx(context, EXECUTE, 0, 0)?;
                info!("Execution tx: {:?}", tx);

                context.bitcoin_coordinator.dispatch(
                    self.get_signed_tx(context, EXECUTE, 0, 0)?,
                    Context::ProgramId(self.ctx.id).to_string()?,
                    None,
                )?;
            }
            _ => {
                info!("Execution result: {:?}", result);
            }
        }
        Ok(())
    }

    pub fn decode_witness_for_tx(
        &self,
        name: &str,
        input_index: u32,
        program_context: &ProgramContext,
        participant_keys: &ParticipantKeys,
        transaction: &Transaction,
    ) -> Result<Vec<String>, BitVMXError> {
        info!(
            "Program {}: Decoding witness for {} with input index {}",
            self.ctx.id, name, input_index
        );
        let protocol = self.load_protocol()?;
        //TODO: detect leaf index from the first forced witness of the tx
        let script = protocol.get_script_to_spend(&name, input_index, 0)?;

        let mut names = vec![];
        let mut sizes = vec![];
        script.get_keys().iter().rev().for_each(|k| {
            names.push(k.name().to_string());
            sizes.push(message_bytes_length(
                participant_keys
                    .get_winternitz(k.name())
                    .unwrap()
                    .message_size()
                    .unwrap(),
            ));
        });
        info!("Decoding data for {}", name);
        info!("Names: {:?}", names);
        info!("Sizes: {:?}", sizes);

        let witness = transaction.input[0].witness.clone();

        let data = witness::decode_witness(sizes, WinternitzType::HASH160, witness)?;
        for i in 0..data.len() {
            info!(
                "Program {}:{} Witness data decoded: {}",
                self.ctx.id,
                names[i],
                hex::encode(&data[i].message_bytes())
            );
            program_context.witness.set_witness(
                &self.ctx.id,
                &names[i],
                WitnessTypes::Winternitz(data[i].clone()),
            )?;
        }
        Ok(names)
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
