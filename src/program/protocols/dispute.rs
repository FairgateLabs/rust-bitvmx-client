use std::collections::HashMap;

use bitcoin::{PublicKey, Transaction, Txid};
use bitcoin_coordinator::{coordinator::BitcoinCoordinatorApi, TransactionStatus};
use bitvmx_cpu_definitions::challenge::EmulatorResultType;
use bitvmx_job_dispatcher::dispatcher_job::DispatcherJob;
use bitvmx_job_dispatcher_types::emulator_messages::EmulatorJobType;
use emulator::loader::program_definition::ProgramDefinition;
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

        if self.role() == ParticipantRole::Prover {
            let program_input_leaf_1 = key_chain.derive_winternitz_hash160(4)?;

            let last_step = key_chain.derive_winternitz_hash160(8)?;
            let last_hash = key_chain.derive_winternitz_hash160(20)?;
            keys.push(("program_input_1".to_string(), program_input_leaf_1.into()));

            keys.push(("last_step".to_string(), last_step.into()));
            keys.push(("last_hash".to_string(), last_hash.into()));
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

            //TODO: concatenate all inputs
            let input_program = program_context
                .globals
                .get_var(&self.ctx.id, "program_input_1")?
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
            let input_program = program_context
                .witness
                .get_witness(&self.ctx.id, "program_input_1")?
                .unwrap()
                .winternitz()?
                .message_bytes();

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

            let (_program_definition, pdf) = self.get_program_definition(program_context)?;
            let execution_path = self.get_execution_path()?;
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
            program_context.broker_channel.send(EMULATOR_ID, msg)?;
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

        self.add_winternitz_check(
            aggregated,
            &mut protocol,
            TIMELOCK_BLOCKS,
            &keys[0],
            amount,
            speedup_dust,
            &vec!["program_input_1"],
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

        //DUMMY last tx to test
        self.add_winternitz_check(
            aggregated,
            &mut protocol,
            TIMELOCK_BLOCKS,
            &keys[1],
            amount,
            amount - fee,
            &vec![&format!("selection_bits_{}", 1)],
            &prev,
            "DUMMY",
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
                context.globals.set_var(
                    &self.ctx.id,
                    "last_step",
                    VariableTypes::Input(last_step.to_be_bytes().to_vec()),
                )?;

                context.globals.set_var(
                    &self.ctx.id,
                    "last_hash",
                    VariableTypes::Input(hex::decode(last_hash)?),
                )?;

                context.bitcoin_coordinator.dispatch(
                    self.get_signed_tx(context, COMMITMENT, 0, 0)?,
                    Context::ProgramId(self.ctx.id).to_string()?,
                    None,
                )?;
            }
            EmulatorResultType::ProverGetHashesForRoundResult { hashes } => {
                let round = context
                    .globals
                    .get_var(&self.ctx.id, "current_round")?
                    .number()? as u8;
                for (i, h) in hashes.iter().enumerate() {
                    context.globals.set_var(
                        &self.ctx.id,
                        &format!("prover_hash_{}_{}", round, i),
                        VariableTypes::Input(hex::decode(h)?),
                    )?;
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

                context.globals.set_var(
                    &self.ctx.id,
                    &format!("selection_bits_{}", round),
                    VariableTypes::Input(vec![*v_decision as u8]),
                )?;
                context.bitcoin_coordinator.dispatch(
                    self.get_signed_tx(context, &format!("NARY_VERIFIER_{}", round), 0, 0)?,
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
}
