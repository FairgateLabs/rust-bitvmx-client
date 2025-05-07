use std::collections::HashMap;

use bitcoin::{PublicKey, Transaction, Txid};
use bitcoin_coordinator::TransactionStatus;
use bitvmx_job_dispatcher::dispatcher_job::DispatcherJob;
use bitvmx_job_dispatcher_types::emulator_messages::{EmulatorJobType, EmulatorResultType};
use emulator::loader::program_definition::ProgramDefinition;
use key_manager::winternitz::WinternitzType;
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
    errors::BitVMXError,
    keychain::KeyChain,
    program::{
        participant::ParticipantRole, protocols::slot::external_fund_tx, variables::WitnessTypes,
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

    fn generate_keys(&self, key_chain: &mut KeyChain) -> Result<ParticipantKeys, BitVMXError> {
        //TODO: define which keys are generated for each role

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
            let initial_hash = key_chain.derive_winternitz_hash160(20)?;
            keys.push(("program_input_1".to_string(), program_input_leaf_1.into()));

            keys.push(("last_step".to_string(), last_step.into()));
            keys.push(("initial_hash".to_string(), initial_hash.into()));
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

            let execution_path = format!("runs/{}/prover/", self.ctx.id);
            let _ = std::fs::create_dir_all(&execution_path);

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
            let witness = tx_status.tx.input[0].witness.clone();
            let data = witness::decode_witness(vec![4], WinternitzType::HASH160, witness)?;

            let message = u32::from_be_bytes(data[0].message_bytes().try_into().unwrap());
            info!(
                "Program {}:{} Witness data decoded: {:0x}",
                self.ctx.id, name, message
            );

            program_context.witness.set_witness(
                &self.ctx.id,
                "program_input_1",
                WitnessTypes::Winternitz(data),
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
        let fee = 1000;
        let speedup_dust = 500;
        const TIMELOCK_BLOCKS: u16 = 10;

        let utxo = context.globals.get_var(&self.ctx.id, "utxo")?.utxo()?;

        let program_definition = context
            .globals
            .get_var(&self.ctx.id, "program_definition")?
            .string()?;
        let _program = ProgramDefinition::from_config(&program_definition)?;

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
            amount - fee, //in the last one goes the change
            &vec!["last_step", "initial_hash"],
            INPUT_1,
            COMMITMENT,
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

    pub fn input_1_tx(&self, context: &ProgramContext) -> Result<Transaction, BitVMXError> {
        self.get_signed_tx(context, INPUT_1, 0, 0)
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
            &format!("{}-{}", from, to),
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

    pub fn execution_result(&self, result: &EmulatorResultType, _context: &ProgramContext) {
        info!("Execution result: {:?}", result);
    }
}
