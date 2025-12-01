pub mod challenge;
pub mod config;
pub mod execution;
pub mod input_handler;
pub mod tx_news;
use std::{collections::HashMap, vec};

use bitcoin::{PublicKey, Transaction, Txid};
use bitcoin_coordinator::TransactionStatus;
use bitcoin_script_riscv::riscv::instruction_mapping::create_verification_script_mapping;
use bitcoin_script_stack::stack::StackTracker;
use bitvmx_cpu_definitions::challenge::EmulatorResultType;
use console::style;
use emulator::{
    constants::REGISTERS_BASE_ADDRESS, decision::nary_search::NArySearchType,
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
        OutputType,
    },
};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::{
    errors::BitVMXError,
    program::{
        participant::{ParticipantKeys, ParticipantRole, PublicKeyType},
        protocols::{
            claim::ClaimGate,
            dispute::{
                challenge::{challenge_scripts, get_verifier_keys},
                config::DisputeConfiguration,
                execution::execution_result,
                input_handler::{get_required_keys, get_txs_configuration, split_input},
            },
            protocol_handler::{ProtocolContext, ProtocolHandler},
        },
        variables::{PartialUtxo, VariableTypes},
    },
    types::ProgramContext,
};

pub const EXTERNAL_START: &str = "EXTERNAL_START";
pub const START_CH: &str = "START_CHALLENGE";
pub const INPUT_TX: &str = "INPUT_";
pub const COMMITMENT: &str = "COMMITMENT";
pub const EXECUTE: &str = "EXECUTE";
pub const TIMELOCK_BLOCKS: u16 = 15;
pub const PROVER_WINS: &str = "PROVER_WINS";
pub const VERIFIER_WINS: &str = "VERIFIER_WINS";
pub const CHALLENGE: &str = "CHALLENGE";
pub const CHALLENGE_READ: &str = "CHALLENGE_READ"; // For the second N-ary search
pub const TIMELOCK_BLOCKS_KEY: &str = "TIMELOCK_BLOCKS";
pub const VERIFIER_FINAL: &str = "VERIFIER_FINAL";

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
    38_000 // This is a placeholder value, adjust as needed
}

fn get_role(my_idx: usize) -> ParticipantRole {
    if my_idx == 0 {
        ParticipantRole::Prover
    } else {
        ParticipantRole::Verifier
    }
}

pub fn action_wins_prefix(role: &ParticipantRole) -> String {
    match role {
        ParticipantRole::Prover => "ACTION_PROVER_WINS_".to_string(),
        ParticipantRole::Verifier => "ACTION_VERIFIER_WINS_".to_string(),
    }
}

pub fn action_wins(role: &ParticipantRole, n: u32) -> String {
    format!("{}{}", action_wins_prefix(role), n)
}

pub fn external_action(role: &ParticipantRole, n: u32) -> String {
    match role {
        ParticipantRole::Prover => format!("EXTERNAL_ACTION_PROVER_{n}"),
        ParticipantRole::Verifier => format!("EXTERNAL_ACTION_VERIFIER_{n}"),
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

pub fn timeout_tx(name: &str) -> String {
    format!("{}_TO", name)
}

pub fn timeout_input_tx(name: &str) -> String {
    format!("{}_INPUT_TO", name)
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
        let config = DisputeConfiguration::load(&self.ctx.id, &context.globals)?;

        Ok(vec![(
            "pregenerated".to_string(),
            config.operators_aggregated_pub.clone(),
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
                    let key2 = key_chain.derive_winternitz_hash160(20)?;
                    keys.push((format!("prover_hash_{}_{}", i, h), key.into()));
                    keys.push((format!("prover_hash2_{}_{}", i, h), key2.into()));
                    // for the second n-ary search
                }
            } else {
                let _bits = nary_def.bits_for_round(i);
                let key = key_chain.derive_winternitz_hash160(1)?;
                let key2 = key_chain.derive_winternitz_hash160(1)?;
                keys.push((format!("selection_bits_{}", i), key.into()));
                keys.push((format!("selection_bits2_{}", i), key2.into())); // for the second n-ary search
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
            let idx = name.strip_prefix(INPUT_TX).unwrap().parse::<u32>()?;
            split_input(&self.ctx.id, idx, context)?;
            let (tx, speedup) =
                self.get_tx_with_speedup_data(context, &input_tx_name(idx), 0, 0, true)?;
            Ok((tx, Some(speedup)))
        } else if name == START_CH {
            let tx = self.get_signed_tx(context, START_CH, 0, 1, false, 0)?;
            let speedup = self.get_speedup_data_from_tx(&tx, context, Some(0))?;
            Ok((tx, Some(speedup)))
        } else {
            Err(BitVMXError::InvalidTransactionName(name.to_string()))
        }
    }

    fn notify_news(
        &self,
        tx_id: Txid,
        vout: Option<u32>,
        tx_status: TransactionStatus,
        _context: String,
        program_context: &ProgramContext,
        _participant_keys: Vec<&ParticipantKeys>,
    ) -> Result<(), BitVMXError> {
        tx_news::handle_tx_news(&self, tx_id, vout, tx_status, program_context)
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

        let config = DisputeConfiguration::load(&self.ctx.id, &context.globals)?;
        let utxo = config.protocol_connection.0.clone();

        let prover_speedup_pub = keys[0].get_public("speedup")?;
        let verifier_speedup_pub = keys[1].get_public("speedup")?;
        let aggregated = computed_aggregated.get("aggregated_1").unwrap();
        let (agg_or_prover, agg_or_verifier, sign_mode) =
            (prover_speedup_pub, verifier_speedup_pub, SignMode::Single);

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

        let prover_outputs = config.prover_actions.len() + config.prover_enablers.len();
        let verifier_outputs = config.verifier_actions.len() + config.verifier_enablers.len();
        amount = self.checked_sub(
            amount,
            ClaimGate::cost(fee, speedup_dust, 1, prover_outputs, true),
        )?;
        amount = self.checked_sub(
            amount,
            ClaimGate::cost(fee, speedup_dust, 1, verifier_outputs, false),
        )?;

        let timelock_blocks = config.timelock_blocks;

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
            config.prover_actions.len() as u64,
            config.prover_enablers,
            true,
            None,
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
            config.verifier_actions.len() as u64,
            config.verifier_enablers,
            false,
            claim_prover.exclusive_success_vout,
        )?;

        for (n, (utxo, leaves)) in config.prover_actions.iter().enumerate() {
            self.add_action(
                &mut protocol,
                utxo,
                leaves,
                &prover_speedup_pub,
                &ParticipantRole::Prover,
                PROVER_WINS,
                n as u32 + 1,
            )?;
        }

        for (n, (utxo, leaves)) in config.verifier_actions.iter().enumerate() {
            self.add_action(
                &mut protocol,
                utxo,
                leaves,
                &verifier_speedup_pub,
                &ParticipantRole::Verifier,
                VERIFIER_WINS,
                n as u32 + 1,
            )?;
        }

        let mut prev_tx = START_CH.to_string();
        let mut input_tx = String::new();

        let (input_txs, input_txs_sizes, input_txs_offsets, _) =
            get_txs_configuration(&self.ctx.id, context)?;

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
                &claim_verifier,
                Self::winternitz_check(agg_or_prover, sign_mode, &keys[0], &input_vars)?,
                (&prover_speedup_pub, &verifier_speedup_pub),
            )?;

            amount = self.checked_sub(amount, fee)?;
            amount = self.checked_sub(amount, speedup_dust)?;
            prev_tx = input_tx.clone();
        }

        self.add_connection_with_scripts(
            context,
            aggregated,
            &mut protocol,
            timelock_blocks,
            amount,
            speedup_dust,
            &input_tx,
            COMMITMENT,
            &claim_verifier,
            Self::winternitz_check(
                agg_or_prover,
                sign_mode,
                &keys[0],
                &vec!["prover_last_step", "prover_last_hash"],
            )?,
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
                &claim_verifier,
                Self::winternitz_check(
                    agg_or_prover,
                    sign_mode,
                    &keys[0],
                    &vars.iter().map(|s| s.as_str()).collect::<Vec<&str>>(),
                )?,
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
                &claim_prover,
                Self::winternitz_check(
                    agg_or_verifier,
                    sign_mode,
                    &keys[1],
                    &vec![&format!("selection_bits_{}", i)],
                )?,
                (&verifier_speedup_pub, &prover_speedup_pub),
            )?;
            amount = self.checked_sub(amount, fee)?;
            amount = self.checked_sub(amount, speedup_dust)?;
            prev = next;
        }

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
            &claim_verifier,
            self.execute_script(context, agg_or_prover, sign_mode, &keys[0], &vars)?,
            (&prover_speedup_pub, &verifier_speedup_pub),
        )?;

        info!(
            "Amount {}, fee {}, speedup_dust {}",
            amount, fee, speedup_dust
        );
        amount = self.checked_sub(amount, fee)?;
        amount = self.checked_sub(amount, speedup_dust)?;

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
            &claim_prover,
            challenge_scripts(
                &self.ctx.id,
                self.role(),
                &program_def,
                context,
                agg_or_verifier,
                sign_mode,
                &keys,
                NArySearchType::ConflictStep,
            )?,
            (&verifier_speedup_pub, &prover_speedup_pub),
        )?;

        amount = self.checked_sub(amount, fee)?;
        amount = self.checked_sub(amount, speedup_dust)?;
        prev = CHALLENGE.to_string();
        for i in 2..nary_def.total_rounds() + 1 {
            let next = format!("NARY2_PROVER_{}", i);
            let hashes = nary_def.hashes_for_round(i);
            let vars = (0..hashes)
                .map(|h| format!("prover_hash2_{}_{}", i, h))
                .collect::<Vec<_>>();

            if i != 1 {
                self.add_connection_with_scripts(
                    context,
                    aggregated,
                    &mut protocol,
                    timelock_blocks,
                    amount,
                    speedup_dust,
                    &prev,
                    &next,
                    &claim_verifier,
                    Self::winternitz_check(
                        agg_or_prover,
                        sign_mode,
                        &keys[0],
                        &vars.iter().map(|s| s.as_str()).collect::<Vec<&str>>(),
                    )?,
                    (&prover_speedup_pub, &verifier_speedup_pub),
                )?;
                amount = self.checked_sub(amount, fee)?;
                amount = self.checked_sub(amount, speedup_dust)?;

                prev = next;
            }
            let next = format!("NARY2_VERIFIER_{}", i);
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
                &claim_prover,
                Self::winternitz_check(
                    agg_or_verifier,
                    sign_mode,
                    &keys[1],
                    &vec![&format!("selection_bits2_{}", i)],
                )?,
                (&verifier_speedup_pub, &prover_speedup_pub),
            )?;
            amount = self.checked_sub(amount, fee)?;
            amount = self.checked_sub(amount, speedup_dust)?;
            prev = next;
        }

        self.add_connection_with_scripts(
            context,
            aggregated,
            &mut protocol,
            timelock_blocks,
            amount,
            speedup_dust,
            &prev,
            CHALLENGE_READ,
            &claim_prover,
            challenge_scripts(
                &self.ctx.id,
                self.role(),
                &program_def,
                context,
                agg_or_verifier,
                sign_mode,
                &keys,
                NArySearchType::ReadValueChallenge,
            )?,
            (&verifier_speedup_pub, &prover_speedup_pub),
        )?;

        amount = self.checked_sub(amount, fee)?;
        amount = self.checked_sub(amount, speedup_dust)?;

        let timeout_leaf = scripts::timelock(2 * timelock_blocks, &aggregated, SignMode::Aggregate);
        let output_type = OutputType::taproot(amount, aggregated, &vec![timeout_leaf])?;

        protocol.add_connection(
            &format!("{}__{}", CHALLENGE_READ, VERIFIER_FINAL),
            CHALLENGE_READ,
            output_type.into(),
            VERIFIER_FINAL,
            InputSpec::Auto(SighashType::taproot_all(), SpendMode::Script { leaf: 0 }),
            Some(2 * timelock_blocks),
            None,
        )?;

        pb.add_speedup_output(
            &mut protocol,
            VERIFIER_FINAL,
            speedup_dust,
            &verifier_speedup_pub,
        )?;

        claim_verifier.add_claimer_win_connection(&mut protocol, VERIFIER_FINAL)?;
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

    fn partial_utxo_from(&self, tx: &Transaction, vout: u32) -> (Txid, u32, u64) {
        let txid = tx.compute_txid();
        let amount = tx.output[vout as usize].value.to_sat();
        (txid, vout, amount)
    }

    fn add_action(
        &self,
        protocol: &mut Protocol,
        utxo_action: &PartialUtxo,
        leaves: &Vec<usize>,
        speedup_pub: &PublicKey,
        role: &ParticipantRole,
        claim: &str,
        action_number: u32,
    ) -> Result<(), BitVMXError> {
        let speedup_dust = DUST;
        protocol.add_transaction(&action_wins(role, action_number))?;
        protocol.add_connection(
            &format!("{:?}_ACTION_{action_number}", role),
            &ClaimGate::tx_success(claim),
            0.into(),
            &action_wins(role, action_number),
            InputSpec::Auto(
                SighashType::taproot_all(),
                SpendMode::All {
                    key_path_sign: SignMode::Aggregate,
                },
            ),
            None,
            None,
        )?;

        let output_type = utxo_action.3.as_ref().unwrap();
        protocol.add_external_transaction(&external_action(role, action_number))?;
        protocol.add_unknown_outputs(&external_action(role, action_number), utxo_action.1)?;
        protocol.add_transaction_output(&external_action(role, action_number), &output_type)?;
        protocol.add_connection(
            &format!("EXTERNAL_ACTION__{:?}_WINS", role),
            &external_action(role, action_number),
            (utxo_action.1 as usize).into(),
            &action_wins(role, action_number),
            InputSpec::Auto(
                SighashType::taproot_all(),
                SpendMode::Scripts {
                    leaves: leaves.clone(),
                },
            ),
            None,
            Some(utxo_action.0),
        )?;

        let pb = ProtocolBuilder {};
        pb.add_speedup_output(
            protocol,
            &action_wins(role, action_number),
            speedup_dust,
            &speedup_pub,
        )?;

        Ok(())
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
        _context: &ProgramContext,
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
        claim_gate: &ClaimGate,
        mut leaves: Vec<ProtocolScript>,
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

        let (_mine_speedup, other_speedup) = speedup_keys;

        //add a tiemouet leaf to the possible leaves
        let timeout_input = scripts::timelock(timelock_blocks, &aggregated, SignMode::Aggregate);
        leaves.push(timeout_input);
        for (pos, leave) in leaves.iter_mut().enumerate() {
            leave.set_assert_leaf_id(pos as u32);
        }

        //creates the connector output with the connection and timeout leaves
        //the connector needs two times the timelock, because it needs to give time to the input in speedup timeout
        let mut connection_leaf = scripts::check_signature(aggregated, SignMode::Aggregate);
        connection_leaf.set_assert_leaf_id(0);
        let mut timeout_leaf =
            scripts::timelock(2 * timelock_blocks, &aggregated, SignMode::Aggregate);
        timeout_leaf.set_assert_leaf_id(1);
        let connector_leaves = vec![connection_leaf, timeout_leaf];

        let output_type = OutputType::taproot(amount, aggregated, &connector_leaves)?;

        // connector from -> to
        protocol.add_connection(
            &format!("{}__{}", from, to),
            from,
            output_type.clone().into(),
            to,
            InputSpec::Auto(SighashType::taproot_all(), SpendMode::Script { leaf: 0 }),
            None,
            None,
        )?;

        // creates the speedup output where the input will be commited
        let output_type = OutputType::taproot(amount_speedup, &aggregated, &leaves)?;
        protocol.add_transaction_output(to, &output_type)?;
        let last = protocol.get_output_count(to)? - 1;
        self.add_vout_to_monitor(context, to, last)?;

        // store the input and leaf for the timeout tx
        context.globals.set_var(
            &self.ctx.id,
            &timeout_tx(to),
            VariableTypes::VecNumber(vec![0, 1, timelock_blocks as u32 * 2]),
        )?;

        // add the timeout tx to penalize the non-acting party
        protocol.add_connection(
            &format!("{}_TL_{}_{}_TO", from, 2 * timelock_blocks, to),
            from,
            OutputSpec::Last,
            &timeout_tx(to),
            InputSpec::Auto(SighashType::taproot_all(), SpendMode::Script { leaf: 1 }),
            Some(2 * timelock_blocks),
            None,
        )?;

        //connect the opositte party claim gate to the timeout tx
        claim_gate.add_claimer_win_connection(protocol, &timeout_tx(to))?;
        let pb = ProtocolBuilder {};
        pb.add_speedup_output(protocol, &timeout_tx(to), amount_speedup, other_speedup)?;

        // store the input and leaf for the timeout tx
        context.globals.set_var(
            &self.ctx.id,
            &timeout_input_tx(to),
            VariableTypes::VecNumber(vec![0, leaves.len() as u32 - 1, timelock_blocks as u32]),
        )?;

        // add the timeout tx to penalize the party for not commiting the input
        protocol.add_connection(
            &format!("{}_TL_{}_{}_INPUT_TO", from, timelock_blocks, to),
            to,
            OutputSpec::Last,
            &timeout_input_tx(to),
            InputSpec::Auto(
                SighashType::taproot_all(),
                SpendMode::Script {
                    leaf: leaves.len() - 1,
                },
            ),
            Some(timelock_blocks),
            None,
        )?;

        //connect the opositte party claim gate to the timeout tx
        claim_gate.add_claimer_win_connection(protocol, &timeout_input_tx(to))?;
        let pb = ProtocolBuilder {};
        pb.add_speedup_output(
            protocol,
            &timeout_input_tx(to),
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
        let config = DisputeConfiguration::load(&self.ctx.id, &context.globals)?;
        Ok((
            ProgramDefinition::from_config(&config.program_definition)?,
            config.program_definition,
        ))
    }
}
