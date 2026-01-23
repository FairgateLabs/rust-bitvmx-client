pub mod challenge;
pub mod config;
pub mod execution;
pub mod input_handler;
pub mod tx_news;
use std::{
    collections::HashMap,
    sync::{OnceLock, RwLock},
    vec,
};

use bitcoin::{PublicKey, ScriptBuf, Transaction, Txid};
use bitcoin_coordinator::TransactionStatus;
use bitcoin_script_riscv::riscv::{
    instruction_mapping::create_verification_script_mapping,
    script_utils::{
        is_lower_than, var_to_decisions_in_altstack, verify_challenge_step, StackTables,
    },
};
use bitcoin_script_stack::stack::StackTracker;
use bitvmx_cpu_definitions::challenge::EmulatorResultType;
use console::style;
use emulator::{
    constants::REGISTERS_BASE_ADDRESS, decision::nary_search::NArySearchType,
    loader::program_definition::ProgramDefinition,
};
use key_manager::key_type::BitcoinKeyType;
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
use tracing::{info, warn};

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
                input_handler::{
                    get_required_keys, get_txs_configuration, set_input_u8, split_input,
                },
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
pub const PRE_COMMITMENT: &str = "PRE_COMMITMENT"; // TODO: Only to complete challenge-response sequence. See if can be avoided
pub const COMMITMENT: &str = "COMMITMENT";
pub const POST_COMMITMENT: &str = "POST_COMMITMENT"; // TODO: Only to complete challenge-response sequence. See if can be avoided
pub const EXECUTE: &str = "EXECUTE";
pub const TIMELOCK_BLOCKS: u16 = 15;
pub const PROVER_WINS: &str = "PROVER_WINS";
pub const VERIFIER_WINS: &str = "VERIFIER_WINS";
pub const CHALLENGE: &str = "CHALLENGE";
pub const GET_HASHES_AND_STEP: &str = "GET_HASHES_AND_STEP";
pub const CHALLENGE_READ: &str = "CHALLENGE_READ"; // For the second N-ary search
pub const TIMELOCK_BLOCKS_KEY: &str = "TIMELOCK_BLOCKS";
pub const VERIFIER_FINAL: &str = "VERIFIER_FINAL";

pub static TRACE_VARS: OnceLock<RwLock<Vec<(String, usize)>>> = OnceLock::new();
pub static PROVER_CHALLENGE_STEP1: OnceLock<RwLock<Vec<(String, usize)>>> = OnceLock::new();

pub static TK_2NARY: OnceLock<RwLock<Vec<(String, usize)>>> = OnceLock::new();
pub static PROVER_CHALLENGE_STEP2: OnceLock<RwLock<Vec<(String, usize)>>> = OnceLock::new();

fn build_trace_vars(rounds: u8) -> Vec<(String, usize)> {
    let mut vars = vec![
        ("prover_write_address".to_string(), 4),
        ("prover_write_value".to_string(), 4),
        ("prover_write_pc".to_string(), 4),
        ("prover_write_micro".to_string(), 1),
        ("prover_witness".to_string(), 4),
        ("prover_mem_witness".to_string(), 1),
        ("prover_read_1_address".to_string(), 4),
        ("prover_read_1_value".to_string(), 4),
        ("prover_read_1_last_step".to_string(), 8),
        ("prover_read_2_address".to_string(), 4),
        ("prover_read_2_value".to_string(), 4),
        ("prover_read_2_last_step".to_string(), 8),
        ("prover_read_pc_address".to_string(), 4),
        ("prover_read_pc_micro".to_string(), 1),
        ("prover_read_pc_opcode".to_string(), 4),
        ("prover_step_number".to_string(), 8),
        ("prover_step_hash_tk".to_string(), 20),
        ("prover_next_hash_tk".to_string(), 20),
        ("prover_conflict_step_tk".to_string(), 8),
        // the verifier needs this to continue with the challenge, if the prover chooses to challenge the step,
        // he won't sign this variable and the verifier won't be able to continue
        ("prover_continue".to_string(), 1),
    ];

    for i in 1..rounds + 1 {
        vars.push((format!("verifier_selection_bits_{}", i), 1));
    }

    vars
}

fn build_challenge_step_vars(rounds: u8) -> Vec<(String, usize)> {
    let mut vars = vec![("verifier_last_step_tk".to_string(), 8)];

    for i in 1..rounds + 1 {
        vars.push((format!("verifier_selection_bits_{}", i), 1));
    }

    vars
}

fn build_translation_keys_2nd_nary(rounds: u8) -> Vec<(String, usize)> {
    let mut vars = vec![
        ("prover_step_hash_tk2".to_string(), 20),
        ("prover_next_hash_tk2".to_string(), 20),
        ("prover_write_step_tk2".to_string(), 8),
        ("prover_continue2".to_string(), 1),
    ];

    for i in 1..rounds + 1 {
        vars.push((format!("verifier_selection_bits2_{}", i), 1));
    }

    vars
}

fn build_challenge_step_vars_2nd_nary(rounds: u8) -> Vec<(String, usize)> {
    let mut vars = vec![];

    for i in 1..rounds + 1 {
        vars.push((format!("verifier_selection_bits_{}", i), 1));
    }

    for i in 1..rounds + 1 {
        vars.push((format!("verifier_selection_bits2_{}", i), 1));
    }

    vars
}

pub fn init_trace_vars(rounds: u8) -> Result<(), BitVMXError> {
    let trace_lock = TRACE_VARS.get_or_init(|| RwLock::new(Vec::new()));
    let challenge_step_lock = PROVER_CHALLENGE_STEP1.get_or_init(|| RwLock::new(Vec::new()));

    let tk_lock = TK_2NARY.get_or_init(|| RwLock::new(Vec::new()));
    let challenge_step2_lock = PROVER_CHALLENGE_STEP2.get_or_init(|| RwLock::new(Vec::new()));

    // Read both locks to check existing consistency //TODO: now there is no need for round parameter
    let trace = trace_lock.read()?;
    let challenge_step = challenge_step_lock.read()?;

    let tk = tk_lock.read()?;
    let challenge_step2 = challenge_step2_lock.read()?;

    let existing_trace_rounds = trace
        .iter()
        .filter(|(name, _)| name.starts_with("verifier_selection_bits_"))
        .count() as u8;

    let existing_step_rounds = challenge_step
        .iter()
        .filter(|(name, _)| name.starts_with("verifier_selection_bits_"))
        .count() as u8;

    let existing_tk_rounds = tk
        .iter()
        .filter(|(name, _)| name.starts_with("verifier_selection_bits2_"))
        .count() as u8;

    let existing_step2_rounds = challenge_step2
        .iter()
        .filter(|(name, _)| name.starts_with("verifier_selection_bits_"))
        .count() as u8;

    let is_consistent = existing_trace_rounds == rounds
        && existing_tk_rounds == rounds
        && existing_step_rounds == rounds
        && existing_step2_rounds == rounds;

    if is_consistent {
        return Ok(()); // already consistent
    }

    drop(trace);
    drop(challenge_step);
    drop(tk);
    drop(challenge_step2);

    // Rebuild all in a consistent state
    {
        let mut trace = trace_lock.write()?;
        *trace = build_trace_vars(rounds);
    }
    {
        let mut tk = tk_lock.write()?;
        *tk = build_translation_keys_2nd_nary(rounds);
    }
    {
        let mut challenge_step = challenge_step_lock.write()?;
        *challenge_step = build_challenge_step_vars(rounds);
    }
    {
        let mut challenge_step2 = challenge_step2_lock.write()?;
        *challenge_step2 = build_challenge_step_vars_2nd_nary(rounds);
    }
    Ok(())
}

#[derive(Clone, Serialize, Deserialize)]
pub struct DisputeResolutionProtocol {
    ctx: ProtocolContext,
}

const MIN_RELAY_FEE: u64 = 1;
pub const DUST: u64 = 500 * MIN_RELAY_FEE;

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
pub fn program_input(index: u32, role: Option<&ParticipantRole>) -> String {
    match role {
        Some(ParticipantRole::Prover) => format!("prover_program_input_{}", index),
        Some(ParticipantRole::Verifier) => format!("verifier_program_input_{}", index),
        None => format!("program_input_{}", index),
    }
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
        let nary_def = program_def.nary_def();
        init_trace_vars(nary_def.total_rounds())?;

        let aggregated_1 = program_context
            .key_chain
            .derive_keypair(BitcoinKeyType::P2tr)?;

        let speedup = program_context
            .key_chain
            .derive_keypair(BitcoinKeyType::P2tr)?;

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

        if self.role() == ParticipantRole::Prover {
            set_input_u8(&self.ctx.id, &program_context, "prover_continue", 0)?;
            set_input_u8(&self.ctx.id, &program_context, "prover_continue2", 0)?;
        }

        let key_chain = &mut program_context.key_chain;

        if self.role() == ParticipantRole::Prover {
            let last_step = key_chain.derive_winternitz_hash160(8)?;
            keys.push(("prover_last_step".to_string(), last_step.into()));

            let last_hash = key_chain.derive_winternitz_hash160(20)?;
            keys.push(("prover_last_hash".to_string(), last_hash.into()));

            let trace = TRACE_VARS
                .get()
                .ok_or_else(|| {
                    BitVMXError::InitializationError("TRACE_VARS not initialized".to_string())
                })?
                .read()?;
            let tk = TK_2NARY
                .get()
                .ok_or_else(|| {
                    BitVMXError::InitializationError("TK_2NARY not initialized".to_string())
                })?
                .read()?;
            for (name, size) in trace.iter() {
                if name.starts_with("prover") {
                    let key = key_chain.derive_winternitz_hash160(*size)?;
                    keys.push((name.to_string(), key.into()));
                }
            }
            for (name, size) in tk.iter() {
                if name.starts_with("prover") {
                    let key = key_chain.derive_winternitz_hash160(*size)?;
                    keys.push((name.to_string(), key.into()));
                }
            }
        }

        if self.role() == ParticipantRole::Verifier {
            keys.push((
                "verifier_last_step_tk".to_string(),
                key_chain.derive_winternitz_hash160(8)?.into(),
            ));

            let ver_keys = get_verifier_keys()
                .iter()
                .map(|(name, size)| {
                    let key = key_chain.derive_winternitz_hash160(*size)?;
                    Ok::<_, BitVMXError>((name.to_string(), PublicKeyType::Winternitz(key)))
                })
                .collect::<Result<Vec<_>, _>>()?;
            keys.extend_from_slice(&ver_keys);
        }

        //generate keys for the nary search
        let nary_def = program_def.nary_def();
        info!("Nary def: {:?}", nary_def);
        for i in 1..nary_def.total_rounds() + 1 {
            if self.role() == ParticipantRole::Prover {
                let hashes = nary_def.hashes_for_round(i);
                for h in 1..hashes + 1 {
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
                keys.push((format!("verifier_selection_bits_{}", i), key.into()));
                keys.push((format!("verifier_selection_bits2_{}", i), key2.into()));
                // for the second n-ary search
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
            let idx = name
                .strip_prefix(INPUT_TX)
                .ok_or_else(|| BitVMXError::InvalidStringOperation(name.to_string()))?
                .parse::<u32>()?;
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
        config.fail_force_config.map(|fail_force_config| {
            fail_force_config.fail_input_tx.map(|fail_input_tx| {
                context.globals.set_var(
                    &self.ctx.id,
                    format!("fail_input_{fail_input_tx}").as_str(),
                    VariableTypes::Bool(true),
                )
            })
        });
        let utxo = config.protocol_connection.0.clone();

        let prover_speedup_pub = keys[0].get_public("speedup")?;
        let verifier_speedup_pub = keys[1].get_public("speedup")?;
        let aggregated = computed_aggregated
            .get("aggregated_1")
            .ok_or_else(|| BitVMXError::NotFound("aggregated_1".to_string()))?;
        let (agg_or_prover, agg_or_verifier, sign_mode) =
            (prover_speedup_pub, verifier_speedup_pub, SignMode::Single);

        let program_def = self.get_program_definition(context)?;
        let nary_def = program_def.0.nary_def();

        let mut protocol = self.load_or_create_protocol();

        let mut amount = utxo
            .2
            .ok_or_else(|| BitVMXError::MissingParameter("UTXO amount is required".to_string()))?;
        info!("Protocol amount: {}", amount);
        let output_type = utxo.3.ok_or_else(|| {
            BitVMXError::MissingParameter("UTXO output type is required".to_string())
        })?;

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

        let (input_txs, input_txs_sizes, input_txs_offsets, _) =
            get_txs_configuration(&self.ctx.id, context)?;

        for (idx, tx_owner) in input_txs.iter().enumerate() {
            if tx_owner == "skip" || tx_owner == "prover_prev" {
                continue;
            }
            let input_tx = format!("INPUT_{}", idx);

            let words = input_txs_sizes[idx];
            let offset = input_txs_offsets[idx];

            let (owner, claim, agg, ordered_keys, speedup_keys, extra_script, extra_vars) =
                match tx_owner.as_str() {
                    "verifier" => (
                        ParticipantRole::Verifier,
                        &claim_prover,
                        agg_or_verifier,
                        &keys.iter().cloned().rev().collect::<Vec<_>>(),
                        (verifier_speedup_pub, prover_speedup_pub),
                        None,
                        vec![],
                    ),
                    "prover_cosign" => (
                        ParticipantRole::Prover,
                        &claim_verifier,
                        agg_or_prover,
                        &keys,
                        (prover_speedup_pub, verifier_speedup_pub),
                        Some(vec![Self::get_cosign_extra_script(words)]),
                        (offset..offset + words)
                            .map(|i| program_input(i, Some(&ParticipantRole::Verifier)))
                            .collect(),
                    ),
                    "prover" => (
                        ParticipantRole::Prover,
                        &claim_verifier,
                        agg_or_prover,
                        &keys,
                        (prover_speedup_pub, verifier_speedup_pub),
                        None,
                        vec![],
                    ),
                    _ => {
                        return Err(BitVMXError::InvalidInput(format!(
                            "Invalid input tx owner: {}",
                            tx_owner
                        )))
                    }
                };

            let input_var = (offset..offset + words)
                .map(|i| program_input(i, Some(&owner)))
                .collect::<Vec<_>>();
            let composite_input_vars = vec![input_var, extra_vars];
            let input_vars = composite_input_vars.iter().collect();

            self.add_connection_with_scripts(
                context,
                aggregated,
                &mut protocol,
                timelock_blocks,
                amount,
                speedup_dust,
                &prev_tx,
                &input_tx,
                &claim,
                Self::winternitz_check_cosigned_input_script(
                    agg,
                    sign_mode,
                    ordered_keys,
                    &input_vars,
                    extra_script,
                )?,
                speedup_keys,
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
            &prev_tx,
            PRE_COMMITMENT,
            &claim_prover,
            Self::winternitz_check(agg_or_verifier, sign_mode, &keys[1], &Vec::<&str>::new())?,
            (&verifier_speedup_pub, &prover_speedup_pub),
        )?;

        amount = self.checked_sub(amount, fee)?;
        amount = self.checked_sub(amount, speedup_dust)?;

        let reverse_script = Self::get_reverse_script(16 + 40); // sizeof prover_last_step + sizeof prover_last_hash
        let validate_last_step_script =
            Self::get_validate_last_step_script(program_def.0.max_steps);

        self.add_connection_with_scripts(
            context,
            aggregated,
            &mut protocol,
            timelock_blocks,
            amount,
            speedup_dust,
            PRE_COMMITMENT,
            COMMITMENT,
            &claim_verifier,
            Self::winternitz_check_extra_script(
                agg_or_prover,
                sign_mode,
                &keys[0],
                &vec!["prover_last_step", "prover_last_hash"],
                Some(vec![reverse_script, validate_last_step_script]),
            )?,
            (&prover_speedup_pub, &verifier_speedup_pub),
        )?;
        amount = self.checked_sub(amount, fee)?;
        amount = self.checked_sub(amount, speedup_dust)?;

        self.add_connection_with_scripts(
            context,
            aggregated,
            &mut protocol,
            timelock_blocks,
            amount,
            speedup_dust,
            COMMITMENT,
            POST_COMMITMENT,
            &claim_prover,
            Self::winternitz_check_cosigned_input_script(
                agg_or_verifier,
                sign_mode,
                &keys,
                &vec![&vec!["prover_last_step"], &vec!["verifier_last_step_tk"]],
                Some(vec![Self::get_verify_last_step_script()]),
            )?,
            (&verifier_speedup_pub, prover_speedup_pub),
        )?;

        amount = self.checked_sub(amount, fee)?;
        amount = self.checked_sub(amount, speedup_dust)?;

        let mut prev = POST_COMMITMENT.to_string();
        for i in 1..nary_def.total_rounds() + 1 {
            let next = format!("NARY_PROVER_{}", i);
            let hashes = nary_def.hashes_for_round(i);
            let vars = (1..hashes + 1)
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
            let bits = nary_def.bits_for_round(i);
            let validate_selection_bits_script =
                Self::get_validate_selection_bits_script((1 << bits) - 1);

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
                Self::winternitz_check_extra_script(
                    agg_or_verifier,
                    sign_mode,
                    &keys[1],
                    &vec![&format!("verifier_selection_bits_{}", i)],
                    Some(vec![validate_selection_bits_script]),
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
            EXECUTE,
            &claim_verifier,
            self.execute_script(
                context,
                agg_or_prover,
                sign_mode,
                &keys,
                NArySearchType::ConflictStep,
            )?,
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
            let vars = (1..hashes + 1)
                .map(|h| format!("prover_hash2_{}_{}", i, h))
                .collect::<Vec<_>>();

            let winternitz_check = if i == 2 {
                Self::winternitz_check_cosigned_input_script(
                    agg_or_prover,
                    sign_mode,
                    &keys,
                    &vec![
                        &vars.iter().map(|s| s.as_str()).collect(),
                        &vec!["verifier_selection_bits2_1"],
                    ],
                    None,
                )?
            } else {
                Self::winternitz_check(
                    agg_or_prover,
                    sign_mode,
                    &keys[0],
                    &vars.iter().map(|s| s.as_str()).collect::<Vec<&str>>(),
                )?
            };

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
                winternitz_check,
                (&prover_speedup_pub, &verifier_speedup_pub),
            )?;
            amount = self.checked_sub(amount, fee)?;
            amount = self.checked_sub(amount, speedup_dust)?;

            prev = next;
            let next = format!("NARY2_VERIFIER_{}", i);
            let bits = nary_def.bits_for_round(i);
            let validate_selection_bits_script =
                Self::get_validate_selection_bits_script((1 << bits) - 1);

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
                Self::winternitz_check_extra_script(
                    agg_or_verifier,
                    sign_mode,
                    &keys[1],
                    &vec![&format!("verifier_selection_bits2_{}", i)],
                    Some(vec![validate_selection_bits_script]),
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
            GET_HASHES_AND_STEP,
            &claim_verifier,
            self.execute_script(
                context,
                agg_or_prover,
                sign_mode,
                &keys,
                NArySearchType::ReadValueChallenge,
            )?,
            (&prover_speedup_pub, &verifier_speedup_pub),
        )?;

        amount = self.checked_sub(amount, fee)?;
        amount = self.checked_sub(amount, speedup_dust)?;

        self.add_connection_with_scripts(
            context,
            aggregated,
            &mut protocol,
            timelock_blocks,
            amount,
            speedup_dust,
            &GET_HASHES_AND_STEP,
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
            &format!(
                "{}_TL_{}_{}",
                CHALLENGE_READ,
                2 * timelock_blocks,
                VERIFIER_FINAL
            ),
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

        let output_type = utxo_action.3.as_ref().ok_or_else(|| {
            BitVMXError::MissingParameter("UTXO output type is required".to_string())
        })?;
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
        mut leaf_index: u32,
        leaf_identification: bool,
    ) -> Result<(Transaction, SpeedupData), BitVMXError> {
        let tx = self.get_signed_tx(context, name, 0, 0, leaf_identification, 0)?;
        let protocol = self.load_protocol()?;
        let (output_type, scripts) = protocol.get_script_from_output(name, 0)?;
        info!("Scripts length: {}", scripts.len());
        let wots_sigs =
            self.get_winternitz_signature_for_script(&scripts[leaf_index as usize], context)?;

        if context
            .globals
            .get_var(&self.ctx.id, format!("fail_input_{name}").as_str())?
            .is_some_and(|var| matches!(var, VariableTypes::Bool(true)))
        {
            // last script is timeout, we don't want to fail on timeouts.
            if leaf_index != scripts.len() as u32 - 1 {
                warn!("Failing input {name}");
                leaf_index += 1;
            }
        };

        let speedup_data = SpeedupData::new_with_input(
            self.partial_utxo_from(&tx, 0),
            output_type,
            wots_sigs,
            leaf_index as usize,
            true,
        );

        Ok((tx, speedup_data))
    }

    fn winternitz_check_extra_script<T: AsRef<str> + std::fmt::Debug>(
        aggregated: &PublicKey,
        sign_mode: SignMode,
        keys: &ParticipantKeys,
        var_names: &Vec<T>,
        extra_check_scripts: Option<Vec<ScriptBuf>>,
    ) -> Result<Vec<ProtocolScript>, BitVMXError> {
        info!("Winternitz check for variables: {:?}", &var_names);
        let names_and_keys = var_names
            .iter()
            .map(|v| Ok::<_, BitVMXError>((v, keys.get_winternitz(v.as_ref())?)))
            .collect::<Result<Vec<_>, _>>()?;

        let winternitz_check = scripts::verify_winternitz_signatures_aux(
            aggregated,
            &names_and_keys,
            sign_mode,
            extra_check_scripts.is_some(),
            extra_check_scripts,
        )?;

        Ok(vec![winternitz_check])
    }

    fn winternitz_check_cosigned_input_script<T: AsRef<str> + std::fmt::Debug>(
        aggregated: &PublicKey,
        sign_mode: SignMode,
        keys: &Vec<ParticipantKeys>,
        var_names: &Vec<&Vec<T>>,
        extra_check_scripts: Option<Vec<ScriptBuf>>,
    ) -> Result<Vec<ProtocolScript>, BitVMXError> {
        if keys.len() != var_names.len() {
            return Err(BitVMXError::InvalidInput(
                "Keys and var_names length mismatch".to_string(),
            ));
        }
        let names_and_keys: Vec<_> = keys
            .iter()
            .zip(var_names.iter())
            .map(|(k, vars)| {
                vars.iter()
                    .map(move |v| Ok::<_, BitVMXError>((v, k.get_winternitz(v.as_ref())?)))
            })
            .flatten()
            .collect::<Result<Vec<_>, _>>()?;

        let winternitz_check = scripts::verify_winternitz_signatures_aux(
            aggregated,
            &names_and_keys,
            sign_mode,
            extra_check_scripts.is_some(),
            extra_check_scripts,
        )?;

        Ok(vec![winternitz_check])
    }

    fn winternitz_check<T: AsRef<str> + std::fmt::Debug>(
        aggregated: &PublicKey,
        sign_mode: SignMode,
        keys: &ParticipantKeys,
        var_names: &Vec<T>,
    ) -> Result<Vec<ProtocolScript>, BitVMXError> {
        Self::winternitz_check_extra_script(aggregated, sign_mode, keys, var_names, None)
    }

    fn get_reverse_script(total_size: u32) -> ScriptBuf {
        //TODO: This is a workaround to inverse the order of the stack
        let mut stack = StackTracker::new();
        let all = stack.define(total_size, "all");
        for i in 1..total_size {
            stack.move_var_sub_n(all, total_size - i - 1);
        }
        stack.get_script()
    }

    fn get_reverse_and_strip_scripts(
        vars: &Vec<(String, usize)>,
        program_definitions: &ProgramDefinition,
        nary_search_type: NArySearchType,
    ) -> (ScriptBuf, ScriptBuf) {
        let rounds = program_definitions.nary_def().total_rounds();
        let nary = program_definitions.nary_def().nary;
        let nary_last_round = program_definitions.nary_def().nary_last_round;
        let total_size = vars.iter().map(|(_, size)| (*size as u32) * 2).sum();
        let reverse_script = Self::get_reverse_script(total_size);
        //TODO: This is a workaround to remove one nibble from the micro instructions
        //and drop the last steps. (this can be avoided)
        let mut stack = StackTracker::new();
        let mut stackvars = HashMap::new();
        for (name, size) in vars.iter() {
            stackvars.insert(name.clone(), stack.define((size * 2) as u32, name));
        }

        match nary_search_type {
            NArySearchType::ConflictStep => {
                let prover_continue = stack.move_var(stackvars["prover_continue"]);
                stack.drop(prover_continue);
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
                let step_hash = stack.move_var(stackvars["prover_step_hash_tk"]);
                stack.drop(step_hash);
                let next_hash = stack.move_var(stackvars["prover_next_hash_tk"]);
                stack.drop(next_hash);
                for i in 1..rounds + 1 {
                    let selection_bits_0 = stack
                        .move_var_sub_n(stackvars[&format!("verifier_selection_bits_{}", i)], 0);
                    stack.drop(selection_bits_0);
                    stack.move_var_sub_n(stackvars[&format!("verifier_selection_bits_{}", i)], 0);
                }
                let selection = stack.join_in_stack(rounds as u32, None, Some("selection_bits"));
                verify_challenge_step(
                    &mut stack,
                    stackvars["prover_conflict_step_tk"],
                    selection,
                    nary,
                    nary_last_round,
                    rounds,
                );
            }
            NArySearchType::ReadValueChallenge => {
                let prover_continue = stack.move_var(stackvars["prover_continue2"]);
                stack.drop(prover_continue);
                let step_hash = stack.move_var(stackvars["prover_step_hash_tk2"]);
                stack.drop(step_hash);
                let next_hash = stack.move_var(stackvars["prover_next_hash_tk2"]);
                stack.drop(next_hash);
                for i in 1..rounds + 1 {
                    let selection_bits_0 = stack
                        .move_var_sub_n(stackvars[&format!("verifier_selection_bits2_{}", i)], 0);
                    stack.drop(selection_bits_0);
                    stack.move_var_sub_n(stackvars[&format!("verifier_selection_bits2_{}", i)], 0);
                }
                let selection = stack.join_in_stack(rounds as u32, None, Some("selection_bits"));
                // stack.drop(selection);
                verify_challenge_step(
                    &mut stack,
                    stackvars["prover_write_step_tk2"],
                    selection,
                    nary,
                    nary_last_round,
                    rounds,
                );
            }
        }

        (reverse_script, stack.get_script())
    }

    fn challenge_step_script(
        &self,
        context: &ProgramContext,
        aggregated: &PublicKey,
        sign_mode: SignMode,
        keys: &Vec<ParticipantKeys>,
        nary_search_type: NArySearchType,
    ) -> Result<ProtocolScript, BitVMXError> {
        let prover_keys = &keys[0];
        let verifier_keys = &keys[1];

        let challenge_step_vars = match nary_search_type {
            NArySearchType::ConflictStep => PROVER_CHALLENGE_STEP1
                .get()
                .ok_or_else(|| {
                    BitVMXError::InitializationError(
                        "PROVER_CHALLENGE_STEP1 not initialized".to_string(),
                    )
                })?
                .read()?,
            _ => PROVER_CHALLENGE_STEP2
                .get()
                .ok_or_else(|| {
                    BitVMXError::InitializationError(
                        "PROVER_CHALLENGE_STEP2 not initialized".to_string(),
                    )
                })?
                .read()?,
        };

        let challenge_names_and_keys: Vec<(&str, &key_manager::winternitz::WinternitzPublicKey)> =
            challenge_step_vars
                .iter()
                .map(|(name, _)| {
                    let key_provider = if name.starts_with("prover") {
                        prover_keys
                    } else {
                        verifier_keys
                    };
                    Ok::<_, BitVMXError>((name.as_str(), key_provider.get_winternitz(name)?))
                })
                .collect::<Result<Vec<_>, _>>()?;

        let mut stack = StackTracker::new();
        let mut stackvars = HashMap::new();
        for (name, size) in challenge_step_vars.iter() {
            stackvars.insert(name.clone(), stack.define((size * 2) as u32, name));
        }

        let program_def = self.get_program_definition(context)?.0;
        let rounds = program_def.nary_def().total_rounds();
        let nary = program_def.nary_def().nary;
        let nary_last_round = program_def.nary_def().nary_last_round;
        let total_size = challenge_step_vars
            .iter()
            .map(|(_, size)| (*size as u32) * 2)
            .sum();
        let reverse_script = Self::get_reverse_script(total_size);

        if nary_search_type == NArySearchType::ConflictStep {
            let tables = &StackTables::new(&mut stack, false, false, 0b111, 0b111, 0);

            for i in 1..rounds + 1 {
                let selection_bits_0 =
                    stack.move_var_sub_n(stackvars[&format!("verifier_selection_bits_{}", i)], 0);
                stack.drop(selection_bits_0);
                stack.move_var_sub_n(stackvars[&format!("verifier_selection_bits_{}", i)], 0);
            }
            let selection = stack.join_in_stack(rounds as u32, None, Some("selection_bits"));

            // Convert the last step to the same format as the selection bits to be able to compare them.
            var_to_decisions_in_altstack(
                &mut stack,
                tables,
                stackvars["verifier_last_step_tk"],
                nary,
                nary_last_round,
                rounds,
            );
            let last_step = stack.from_altstack_joined(rounds as u32, "last_step");

            // The prover can challenge only if the selected step is greater or equal than the commited last_step
            // It's invalid for the selected step to be equal because the nary search is off by one, the trace the verifier is asking
            // corresponds to the 'selected_step+1' step and 'last_step+1' is an invalid step.
            stack.equality(last_step, false, selection, false, true, false); // last_step == selection
            is_lower_than(&mut stack, last_step, selection, true); // last_step < selection
            stack.op_boolor(); // last_step == selection || last_step < selection -> last_step <= selection
            stack.op_verify(); // verify(last_step <= selection)
            tables.drop(&mut stack);
        } else {
            for i in 1..rounds + 1 {
                let selection_bits_0 =
                    stack.move_var_sub_n(stackvars[&format!("verifier_selection_bits_{}", i)], 0);
                stack.drop(selection_bits_0);
                stack.move_var_sub_n(stackvars[&format!("verifier_selection_bits_{}", i)], 0);
            }

            let selection_first_nary =
                stack.join_in_stack(rounds as u32, None, Some("selection_bits_1"));

            for i in 1..rounds + 1 {
                let selection_bits_0 =
                    stack.move_var_sub_n(stackvars[&format!("verifier_selection_bits2_{}", i)], 0);
                stack.drop(selection_bits_0);
                stack.move_var_sub_n(stackvars[&format!("verifier_selection_bits2_{}", i)], 0);
            }

            let selection_second_nary =
                stack.join_in_stack(rounds as u32, None, Some("selection_bits_2"));
            // The prover can challenge only if the selected step in the second nary search is greater than the one in the first nary search.
            // Note that this time the prover can't challenge if the selected step is the same in both searches, the verifier has to challenge
            // if in the second nary search the prover changed the hash of the selected step in the first nary search.
            is_lower_than(
                &mut stack,
                selection_first_nary,
                selection_second_nary,
                true,
            );
            stack.op_verify();
        };

        let winternitz_check = scripts::verify_winternitz_signatures_aux(
            aggregated,
            &challenge_names_and_keys.iter().cloned().collect(),
            sign_mode,
            true,
            Some(vec![reverse_script, stack.get_script()]),
        )?;

        Ok(winternitz_check)
    }

    fn execute_script(
        &self,
        context: &ProgramContext,
        aggregated: &PublicKey,
        sign_mode: SignMode,
        keys: &Vec<ParticipantKeys>,
        nary_search_type: NArySearchType,
    ) -> Result<Vec<ProtocolScript>, BitVMXError> {
        let prover_keys = &keys[0];
        let verifier_keys = &keys[1];
        let vars = match nary_search_type {
            NArySearchType::ConflictStep => TRACE_VARS
                .get()
                .ok_or_else(|| {
                    BitVMXError::InitializationError("TRACE_VARS not initialized".to_string())
                })?
                .read()?,
            NArySearchType::ReadValueChallenge => TK_2NARY
                .get()
                .ok_or_else(|| {
                    BitVMXError::InitializationError("TK_2NARY not initialized".to_string())
                })?
                .read()?,
        };

        let vars_names = vars
            .iter()
            .filter(|(name, _)| name.starts_with("prover"))
            .map(|(name, _)| name.as_str())
            .collect::<Vec<&str>>();

        let mut names_and_keys: Vec<(&str, &key_manager::winternitz::WinternitzPublicKey)> =
            vars_names
                .iter()
                .map(|v| Ok::<_, BitVMXError>((*v, prover_keys.get_winternitz(v)?)))
                .collect::<Result<Vec<_>, _>>()?;

        names_and_keys.extend(
            vars.iter()
                .filter(|(name, _)| name.starts_with("verifier_selection_bits"))
                .map(|(name, _)| {
                    verifier_keys
                        .get_winternitz(name)
                        .map(|k| (name.as_str(), k))
                })
                .collect::<Result<Vec<_>, _>>()?,
        );

        let program_def = self.get_program_definition(context)?.0;

        let vars_without_witness = vars
            .iter()
            .filter(|(var, _)| var != "prover_witness")
            .cloned()
            .collect();

        let (reverse_script, strip_script) =
            Self::get_reverse_and_strip_scripts(&vars, &program_def, nary_search_type);

        let (reverse_script_ww, strip_script_ww) = Self::get_reverse_and_strip_scripts(
            &vars_without_witness,
            &program_def,
            nary_search_type,
        );

        let mut winternitz_check_list = vec![self.challenge_step_script(
            context,
            aggregated,
            sign_mode,
            keys,
            nary_search_type,
        )?];

        match nary_search_type {
            NArySearchType::ConflictStep => {
                let mapping = create_verification_script_mapping(REGISTERS_BASE_ADDRESS);
                let mut instruction_names: Vec<_> = mapping.keys().cloned().collect();
                instruction_names.sort();

                for (_, name) in instruction_names.iter().enumerate() {
                    let (script, requires_witness) = mapping[name].clone();
                    let (reverse, strip) = if requires_witness {
                        (reverse_script.clone(), strip_script.clone())
                    } else {
                        (reverse_script_ww.clone(), strip_script_ww.clone())
                    };

                    let winternitz_check = scripts::verify_winternitz_signatures_aux(
                        aggregated,
                        &names_and_keys
                            .iter()
                            .filter(|(var_name, _)| {
                                requires_witness || *var_name != "prover_witness"
                            })
                            .cloned()
                            .collect(),
                        sign_mode,
                        true,
                        Some(vec![reverse, strip, script]),
                    )?;
                    winternitz_check_list.push(winternitz_check);
                }
            }
            NArySearchType::ReadValueChallenge => {
                let winternitz_check = scripts::verify_winternitz_signatures_aux(
                    aggregated,
                    &names_and_keys,
                    sign_mode,
                    true,
                    Some(vec![reverse_script.clone(), strip_script.clone()]),
                )?;
                winternitz_check_list.push(winternitz_check);
            }
        };

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

    fn get_cosign_extra_script(words: u32) -> ScriptBuf {
        let word_size = 4;
        let mut stack = StackTracker::new();
        let verifier = stack.define(word_size * 2 * words, "value_verifier"); // each word is 4 bytes, each byte is 2 nibbles
        let prover = stack.define(word_size * 2 * words, "value_prover");
        stack.equals(verifier, true, prover, true);
        stack.get_script()
    }

    pub fn get_validate_selection_bits_script(max_bits: u8) -> ScriptBuf {
        let mut stack = StackTracker::new();
        let selection_bits = stack.define(2, "verifier_selection_bits");

        // we have to check that the most significant nibble is zero, but since we won't use the reverse script it is at position 1 instead of 0
        stack.move_var_sub_n(selection_bits, 1);
        stack.number(0);
        stack.op_equalverify();

        stack.number(max_bits as u32);
        stack.op_lessthanorequal();
        stack.op_verify();
        stack.get_script()
    }

    fn get_validate_last_step_script(max_steps: u64) -> ScriptBuf {
        let mut stack = StackTracker::new();
        let last_step = stack.define(16, "prover_last_step");
        let last_hash = stack.define(40, "prover_last_hash");
        stack.drop(last_hash);

        let zero = stack.number_u64(0);
        stack.equality(zero, true, last_step, false, false, true);

        let max_steps = stack.number_u64(max_steps);
        stack.equality(last_step, false, max_steps, false, true, false);
        is_lower_than(&mut stack, last_step, max_steps, true);
        stack.op_boolor();
        stack.op_verify();

        stack.get_script()
    }

    fn get_verify_last_step_script() -> ScriptBuf {
        let mut stack = StackTracker::new();
        // vars are swaped and inverted because we won't use the reverse script but it doesn't matter since a == b iff rev(b) == rev(a)
        let verifier_last_step = stack.define(16, "verifier_last_step_tk");
        let prover_last_step = stack.define(16, "prover_last_step");

        stack.equals(verifier_last_step, true, prover_last_step, true);

        stack.get_script()
    }
}
