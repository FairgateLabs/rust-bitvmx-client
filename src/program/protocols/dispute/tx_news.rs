use bitcoin::Txid;
use bitcoin_coordinator::{coordinator::BitcoinCoordinatorApi, TransactionStatus};
use bitvmx_cpu_definitions::{memory::MemoryWitness, trace::*};
use bitvmx_job_dispatcher::dispatcher_job::DispatcherJob;
use bitvmx_job_dispatcher_types::emulator_messages::EmulatorJobType;
use console::style;
use emulator::decision::nary_search::NArySearchType;
use tracing::info;

use crate::{
    bitvmx::Context,
    errors::BitVMXError,
    program::{
        participant::ParticipantRole::{self, Prover, Verifier},
        protocols::{
            claim::ClaimGate,
            dispute::{
                action_wins, action_wins_prefix,
                challenge::READ_VALUE_NARY_SEARCH_CHALLENGE,
                config::{ConfigResults, DisputeConfiguration},
                input_handler::{get_txs_configuration, unify_inputs, unify_witnesses},
                input_tx_name, timeout_input_tx, timeout_tx, DisputeResolutionProtocol, CHALLENGE,
                CHALLENGE_READ, COMMITMENT, EXECUTE, INPUT_TX, PROVER_WINS, START_CH, TRACE_VARS,
                VERIFIER_FINAL, VERIFIER_WINS,
            },
            protocol_handler::ProtocolHandler,
        },
        variables::VariableTypes,
    },
    types::ProgramContext,
};

fn dispatch_timeout_tx(
    drp: &DisputeResolutionProtocol,
    program_context: &ProgramContext,
    name: &str,
    current_height: u32,
) -> Result<(), BitVMXError> {
    let params = program_context
        .globals
        .get_var(&drp.ctx.id, name)?
        .unwrap()
        .vec_number()?;
    let input = params[0];
    let leaf = params[1];
    let timelock_blocks = params[2];

    info!(
        "Current block: {}. Will try to dispatch timeout tx: {} in {} blocks. ",
        current_height, name, timelock_blocks
    );

    let tx = drp.get_signed_tx(program_context, name, input, leaf, true, 0)?;
    let speedup_data = drp.get_speedup_data_from_tx(&tx, program_context, None)?;
    program_context.bitcoin_coordinator.dispatch(
        tx,
        Some(speedup_data),
        Context::ProgramId(drp.ctx.id).to_string()?,
        Some(current_height + timelock_blocks),
    )?;
    Ok(())
}

// When I see [tx_name], and vout is [has_vout],
// if I'm [role], then I dispatch
// [is_input] ? timeout_input_tx[timeout_name] : timeout_tx[timeout_name].#[derive(Debug, Clone)]
pub struct TimeoutDispatchRule {
    pub tx_name: String,
    pub has_vout: bool,
    pub role: ParticipantRole,
    pub timeout_name: String,
    pub apply_timeout: bool,
    pub is_input: bool,
}

impl TimeoutDispatchRule {
    pub fn new(
        tx_name: &str,
        has_vout: bool,
        role: ParticipantRole,
        timeout_name: &str,
        apply_timeout: bool,
        is_input: bool,
    ) -> Self {
        Self {
            tx_name: tx_name.to_string(),
            has_vout,
            role,
            timeout_name: timeout_name.to_string(),
            apply_timeout,
            is_input,
        }
    }
}

pub struct TimeoutDispatchTable {
    pub rules: Vec<TimeoutDispatchRule>,
}

impl TimeoutDispatchTable {
    pub fn new(rules: Vec<TimeoutDispatchRule>) -> Self {
        Self { rules }
    }
    pub fn new_predefined(first_2nd_nary_prover_tx: &str, last_2nd_nary_verifier_tx: &str) -> Self {
        Self {
            rules: vec![
                TimeoutDispatchRule::new(EXECUTE, false, Prover, CHALLENGE, true, false),
                TimeoutDispatchRule::new(CHALLENGE, false, Prover, CHALLENGE, true, true),
                TimeoutDispatchRule::new(EXECUTE, false, Verifier, EXECUTE, true, true),
                TimeoutDispatchRule::new(
                    CHALLENGE,
                    false,
                    Verifier,
                    first_2nd_nary_prover_tx,
                    false,
                    false,
                ),
                TimeoutDispatchRule::new(
                    last_2nd_nary_verifier_tx,
                    false,
                    Prover,
                    CHALLENGE_READ,
                    true,
                    false,
                ),
                TimeoutDispatchRule::new(CHALLENGE_READ, false, Prover, CHALLENGE_READ, true, true),
            ],
        }
    }
    pub fn add_rule(&mut self, rule: TimeoutDispatchRule) {
        self.rules.push(rule);
    }
    pub fn iter(
        &self,
    ) -> impl Iterator<Item = (&String, &bool, &ParticipantRole, &String, &bool, &bool)> {
        self.rules.iter().map(|r| {
            (
                &r.tx_name,
                &r.has_vout,
                &r.role,
                &r.timeout_name,
                &r.apply_timeout,
                &r.is_input,
            )
        })
    }
}

fn get_timeout_name(name: &str, apply_timeout: bool, is_input: bool) -> String {
    if !apply_timeout {
        name.to_string()
    } else if is_input {
        timeout_input_tx(name)
    } else {
        timeout_tx(name)
    }
}

fn auto_dispatch_timeout(
    drp: &DisputeResolutionProtocol,
    name: &str,
    vout: Option<u32>,
    program_context: &ProgramContext,
    current_height: u32,
    timeout_table: &TimeoutDispatchTable,
) -> Result<(), BitVMXError> {
    for (tx_name, tx_vout, tx_role, timeout_name, not_ignore, is_input) in timeout_table.iter() {
        if *tx_name == name && *tx_role == drp.role() && *tx_vout == (vout.is_some()) {
            dispatch_timeout_tx(
                drp,
                program_context,
                &get_timeout_name(&timeout_name, *not_ignore, *is_input),
                current_height,
            )?;
        }
    }
    Ok(())
}

fn cancel_timeout(
    drp: &DisputeResolutionProtocol,
    name: &str,
    vout: Option<u32>,
    program_context: &ProgramContext,
) -> Result<(), BitVMXError> {
    let cancel = match name {
        EXECUTE => drp.role() == ParticipantRole::Verifier,
        CHALLENGE => drp.role() == ParticipantRole::Prover,
        CHALLENGE_READ => drp.role() == ParticipantRole::Prover,
        _ => false,
    };

    if cancel {
        let tx_to_cancel = if vout.is_none() {
            timeout_tx(name)
        } else {
            timeout_input_tx(name)
        };
        info!("Cancel timeout tx: {}", tx_to_cancel);
        let tx_id = drp.get_transaction_id_by_name(&tx_to_cancel)?;
        program_context.bitcoin_coordinator.cancel(
            bitcoin_coordinator::TypesToMonitor::Transactions(vec![tx_id], String::default()),
        )?;
    }
    Ok(())
}

fn get_claim_name(drp: &DisputeResolutionProtocol, other: bool) -> &str {
    let (role, other_role) = match drp.role() {
        ParticipantRole::Prover => (PROVER_WINS, VERIFIER_WINS),
        ParticipantRole::Verifier => (VERIFIER_WINS, PROVER_WINS),
    };
    if other {
        other_role
    } else {
        role
    }
}

fn auto_claim_start(
    drp: &DisputeResolutionProtocol,
    name: &str,
    vout: Option<u32>,
    program_context: &ProgramContext,
    timeout_table: &TimeoutDispatchTable,
) -> Result<(), BitVMXError> {
    if vout.is_some() {
        return Ok(());
    }
    for (_, _, tx_role, timeout_name, not_ignore, is_input) in timeout_table.iter() {
        let timeout_name = get_timeout_name(timeout_name, *not_ignore, *is_input);
        if &timeout_name == name && *tx_role == drp.role() {
            let claim_name = ClaimGate::tx_start(get_claim_name(drp, false));
            let tx = drp.get_signed_tx(program_context, &claim_name, 0, 0, false, 0)?;
            let speedup_data = drp.get_speedup_data_from_tx(&tx, program_context, None)?;
            info!("{claim_name}: {:?}", tx);
            program_context.bitcoin_coordinator.dispatch(
                tx,
                Some(speedup_data),
                Context::ProgramId(drp.ctx.id).to_string()?,
                None,
            )?;
        }
    }

    Ok(())
}

fn claim_state_handle(
    drp: &DisputeResolutionProtocol,
    tx_id: Txid,
    name: &str,
    vout: Option<u32>,
    tx_status: TransactionStatus,
    program_context: &ProgramContext,
    current_height: u32,
    timelock_blocks: u32,
) -> Result<(), BitVMXError> {
    if vout.is_some() {
        return Ok(());
    }
    let my_claim = get_claim_name(drp, false);
    let other_claim = get_claim_name(drp, true);
    // start claim
    if name == ClaimGate::tx_start(PROVER_WINS) || name == ClaimGate::tx_start(VERIFIER_WINS) {
        // my start
        if name == ClaimGate::tx_start(my_claim) {
            info!("{my_claim} SUCCESS dispatch");

            let prover_wins_tx = drp.get_signed_tx(
                program_context,
                &ClaimGate::tx_success(&my_claim),
                0,
                1,
                false,
                0,
            )?;
            let speedup_data =
                drp.get_speedup_data_from_tx(&prover_wins_tx, program_context, None)?;
            program_context.bitcoin_coordinator.dispatch(
                prover_wins_tx,
                Some(speedup_data),
                Context::ProgramId(drp.ctx.id).to_string()?,
                Some(current_height + timelock_blocks),
            )?;
        }
        //other start
        else {
            info!("{other_claim} STOP dispatch attempt");
            let prover_win_stop = drp.get_signed_tx(
                program_context,
                &ClaimGate::tx_stop(&other_claim, 0),
                0,
                0,
                false,
                0,
            )?;
            let speedup_data =
                drp.get_speedup_data_from_tx(&prover_win_stop, program_context, None)?;
            program_context.bitcoin_coordinator.dispatch(
                prover_win_stop,
                Some(speedup_data),
                Context::ProgramId(drp.ctx.id).to_string()?,
                None,
            )?;
        }
    }

    if (name == ClaimGate::tx_success(PROVER_WINS) && drp.role() == ParticipantRole::Prover)
        || (name == ClaimGate::tx_success(VERIFIER_WINS) && drp.role() == ParticipantRole::Verifier)
    {
        let config = DisputeConfiguration::load(&drp.ctx.id, &program_context.globals)?;
        let actions = match drp.role() {
            ParticipantRole::Prover => &config.prover_actions,
            ParticipantRole::Verifier => &config.verifier_actions,
        };

        for (i, action) in actions.iter().enumerate() {
            info!("{}. Execute Action {}", drp.role(), i);
            let win_action_tx = drp.get_signed_tx(
                program_context,
                &action_wins(&drp.role(), 1),
                0,
                0,
                false,
                action.1[0],
            )?;
            let speedup_data =
                drp.get_speedup_data_from_tx(&win_action_tx, program_context, None)?;

            program_context.bitcoin_coordinator.dispatch(
                win_action_tx,
                Some(speedup_data),
                Context::ProgramId(drp.ctx.id).to_string()?,
                None,
            )?;
        }
    }

    if name.starts_with(&action_wins_prefix(&ParticipantRole::Prover))
        || name.starts_with(&action_wins_prefix(&ParticipantRole::Verifier))
    {
        let config = DisputeConfiguration::load(&drp.ctx.id, &program_context.globals)?;
        for (protocol_name, protocol_id) in config.notify_protocol {
            let protocol = drp.load_protocol_by_name(&protocol_name, protocol_id)?;
            protocol.notify_news(
                tx_id,
                vout,
                tx_status.clone(),
                drp.ctx.id.to_string(),
                program_context,
                vec![],
            )?;
        }
    }

    Ok(())
}

pub fn handle_tx_news(
    drp: &DisputeResolutionProtocol,
    tx_id: Txid,
    vout: Option<u32>,
    tx_status: TransactionStatus,
    program_context: &ProgramContext,
) -> Result<(), BitVMXError> {
    let name = drp.get_transaction_name_by_id(tx_id)?;
    let current_height = tx_status.block_info.as_ref().unwrap().height;
    info!(
        "Program {}: Transaction name: {}  id: {}:{:?} has been seen on-chain {}. Height: {}",
        drp.ctx.id,
        style(&name).blue(),
        style(&tx_id).green(),
        style(&vout).yellow(),
        drp.role(),
        current_height,
    );

    let config = DisputeConfiguration::load(&drp.ctx.id, &program_context.globals)?;

    cancel_timeout(drp, &name, vout, program_context)?;

    let timelock_blocks = config.timelock_blocks;

    let timeout_table =
        TimeoutDispatchTable::new_predefined("NARY2_PROVER_2_TO", "NARY2_VERIFIER_4"); //TODO: obtain from globals?

    auto_dispatch_timeout(
        drp,
        &name,
        vout,
        program_context,
        current_height,
        &timeout_table,
    )?;

    auto_claim_start(drp, &name, vout, program_context, &timeout_table)?;

    claim_state_handle(
        drp,
        tx_id,
        &name,
        vout,
        tx_status.clone(),
        program_context,
        current_height,
        timelock_blocks as u32,
    )?;

    let fail_force_config = config.fail_force_config.unwrap_or_default();

    if let Some(auto_dispatch_input) = config.auto_dispatch_input {
        if name == START_CH && drp.role() == ParticipantRole::Prover {
            let (tx, speedup) = drp.get_transaction_by_name(
                &input_tx_name(auto_dispatch_input as u32),
                program_context,
            )?;

            info!(
                "Auto Dispatching input tx {}",
                &input_tx_name(auto_dispatch_input as u32)
            );
            program_context.bitcoin_coordinator.dispatch(
                tx,
                speedup,
                Context::ProgramId(drp.context().id).to_string()?,
                None,
            )?;
        }
    }

    if name.starts_with(INPUT_TX) && vout.is_some() {
        let idx = name.strip_prefix(INPUT_TX).unwrap().parse::<u32>()?;

        let (input_txs, _input_txs_sizes, _input_txs_offsets, last_tx_id) =
            get_txs_configuration(&drp.ctx.id, program_context)?;

        let owner = input_txs[idx as usize].as_str();

        if owner == drp.role().to_string() {
            //if I'm the prover and it's the last input
            if drp.role() == ParticipantRole::Prover && idx == last_tx_id {
                let (def, program_definition) = drp.get_program_definition(program_context)?;
                let full_input = unify_inputs(&drp.ctx.id, program_context, &def)?;

                let execution_path = drp.get_execution_path()?;
                let msg = serde_json::to_string(&DispatcherJob {
                    job_id: drp.ctx.id.to_string(),
                    job_type: EmulatorJobType::ProverExecute(
                        program_definition,
                        full_input,
                        execution_path.clone(),
                        format!("{}/{}", execution_path, "execution.json").to_string(),
                        fail_force_config.main.fail_config_prover.clone(),
                    ),
                })?;
                program_context
                    .broker_channel
                    .send(&program_context.components_config.emulator, msg)?;
            }
        } else {
            //if it's not my input, decode the witness
            drp.decode_witness_from_speedup(
                tx_id,
                vout.unwrap(),
                &name,
                program_context,
                &tx_status.tx,
                None,
            )?;

            unify_witnesses(&drp.ctx.id, program_context, idx as usize)?;
        }
    }

    if name == COMMITMENT && drp.role() == ParticipantRole::Verifier && vout.is_some() {
        drp.decode_witness_from_speedup(
            tx_id,
            vout.unwrap(),
            &name,
            program_context,
            &tx_status.tx,
            None,
        )?;

        let execution_path = drp.get_execution_path()?;

        let (def, program_definition) = drp.get_program_definition(program_context)?;
        let input_program = unify_inputs(&drp.ctx.id, program_context, &def)?;

        let last_hash = program_context
            .witness
            .get_witness(&drp.ctx.id, "prover_last_hash")?
            .unwrap()
            .winternitz()?
            .message_bytes();

        let last_step = program_context
            .witness
            .get_witness(&drp.ctx.id, "prover_last_step")?
            .unwrap()
            .winternitz()?
            .message_bytes();
        let last_step = u64::from_be_bytes(last_step.try_into().unwrap());

        let msg = serde_json::to_string(&DispatcherJob {
            job_id: drp.ctx.id.to_string(),
            job_type: EmulatorJobType::VerifierCheckExecution(
                program_definition,
                input_program,
                execution_path.clone(),
                last_step,
                hex::encode(last_hash),
                format!("{}/{}", execution_path, "execution.json").to_string(),
                fail_force_config.main.force_condition.clone(),
                fail_force_config.main.fail_config_verifier.clone(),
            ),
        })?;

        program_context
            .broker_channel
            .send(&program_context.components_config.emulator, msg)?;
    }

    if (name == COMMITMENT || name.starts_with("NARY_VERIFIER")) && vout.is_some() {
        let round = name
            .strip_prefix("NARY_VERIFIER_")
            .unwrap_or("0")
            .parse::<u32>()
            .unwrap();
        handle_nary_verifier(
            &name,
            drp,
            program_context,
            tx_id,
            vout,
            &tx_status,
            current_height,
            &fail_force_config,
            "selection_bits",
            COMMITMENT,
            EXECUTE,
            0,
            round,
            NArySearchType::ConflictStep,
        )?;
    }

    if (name.starts_with("NARY_PROVER"))
        && drp.role() == ParticipantRole::Verifier
        && vout.is_some()
    {
        handle_nary_prover(
            &name,
            drp,
            program_context,
            tx_id,
            vout,
            &tx_status,
            &fail_force_config,
            "NARY_PROVER_",
            "prover_hash",
            NArySearchType::ConflictStep,
        )?;
    }

    if name == EXECUTE && drp.role() == ParticipantRole::Verifier && vout.is_some() {
        let (_, leaf) = drp.decode_witness_from_speedup(
            tx_id,
            vout.unwrap(),
            &name,
            program_context,
            &tx_status.tx,
            None,
        )?;

        let params = program_context
            .globals
            .get_var(&drp.ctx.id, &timeout_input_tx(EXECUTE))?
            .unwrap()
            .vec_number()?;
        let timeout_leaf = params[1];
        if leaf == timeout_leaf {
            info!("Verifier consumed the timeout input for EXECUTE");
            return Ok(());
        }

        let (_program_definition, pdf) = drp.get_program_definition(program_context)?;
        let execution_path = drp.get_execution_path()?;

        let mut values = std::collections::HashMap::new();

        for (name, _) in TRACE_VARS.iter() {
            if *name == "prover_witness" {
                continue;
            }
            if let Some(value) = program_context.witness.get_witness(&drp.ctx.id, name)? {
                values.insert(*name, value.winternitz().unwrap().message_bytes());
            } else {
                return Err(BitVMXError::VariableNotFound(drp.ctx.id, name.to_string()));
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
        let read_pc = TraceReadPC::new(program_counter, to_u32(&values["prover_read_pc_opcode"]));
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
            job_id: drp.ctx.id.to_string(),
            job_type: EmulatorJobType::VerifierChooseChallenge(
                pdf,
                execution_path.clone(),
                final_trace,
                format!("{}/{}", execution_path, "execution.json").to_string(),
                fail_force_config.main.fail_config_verifier.clone(),
                fail_force_config.main.force_challenge.clone(),
            ),
        })?;
        program_context
            .broker_channel
            .send(&program_context.components_config.emulator, msg)?;
    }

    if name == CHALLENGE && drp.role() == ParticipantRole::Prover && vout.is_some() {
        let (names, leaf) = drp.decode_witness_from_speedup(
            tx_id,
            vout.unwrap(),
            &name,
            program_context,
            &tx_status.tx,
            None,
        )?;

        let read_value_nary_search_leaf = program_context
            .globals
            .get_var(
                &drp.ctx.id,
                &format!("challenge_leaf_start_{}", "read_value_nary_search"),
            )?
            .unwrap()
            .number()? as u32;

        //TODO: if the verifier is able to execute the challenge, the prover can react only to the read challenge nary search

        match leaf {
            l if l == read_value_nary_search_leaf => {
                let expected_names: Vec<&str> = READ_VALUE_NARY_SEARCH_CHALLENGE
                    .iter()
                    .map(|(name, _)| *name)
                    .collect();

                if names.len() == 1 && names == expected_names {
                    let bits_name = &names[0];
                    let witness = program_context
                        .witness
                        .get_witness(&drp.ctx.id, bits_name)?
                        .ok_or_else(|| {
                            BitVMXError::VariableNotFound(drp.ctx.id, bits_name.to_string())
                        })?;
                    let bytes = witness.winternitz()?.message_bytes();

                    info!(
                        "Challenge will be extended with a 2nd nary search. {bits_name} are {:?}",
                        bytes
                    );

                    handle_nary_verifier(
                        &name,
                        drp,
                        program_context,
                        tx_id,
                        vout,
                        &tx_status,
                        current_height,
                        &fail_force_config,
                        "selection_bits2",
                        CHALLENGE,
                        CHALLENGE_READ,
                        bytes[0],
                        1, // round 2
                        NArySearchType::ReadValueChallenge,
                    )?;
                } else {
                    panic!(
                        "The challenge leaf does not match the expected witness names.\n\
                 Expected: {:?}, got: {:?}",
                        expected_names, names
                    );
                }
            }
            _ => {
                info!("Challenge ended successfully");
            }
        }
    }

    if name.starts_with("NARY2_VERIFIER") && vout.is_some() {
        let round = name
            .strip_prefix("NARY2_VERIFIER_")
            .unwrap()
            .parse::<u32>()
            .unwrap();
        handle_nary_verifier(
            &name,
            drp,
            program_context,
            tx_id,
            vout,
            &tx_status,
            current_height,
            &fail_force_config,
            "selection_bits2",
            CHALLENGE,
            CHALLENGE_READ,
            0, // Will be ignored
            round,
            NArySearchType::ReadValueChallenge,
        )?;
    }

    if name.starts_with("NARY2_PROVER") && drp.role() == ParticipantRole::Verifier && vout.is_some()
    {
        handle_nary_prover(
            &name,
            drp,
            program_context,
            tx_id,
            vout,
            &tx_status,
            &fail_force_config,
            "NARY2_PROVER_",
            "prover_hash2",
            NArySearchType::ReadValueChallenge,
        )?;
    }

    if name == CHALLENGE_READ && drp.role() == ParticipantRole::Prover && vout.is_some() {
        info!("The challenge has ended after the 2nd n-ary search.");
        drp.decode_witness_from_speedup(
            tx_id,
            vout.unwrap(),
            &name,
            program_context,
            &tx_status.tx,
            None,
        )?;
    }

    if CHALLENGE_READ == name && ParticipantRole::Verifier == drp.role() && vout.is_none() {
        let verifier_final_tx =
            drp.get_signed_tx(program_context, &VERIFIER_FINAL, 0, 0, false, 0)?;
        let speedup_data =
            drp.get_speedup_data_from_tx(&verifier_final_tx, program_context, None)?;
        program_context.bitcoin_coordinator.dispatch(
            verifier_final_tx,
            Some(speedup_data),
            Context::ProgramId(drp.ctx.id).to_string()?,
            Some(current_height + 2 * timelock_blocks as u32),
        )?;
    }

    if VERIFIER_FINAL == name && ParticipantRole::Verifier == drp.role() && vout.is_none() {
        let claim_name = ClaimGate::tx_start(VERIFIER_WINS);
        let tx = drp.get_signed_tx(program_context, &claim_name, 0, 0, false, 0)?;
        let speedup_data = drp.get_speedup_data_from_tx(&tx, program_context, None)?;
        info!("{claim_name}: {:?}", tx);
        program_context.bitcoin_coordinator.dispatch(
            tx,
            Some(speedup_data),
            Context::ProgramId(drp.ctx.id).to_string()?,
            None,
        )?;
    }

    Ok(())
}

fn handle_nary_verifier(
    name: &str,
    drp: &DisputeResolutionProtocol,
    program_context: &ProgramContext,
    tx_id: Txid,
    vout: Option<u32>,
    tx_status: &TransactionStatus,
    current_height: u32,
    fail_force_config: &ConfigResults,
    selection_bits: &str,             // "selection_bits"
    prev_name: &str,                  // COMMITMENT
    post_name: &str,                  // EXECUTE
    decision_start_value: u8,         // 0
    mut round: u32,                   // current round
    nary_search_type: NArySearchType, // ConflictStep
) -> Result<(), BitVMXError> {
    let (program_definition, pdf) = drp.get_program_definition(program_context)?;
    let nary = program_definition.nary_def();

    let (prover_config, current_round) = match nary_search_type {
        NArySearchType::ConflictStep => (
            fail_force_config.main.fail_config_prover.clone(),
            "current_round",
        ),
        NArySearchType::ReadValueChallenge => (
            fail_force_config.read.fail_config_prover.clone(),
            "current_round2",
        ),
    };
    if drp.role() == ParticipantRole::Prover {
        let decision = if name == prev_name {
            decision_start_value
        } else {
            drp.decode_witness_from_speedup(
                tx_id,
                vout.unwrap(),
                &name,
                program_context,
                &tx_status.tx,
                None,
            )?;

            let bits = program_context
                .witness
                .get_witness(&drp.ctx.id, &format!("{}_{}", selection_bits, round))?
                .unwrap()
                .winternitz()?
                .message_bytes();
            let bits = bits[0];
            bits
        };

        round += 1;

        //TODO: make this value return from execution
        program_context.globals.set_var(
            &drp.ctx.id,
            current_round,
            VariableTypes::Number(round as u32),
        )?;

        let execution_path = drp.get_execution_path()?;
        if round <= nary.total_rounds() as u32 {
            let msg = serde_json::to_string(&DispatcherJob {
                job_id: drp.ctx.id.to_string(),
                job_type: EmulatorJobType::ProverGetHashesForRound(
                    pdf,
                    execution_path.clone(),
                    round as u8,
                    decision as u32,
                    format!("{}/{}", execution_path, "execution.json").to_string(),
                    prover_config,
                    nary_search_type,
                ),
            })?;
            program_context
                .broker_channel
                .send(&program_context.components_config.emulator, msg)?;
        } else {
            match nary_search_type {
                NArySearchType::ConflictStep => {
                    let msg = serde_json::to_string(&DispatcherJob {
                        job_id: drp.ctx.id.to_string(),
                        job_type: EmulatorJobType::ProverFinalTrace(
                            pdf,
                            execution_path.clone(),
                            (decision + 1) as u32,
                            format!("{}/{}", execution_path, "execution.json").to_string(),
                            fail_force_config.main.fail_config_prover.clone(),
                        ),
                    })?;
                    program_context
                        .broker_channel
                        .send(&program_context.components_config.emulator, msg)?;
                }
                NArySearchType::ReadValueChallenge => {
                    info!("The dispute has ended after the 2nd n-ary search.");
                    // TODO: implement transaction to end the dispute after the 2nd n-ary search
                }
            }
        }
    } else {
        if round == nary.total_rounds() as u32 && nary_search_type == NArySearchType::ConflictStep {
            dispatch_timeout_tx(drp, program_context, &timeout_tx(post_name), current_height)?;
        }
        // TODO: this is a temporary solution to force the verifier to choose the challenge after the last n-ary search round
        // After a transaction to end the dispute is implemented, this can be removed
        if round == nary.total_rounds() as u32
            && drp.role() == ParticipantRole::Verifier
            && nary_search_type == NArySearchType::ReadValueChallenge
        {
            info!("Forcing the verifier to choose the challenge after the last n-ary search round");
            let execution_path = drp.get_execution_path()?;
            info!("Path is {execution_path}");
            let msg = serde_json::to_string(&DispatcherJob {
                job_id: drp.ctx.id.to_string(),
                job_type: EmulatorJobType::VerifierChooseChallengeForReadChallenge(
                    pdf,
                    execution_path.clone(),
                    format!("{}/{}", execution_path, "execution.json").to_string(),
                    fail_force_config.read.fail_config_verifier.clone(),
                    fail_force_config.read.force_challenge.clone(),
                ),
            })?;
            program_context
                .broker_channel
                .send(&program_context.components_config.emulator, msg)?;
        }
    }
    Ok(())
}

fn handle_nary_prover(
    name: &str,
    drp: &DisputeResolutionProtocol,
    program_context: &ProgramContext,
    tx_id: Txid,
    vout: Option<u32>,
    tx_status: &TransactionStatus,
    fail_force_config: &ConfigResults,
    strip_prefix: &str,               // "NARY_PROVER_"
    prover_hash: &str,                // "prover_hash"
    nary_search_type: NArySearchType, // ConflictStep
) -> Result<(), BitVMXError> {
    drp.decode_witness_from_speedup(
        tx_id,
        vout.unwrap(),
        &name,
        program_context,
        &tx_status.tx,
        None,
    )?;

    let round = name
        .strip_prefix(strip_prefix)
        .unwrap()
        .parse::<u32>()
        .unwrap();

    let (fail_config, current_round) = match nary_search_type {
        NArySearchType::ConflictStep => (
            fail_force_config.main.fail_config_verifier.clone(),
            "current_round",
        ),
        NArySearchType::ReadValueChallenge => (
            fail_force_config.read.fail_config_verifier.clone(),
            "current_round2",
        ),
    };

    //TODO: make this value return from execution
    program_context.globals.set_var(
        &drp.ctx.id,
        current_round,
        VariableTypes::Number(round as u32),
    )?;

    let (program_definition, pdf) = drp.get_program_definition(program_context)?;
    let nary = program_definition.nary_def();
    let hashes_count = nary.hashes_for_round(round as u8);
    let execution_path = drp.get_execution_path()?;

    let hashes: Vec<String> = (0..hashes_count)
        .map(|h| {
            hex::encode(
                program_context
                    .witness
                    .get_witness(&drp.ctx.id, &format!("{}_{}_{}", prover_hash, round, h))
                    .unwrap()
                    .unwrap()
                    .winternitz()
                    .unwrap()
                    .message_bytes(),
            )
        })
        .collect();

    let msg = serde_json::to_string(&DispatcherJob {
        job_id: drp.ctx.id.to_string(),
        job_type: EmulatorJobType::VerifierChooseSegment(
            pdf,
            execution_path.clone(),
            round as u8,
            hashes,
            format!("{}/{}", execution_path, "execution.json").to_string(),
            fail_config,
            nary_search_type,
        ),
    })?;

    if round > 1 {
        program_context
            .broker_channel
            .send(&program_context.components_config.emulator, msg)?;
    } else {
        if let Some(_ready) = program_context
            .globals
            .get_var(&drp.ctx.id, "execution-check-ready")?
        {
            info!("The execution is ready. Sending the choose segment message");
            program_context
                .broker_channel
                .send(&program_context.components_config.emulator, msg)?;
        } else {
            info!("The execution is not ready. Saving the message.");
            program_context.globals.set_var(
                &drp.ctx.id,
                "choose-segment-msg",
                VariableTypes::String(msg),
            )?;
        }
    }

    Ok(())
}
