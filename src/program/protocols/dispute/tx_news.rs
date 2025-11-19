use crate::{
    bitvmx::Context,
    errors::BitVMXError,
    program::{
        participant::ParticipantRole::{self, Prover, Verifier},
        protocols::{
            claim::ClaimGate,
            dispute::{
                action_wins,
                challenge::READ_VALUE_NARY_SEARCH_CHALLENGE,
                config::{ConfigResults, DisputeConfiguration},
                input_handler::{get_txs_configuration, unify_inputs, unify_witnesses},
                input_tx_name, timeout_input_tx, timeout_tx, DisputeResolutionProtocol, CHALLENGE,
                CHALLENGE_READ, COMMITMENT, EXECUTE, GET_BITS_AND_HASHES, INPUT_TX,
                POST_COMMITMENT, PRE_COMMITMENT, PROVER_WINS, TK_2NARY, TRACE_VARS, VERIFIER_FINAL,
                VERIFIER_WINS,
            },
            protocol_handler::ProtocolHandler,
        },
        variables::VariableTypes,
    },
    types::{OutgoingBitVMXApiMessages, ProgramContext},
};
use bitcoin::Txid;
use bitcoin_coordinator::{coordinator::BitcoinCoordinatorApi, TransactionStatus};
use bitvmx_cpu_definitions::{memory::MemoryWitness, trace::*};
use bitvmx_job_dispatcher::dispatcher_job::DispatcherJob;
use bitvmx_job_dispatcher_types::emulator_messages::EmulatorJobType;
use console::style;
use emulator::decision::nary_search::NArySearchType;
use tracing::info;

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

#[derive(Debug, Clone)]
pub enum TimeoutType {
    Timeout(String),
    TimeoutInput(String),
}

impl TimeoutType {
    pub fn timeout<S: Into<String>>(s: S) -> Self {
        TimeoutType::Timeout(s.into())
    }

    pub fn timeout_input<S: Into<String>>(s: S) -> Self {
        TimeoutType::TimeoutInput(s.into())
    }

    pub fn is_input(&self) -> bool {
        matches!(self, TimeoutType::TimeoutInput(_))
    }

    pub fn name(&self) -> String {
        match self {
            TimeoutType::Timeout(name) => name.to_string(),
            TimeoutType::TimeoutInput(name) => name.to_string(),
        }
    }
}

// When I see [tx_name], and vout is [has_vout],
// if I'm [role], then I dispatch
// timeout_type[timeout_name].
#[derive(Debug, Clone)]
pub struct TimeoutDispatchRule {
    pub tx_name: String,
    pub has_vout: bool,
    pub my_role: ParticipantRole,
    pub timeout: TimeoutType,
    pub apply_timeout: bool,
}

impl TimeoutDispatchRule {
    pub fn new(
        tx_name: &str,
        has_vout: bool,
        my_role: ParticipantRole,
        timeout: TimeoutType,
        apply_timeout: bool,
    ) -> Self {
        Self {
            tx_name: tx_name.to_string(),
            has_vout,
            my_role,
            timeout,
            apply_timeout,
        }
    }
    pub fn new_without_vout(tx_name: &str, my_role: ParticipantRole, timeout: TimeoutType) -> Self {
        Self {
            tx_name: tx_name.to_string(),
            has_vout: false,
            my_role,
            timeout,
            apply_timeout: true,
        }
    }
    pub fn new_not_apply_not_vout(
        tx_name: &str,
        my_role: ParticipantRole,
        timeout: TimeoutType,
    ) -> Self {
        Self {
            tx_name: tx_name.to_string(),
            has_vout: false,
            my_role,
            timeout,
            apply_timeout: false,
        }
    }
    pub fn new_prover_without_vout(tx_name: &str, timeout: TimeoutType) -> Self {
        Self {
            tx_name: tx_name.to_string(),
            has_vout: false,
            my_role: ParticipantRole::Prover,
            timeout,
            apply_timeout: true,
        }
    }
    pub fn new_verifier_without_vout(tx_name: &str, timeout: TimeoutType) -> Self {
        Self {
            tx_name: tx_name.to_string(),
            has_vout: false,
            my_role: ParticipantRole::Verifier,
            timeout,
            apply_timeout: true,
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
    pub fn new_predefined(rounds: u8, n_inputs: u32) -> Self {
        assert_ne!(rounds, 0);
        assert_ne!(n_inputs, 0); // Inputs should be at least 1

        let last_tx_first_nary = &format!("NARY_VERIFIER_{}", rounds);
        let last_tx_second_nary = &format!("NARY2_VERIFIER_{}", rounds);
        let to_second_nary = TimeoutType::timeout("NARY2_PROVER_2_TO");

        let mut table = TimeoutDispatchTable::new(vec![]);

        for i in 1..n_inputs {
            let role = if i % 2 == 1 { Verifier } else { Prover }; //TODO: make it configurable
            table.add_classic_to(&input_tx_name(i - 1), &input_tx_name(i), role);
        }
        table.add_classic_to(&input_tx_name(n_inputs - 1), PRE_COMMITMENT, Prover);
        table.add_classic_to(PRE_COMMITMENT, COMMITMENT, Verifier);
        table.add_classic_to(COMMITMENT, POST_COMMITMENT, Prover);
        table.add_classic_to(POST_COMMITMENT, "NARY_PROVER_1", Verifier);
        table.add_nary_search_table("NARY", 1, rounds);
        table.add_classic_to(last_tx_first_nary, EXECUTE, Verifier);
        table.add_classic_to(EXECUTE, CHALLENGE, Prover);
        table.add_verifier_without_vout(EXECUTE, TimeoutType::timeout_input(EXECUTE));
        table.add_not_apply_not_vout(CHALLENGE, Verifier, to_second_nary);
        table.add_nary_search_table("NARY2", 2, rounds);
        table.add_classic_to(&last_tx_second_nary, CHALLENGE_READ, Prover);
        table
    }

    fn add_nary_search_table(&mut self, nary_type: &str, start_round: u8, total_rounds: u8) {
        for round in start_round..=total_rounds {
            let prover = format!("{}_PROVER_{}", nary_type, round);
            let verifier = format!("{}_VERIFIER_{}", nary_type, round);
            let next_prover = format!("{}_PROVER_{}", nary_type, round + 1);

            self.add_classic_to(&prover, &verifier, Prover);
            if round < total_rounds {
                // If not the last round
                self.add_classic_to(&verifier, &next_prover, Verifier);
            }
        }
    }

    pub fn add_rule(&mut self, rule: TimeoutDispatchRule) {
        self.rules.push(rule);
    }
    pub fn add_without_vout(
        &mut self,
        tx_name: &str,
        my_role: ParticipantRole,
        timeout: TimeoutType,
    ) {
        self.rules.push(TimeoutDispatchRule::new_without_vout(
            tx_name, my_role, timeout,
        ));
    }
    pub fn add_not_apply_not_vout(
        &mut self,
        tx_name: &str,
        my_role: ParticipantRole,
        timeout: TimeoutType,
    ) {
        self.rules.push(TimeoutDispatchRule::new_not_apply_not_vout(
            tx_name, my_role, timeout,
        ));
    }
    pub fn add_prover_without_vout(&mut self, tx_name: &str, timeout: TimeoutType) {
        self.rules
            .push(TimeoutDispatchRule::new_prover_without_vout(
                tx_name, timeout,
            ));
    }
    pub fn add_verifier_without_vout(&mut self, tx_name: &str, timeout: TimeoutType) {
        self.rules
            .push(TimeoutDispatchRule::new_verifier_without_vout(
                tx_name, timeout,
            ));
    }
    fn add_classic_to(&mut self, prev_tx: &str, next_tx: &str, role: ParticipantRole) {
        self.add_without_vout(
            prev_tx,
            role.clone(),
            TimeoutType::Timeout(next_tx.to_string()),
        );
        self.add_without_vout(
            next_tx,
            role,
            TimeoutType::TimeoutInput(next_tx.to_string()),
        );
    }
    pub fn iter(
        &self,
    ) -> impl Iterator<Item = (&String, &bool, &ParticipantRole, &TimeoutType, &bool)> {
        self.rules.iter().map(|r| {
            (
                &r.tx_name,
                &r.has_vout,
                &r.my_role,
                &r.timeout,
                &r.apply_timeout,
            )
        })
    }
    pub fn visualize(&self) {
        let headers = [
            "Tx name",
            "Timeout string",
            "Timeout type",
            "Role",
            "Has vout",
            "Apply timeout",
        ];
        let sep = " | ";

        // Collect column strings in desired order
        let mut cols: Vec<Vec<String>> = vec![Vec::new(); headers.len()];
        for r in &self.rules {
            let (timeout_type, timeout_str) = match &r.timeout {
                TimeoutType::Timeout(s) => ("Timeout", s.clone()),
                TimeoutType::TimeoutInput(s) => ("TimeoutInput", s.clone()),
            };

            cols[0].push(r.tx_name.clone());
            cols[1].push(timeout_str);
            cols[2].push(timeout_type.to_string());
            cols[3].push(format!("{:?}", r.my_role));
            cols[4].push(format!("{}", r.has_vout));
            cols[5].push(format!("{}", r.apply_timeout));
        }

        // Compute column widths (based on header and content)
        let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
        for (i, col) in cols.iter().enumerate() {
            for cell in col {
                widths[i] = widths[i].max(cell.len());
            }
        }

        // Build header
        let header_line = headers
            .iter()
            .enumerate()
            .map(|(i, h)| format!("{:width$}", h, width = widths[i]))
            .collect::<Vec<_>>()
            .join(sep);

        let total_width = header_line.len();
        let mut output = String::new();

        output.push_str(&format!("{}\n", header_line));
        output.push_str(&format!("{}\n", "-".repeat(total_width)));

        // Rows
        for r in &self.rules {
            let (timeout_type, timeout_str) = match &r.timeout {
                TimeoutType::Timeout(s) => ("Timeout", s.clone()),
                TimeoutType::TimeoutInput(s) => ("TimeoutInput", s.clone()),
            };

            let cells = [
                &r.tx_name,
                &timeout_str,
                timeout_type,
                &format!("{:?}", r.my_role),
                &format!("{}", r.has_vout),
                &format!("{}", r.apply_timeout),
            ];

            let row = cells
                .iter()
                .enumerate()
                .map(|(i, c)| format!("{:width$}", c, width = widths[i]))
                .collect::<Vec<_>>()
                .join(sep);
            output.push_str(&format!("{}\n", row));
        }

        info!("\n{}", output);
    }
}

fn get_timeout_name(timeout: &TimeoutType, apply_timeout: bool) -> String {
    if !apply_timeout {
        timeout.name()
    } else if timeout.is_input() {
        timeout_input_tx(&timeout.name())
    } else {
        timeout_tx(&timeout.name())
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
    for (tx_name, tx_vout, tx_role, timeout, not_ignore) in timeout_table.iter() {
        if *tx_name == name && *tx_role == drp.role() && *tx_vout == (vout.is_some()) {
            dispatch_timeout_tx(
                drp,
                program_context,
                &get_timeout_name(&timeout, *not_ignore),
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
    for (_, _, tx_role, timeout, not_ignore) in timeout_table.iter() {
        let timeout_name = get_timeout_name(timeout, *not_ignore);
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
    name: &str,
    vout: Option<u32>,
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

    if name == ClaimGate::tx_success(PROVER_WINS) && drp.role() == ParticipantRole::Prover {
        //handle all actions
        info!("Prover. Execute Action");
        let prover_wins_action_tx = drp.get_signed_tx(
            program_context,
            &action_wins(&ParticipantRole::Prover, 1),
            0,
            0,
            false,
            1,
        )?;
        let speedup_data =
            drp.get_speedup_data_from_tx(&prover_wins_action_tx, program_context, None)?;

        program_context.bitcoin_coordinator.dispatch(
            prover_wins_action_tx,
            Some(speedup_data),
            Context::ProgramId(drp.ctx.id).to_string()?,
            None,
        )?;
    } else if name == ClaimGate::tx_success(VERIFIER_WINS)
        && drp.role() == ParticipantRole::Verifier
    {
        //handle all actions
        info!("Verifier. Execute Action");
        let verifier_wins_action_tx = drp.get_signed_tx(
            program_context,
            &action_wins(&ParticipantRole::Verifier, 1),
            0,
            0,
            false,
            1,
        )?;
        let speedup_data =
            drp.get_speedup_data_from_tx(&verifier_wins_action_tx, program_context, None)?;

        program_context.bitcoin_coordinator.dispatch(
            verifier_wins_action_tx,
            Some(speedup_data),
            Context::ProgramId(drp.ctx.id).to_string()?,
            None,
        )?;
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

    let rounds = drp
        .get_program_definition(program_context)?
        .0
        .nary_def()
        .total_rounds();

    let n_inputs = program_context
        .globals
        .get_var(&drp.ctx.id, "input_txs")?
        .unwrap()
        .vec_string()?
        .len() as u32;
    let timeout_table = TimeoutDispatchTable::new_predefined(rounds, n_inputs);
    // timeout_table.visualize();

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
        &name,
        vout,
        program_context,
        current_height,
        timelock_blocks as u32,
    )?;

    let fail_force_config = config.fail_force_config.unwrap_or_default();

    if name.starts_with(INPUT_TX) && vout.is_some() {
        let idx = name.strip_prefix(INPUT_TX).unwrap().parse::<u32>()?;

        let (input_txs, _input_txs_sizes, _input_txs_offsets, last_tx_id) =
            get_txs_configuration(&drp.ctx.id, program_context)?;

        let owner = input_txs[idx as usize].as_str();

        // decode the witness
        if owner != drp.role().to_string() {
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

        if drp.role() == ParticipantRole::Prover && idx != last_tx_id as u32 {
            let (def, _program_definition) = drp.get_program_definition(program_context)?;
            let full_input = unify_inputs(&drp.ctx.id, program_context, &def)?;
            program_context.broker_channel.send(
                &program_context.components_config.l2,
                OutgoingBitVMXApiMessages::SetInput(full_input).to_string()?,
            )?;
        }
        if idx == last_tx_id as u32 {
            //if it's the last input
            if drp.role() == ParticipantRole::Verifier {
                let (tx, sp) =
                    drp.get_tx_with_speedup_data(program_context, PRE_COMMITMENT, 0, 0, true)?;
                program_context.bitcoin_coordinator.dispatch(
                    tx,
                    Some(sp),
                    Context::ProgramId(drp.ctx.id).to_string()?,
                    None,
                )?;
            } else {
                //Prover
                let (def, program_definition) = drp.get_program_definition(program_context)?;
                let full_input = unify_inputs(&drp.ctx.id, program_context, &def)?;
                info!("Full input: {:?}", full_input);
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
        }
    }

    if name == PRE_COMMITMENT && drp.role() == ParticipantRole::Prover && vout.is_some() {
        let (tx, sp) = drp.get_tx_with_speedup_data(program_context, COMMITMENT, 0, 0, true)?;
        program_context.bitcoin_coordinator.dispatch(
            tx,
            Some(sp),
            Context::ProgramId(drp.ctx.id).to_string()?,
            None,
        )?;
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

        let (tx, sp) =
            drp.get_tx_with_speedup_data(program_context, POST_COMMITMENT, 0, 0, true)?;
        program_context.bitcoin_coordinator.dispatch(
            tx,
            Some(sp),
            Context::ProgramId(drp.ctx.id).to_string()?,
            None,
        )?;
    }

    if (name == POST_COMMITMENT || name.starts_with("NARY_VERIFIER")) && vout.is_some() {
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
            "verifier_selection_bits",
            POST_COMMITMENT,
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

        let trace_vars = TRACE_VARS
            .get()
            .expect("TRACE_VARS not initialized")
            .read()?;
        for (name, _) in trace_vars.iter() {
            if *name == "prover_witness" {
                continue;
            }
            if let Some(value) = program_context.witness.get_witness(&drp.ctx.id, name)? {
                values.insert(name.clone(), value.winternitz().unwrap().message_bytes());
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
        fn to_hex(bytes: &[u8]) -> String {
            hex::encode(bytes)
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
        let prover_step_hash = to_hex(&values["prover_prev_hash_tk"]);
        let prover_next_hash = to_hex(&values["prover_step_hash_tk"]);
        let mut decision_bits: Vec<u32> = Vec::new();
        for i in 1..rounds + 1 {
            let key = format!("prover_selection_bits_{}_tk", i);
            decision_bits.push(to_u8(&values[&*key]) as u32);
        }

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
                (
                    final_trace,
                    prover_step_hash,
                    prover_next_hash,
                    decision_bits,
                ),
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
                    assert_eq!(bytes.len(), 4);
                    let selection_bits = u32::from_be_bytes(bytes.try_into().unwrap());
                    handle_nary_verifier(
                        &name,
                        drp,
                        program_context,
                        tx_id,
                        vout,
                        &tx_status,
                        current_height,
                        &fail_force_config,
                        "verifier_selection_bits2",
                        CHALLENGE,
                        CHALLENGE_READ,
                        selection_bits,
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
            "verifier_selection_bits2",
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

    if GET_BITS_AND_HASHES == name && drp.role() == ParticipantRole::Verifier && vout.is_some() {
        drp.decode_witness_from_speedup(
            tx_id,
            vout.unwrap(),
            &name,
            program_context,
            &tx_status.tx,
            None,
        )?;
        let (_program_definition, pdf) = drp.get_program_definition(program_context)?;
        let execution_path = drp.get_execution_path()?;

        let mut values = std::collections::HashMap::new();

        let trace_vars = TK_2NARY.get().expect("TK_2NARY not initialized").read()?;
        for (name, _) in trace_vars.iter() {
            if let Some(value) = program_context.witness.get_witness(&drp.ctx.id, name)? {
                values.insert(name.clone(), value.winternitz().unwrap().message_bytes());
            } else {
                return Err(BitVMXError::VariableNotFound(drp.ctx.id, name.to_string()));
            }
        }
        fn to_u8(bytes: &[u8]) -> u8 {
            u8::from_be_bytes(bytes.try_into().expect("Expected 1 byte for u8"))
        }
        fn to_hex(bytes: &[u8]) -> String {
            hex::encode(bytes)
        }

        let prover_step_hash = to_hex(&values["prover_step_hash_tk2"]);
        let prover_next_hash = to_hex(&values["prover_next_hash_tk2"]);
        let mut decision_bits: Vec<u32> = Vec::new(); //TODO: not used?
        for i in 1..rounds + 1 {
            let key = format!("prover_selection_bits_{}_tk2", i);
            decision_bits.push(to_u8(&values[&*key]) as u32);
        }

        let msg = serde_json::to_string(&DispatcherJob {
            job_id: drp.ctx.id.to_string(),
            job_type: EmulatorJobType::VerifierChooseChallengeForReadChallenge(
                pdf,
                execution_path.clone(),
                format!("{}/{}", execution_path, "execution.json").to_string(),
                prover_step_hash,
                prover_next_hash,
                fail_force_config.read.fail_config_verifier.clone(),
                fail_force_config.read.force_challenge.clone(),
            ),
        })?;
        program_context
            .broker_channel
            .send(&program_context.components_config.emulator, msg)?;
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
    decision_start_value: u32,        // 0
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
            assert!(bits.len() == 1);
            bits[0] as u32
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
                    decision,
                    format!("{}/{}", execution_path, "execution.json").to_string(),
                    prover_config,
                    nary_search_type,
                ),
            })?;
            program_context
                .broker_channel
                .send(&program_context.components_config.emulator, msg)?;
        } else {
            let msg = match nary_search_type {
                NArySearchType::ConflictStep => serde_json::to_string(&DispatcherJob {
                    job_id: drp.ctx.id.to_string(),
                    job_type: EmulatorJobType::ProverFinalTrace(
                        pdf,
                        execution_path.clone(),
                        (decision + 1) as u32,
                        format!("{}/{}", execution_path, "execution.json").to_string(),
                        fail_force_config.main.fail_config_prover.clone(),
                    ),
                })?,
                NArySearchType::ReadValueChallenge => serde_json::to_string(&DispatcherJob {
                    job_id: drp.ctx.id.to_string(),
                    job_type: EmulatorJobType::ProverGetCosignedBitsAndHashes(
                        pdf,
                        execution_path.clone(),
                        (decision) as u32,
                        format!("{}/{}", execution_path, "execution.json").to_string(),
                        fail_force_config.read.fail_config_prover.clone(),
                    ),
                })?,
            };
            info!("Sending final trace or cosigned bits and hashes");
            program_context
                .broker_channel
                .send(&program_context.components_config.emulator, msg)?;
        }
    } else {
        if round == nary.total_rounds() as u32 && nary_search_type == NArySearchType::ConflictStep {
            dispatch_timeout_tx(drp, program_context, &timeout_tx(post_name), current_height)?;
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
