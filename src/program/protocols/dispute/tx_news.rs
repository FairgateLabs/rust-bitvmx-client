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
                config::{DisputeConfiguration, ForceFailConfiguration},
                input_handler::{
                    get_txs_configuration, set_input, set_input_u64, unify_inputs, unify_witnesses,
                },
                input_tx_name, program_input, timeout_input_tx, timeout_tx,
                DisputeResolutionProtocol, CHALLENGE, CHALLENGE_READ, COMMITMENT, EXECUTE,
                GET_HASHES_AND_STEP, INPUT_TX, POST_COMMITMENT, PRE_COMMITMENT, PROVER_WINS,
                START_CH, TK_2NARY, TRACE_VARS, VERIFIER_FINAL, VERIFIER_WINS,
            },
            protocol_handler::ProtocolHandler,
        },
        variables::VariableTypes,
    },
    types::{ProgramContext, PROGRAM_TYPE_DRP},
};
use bitcoin::{script::read_scriptint, Txid};
use bitcoin_coordinator::{coordinator::BitcoinCoordinatorApi, TransactionStatus};
use bitvmx_cpu_definitions::{memory::MemoryWitness, trace::*};
use bitvmx_job_dispatcher::dispatcher_job::DispatcherJob;
use bitvmx_job_dispatcher_types::emulator_messages::EmulatorJobType;
use console::style;
use emulator::decision::nary_search::NArySearchType;
use tracing::{info, warn};

fn dispatch_timeout_tx(
    drp: &DisputeResolutionProtocol,
    program_context: &ProgramContext,
    name: &str,
    current_height: u32,
) -> Result<(), BitVMXError> {
    info!("Dispatching timeout tx: {}", name);
    let params = program_context
        .globals
        .get_var_or_err(&drp.ctx.id, name)?
        .vec_number()?;
    let leaf = params[0];
    let timelock_blocks = params[1];

    info!(
        "Current block: {}. Will try to dispatch timeout tx: {} in {} blocks. ",
        current_height, name, timelock_blocks
    );

    let tx = drp.get_signed(program_context, name, vec![(leaf, true).into()])?;
    let speedup_data = drp.get_speedup_data_from_tx(&tx, program_context, None)?;
    program_context.bitcoin_coordinator.dispatch(
        tx,
        Some(speedup_data),
        Context::ProgramId(drp.ctx.id).to_string()?,
        Some(current_height + timelock_blocks),
        drp.requested_confirmations(program_context),
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
    pub fn new_predefined(rounds: u8, inputs: Vec<(usize, &String)>) -> Result<Self, BitVMXError> {
        if rounds == 0 || inputs.is_empty() {
            return Err(Self::invalid_inputs(&inputs));
        }

        let last_tx_first_nary = &format!("NARY_VERIFIER_{}", rounds);
        let last_tx_second_nary = &format!("NARY2_VERIFIER_{}", rounds);
        let to_second_nary = TimeoutType::timeout("NARY2_PROVER_2_TO");

        let mut table = TimeoutDispatchTable::new(vec![]);

        let &(first_index, first_owner) = inputs
            .first()
            .ok_or_else(|| Self::invalid_inputs(&inputs))?;

        if first_owner == "verifier" {
            table.add_prover_without_vout(
                &input_tx_name(first_index as u32),
                TimeoutType::timeout_input(&input_tx_name(first_index as u32)),
            );
        } else {
            table.add_verifier_without_vout(
                &input_tx_name(first_index as u32),
                TimeoutType::timeout_input(&input_tx_name(first_index as u32)),
            );
        }

        for window in inputs.windows(2) {
            let (prev_index, prev_owner) = window[0];
            let (next_index, next_owner) = window[1];

            if prev_owner == next_owner {
                return Err(Self::invalid_inputs(&inputs));
            }

            let role = if prev_owner == "verifier" {
                Verifier
            } else {
                Prover
            };

            table.add_classic_to(
                &input_tx_name(prev_index as u32),
                &input_tx_name(next_index as u32),
                role,
            );
        }
        let &(last_index, last_owner) =
            inputs.last().ok_or_else(|| Self::invalid_inputs(&inputs))?;
        if !last_owner.starts_with("prover") {
            return Err(Self::invalid_inputs(&inputs));
        }

        table.add_classic_to(&input_tx_name(last_index as u32), PRE_COMMITMENT, Prover);
        table.add_classic_to(PRE_COMMITMENT, COMMITMENT, Verifier);
        table.add_classic_to(COMMITMENT, POST_COMMITMENT, Prover);
        table.add_classic_to(POST_COMMITMENT, "NARY_PROVER_1", Verifier);
        table.add_nary_search_table("NARY", 1, rounds);
        table.add_classic_to(last_tx_first_nary, EXECUTE, Verifier);
        table.add_classic_to(EXECUTE, CHALLENGE, Prover);
        table.add_not_apply_not_vout(CHALLENGE, Verifier, to_second_nary);
        table.add_nary_search_table("NARY2", 2, rounds);
        table.add_classic_to(&last_tx_second_nary, GET_HASHES_AND_STEP, Verifier);
        table.add_classic_to(GET_HASHES_AND_STEP, CHALLENGE_READ, Prover);
        Ok(table)
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

    fn invalid_inputs(inputs: &[(usize, &String)]) -> BitVMXError {
        BitVMXError::InvalidInputs(inputs.iter().map(|(i, s)| (*i, (*s).clone())).collect())
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
    timeout_table: &TimeoutDispatchTable,
) -> Result<(), BitVMXError> {
    let cancel = timeout_table
        .iter()
        .any(|(_tx_name, _tx_vout, tx_role, timeout, _not_ignore)| {
            timeout.name().trim_end_matches("_TO") == name && *tx_role == drp.role()
        });

    if cancel {
        let tx_to_cancel = if vout.is_none() {
            &timeout_tx(name)
        } else {
            &timeout_input_tx(name)
        };
        cancel_to_tx(drp, program_context, tx_to_cancel)?;
    }
    Ok(())
}

fn cancel_to_tx(
    drp: &DisputeResolutionProtocol,
    program_context: &ProgramContext,
    tx_to_cancel: &str,
) -> Result<(), BitVMXError> {
    info!("Cancel timeout tx: {}", tx_to_cancel);
    let tx_id = drp.get_transaction_id_by_name(&tx_to_cancel)?;
    program_context.bitcoin_coordinator.cancel(
        bitcoin_coordinator::TypesToMonitor::Transactions(vec![tx_id], String::default(), None),
    )?;
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
            let tx = drp.get_signed(program_context, &claim_name, vec![0.into()])?;
            let speedup_data = drp.get_speedup_data_from_tx(&tx, program_context, None)?;
            info!("{claim_name}: {:?}", tx);
            program_context.bitcoin_coordinator.dispatch(
                tx,
                Some(speedup_data),
                Context::ProgramId(drp.ctx.id).to_string()?,
                None,
                drp.requested_confirmations(program_context),
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

            let prover_wins_tx = drp.get_signed(
                program_context,
                &ClaimGate::tx_success(&my_claim),
                vec![1.into()],
            )?;
            let speedup_data =
                drp.get_speedup_data_from_tx(&prover_wins_tx, program_context, None)?;
            program_context.bitcoin_coordinator.dispatch(
                prover_wins_tx,
                Some(speedup_data),
                Context::ProgramId(drp.ctx.id).to_string()?,
                Some(current_height + timelock_blocks),
                drp.requested_confirmations(program_context),
            )?;
        }
        //other start
        else {
            info!("{other_claim} STOP dispatch attempt");
            let prover_win_stop = drp.get_signed(
                program_context,
                &ClaimGate::tx_stop(&other_claim, 0),
                vec![0.into()],
            )?;
            let speedup_data =
                drp.get_speedup_data_from_tx(&prover_win_stop, program_context, None)?;
            program_context.bitcoin_coordinator.dispatch(
                prover_win_stop,
                Some(speedup_data),
                Context::ProgramId(drp.ctx.id).to_string()?,
                None,
                drp.requested_confirmations(program_context),
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
            let win_action_tx = drp.get_signed(
                program_context,
                &action_wins(&drp.role(), 1),
                vec![0.into(), (action.1[0] as u32).into()],
            )?;
            let speedup_data =
                drp.get_speedup_data_from_tx(&win_action_tx, program_context, None)?;

            program_context.bitcoin_coordinator.dispatch(
                win_action_tx,
                Some(speedup_data),
                Context::ProgramId(drp.ctx.id).to_string()?,
                None,
                drp.requested_confirmations(program_context),
            )?;
        }
    }

    if name.starts_with(&action_wins_prefix(&ParticipantRole::Prover))
        || name.starts_with(&action_wins_prefix(&ParticipantRole::Verifier))
    {
        let config = DisputeConfiguration::load(&drp.ctx.id, &program_context.globals)?;
        for (protocol_name, protocol_id) in config.notify_protocol {
            let protocol = drp.load_protocol_by_name(&protocol_name, protocol_id)?;
            info!(
                "Notifying protocol {} about tx {}:{:?} seen on-chain",
                protocol_name, tx_id, vout
            );
            protocol.notify_external_news(
                tx_id,
                vout,
                tx_status.clone(),
                Context::Protocol(drp.ctx.id, PROGRAM_TYPE_DRP.to_string()).to_string()?,
                program_context,
            )?;
            info!(
                "Notified protocol {} about tx {}:{:?} seen on-chain",
                protocol_name, tx_id, vout
            );
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
    let current_height = tx_status
        .block_info
        .as_ref()
        .ok_or_else(|| {
            BitVMXError::InvalidTransactionStatus(
                "TransactionStatus missing block_info".to_string(),
            )
        })?
        .height;
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

    let rounds = drp
        .get_program_definition(program_context)?
        .0
        .nary_def()
        .total_rounds();

    let inputs = program_context
        .globals
        .get_var_or_err(&drp.ctx.id, "input_txs")?
        .vec_string()?;

    let inputs = inputs
        .iter()
        .enumerate()
        .filter(|(_, owner)| owner.as_str() != "skip" && owner.as_str() != "prover_prev")
        .collect();

    let timeout_table = TimeoutDispatchTable::new_predefined(rounds, inputs)?;
    // timeout_table.visualize();

    cancel_timeout(drp, &name, vout, program_context, &timeout_table)?;

    let timelock_blocks = config.timelock_blocks;

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
                drp.requested_confirmations(program_context),
            )?;
        }
    }

    match vout {
        Some(vout) => {
            let transaction = &tx_status.tx;
            let input_index = drp.find_prevout(tx_id, vout, transaction)?;
            let witness = transaction.input[input_index as usize].witness.clone();

            let leaf = read_scriptint(
                witness
                    .third_to_last()
                    .ok_or_else(|| BitVMXError::InvalidWitness(witness.clone()))?,
            )? as u32;

            let params = program_context
                .globals
                .get_var_or_err(&drp.ctx.id, &timeout_input_tx(&name))?
                .vec_number()?;

            let timeout_leaf = params[1];

            if leaf == timeout_leaf {
                let role = timeout_table
                    .iter()
                    .find_map(|(_, _, role, timeout_type, _)| match timeout_type {
                        TimeoutType::TimeoutInput(timeout_name) if timeout_name == &name => {
                            Some(role.to_string())
                        }
                        _ => None,
                    })
                    .unwrap_or("Unknown role".to_string());

                warn!("{role} consumed timeout input for {name}");
                return Ok(());
            }

            if name.starts_with(INPUT_TX) {
                let idx = name
                    .strip_prefix(INPUT_TX)
                    .ok_or_else(|| BitVMXError::InvalidStringOperation(name.clone()))?
                    .parse::<u32>()?;

                let (input_txs, _input_txs_sizes, _input_txs_offsets, last_tx_id) =
                    get_txs_configuration(&drp.ctx.id, program_context)?;

                let owner = input_txs[idx as usize].as_str();

                // decode the witness
                if owner != drp.role().to_string() {
                    drp.decode_witness_from_speedup(
                        tx_id,
                        vout,
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
                    for (i, input_chunk) in full_input.chunks(4).enumerate() {
                        // It is assumed that each input chunk is 4 bytes
                        set_input(
                            &drp.ctx.id,
                            program_context,
                            &program_input(i as u32, Some(&ParticipantRole::Prover)),
                            input_chunk.to_vec(),
                        )?;
                    }
                    let (tx, sp) = drp.get_tx_with_speedup_data(
                        program_context,
                        &input_tx_name(idx + 1),
                        0,
                        0,
                        true,
                    )?;
                    program_context.bitcoin_coordinator.dispatch(
                        tx,
                        Some(sp),
                        Context::ProgramId(drp.ctx.id).to_string()?,
                        None,
                        drp.requested_confirmations(program_context),
                    )?;
                }
                if idx == last_tx_id as u32 {
                    //if it's the last input
                    if drp.role() == ParticipantRole::Verifier {
                        let (tx, sp) = drp.get_tx_with_speedup_data(
                            program_context,
                            PRE_COMMITMENT,
                            0,
                            0,
                            true,
                        )?;
                        program_context.bitcoin_coordinator.dispatch(
                            tx,
                            Some(sp),
                            Context::ProgramId(drp.ctx.id).to_string()?,
                            None,
                            drp.requested_confirmations(program_context),
                        )?;
                    } else {
                        //Prover
                        let (def, _program_definition) =
                            drp.get_program_definition(program_context)?;
                        let full_input = unify_inputs(&drp.ctx.id, program_context, &def)?;
                        program_context.globals.set_var(
                            &drp.ctx.id,
                            "full_input",
                            VariableTypes::Input(full_input.clone()),
                        )?;
                    }
                }
            }

            if name == PRE_COMMITMENT && drp.role() == ParticipantRole::Prover {
                let (_def, program_definition) = drp.get_program_definition(program_context)?;
                let execution_path = drp.get_execution_path()?;
                let full_input = program_context
                    .globals
                    .get_var_or_err(&drp.ctx.id, "full_input")?
                    .input()?;
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

            if name == COMMITMENT && drp.role() == ParticipantRole::Verifier {
                drp.decode_witness_from_speedup(
                    tx_id,
                    vout,
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
                    .get_witness_or_err(&drp.ctx.id, "prover_last_hash")?
                    .winternitz()?
                    .message_bytes();

                let last_step = program_context
                    .witness
                    .get_witness_or_err(&drp.ctx.id, "prover_last_step")?
                    .winternitz()?
                    .message_bytes();
                let last_step_len = last_step.len();
                let last_step = u64::from_be_bytes(last_step.try_into().map_err(|_| {
                    BitVMXError::InvalidParameter(format!(
                        "Invalid last_step length: {}",
                        last_step_len
                    ))
                })?);
                set_input_u64(
                    &drp.ctx.id,
                    program_context,
                    "verifier_last_step_tk",
                    last_step,
                )?;

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
                    drp.requested_confirmations(program_context),
                )?;
            }

            if name == POST_COMMITMENT || name.starts_with("NARY_VERIFIER") {
                let round = name
                    .strip_prefix("NARY_VERIFIER_")
                    .unwrap_or("0")
                    .parse::<u32>()?;

                if round == 0 {
                    drp.decode_witness_from_speedup(
                        tx_id,
                        vout,
                        &name,
                        program_context,
                        &tx_status.tx,
                        None,
                    )?;
                }

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

            if (name.starts_with("NARY_PROVER")) && drp.role() == ParticipantRole::Verifier {
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

            if name == EXECUTE && drp.role() == ParticipantRole::Verifier {
                let (_, leaf) = drp.decode_witness_from_speedup(
                    tx_id,
                    vout,
                    &name,
                    program_context,
                    &tx_status.tx,
                    None,
                )?;

                // leaf 0 is prover_challenge_step, we lost
                if leaf == 0 {
                    return Ok(());
                }

                let (_program_definition, pdf) = drp.get_program_definition(program_context)?;
                let execution_path = drp.get_execution_path()?;

                let mut values = std::collections::HashMap::new();

                let trace_vars = TRACE_VARS
                    .get()
                    .ok_or_else(|| {
                        BitVMXError::InitializationError("TRACE_VARS not initialized".to_string())
                    })?
                    .read()?;
                for (name, _) in trace_vars.iter() {
                    if *name == "prover_witness" {
                        continue;
                    }
                    let value = program_context
                        .witness
                        .get_witness_or_err(&drp.ctx.id, name)?
                        .winternitz()?
                        .message_bytes();
                    values.insert(name.clone(), value);
                }
                fn to_u8(bytes: &[u8]) -> Result<u8, BitVMXError> {
                    Ok(u8::from_be_bytes(bytes.try_into()?))
                }
                fn to_u32(bytes: &[u8]) -> Result<u32, BitVMXError> {
                    Ok(u32::from_be_bytes(bytes.try_into()?))
                }
                fn to_u64(bytes: &[u8]) -> Result<u64, BitVMXError> {
                    Ok(u64::from_be_bytes(bytes.try_into()?))
                }
                fn to_hex(bytes: &[u8]) -> String {
                    hex::encode(bytes)
                }

                let step_number = to_u64(&values["prover_step_number"])?;
                let trace_read1 = TraceRead::new(
                    to_u32(&values["prover_read_1_address"])?,
                    to_u32(&values["prover_read_1_value"])?,
                    to_u64(&values["prover_read_1_last_step"])?,
                );
                let trace_read2 = TraceRead::new(
                    to_u32(&values["prover_read_2_address"])?,
                    to_u32(&values["prover_read_2_value"])?,
                    to_u64(&values["prover_read_2_last_step"])?,
                );
                let program_counter = ProgramCounter::new(
                    to_u32(&values["prover_read_pc_address"])?,
                    to_u8(&values["prover_read_pc_micro"])?,
                );
                let read_pc =
                    TraceReadPC::new(program_counter, to_u32(&values["prover_read_pc_opcode"])?);
                let trace_write = TraceWrite::new(
                    to_u32(&values["prover_write_address"])?,
                    to_u32(&values["prover_write_value"])?,
                );
                let program_counter = ProgramCounter::new(
                    to_u32(&values["prover_write_pc"])?,
                    to_u8(&values["prover_write_micro"])?,
                );
                let trace_step = TraceStep::new(trace_write, program_counter);
                let witness = if let Some(witness) = program_context
                    .witness
                    .get_witness(&drp.ctx.id, "prover_witness")?
                {
                    let bytes = witness.winternitz()?.message_bytes();
                    Some(to_u32(&bytes)?)
                } else {
                    None
                };

                let mem_witness = MemoryWitness::from_byte(to_u8(&values["prover_mem_witness"])?);
                let prover_step_hash = to_hex(&values["prover_step_hash_tk"]);
                let prover_next_hash = to_hex(&values["prover_next_hash_tk"]);
                let _conflict_step = to_u64(&values["prover_conflict_step_tk"])?;

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
                        prover_step_hash,
                        prover_next_hash,
                        format!("{}/{}", execution_path, "execution.json").to_string(),
                        fail_force_config.main.fail_config_verifier.clone(),
                        fail_force_config.main.force_challenge.clone(),
                    ),
                })?;
                program_context
                    .broker_channel
                    .send(&program_context.components_config.emulator, msg)?;
            }

            if name == CHALLENGE && drp.role() == ParticipantRole::Prover {
                let (names, leaf) = drp.decode_witness_from_speedup(
                    tx_id,
                    vout,
                    &name,
                    program_context,
                    &tx_status.tx,
                    None,
                )?;

                let read_value_nary_search_leaf = program_context
                    .globals
                    .get_var_or_err(
                        &drp.ctx.id,
                        &format!("challenge_leaf_start_{}", "read_value_nary_search"),
                    )?
                    .number()? as u32;

                match leaf {
                    l if l == read_value_nary_search_leaf => {
                        let mut expected_names: Vec<&str> = READ_VALUE_NARY_SEARCH_CHALLENGE
                            .iter()
                            .map(|(name, _)| *name)
                            .collect();

                        expected_names.insert(0, "prover_continue");

                        if names == expected_names {
                            let bits_name = &names[1];
                            let witness = program_context
                                .witness
                                .get_witness_or_err(&drp.ctx.id, bits_name)?;
                            let bytes = witness.winternitz()?.message_bytes();
                            info!(
                                "Challenge will be extended with a 2nd nary search. {bits_name} are {:?}",
                                bytes
                            );
                            if bytes.len() != 1 {
                                return Err(BitVMXError::InvalidState(
                                    "Expected exactly one byte for selection bits".to_string(),
                                ));
                            }
                            let selection_bits = bytes[0] as u32;
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
                            return Err(BitVMXError::InvalidLeaf(format!(
                                "The challenge leaf does not match the expected witness names.\n\
                                Expected: {:?}, got: {:?}",
                                expected_names, names
                            )));
                        }
                    }
                    _ => {
                        if fail_force_config.prover_force_second_nary {
                            // for testing purposes we will try to start the second nary search but it should fail
                            let selection_bits = 0;
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
                            info!("Challenge ended successfully");
                        }
                    }
                }
            }

            if name.starts_with("NARY2_VERIFIER") {
                let round = name
                    .strip_prefix("NARY2_VERIFIER_")
                    .ok_or_else(|| BitVMXError::InvalidStringOperation(name.clone()))?
                    .parse::<u32>()?;
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

            if name.starts_with("NARY2_PROVER") && drp.role() == ParticipantRole::Verifier {
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

            if GET_HASHES_AND_STEP == name && drp.role() == ParticipantRole::Verifier {
                let (_, leaf) = drp.decode_witness_from_speedup(
                    tx_id,
                    vout,
                    &name,
                    program_context,
                    &tx_status.tx,
                    None,
                )?;

                // leaf 0 is prover_challenge_step2, we lost
                if leaf == 0 {
                    return Ok(());
                }

                let (_program_definition, pdf) = drp.get_program_definition(program_context)?;
                let execution_path = drp.get_execution_path()?;

                let mut values = std::collections::HashMap::new();

                let trace_vars = TK_2NARY
                    .get()
                    .ok_or_else(|| {
                        BitVMXError::InitializationError("TK_2NARY not initialized".to_string())
                    })?
                    .read()?;
                for (name, _) in trace_vars.iter() {
                    let value = program_context
                        .witness
                        .get_witness_or_err(&drp.ctx.id, name)?
                        .winternitz()?
                        .message_bytes();
                    values.insert(name.clone(), value);
                }
                fn to_u64(bytes: &[u8]) -> Result<u64, BitVMXError> {
                    Ok(u64::from_be_bytes(bytes.try_into()?))
                }
                fn to_hex(bytes: &[u8]) -> String {
                    hex::encode(bytes)
                }

                let prover_step_hash = to_hex(&values["prover_step_hash_tk2"]);
                let prover_next_hash = to_hex(&values["prover_next_hash_tk2"]);
                let _prover_write_step = to_u64(&values["prover_write_step_tk2"])?;

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

            if name == CHALLENGE_READ && drp.role() == ParticipantRole::Prover {
                info!("The challenge has ended after the 2nd n-ary search.");
                drp.decode_witness_from_speedup(
                    tx_id,
                    vout,
                    &name,
                    program_context,
                    &tx_status.tx,
                    None,
                )?;
            }
        }
        None => {
            if CHALLENGE_READ == name && ParticipantRole::Verifier == drp.role() {
                let verifier_final_tx =
                    drp.get_signed(program_context, &VERIFIER_FINAL, vec![1.into()])?;
                let speedup_data =
                    drp.get_speedup_data_from_tx(&verifier_final_tx, program_context, None)?;
                program_context.bitcoin_coordinator.dispatch(
                    verifier_final_tx,
                    Some(speedup_data),
                    Context::ProgramId(drp.ctx.id).to_string()?,
                    Some(current_height + 2 * timelock_blocks as u32),
                    drp.requested_confirmations(program_context),
                )?;
            }

            if VERIFIER_FINAL == name && ParticipantRole::Verifier == drp.role() {
                let claim_name = ClaimGate::tx_start(VERIFIER_WINS);
                let tx = drp.get_signed(program_context, &claim_name, vec![0.into()])?;
                let speedup_data = drp.get_speedup_data_from_tx(&tx, program_context, None)?;
                info!("{claim_name}: {:?}", tx);
                program_context.bitcoin_coordinator.dispatch(
                    tx,
                    Some(speedup_data),
                    Context::ProgramId(drp.ctx.id).to_string()?,
                    None,
                    drp.requested_confirmations(program_context),
                )?;
            }
        }
    }
    Ok(())
}

fn handle_nary_verifier(
    name: &str,
    drp: &DisputeResolutionProtocol,
    program_context: &ProgramContext,
    tx_id: Txid,
    vout: u32,
    tx_status: &TransactionStatus,
    current_height: u32,
    fail_force_config: &ForceFailConfiguration,
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
                vout,
                &name,
                program_context,
                &tx_status.tx,
                None,
            )?;

            let bits = program_context
                .witness
                .get_witness_or_err(&drp.ctx.id, &format!("{}_{}", selection_bits, round))?
                .winternitz()?
                .message_bytes();
            if bits.len() != 1 {
                return Err(BitVMXError::InvalidState(
                    "Expected exactly one byte for selection bits".to_string(),
                ));
            }
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
                    job_type: EmulatorJobType::ProverGetHashesAndStep(
                        pdf,
                        execution_path.clone(),
                        (decision) as u32,
                        format!("{}/{}", execution_path, "execution.json").to_string(),
                        fail_force_config.read.fail_config_prover.clone(),
                    ),
                })?,
            };
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
    vout: u32,
    tx_status: &TransactionStatus,
    fail_force_config: &ForceFailConfiguration,
    strip_prefix: &str,               // "NARY_PROVER_"
    prover_hash: &str,                // "prover_hash"
    nary_search_type: NArySearchType, // ConflictStep
) -> Result<(), BitVMXError> {
    let (_, leaf) =
        drp.decode_witness_from_speedup(tx_id, vout, &name, program_context, &tx_status.tx, None)?;

    let params = program_context
        .globals
        .get_var_or_err(&drp.ctx.id, &timeout_input_tx(name))?
        .vec_number()?;
    let timeout_leaf = params[1];
    if leaf == timeout_leaf {
        info!("Verifier consumed the timeout input for {name}");
        return Ok(());
    }

    let round = name
        .strip_prefix(strip_prefix)
        .map(str::trim)
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(1);

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

    let hashes: Vec<String> = (1..=hashes_count)
        .map(|h| -> Result<String, BitVMXError> {
            let name = format!("{}_{}_{}", prover_hash, round, h);

            let bytes = program_context
                .witness
                .get_witness_or_err(&drp.ctx.id, &name)?
                .winternitz()?
                .message_bytes();

            Ok(hex::encode(bytes))
        })
        .collect::<Result<_, _>>()?;

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
