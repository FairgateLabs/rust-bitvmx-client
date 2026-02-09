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
                get_tx_name_from_timeout,
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
use bitcoin::{script::read_scriptint, Transaction, Txid};
use bitcoin_coordinator::{coordinator::BitcoinCoordinatorApi, TransactionStatus};
use bitvmx_cpu_definitions::{memory::MemoryWitness, trace::*};
use bitvmx_job_dispatcher::dispatcher_job::DispatcherJob;
use bitvmx_job_dispatcher_types::emulator_messages::EmulatorJobType;
use console::style;
use emulator::decision::nary_search::NArySearchType;
use protocol_builder::types::output::SpeedupData;
use tracing::{info, warn};

fn dispatch_timeout_tx(
    drp: &DisputeResolutionProtocol,
    program_context: &ProgramContext,
    name: &str,
    current_height: u32,
    require_leaf_id: bool,
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

    let inputs = if require_leaf_id {
        vec![(leaf, true).into(), (0, false).into(), (0, true).into()]
    } else {
        vec![(leaf, true).into()]
    };

    let tx = drp.get_signed(program_context, name, inputs)?;
    let speedup_data = drp.get_speedup_data_from_tx(&tx, program_context, None)?;
    let height = Some(current_height + timelock_blocks);
    dispatch(program_context, drp, tx, Some(speedup_data), height)?;
    Ok(())
}

#[derive(Debug, Clone)]
pub struct TxOwnership {
    pub tx_name: String,
    pub owner: ParticipantRole,
}

impl TxOwnership {
    pub fn new(tx_name: &str, owner: ParticipantRole) -> Self {
        Self {
            tx_name: tx_name.to_string(),
            owner,
        }
    }
}

pub struct TxOwnershipTable {
    pub txs: Vec<TxOwnership>,
}

impl TxOwnershipTable {
    pub fn new(rounds: u8, inputs: Vec<(usize, String)>) -> Result<Self, BitVMXError> {
        if rounds == 0 || inputs.is_empty() {
            return Err(Self::invalid_inputs(&inputs));
        }

        let mut table = TxOwnershipTable { txs: vec![] };
        table.add(START_CH, Verifier);

        for (index, owner) in &inputs {
            let owner = if owner.as_str() == "verifier" {
                Verifier
            } else {
                Prover
            };

            table.add(&input_tx_name(*index as u32), owner);
        }

        //requires that the last input is owned by the prover, otherwise the sequence of timeout txs cannot be properly chained
        let &(_last_index, last_owner) =
            &inputs.last().ok_or_else(|| Self::invalid_inputs(&inputs))?;
        if !last_owner.starts_with("prover") {
            return Err(Self::invalid_inputs(&inputs));
        }

        table.add(PRE_COMMITMENT, Verifier);
        table.add(COMMITMENT, Prover);
        table.add(POST_COMMITMENT, Verifier);
        table.add_nary_search("NARY", 1, rounds);
        table.add(EXECUTE, Prover);
        table.add(CHALLENGE, Verifier);
        table.add_nary_search("NARY2", 2, rounds);
        table.add(GET_HASHES_AND_STEP, Prover);
        table.add(CHALLENGE_READ, Verifier);
        table.add(VERIFIER_FINAL, Verifier);
        Ok(table)
    }

    fn add_nary_search(&mut self, nary_type: &str, start_round: u8, total_rounds: u8) {
        for round in start_round..=total_rounds {
            let prover = format!("{}_PROVER_{}", nary_type, round);
            let verifier = format!("{}_VERIFIER_{}", nary_type, round);
            self.add(&prover, Prover);
            self.add(&verifier, Verifier);
        }
    }

    fn is_my_tx(&self, tx_name: &str, drp_role: ParticipantRole) -> bool {
        self.txs
            .iter()
            .find(|tx| tx.tx_name == tx_name && tx.owner == drp_role)
            .is_some()
    }

    fn is_other_tx(&self, tx_name: &str, drp_role: ParticipantRole) -> bool {
        self.txs
            .iter()
            .find(|tx| tx.tx_name == tx_name && tx.owner != drp_role)
            .is_some()
    }

    fn get_tx_and_next(&self, tx_name: &str) -> Option<(&TxOwnership, Option<&TxOwnership>)> {
        let current_index = self.txs.iter().position(|tx| tx.tx_name == tx_name)?;
        let current_tx = &self.txs[current_index];
        let next_tx = self.txs.get(current_index + 1);
        Some((current_tx, next_tx))
    }

    fn get_timeout_tx(&self, name: &str, drp_role: ParticipantRole) -> Option<(String, bool)> {
        if let Some((tx, next_tx)) = self.get_tx_and_next(name) {
            if tx.owner == drp_role {
                // as I observed my tx on-chain I need to send the next tx timeout to force the other part to act
                if let Some(next_tx) = next_tx {
                    //This cover the case of two consecutive tx owned by the same party (in particular START_CHALLENGE followed by the verifier first input)
                    //and CHALLENGE_READ followed by VERIFIER_FINAL
                    if next_tx.owner == drp_role {
                        return None;
                    }
                    Some((timeout_tx(&next_tx.tx_name), false))
                } else {
                    None
                }
            } else {
                // if the observed tx is owned by the other party, I need to force to include the input (except for START_CHALLENGE)
                if name != START_CH && name != VERIFIER_FINAL {
                    Some((timeout_input_tx(name), true))
                } else {
                    None
                }
            }
        } else {
            None
        }
    }

    pub fn add(&mut self, tx_name: &str, owner: ParticipantRole) {
        self.txs.push(TxOwnership::new(tx_name, owner));
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &ParticipantRole)> {
        self.txs.iter().map(|r| (&r.tx_name, &r.owner))
    }

    fn invalid_inputs(inputs: &[(usize, String)]) -> BitVMXError {
        BitVMXError::InvalidInputs(inputs.iter().map(|(i, s)| (*i, (*s).clone())).collect())
    }
}

fn auto_dispatch_timeout(
    drp: &DisputeResolutionProtocol,
    name: &str,
    vout: Option<u32>,
    program_context: &ProgramContext,
    current_height: u32,
    ownership_table: &TxOwnershipTable,
) -> Result<(), BitVMXError> {
    // only dispatch when a tx is observed (not vouts of txs)
    if vout.is_some() {
        return Ok(());
    }

    if let Some((timeout_name, require_leaf_id)) = ownership_table.get_timeout_tx(name, drp.role())
    {
        dispatch_timeout_tx(
            drp,
            program_context,
            &timeout_name,
            current_height,
            require_leaf_id,
        )?;
    }

    Ok(())
}

fn cancel_timeout(
    drp: &DisputeResolutionProtocol,
    name: &str,
    vout: Option<u32>,
    program_context: &ProgramContext,
    ownership_table: &TxOwnershipTable,
) -> Result<(), BitVMXError> {
    if name == START_CH || name == VERIFIER_FINAL {
        return Ok(());
    }

    let is_other_tx = ownership_table.is_other_tx(name, drp.role());
    if is_other_tx {
        let tx_to_cancel = if vout.is_none() {
            &timeout_tx(name)
        } else {
            &timeout_input_tx(name)
        };
        info!("Cancel timeout tx: {}", tx_to_cancel);
        let tx_id = drp.get_transaction_id_by_name(&tx_to_cancel)?;
        program_context.bitcoin_coordinator.cancel(
            bitcoin_coordinator::TypesToMonitor::Transactions(vec![tx_id], String::default(), None),
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
    ownership_table: &TxOwnershipTable,
) -> Result<(), BitVMXError> {
    if vout.is_some() {
        return Ok(());
    }

    if let Some(orig_tx) = get_tx_name_from_timeout(name) {
        if ownership_table.is_other_tx(&orig_tx, drp.role()) {
            let claim_name = ClaimGate::tx_start(get_claim_name(drp, false));
            let tx = drp.get_signed(program_context, &claim_name, vec![0.into()])?;
            let speedup_data = drp.get_speedup_data_from_tx(&tx, program_context, None)?;
            info!("{claim_name}: {:?}", tx);
            dispatch(program_context, drp, tx, Some(speedup_data), None)?;
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

            let tx = drp.get_signed(
                program_context,
                &ClaimGate::tx_success(&my_claim),
                vec![1.into()],
            )?;
            let speedup_data = drp.get_speedup_data_from_tx(&tx, program_context, None)?;
            let height = Some(current_height + timelock_blocks);
            dispatch(program_context, drp, tx, Some(speedup_data), height)?;
        }
        //other start
        else {
            info!("{other_claim} STOP dispatch attempt");
            let tx = drp.get_signed(
                program_context,
                &ClaimGate::tx_stop(&other_claim, 0),
                vec![0.into()],
            )?;
            let speedup_data = drp.get_speedup_data_from_tx(&tx, program_context, None)?;
            dispatch(program_context, drp, tx, Some(speedup_data), None)?;
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
            let tx = drp.get_signed(
                program_context,
                &action_wins(&drp.role(), 1),
                vec![0.into(), (action.1[0] as u32).into()],
            )?;
            let speedup_data = drp.get_speedup_data_from_tx(&tx, program_context, None)?;

            dispatch(program_context, drp, tx, Some(speedup_data), None)?;
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

pub fn dispatch(
    program_context: &ProgramContext,
    drp: &DisputeResolutionProtocol,
    tx: Transaction,
    sp: Option<SpeedupData>,
    block_height: Option<u32>,
) -> Result<(), BitVMXError> {
    Ok(program_context.bitcoin_coordinator.dispatch(
        tx,
        sp,
        Context::ProgramId(drp.ctx.id).to_string()?,
        block_height,
        drp.requested_confirmations(program_context),
    )?)
}

fn execute(
    drp: &DisputeResolutionProtocol,
    program_context: &ProgramContext,
    job_type: EmulatorJobType,
) -> Result<(), BitVMXError> {
    let msg = serde_json::to_string(&DispatcherJob {
        job_id: drp.ctx.id.to_string(),
        job_type: job_type,
    })?;
    program_context
        .broker_channel
        .send(&program_context.components_config.emulator, msg)?;
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
        .map(|(i, owner)| (i, owner.to_string()))
        .collect();

    let ownership_table = TxOwnershipTable::new(rounds, inputs)?;

    cancel_timeout(drp, &name, vout, program_context, &ownership_table)?;

    let timelock_blocks = config.timelock_blocks;

    auto_dispatch_timeout(
        drp,
        &name,
        vout,
        program_context,
        current_height,
        &ownership_table,
    )?;

    auto_claim_start(drp, &name, vout, program_context, &ownership_table)?;

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

            let timeout_leaf = params[0];

            if leaf == timeout_leaf {
                warn!("The timeout input for {name} was consumed");
                return Ok(());
            }

            let my_tx = ownership_table.is_my_tx(&name, drp.role());
            let (def, program_definition) = drp.get_program_definition(program_context)?;

            let mut leaf = 0;
            let mut names = vec![];
            if !my_tx {
                (names, leaf) = drp.decode_witness_from_speedup(
                    tx_id,
                    vout,
                    &name,
                    program_context,
                    &tx_status.tx,
                    None,
                )?;
            }

            if !my_tx {
                let execution_path = drp.get_execution_path()?;
                let execution_file = format!("{}/{}", execution_path, "execution.json").to_string();

                match name.as_str() {
                    name if name.starts_with(INPUT_TX) => {
                        let idx = name
                            .strip_prefix(INPUT_TX)
                            .ok_or_else(|| BitVMXError::InvalidStringOperation(name.to_string()))?
                            .parse::<u32>()?;

                        let (_, _, _, last_tx_id) =
                            get_txs_configuration(&drp.ctx.id, program_context)?;

                        unify_witnesses(&drp.ctx.id, program_context, idx as usize)?;

                        if drp.role() == ParticipantRole::Prover {
                            if idx != last_tx_id as u32 {
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
                                dispatch(program_context, drp, tx, Some(sp), None)?;
                            }
                        } else {
                            if idx == last_tx_id {
                                let (tx, sp) = drp.get_tx_with_speedup_data(
                                    program_context,
                                    PRE_COMMITMENT,
                                    0,
                                    0,
                                    true,
                                )?;
                                dispatch(program_context, drp, tx, Some(sp), None)?;
                            }
                        }
                    }

                    PRE_COMMITMENT => {
                        let full_input = unify_inputs(&drp.ctx.id, program_context, &def)?;
                        execute(
                            drp,
                            program_context,
                            EmulatorJobType::ProverExecute(
                                program_definition.clone(),
                                full_input,
                                execution_path.clone(),
                                execution_file.clone(),
                                fail_force_config.main.fail_config_prover.clone(),
                            ),
                        )?;
                    }

                    COMMITMENT => {
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

                        execute(
                            drp,
                            program_context,
                            EmulatorJobType::VerifierCheckExecution(
                                program_definition.clone(),
                                input_program,
                                execution_path.clone(),
                                last_step,
                                hex::encode(last_hash),
                                format!("{}/{}", execution_path, "execution.json").to_string(),
                                fail_force_config.main.force_condition.clone(),
                                fail_force_config.main.fail_config_verifier.clone(),
                            ),
                        )?;

                        let (tx, sp) = drp.get_tx_with_speedup_data(
                            program_context,
                            POST_COMMITMENT,
                            0,
                            0,
                            true,
                        )?;
                        dispatch(program_context, drp, tx, Some(sp), None)?;
                    }
                    name if name == POST_COMMITMENT || name.starts_with("NARY_VERIFIER") => {
                        let round = name
                            .strip_prefix("NARY_VERIFIER_")
                            .unwrap_or("0")
                            .parse::<u32>()?;

                        handle_nary_verifier(
                            &name,
                            drp,
                            program_context,
                            tx_id,
                            vout,
                            &tx_status,
                            &fail_force_config,
                            "verifier_selection_bits",
                            POST_COMMITMENT,
                            0,
                            round,
                            NArySearchType::ConflictStep,
                        )?;
                    }

                    name if name.starts_with("NARY_PROVER") => {
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

                    EXECUTE => {
                        // leaf 0 is prover_challenge_step, we lost
                        if leaf == 0 {
                            return Ok(());
                        }

                        let execution_path = drp.get_execution_path()?;

                        let mut values = std::collections::HashMap::new();

                        let trace_vars = TRACE_VARS
                            .get()
                            .ok_or_else(|| {
                                BitVMXError::InitializationError(
                                    "TRACE_VARS not initialized".to_string(),
                                )
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
                        let read_pc = TraceReadPC::new(
                            program_counter,
                            to_u32(&values["prover_read_pc_opcode"])?,
                        );
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

                        let mem_witness =
                            MemoryWitness::from_byte(to_u8(&values["prover_mem_witness"])?);
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

                        execute(
                            drp,
                            program_context,
                            EmulatorJobType::VerifierChooseChallenge(
                                program_definition.clone(),
                                execution_path.clone(),
                                final_trace,
                                prover_step_hash,
                                prover_next_hash,
                                format!("{}/{}", execution_path, "execution.json").to_string(),
                                fail_force_config.main.fail_config_verifier.clone(),
                                fail_force_config.main.force_challenge.clone(),
                            ),
                        )?;
                    }

                    CHALLENGE => {
                        let read_value_nary_search_leaf = program_context
                            .globals
                            .get_var_or_err(
                                &drp.ctx.id,
                                &format!("challenge_leaf_start_{}", "read_value_nary_search"),
                            )?
                            .number()?
                            as u32;

                        let selection_bits: Option<u32> = if leaf == read_value_nary_search_leaf {
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
                                Some(selection_bits)
                            } else {
                                return Err(BitVMXError::InvalidLeaf(format!(
                                        "The challenge leaf does not match the expected witness names.\n\
                                        Expected: {:?}, got: {:?}",
                                        expected_names, names
                                    )));
                            }
                        } else if fail_force_config.prover_force_second_nary {
                            // for testing purposes we will try to start the second nary search but it should fail
                            Some(0)
                        } else {
                            info!("Challenge ended successfully");
                            None
                        };

                        if let Some(selection_bits) = selection_bits {
                            handle_nary_verifier(
                                &name,
                                drp,
                                program_context,
                                tx_id,
                                vout,
                                &tx_status,
                                &fail_force_config,
                                "verifier_selection_bits2",
                                CHALLENGE,
                                selection_bits,
                                1, // round 2
                                NArySearchType::ReadValueChallenge,
                            )?;
                        }
                    }

                    name if name.starts_with("NARY2_VERIFIER") => {
                        let round = name
                            .strip_prefix("NARY2_VERIFIER_")
                            .ok_or_else(|| BitVMXError::InvalidStringOperation(name.to_string()))?
                            .parse::<u32>()?;
                        handle_nary_verifier(
                            &name,
                            drp,
                            program_context,
                            tx_id,
                            vout,
                            &tx_status,
                            &fail_force_config,
                            "verifier_selection_bits2",
                            CHALLENGE,
                            0, // Will be ignored
                            round,
                            NArySearchType::ReadValueChallenge,
                        )?;
                    }

                    name if name.starts_with("NARY2_PROVER") => {
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

                    GET_HASHES_AND_STEP => {
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

                        let execution_path = drp.get_execution_path()?;

                        let mut values = std::collections::HashMap::new();

                        let trace_vars = TK_2NARY
                            .get()
                            .ok_or_else(|| {
                                BitVMXError::InitializationError(
                                    "TK_2NARY not initialized".to_string(),
                                )
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
                                program_definition.clone(),
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

                    CHALLENGE_READ => {
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

                    _ => {}
                }
            }
        }
        None => {
            if name == START_CH && drp.role() == ParticipantRole::Prover {
                if let Some(auto_dispatch_input) = config.auto_dispatch_input {
                    let (tx, speedup) = drp.get_transaction_by_name(
                        &input_tx_name(auto_dispatch_input as u32),
                        program_context,
                    )?;

                    info!(
                        "Auto Dispatching input tx {}",
                        &input_tx_name(auto_dispatch_input as u32)
                    );
                    dispatch(program_context, drp, tx, speedup, None)?;
                }
            }

            if CHALLENGE_READ == name && ParticipantRole::Verifier == drp.role() {
                let tx =
                    drp.get_signed(program_context, &VERIFIER_FINAL, vec![(1, true).into()])?;
                let speedup_data = drp.get_speedup_data_from_tx(&tx, program_context, None)?;
                let height = Some(current_height + 2 * timelock_blocks as u32);
                dispatch(program_context, drp, tx, Some(speedup_data), height)?;
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
    fail_force_config: &ForceFailConfiguration,
    selection_bits: &str,             // "selection_bits"
    prev_name: &str,                  // COMMITMENT
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
    let decision = if name == prev_name {
        decision_start_value
    } else {
        drp.decode_witness_from_speedup(tx_id, vout, &name, program_context, &tx_status.tx, None)?;

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
    let timeout_leaf = params[0];
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tx_ownership_table() {
        let table =
            TxOwnershipTable::new(4, vec![(0, ParticipantRole::Prover.to_string())]).unwrap();

        assert_eq!(
            table.get_timeout_tx("START_CHALLENGE", Verifier).unwrap().0,
            "INPUT_0_TO".to_string()
        );

        assert_eq!(table.get_timeout_tx("START_CHALLENGE", Prover), None);

        assert_eq!(
            table.get_timeout_tx("INPUT_0", Verifier).unwrap().0,
            "INPUT_0_INPUT_TO".to_string()
        );

        assert_eq!(
            table.get_timeout_tx("INPUT_0", Prover).unwrap().0,
            "PRE_COMMITMENT_TO".to_string()
        );
    }
}
