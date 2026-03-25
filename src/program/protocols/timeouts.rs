use crate::{
    bitvmx::Context,
    errors::BitVMXError,
    program::{
        participant::ParticipantRole,
        protocols::{
            claim::ClaimGate,
            dispute,
            protocol_handler::{
                action_wins, action_wins_prefix, get_tx_name_from_timeout, timeout_input_tx,
                timeout_tx, ClaimGateConfig, ProtocolHandler, WithClaimGateConfig,
            },
        },
    },
    types::ProgramContext,
};
use bitcoin::{Transaction, Txid};
use bitcoin_coordinator::{coordinator::BitcoinCoordinatorApi, TransactionStatus};
use bitvmx_job_dispatcher::dispatcher_job::DispatcherJob;
use bitvmx_job_dispatcher_types::emulator_messages::EmulatorJobType;
use protocol_builder::types::output::SpeedupData;
use tracing::info;

pub fn dispatch_timeout_tx<T: ProtocolHandler>(
    protocol_handler: &T,
    program_context: &ProgramContext,
    name: &str,
    current_height: u32,
    require_leaf_id: bool,
) -> Result<(), BitVMXError> {
    info!("Dispatching timeout tx: {}", name);
    let params = program_context
        .globals
        .get_var_or_err(&protocol_handler.context().id, name)?
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

    let tx = protocol_handler.get_signed(program_context, name, inputs)?;
    let speedup_data = protocol_handler.get_speedup_data_from_tx(&tx, program_context, None)?;
    let height = Some(current_height + timelock_blocks);
    dispatch(
        program_context,
        protocol_handler,
        tx,
        Some(speedup_data),
        height,
    )?;
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
    pub fn is_my_tx(&self, tx_name: &str, drp_role: ParticipantRole) -> bool {
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

    pub fn get_timeout_tx(&self, name: &str, drp_role: ParticipantRole) -> Option<(String, bool)> {
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
                if name != dispute::START_CH && name != dispute::VERIFIER_FINAL {
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

    pub fn invalid_inputs(inputs: &[(usize, String)]) -> BitVMXError {
        BitVMXError::InvalidInputs(inputs.iter().map(|(i, s)| (*i, (*s).clone())).collect())
    }
}

pub fn auto_dispatch_timeout<T: ProtocolHandler + WithClaimGateConfig>(
    protocol_handler: &T,
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

    if let Some((timeout_name, require_leaf_id)) =
        ownership_table.get_timeout_tx(name, protocol_handler.role())
    {
        dispatch_timeout_tx(
            protocol_handler,
            program_context,
            &timeout_name,
            current_height,
            require_leaf_id,
        )?;
    }

    Ok(())
}

pub fn cancel_timeout<T: ProtocolHandler + WithClaimGateConfig>(
    protocol_handler: &T,
    name: &str,
    vout: Option<u32>,
    program_context: &ProgramContext,
    ownership_table: &TxOwnershipTable,
) -> Result<(), BitVMXError> {
    if name == dispute::START_CH || name == dispute::VERIFIER_FINAL {
        return Ok(());
    }

    let is_other_tx = ownership_table.is_other_tx(name, protocol_handler.role());
    if is_other_tx {
        let tx_to_cancel = if vout.is_none() {
            &timeout_tx(name)
        } else {
            &timeout_input_tx(name)
        };
        info!("Cancel timeout tx: {}", tx_to_cancel);
        let tx_id = protocol_handler.get_transaction_id_by_name(&tx_to_cancel)?;
        program_context.bitcoin_coordinator.cancel(
            bitcoin_coordinator::TypesToMonitor::Transactions(vec![tx_id], String::default(), None),
        )?;
    }

    Ok(())
}

fn get_claim_name<T: ProtocolHandler + WithClaimGateConfig>(
    protocol_handler: &T,
    other: bool,
) -> String {
    let (role, other_role) = match protocol_handler.role() {
        ParticipantRole::Prover => (dispute::PROVER_WINS, dispute::VERIFIER_WINS),
        ParticipantRole::Verifier => (dispute::VERIFIER_WINS, dispute::PROVER_WINS),
    };
    if other {
        other_role.to_string()
    } else {
        role.to_string()
    }
}

pub fn auto_claim_start<T: ProtocolHandler + WithClaimGateConfig>(
    protocol_handler: &T,
    name: &str,
    vout: Option<u32>,
    program_context: &ProgramContext,
    ownership_table: &TxOwnershipTable,
) -> Result<(), BitVMXError> {
    if vout.is_some() {
        return Ok(());
    }

    if let Some(orig_tx) = get_tx_name_from_timeout(name) {
        if ownership_table.is_other_tx(&orig_tx, protocol_handler.role()) {
            let claim_name = ClaimGate::tx_start(&get_claim_name(protocol_handler, false));
            let tx = protocol_handler.get_signed(program_context, &claim_name, vec![0.into()])?;
            let speedup_data =
                protocol_handler.get_speedup_data_from_tx(&tx, program_context, None)?;
            info!("{claim_name}: {:?}", tx);
            dispatch(
                program_context,
                protocol_handler,
                tx,
                Some(speedup_data),
                None,
            )?;
        }
    }
    Ok(())
}

pub fn claim_state_handle<T: ProtocolHandler + WithClaimGateConfig>(
    protocol_handler: &T,
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
    let my_claim = get_claim_name(protocol_handler, false);
    let other_claim = get_claim_name(protocol_handler, true);
    // start claim
    if name == ClaimGate::tx_start(dispute::PROVER_WINS)
        || name == ClaimGate::tx_start(dispute::VERIFIER_WINS)
    {
        // my start
        if name == ClaimGate::tx_start(&my_claim) {
            info!("{my_claim} SUCCESS dispatch");

            let tx = protocol_handler.get_signed(
                program_context,
                &ClaimGate::tx_success(&my_claim),
                vec![1.into()],
            )?;
            let speedup_data =
                protocol_handler.get_speedup_data_from_tx(&tx, program_context, None)?;
            let height = Some(current_height + timelock_blocks);
            dispatch(
                program_context,
                protocol_handler,
                tx,
                Some(speedup_data),
                height,
            )?;
        }
        //other start
        else {
            info!("{other_claim} STOP dispatch attempt");
            let tx = protocol_handler.get_signed(
                program_context,
                &ClaimGate::tx_stop(&other_claim, 0),
                vec![0.into()],
            )?;
            let speedup_data =
                protocol_handler.get_speedup_data_from_tx(&tx, program_context, None)?;
            dispatch(
                program_context,
                protocol_handler,
                tx,
                Some(speedup_data),
                None,
            )?;
        }
    }

    if (name == ClaimGate::tx_success(dispute::PROVER_WINS)
        && protocol_handler.role() == ParticipantRole::Prover)
        || (name == ClaimGate::tx_success(dispute::VERIFIER_WINS)
            && protocol_handler.role() == ParticipantRole::Verifier)
    {
        let config = T::Config::load(&protocol_handler.context().id, &program_context.globals)?;
        let actions = match protocol_handler.role() {
            ParticipantRole::Prover => &config.get_prover_actions(),
            ParticipantRole::Verifier => &config.get_verifier_actions(),
        };

        for (i, action) in actions.iter().enumerate() {
            info!("{}. Execute Action {}", protocol_handler.role(), i);
            let tx = protocol_handler.get_signed(
                program_context,
                &action_wins(&protocol_handler.role(), 1),
                vec![0.into(), (action.1[0] as u32).into()],
            )?;
            let speedup_data =
                protocol_handler.get_speedup_data_from_tx(&tx, program_context, None)?;

            dispatch(
                program_context,
                protocol_handler,
                tx,
                Some(speedup_data),
                None,
            )?;
        }
    }

    if name.starts_with(&action_wins_prefix(&ParticipantRole::Prover))
        || name.starts_with(&action_wins_prefix(&ParticipantRole::Verifier))
    {
        let config = T::Config::load(&protocol_handler.context().id, &program_context.globals)?;

        for (protocol_name, protocol_id) in config.get_notify_protocol() {
            let protocol = protocol_handler.load_protocol_by_name(&protocol_name, *protocol_id)?;
            info!(
                "Notifying protocol {} about tx {}:{:?} seen on-chain",
                protocol_name, tx_id, vout
            );
            protocol.notify_external_news(
                tx_id,
                vout,
                tx_status.clone(),
                Context::Protocol(protocol_handler.context().id, T::PROGRAM_TYPE.to_string())
                    .to_string()?,
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

pub fn dispatch<T: ProtocolHandler>(
    program_context: &ProgramContext,
    protocol: &T,
    tx: Transaction,
    sp: Option<SpeedupData>,
    block_height: Option<u32>,
) -> Result<(), BitVMXError> {
    Ok(program_context.bitcoin_coordinator.dispatch(
        tx,
        sp,
        Context::ProgramId(protocol.context().id).to_string()?,
        block_height,
        protocol.requested_confirmations(program_context),
    )?)
}

pub fn execute_job<T: ProtocolHandler>(
    protocol_handler: &T,
    program_context: &ProgramContext,
    job_type: EmulatorJobType,
) -> Result<(), BitVMXError> {
    let msg = serde_json::to_string(&DispatcherJob {
        job_id: protocol_handler.context().id.to_string(),
        job_type: job_type,
    })?;
    program_context
        .broker_channel
        .send(&program_context.components_config.emulator, msg)?;
    Ok(())
}
