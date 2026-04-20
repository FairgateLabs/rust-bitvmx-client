use crate::{
    errors::BitVMXError,
    program::{
        participant::ParticipantRole,
        protocols::protocol_handler::{
            timeout_input_tx, timeout_tx, ProtocolHandler, WithClaimGateConfig,
        },
    },
    types::ProgramContext,
};
use bitcoin_coordinator::coordinator::BitcoinCoordinatorApi;
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
    protocol_handler.dispatch(program_context, tx, Some(speedup_data), height)?;
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
    pub ignored_input_txs: Vec<String>,
}

impl TxOwnershipTable {
    pub fn new() -> Self {
        Self {
            txs: vec![],
            ignored_input_txs: vec![],
        }
    }

    pub fn is_my_tx(&self, tx_name: &str, drp_role: ParticipantRole) -> bool {
        self.txs
            .iter()
            .find(|tx| tx.tx_name == tx_name && tx.owner == drp_role)
            .is_some()
    }

    pub fn is_other_tx(&self, tx_name: &str, drp_role: ParticipantRole) -> bool {
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
                if self.ignored_input_txs.contains(&name.to_string()) {
                    None
                } else {
                    // if the observed tx is owned by the other party, I need to force to include the input
                    Some((timeout_input_tx(name), true))
                }
            }
        } else {
            None
        }
    }

    pub fn add(&mut self, tx_name: &str, owner: ParticipantRole) {
        self.txs.push(TxOwnership::new(tx_name, owner));
    }

    pub fn add_ignored(&mut self, tx_name: String) {
        self.ignored_input_txs.push(tx_name);
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
    if ownership_table
        .ignored_input_txs
        .contains(&name.to_string())
    {
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

    let Some(orig_tx) = name.strip_suffix("_INPUT_TO") else {
        return Ok(());
    };

    let Some((_, Some(next))) = ownership_table.get_tx_and_next(&orig_tx) else {
        return Ok(());
    };

    if next.owner != protocol_handler.role() {
        let tx_to_cancel = timeout_tx(&next.tx_name);
        info!("Cancel timeout tx: {}", tx_to_cancel);
        let tx_id = protocol_handler.get_transaction_id_by_name(&tx_to_cancel)?;

        program_context.bitcoin_coordinator.cancel(
            bitcoin_coordinator::TypesToMonitor::Transactions(vec![tx_id], String::default(), None),
        )?;
    }

    Ok(())
}
