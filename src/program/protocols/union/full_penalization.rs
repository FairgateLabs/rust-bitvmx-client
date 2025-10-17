use core::convert::Into;
use std::collections::HashMap;

use bitcoin::{Amount, PublicKey, ScriptBuf, Transaction, Txid};
use bitcoin_coordinator::{coordinator::BitcoinCoordinatorApi, TransactionStatus};
use protocol_builder::{
    graph::graph::GraphOptions,
    scripts::{op_return_script, ProtocolScript},
    types::{
        connection::{InputSpec, OutputSpec},
        input::{SighashType, SpendMode},
        output::SpeedupData,
        InputArgs, OutputType,
    },
};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tracing::info;
use uuid::Uuid;

use crate::{
    errors::BitVMXError,
    program::{
        participant::ParticipantKeys,
        protocols::{
            protocol_handler::{ProtocolContext, ProtocolHandler},
            union::{
                common::{
                    create_transaction_reference, get_dispute_core_pid,
                    get_initial_setup_output_type, get_operator_output_type, indexed_name,
                },
                dispute_core::PEGOUT_ID,
                types::{
                    AdvanceFundsRequest, Committee, FullPenalizationData, ACCEPT_PEGIN_TX,
                    ADVANCE_FUNDS_INPUT, ADVANCE_FUNDS_TX, DISPUTE_CORE_SHORT_TIMELOCK, DUST_VALUE,
                    INITIAL_DEPOSIT_TX_SUFFIX, LAST_OPERATOR_TAKE_UTXO, OPERATOR,
                    OPERATOR_TAKE_ENABLER, OP_DISABLER_DIRECTORY_TX, OP_DISABLER_FEE,
                    OP_DISABLER_TX, OP_INITIAL_DEPOSIT_AMOUNT, OP_INITIAL_DEPOSIT_FLAG,
                    OP_INITIAL_DEPOSIT_OUT_SCRIPT, OP_INITIAL_DEPOSIT_TXID, OP_LAZY_DISABLER_TX,
                    REIMBURSEMENT_KICKOFF_TX, USER_TAKE_FEE,
                },
            },
        },
        variables::{PartialUtxo, VariableTypes},
    },
    types::{ProgramContext, PROGRAM_TYPE_DISPUTE_CORE},
};

#[derive(Clone, Serialize, Deserialize)]
pub struct FullPenalizationProtocol {
    ctx: ProtocolContext,
}

impl ProtocolHandler for FullPenalizationProtocol {
    fn context(&self) -> &ProtocolContext {
        &self.ctx
    }

    fn context_mut(&mut self) -> &mut ProtocolContext {
        &mut self.ctx
    }

    fn get_pregenerated_aggregated_keys(
        &self,
        _context: &ProgramContext,
    ) -> Result<Vec<(String, PublicKey)>, BitVMXError> {
        Ok(vec![])
    }

    fn generate_keys(
        &self,
        _program_context: &mut ProgramContext,
    ) -> Result<ParticipantKeys, BitVMXError> {
        Ok(ParticipantKeys::new(vec![], vec![]))
    }

    fn build(
        &self,
        _keys: Vec<ParticipantKeys>,
        _computed_aggregated: HashMap<String, PublicKey>,
        context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        info!(
            "Building Full Penalization Protocol for program {}",
            self.ctx.id
        );

        let data: FullPenalizationData = self.full_penalization_data(context)?;
        let committee = self.committee(context, data.committee_id)?;
        let operator_take_key = committee.members[data.operator_index].take_key;
        let operator_dispute_key = committee.members[data.operator_index].dispute_key;
        let watchtower_dispute_key = committee.members[data.watchtower_index].dispute_key;

        //create the protocol
        let mut protocol = self.load_or_create_protocol();

        let dispute_core_pid = get_dispute_core_pid(data.committee_id, &operator_take_key);
        self.create_operator_disabler(
            &mut protocol,
            context,
            dispute_core_pid,
            committee.packet_size,
            &operator_dispute_key,
            &watchtower_dispute_key,
            data.operator_index,
        )?;

        protocol.build(&context.key_chain.key_manager, &self.ctx.protocol_name)?;
        info!("\n{}", protocol.visualize(GraphOptions::EdgeArrows)?);
        self.save_protocol(protocol)?;
        Ok(())
    }

    fn get_transaction_by_name(
        &self,
        name: &str,
        _context: &ProgramContext,
    ) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
        // match name {
        //     ADVANCE_FUNDS_TX => Ok(self.advance_funds_tx(context)?),
        //     _ => Err(BitVMXError::InvalidTransactionName(name.to_string())),
        // }
        Err(BitVMXError::InvalidTransactionName(name.to_string()))
    }

    fn notify_news(
        &self,
        tx_id: Txid,
        _vout: Option<u32>,
        tx_status: TransactionStatus,
        _context: String,
        context: &ProgramContext,
        _participant_keys: Vec<&ParticipantKeys>,
    ) -> Result<(), BitVMXError> {
        let tx_name = self.get_transaction_name_by_id(tx_id)?;
        info!(
            "Full Penalization protocol received news of transaction: {}, txid: {} with {} confirmations",
            tx_name, tx_id, tx_status.confirmations
        );

        Ok(())
    }

    fn setup_complete(&self, _context: &ProgramContext) -> Result<(), BitVMXError> {
        // This is called after the protocol is built and ready to be used
        info!(
            "FullPenalizationProtocol setup complete for program {}",
            self.ctx.id
        );

        Ok(())
    }
}

impl FullPenalizationProtocol {
    pub fn new(ctx: ProtocolContext) -> Self {
        Self { ctx }
    }

    fn full_penalization_data(
        &self,
        context: &ProgramContext,
    ) -> Result<FullPenalizationData, BitVMXError> {
        let request = context
            .globals
            .get_var(&self.ctx.id, &FullPenalizationData::name())?
            .unwrap()
            .string()?;

        let data: FullPenalizationData = serde_json::from_str(&request)?;
        Ok(data)
    }

    fn committee(
        &self,
        context: &ProgramContext,
        committee_id: Uuid,
    ) -> Result<Committee, BitVMXError> {
        let committee = context
            .globals
            .get_var(&committee_id, &Committee::name())?
            .unwrap()
            .string()?;

        let committee: Committee = serde_json::from_str(&committee)?;
        Ok(committee)
    }

    fn op_initial_deposit_txid(
        &self,
        context: &ProgramContext,
        dispute_core_pid: Uuid,
    ) -> Result<Txid, BitVMXError> {
        let txid = context
            .globals
            .get_var(&dispute_core_pid, OP_INITIAL_DEPOSIT_TXID)?
            .unwrap()
            .string()?
            .parse::<Txid>()
            .map_err(|e| {
                BitVMXError::InvalidVariableType(format!("Failed to parse txid from string: {}", e))
            })?;
        Ok(txid)
    }

    fn op_initial_deposit_amount(
        &self,
        context: &ProgramContext,
        dispute_core_pid: Uuid,
    ) -> Result<u64, BitVMXError> {
        let amount = context
            .globals
            .get_var(&dispute_core_pid, OP_INITIAL_DEPOSIT_AMOUNT)?
            .unwrap()
            .amount()?;
        Ok(amount)
    }

    fn op_initial_deposit_out_script(
        &self,
        context: &ProgramContext,
        dispute_core_pid: Uuid,
        slot_index: usize,
    ) -> Result<ProtocolScript, BitVMXError> {
        let data = context
            .globals
            .get_var(
                &dispute_core_pid,
                &indexed_name(OP_INITIAL_DEPOSIT_OUT_SCRIPT, slot_index),
            )?
            .unwrap()
            .string()?;

        let script: ProtocolScript = serde_json::from_str(&data)?;
        Ok(script)
    }

    fn create_operator_disabler(
        &self,
        protocol: &mut protocol_builder::builder::Protocol,
        context: &ProgramContext,
        dispute_core_pid: Uuid,
        packet_size: u32,
        operator_key: &PublicKey,
        watchtower_key: &PublicKey,
        operator_index: usize,
    ) -> Result<String, BitVMXError> {
        // Create transaction
        let initial_deposit_name = format!("{}{}", OPERATOR, INITIAL_DEPOSIT_TX_SUFFIX);
        let initial_deposit_txid = self.op_initial_deposit_txid(context, dispute_core_pid)?;
        let amount = self.op_initial_deposit_amount(context, dispute_core_pid)?;

        let op_disabler_change = self.checked_sub(amount + DUST_VALUE, OP_DISABLER_FEE)?;

        // TODO: Add Operator disabler directory single (by now) input. It should came from Operator initial deposit tx

        for slot_index in 0..packet_size as usize {
            let op_disabler_name = indexed_name(OP_DISABLER_TX, slot_index);

            let script =
                self.op_initial_deposit_out_script(context, dispute_core_pid, slot_index)?;

            let output_type = get_initial_setup_output_type(amount, operator_key, &[script])?;

            protocol.add_connection(
                "from_initial_deposit",
                &initial_deposit_name,
                output_type.into(),
                &op_disabler_name,
                // TODO: Review this input
                InputSpec::Auto(SighashType::taproot_all(), SpendMode::ScriptsOnly),
                None,
                Some(initial_deposit_txid),
            )?;

            // FIXME: Here Operator Disabler Directory it's related to the watchtower key, is this okey?
            // What happens if watchtower does not want to dispatch them? Should anyone be able to dispatch it?
            protocol.add_connection(
                "from_disabler_directory",
                &OP_DISABLER_DIRECTORY_TX,
                OutputType::segwit_key(DUST_VALUE, watchtower_key)?.into(),
                &op_disabler_name,
                InputSpec::Auto(SighashType::ecdsa_all(), SpendMode::Segwit),
                None,
                None,
            )?;

            protocol.add_transaction_output(
                &op_disabler_name,
                &OutputType::segwit_key(op_disabler_change, watchtower_key)?,
            )?;

            // Create Lazy Operator disablers
            // Operator take transaction data
            let op_lazy_disabler_name = indexed_name(OP_LAZY_DISABLER_TX, slot_index); // TODO: Change to lazy disabler tx name
            let take_enabler = self.operator_take_enabler(context, dispute_core_pid, slot_index)?;

            protocol.add_connection(
                "reimbursement_kickoff_conn",
                &indexed_name(REIMBURSEMENT_KICKOFF_TX, operator_index),
                take_enabler.3.unwrap().into(),
                &op_lazy_disabler_name,
                InputSpec::Auto(SighashType::taproot_all(), SpendMode::None),
                Some(DISPUTE_CORE_SHORT_TIMELOCK),
                Some(take_enabler.0),
            )?;

            protocol.add_connection(
                "from_disabler_directory",
                &OP_DISABLER_DIRECTORY_TX,
                0.into(),
                &op_lazy_disabler_name,
                InputSpec::Auto(SighashType::ecdsa_all(), SpendMode::Segwit),
                None,
                None,
            )?;

            let op_lazy_disabler_change =
                self.checked_sub(take_enabler.2.unwrap() + DUST_VALUE, OP_DISABLER_FEE)?;

            protocol.add_transaction_output(
                &op_lazy_disabler_name,
                &OutputType::segwit_key(op_lazy_disabler_change, watchtower_key)?,
            )?;
        }

        Ok(initial_deposit_name)
    }

    fn operator_take_enabler(
        &self,
        context: &ProgramContext,
        dispute_protocol_id: Uuid,
        slot_index: usize,
    ) -> Result<PartialUtxo, BitVMXError> {
        Ok(context
            .globals
            .get_var(
                &dispute_protocol_id,
                &indexed_name(OPERATOR_TAKE_ENABLER, slot_index),
            )?
            .unwrap()
            .utxo()?)
    }
}
