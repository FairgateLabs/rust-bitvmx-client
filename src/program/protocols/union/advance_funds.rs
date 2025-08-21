use std::{collections::HashMap, thread};

use bitcoin::{Amount, PublicKey, ScriptBuf, Transaction, Txid};
use bitcoin_coordinator::{coordinator::BitcoinCoordinatorApi, TransactionStatus};
use protocol_builder::{
    errors::ProtocolBuilderError,
    graph::graph::GraphOptions,
    scripts::op_return_script,
    types::{
        connection::{InputSpec, OutputSpec},
        input::{SighashType, SpendMode},
        output::SpeedupData,
        OutputType,
    },
};
use serde::{Deserialize, Serialize};
use tracing::info;
use uuid::Uuid;

use crate::{
    errors::BitVMXError,
    program::{
        participant::ParticipantKeys,
        protocols::{
            protocol_handler::{ProtocolContext, ProtocolHandler},
            union::{
                common::{create_transaction_reference, get_dispute_core_pid, indexed_name},
                dispute_core::PEGOUT_ID,
                types::{
                    AdvanceFundsRequest, ACCEPT_PEGIN_TX, ADVANCE_FUNDS_INPUT, ADVANCE_FUNDS_TX,
                    DUST_VALUE, INITIAL_DEPOSIT_TX_SUFFIX, OPERATOR, OP_INITIAL_DEPOSIT_FLAG,
                    REIMBURSEMENT_KICKOFF_TX,
                },
            },
        },
        variables::{PartialUtxo, VariableTypes},
    },
    types::{ProgramContext, PROGRAM_TYPE_DISPUTE_CORE},
};

#[derive(Clone, Serialize, Deserialize)]
pub struct AdvanceFundsProtocol {
    ctx: ProtocolContext,
}

impl ProtocolHandler for AdvanceFundsProtocol {
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
            "Building Advance Funds Protocol for program {}",
            self.ctx.id
        );

        let request: AdvanceFundsRequest = self.advance_funds_request(context)?;

        //create the protocol
        let mut protocol = self.load_or_create_protocol();

        let accept_pegin_utxo =
            self.accept_pegin_utxo(context, &request.committee_id, request.slot_index)?;
        let pegin_amount = accept_pegin_utxo.2.unwrap();

        // NOTE: This is read from storage now, it will be replaced with the wallet request in the future.
        let input_utxo = self.input_utxo(context, request.slot_index)?;

        let operator_input_tx_name = indexed_name(ADVANCE_FUNDS_INPUT, request.slot_index);
        create_transaction_reference(
            &mut protocol,
            &operator_input_tx_name,
            &mut [input_utxo.clone()].to_vec(),
        )?;

        // Connect the operator input tx with the advance funds tx
        protocol.add_connection(
            "input",
            &operator_input_tx_name,
            OutputSpec::Index(input_utxo.1 as usize),
            ADVANCE_FUNDS_TX,
            InputSpec::Auto(SighashType::ecdsa_all(), SpendMode::None {}),
            None,
            Some(input_utxo.0),
        )?;

        // Add user output
        let user_wpkh = request
            .user_pubkey
            .wpubkey_hash()
            .expect("key is compressed");
        let user_script_pubkey = ScriptBuf::new_p2wpkh(&user_wpkh);

        let user_amount = self.checked_sub(pegin_amount, request.fee)?;

        protocol.add_transaction_output(
            ADVANCE_FUNDS_TX,
            &OutputType::SegwitPublicKey {
                value: Amount::from_sat(user_amount),
                script_pubkey: user_script_pubkey.clone(),
                public_key: request.user_pubkey,
            },
        )?;

        // Add op return output
        let script_op_return = op_return_script(request.pegout_id)?;
        protocol.add_transaction_output(
            ADVANCE_FUNDS_TX,
            &OutputType::segwit_unspendable(script_op_return.get_script().clone())?,
        )?;

        // Add the operator change output if needed
        let mut op_change = self.checked_sub(input_utxo.2.unwrap(), pegin_amount)?;
        op_change = self.checked_sub(op_change, request.fee)?;

        if op_change > DUST_VALUE {
            let op_wpkh = request
                .my_take_pubkey
                .wpubkey_hash()
                .expect("key is compressed");

            let op_script_pubkey = ScriptBuf::new_p2wpkh(&op_wpkh);

            protocol.add_transaction_output(
                ADVANCE_FUNDS_TX,
                &OutputType::SegwitPublicKey {
                    value: Amount::from_sat(op_change),
                    script_pubkey: op_script_pubkey.clone(),
                    public_key: request.my_take_pubkey,
                },
            )?;
        }

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
        match name {
            ADVANCE_FUNDS_TX => Ok((self.advance_funds_tx()?, None)),
            _ => Err(BitVMXError::InvalidTransactionName(name.to_string())),
        }
    }

    fn notify_news(
        &self,
        tx_id: Txid,
        _vout: Option<u32>,
        _tx_status: TransactionStatus,
        _context: String,
        context: &ProgramContext,
        _participant_keys: Vec<&ParticipantKeys>,
    ) -> Result<(), BitVMXError> {
        let transaction_name = self.get_transaction_name_by_id(tx_id)?;
        info!(
            "Transaction {} with id {} has been processed in context AdvanceFundsProtocol",
            transaction_name, tx_id
        );

        if transaction_name == ADVANCE_FUNDS_TX {
            let request: AdvanceFundsRequest = self.advance_funds_request(context)?;
            if !self.is_initial_deposit_tx_dispatched(context, &self.ctx.id)? {
                self.dispatch_op_initial_deposit_tx(
                    context,
                    &request.committee_id,
                    &request.my_take_pubkey,
                )?;
            }

            let dispute_protocol_id =
                get_dispute_core_pid(request.committee_id, &request.my_take_pubkey);

            self.save_pegout_id(
                context,
                dispute_protocol_id,
                request.pegout_id,
                request.slot_index,
            )?;

            info!("Sleeping for 1 second to allow the initial deposit tx to be processed");
            thread::sleep(std::time::Duration::from_secs(1));
            self.dispatch_reimbursement_tx(context, dispute_protocol_id, request.slot_index)?;
        }

        Ok(())
    }

    fn setup_complete(&self, _program_context: &ProgramContext) -> Result<(), BitVMXError> {
        // This is called after the protocol is built and ready to be used
        info!(
            id = self.ctx.my_idx,
            "AdvanceFundsProtocol setup complete for program {}", self.ctx.id
        );
        Ok(())
    }
}

impl AdvanceFundsProtocol {
    pub fn new(ctx: ProtocolContext) -> Self {
        Self { ctx }
    }

    fn advance_funds_request(
        &self,
        context: &ProgramContext,
    ) -> Result<AdvanceFundsRequest, BitVMXError> {
        let request = context
            .globals
            .get_var(&self.ctx.id, &AdvanceFundsRequest::name())?
            .unwrap()
            .string()?;

        let request: AdvanceFundsRequest = serde_json::from_str(&request)?;
        Ok(request)
    }

    fn input_utxo(
        &self,
        context: &ProgramContext,
        slot_index: usize,
    ) -> Result<PartialUtxo, BitVMXError> {
        Ok(context
            .globals
            .get_var(&self.ctx.id, &indexed_name(ADVANCE_FUNDS_INPUT, slot_index))?
            .unwrap()
            .utxo()?)
    }

    fn accept_pegin_utxo(
        &self,
        context: &ProgramContext,
        committee_id: &Uuid,
        slot_index: usize,
    ) -> Result<PartialUtxo, BitVMXError> {
        Ok(context
            .globals
            .get_var(committee_id, &indexed_name(ACCEPT_PEGIN_TX, slot_index))?
            .unwrap()
            .utxo()?)
    }

    pub fn advance_funds_tx(&self) -> Result<Transaction, ProtocolBuilderError> {
        // let signature = self
        //     .load_protocol()?
        //     .input_taproot_key_spend_signature(ADVANCE_FUNDS_TX, 0)?
        //     .unwrap();
        // let mut taproot_arg = InputArgs::new_taproot_key_args();
        // taproot_arg.push_taproot_signature(signature)?;

        Ok(self
            .load_protocol()?
            .transaction_by_name(ADVANCE_FUNDS_TX)?
            .clone())
    }

    pub fn is_initial_deposit_tx_dispatched(
        &self,
        context: &ProgramContext,
        committee_id: &Uuid,
    ) -> Result<bool, BitVMXError> {
        let dispatched = context
            .globals
            .get_var(committee_id, OP_INITIAL_DEPOSIT_FLAG)?
            .unwrap_or_else(|| VariableTypes::Bool(false))
            .bool()?;

        Ok(dispatched)
    }

    pub fn dispatch_op_initial_deposit_tx(
        &self,
        context: &ProgramContext,
        committee_id: &Uuid,
        pubkey: &PublicKey,
    ) -> Result<(), BitVMXError> {
        let dispute_protocol_id = get_dispute_core_pid(*committee_id, pubkey);

        let dispute_core =
            self.load_protocol_by_name(PROGRAM_TYPE_DISPUTE_CORE, dispute_protocol_id)?;

        let tx_name = format!("{}{}", OPERATOR, INITIAL_DEPOSIT_TX_SUFFIX);
        let (tx, _speedup) = dispute_core.get_transaction_by_name(&tx_name, context)?;
        let txid = tx.compute_txid();

        context.bitcoin_coordinator.dispatch(
            tx.clone(),
            None,                                                      //speedup,
            format!("dispute_core_setup_{}:{}", self.ctx.id, tx_name), // Context string
            None,                                                      // Dispatch immediately
        )?;

        info!(
            id = self.ctx.my_idx,
            "{} dispatched with txid: {}", tx_name, txid
        );

        // Set the initial deposit flag to true
        context.globals.set_var(
            &dispute_protocol_id,
            OP_INITIAL_DEPOSIT_FLAG,
            VariableTypes::Bool(true),
        )?;
        Ok(())
    }

    pub fn dispatch_reimbursement_tx(
        &self,
        context: &ProgramContext,
        dispute_protocol_id: Uuid,
        slot_index: usize,
    ) -> Result<(), BitVMXError> {
        info!(
            "Dispatching reimbursement kickoff transaction for slot index {} in dispute protocol {}",
            slot_index, dispute_protocol_id
        );

        let dispute_core_ph =
            self.load_protocol_by_name(PROGRAM_TYPE_DISPUTE_CORE, dispute_protocol_id)?;

        let tx_name = indexed_name(REIMBURSEMENT_KICKOFF_TX, slot_index);
        let (tx, _speedup) = dispute_core_ph.get_transaction_by_name(&tx_name, context)?;
        let txid = tx.compute_txid();

        // Dispatch the transaction through the bitcoin coordinator
        context.bitcoin_coordinator.dispatch(
            tx.clone(),
            None,            //speedup,
            tx_name.clone(), // Context string
            None,            // Dispatch immediately
        )?;

        info!(
            id = self.ctx.my_idx,
            "{} dispatched with txid: {}", tx_name, txid
        );
        Ok(())
    }

    fn save_pegout_id(
        &self,
        context: &ProgramContext,
        dispute_protocol_id: Uuid,
        pegout_id: Vec<u8>,
        slot_index: usize,
    ) -> Result<(), BitVMXError> {
        context.globals.set_var(
            &dispute_protocol_id,
            &indexed_name(PEGOUT_ID, slot_index),
            VariableTypes::Input(pegout_id.clone()),
        )?;
        Ok(())
    }
}
