use std::collections::HashMap;

use bitcoin::{Amount, PublicKey, ScriptBuf, Transaction, Txid};
use bitcoin_coordinator::{coordinator::BitcoinCoordinatorApi, TransactionStatus};
use protocol_builder::{
    graph::graph::GraphOptions,
    scripts::op_return_script,
    types::{
        connection::{InputSpec, OutputSpec},
        input::{SighashType, SpendMode},
        output::SpeedupData,
        InputArgs, OutputType,
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
                common::{
                    create_transaction_reference, get_dispute_core_pid, get_operator_output_type,
                    indexed_name,
                },
                dispute_core::PEGOUT_ID,
                types::{
                    AdvanceFundsRequest, Committee, FundsAdvanced, ACCEPT_PEGIN_TX,
                    ADVANCE_FUNDS_INPUT, ADVANCE_FUNDS_TX, DUST_VALUE, LAST_OPERATOR_TAKE_UTXO,
                    OP_INITIAL_DEPOSIT_FLAG, OP_INITIAL_DEPOSIT_TX, REIMBURSEMENT_KICKOFF_TX,
                    USER_TAKE_FEE,
                },
            },
        },
        variables::{PartialUtxo, VariableTypes},
    },
    types::{OutgoingBitVMXApiMessages, ProgramContext, PROGRAM_TYPE_DISPUTE_CORE},
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
        let accept_pegin_output_amount = accept_pegin_utxo.2.unwrap();

        // NOTE: This is read from storage now, it will be replaced with the wallet request in the future.
        let input_utxo = self.advance_funds_input_utxo(context)?;
        info!("Input UTXO: {:#?}", input_utxo);

        let operator_input_tx_name = "ADVANCE_FUNDS_INPUT_TX";
        create_transaction_reference(
            &mut protocol,
            &operator_input_tx_name,
            &mut [input_utxo.clone()].to_vec(),
        )?;

        // Connect the operator input tx with the advance funds tx
        protocol.add_connection(
            "input",
            &operator_input_tx_name,
            (input_utxo.1 as usize).into(),
            ADVANCE_FUNDS_TX,
            InputSpec::Auto(SighashType::ecdsa_all(), SpendMode::None),
            None,
            Some(input_utxo.0),
        )?;

        let op_take_utxo = self.operator_take_utxo(context)?;
        info!("Operator take UTXO: {:#?}", op_take_utxo);
        if op_take_utxo.is_some() {
            let op_take_utxo = op_take_utxo.clone().unwrap();
            let operator_take_tx_name = "PREV_OPERATOR_TAKE_TX";

            create_transaction_reference(
                &mut protocol,
                &operator_take_tx_name,
                &mut [op_take_utxo.clone()].to_vec(),
            )?;

            // Connect the operator take utxo with the advance funds tx
            protocol.add_connection(
                "input",
                &operator_take_tx_name,
                OutputSpec::Index(op_take_utxo.1 as usize),
                ADVANCE_FUNDS_TX,
                InputSpec::Auto(SighashType::ecdsa_all(), SpendMode::None),
                None,
                Some(op_take_utxo.0),
            )?;
        }

        // Add user output
        let user_wpkh = request
            .user_pubkey
            .wpubkey_hash()
            .expect("key is compressed");
        let user_script_pubkey = ScriptBuf::new_p2wpkh(&user_wpkh);

        let user_amount = self.checked_sub(accept_pegin_output_amount, USER_TAKE_FEE)?;
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
        let mut input_amount = input_utxo.2.unwrap();

        if op_take_utxo.is_some() {
            input_amount += op_take_utxo.unwrap().2.unwrap();
        }

        let op_change = self.checked_sub(
            input_amount + USER_TAKE_FEE,
            accept_pegin_output_amount + request.fee,
        )?;
        if op_change > DUST_VALUE {
            let op_wpkh = self
                .my_dispute_key(context)?
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
        context: &ProgramContext,
    ) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
        match name {
            ADVANCE_FUNDS_TX => Ok(self.advance_funds_tx(context)?),
            _ => Err(BitVMXError::InvalidTransactionName(name.to_string())),
        }
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
            "Advance funds protocol received news of transaction: {}, txid: {} with {} confirmations",
            tx_name, tx_id, tx_status.confirmations
        );

        if tx_name == ADVANCE_FUNDS_TX {
            let request: AdvanceFundsRequest = self.advance_funds_request(context)?;
            let mut block_height = None;

            if !self.is_initial_deposit_tx_dispatched(context, &self.committee_id(context)?)? {
                self.dispatch_op_initial_deposit_tx(
                    context,
                    &request.committee_id,
                    &request.my_take_pubkey,
                )?;

                // In the first reimbursement delay one block to ensure the initial deposit is dispatched
                block_height = Some(tx_status.block_info.as_ref().unwrap().height + 1);
            }

            let dispute_protocol_id =
                get_dispute_core_pid(request.committee_id, &request.my_take_pubkey);

            self.save_pegout_id(
                context,
                dispute_protocol_id,
                request.pegout_id,
                request.slot_index,
            )?;

            self.dispatch_reimbursement_tx(
                context,
                dispute_protocol_id,
                request.slot_index,
                block_height,
            )?;

            let tx = tx_status.tx;
            self.update_advance_funds_input(context, &tx)?;
        }

        Ok(())
    }

    fn setup_complete(&self, context: &ProgramContext) -> Result<(), BitVMXError> {
        // This is called after the protocol is built and ready to be used
        info!(
            "AdvanceFundsProtocol setup complete for program {}",
            self.ctx.id
        );

        let txid = self.dispatch_advance_funds_tx(context)?;
        self.send_funds_advanced(&context, txid)?;

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

    fn advance_funds_input_utxo(
        &self,
        context: &ProgramContext,
    ) -> Result<PartialUtxo, BitVMXError> {
        Ok(context
            .globals
            .get_var(&self.committee_id(context)?, &ADVANCE_FUNDS_INPUT)?
            .unwrap()
            .utxo()?)
    }

    fn operator_take_utxo(
        &self,
        context: &ProgramContext,
    ) -> Result<Option<PartialUtxo>, BitVMXError> {
        let var = context
            .globals
            .get_var(&self.committee_id(context)?, &LAST_OPERATOR_TAKE_UTXO)?;

        match var {
            Some(value) => Ok(Some(value.utxo()?)),
            None => Ok(None),
        }
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

    fn is_initial_deposit_tx_dispatched(
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

    fn dispatch_op_initial_deposit_tx(
        &self,
        context: &ProgramContext,
        committee_id: &Uuid,
        pubkey: &PublicKey,
    ) -> Result<(), BitVMXError> {
        let dispute_protocol_id = get_dispute_core_pid(*committee_id, pubkey);

        let dispute_core =
            self.load_protocol_by_name(PROGRAM_TYPE_DISPUTE_CORE, dispute_protocol_id)?;

        let tx_name = OP_INITIAL_DEPOSIT_TX;
        let (tx, speedup) = dispute_core.get_transaction_by_name(&tx_name, context)?;
        let txid = tx.compute_txid();

        context.bitcoin_coordinator.dispatch(
            tx.clone(),
            speedup,
            format!("dispute_core_setup_{}:{}", self.ctx.id, tx_name), // Context string
            None,                                                      // Dispatch immediately
        )?;

        info!("{} dispatched with txid: {}", tx_name, txid);

        // Set the initial deposit flag to true
        context.globals.set_var(
            &self.committee_id(context)?,
            OP_INITIAL_DEPOSIT_FLAG,
            VariableTypes::Bool(true),
        )?;
        Ok(())
    }

    fn dispatch_reimbursement_tx(
        &self,
        context: &ProgramContext,
        dispute_protocol_id: Uuid,
        slot_index: usize,
        block_height: Option<u32>,
    ) -> Result<(), BitVMXError> {
        info!(
            "Dispatching reimbursement kickoff transaction for slot index {} in dispute protocol {}",
            slot_index, dispute_protocol_id
        );

        let dispute_core_ph =
            self.load_protocol_by_name(PROGRAM_TYPE_DISPUTE_CORE, dispute_protocol_id)?;

        let tx_name = indexed_name(REIMBURSEMENT_KICKOFF_TX, slot_index);
        let (tx, speedup) = dispute_core_ph.get_transaction_by_name(&tx_name, context)?;
        let txid = tx.compute_txid();

        // Dispatch the transaction through the bitcoin coordinator
        context.bitcoin_coordinator.dispatch(
            tx.clone(),
            speedup,
            tx_name.clone(), // Context string
            block_height,    // Dispatch immediately
        )?;

        info!("{} dispatched with txid: {}", tx_name, txid);
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

    fn my_dispute_key(&self, context: &ProgramContext) -> Result<PublicKey, BitVMXError> {
        let my_index = self.find_my_index(context)?;

        let committee = self.committee(context)?;
        Ok(committee.members[my_index].dispute_key.clone())
    }

    fn committee(&self, context: &ProgramContext) -> Result<Committee, BitVMXError> {
        let committee_id = self.committee_id(context)?;

        let committee = context
            .globals
            .get_var(&committee_id, &Committee::name())?
            .unwrap()
            .string()?;

        let committee: Committee = serde_json::from_str(&committee)?;
        Ok(committee)
    }

    fn committee_id(&self, context: &ProgramContext) -> Result<Uuid, BitVMXError> {
        Ok(self.advance_funds_request(context)?.committee_id)
    }

    fn find_my_index(&self, context: &ProgramContext) -> Result<usize, BitVMXError> {
        let my_key = self.advance_funds_request(context)?.my_take_pubkey;

        let committee = self.committee(context)?;
        for (i, member) in committee.members.iter().enumerate() {
            if member.take_key == my_key {
                return Ok(i);
            }
        }

        Err(BitVMXError::InvalidParticipant(
            "My dispute key not found in committee".to_string(),
        ))
    }

    fn update_advance_funds_input(
        &self,
        context: &ProgramContext,
        tx: &Transaction,
    ) -> Result<(), BitVMXError> {
        const CHANGE_INDEX: usize = 2;
        if tx.output.len() < CHANGE_INDEX + 1 {
            info!(
                "Transaction {:#?} has less than 3 outputs, skipping advance funds input update",
                tx
            );
            return Ok(());
        }

        let amount = tx.output[CHANGE_INDEX].value.to_sat();

        let utxo = (
            tx.compute_txid(),
            CHANGE_INDEX as u32,
            Some(amount),
            Some(get_operator_output_type(
                &self.my_dispute_key(context)?,
                amount,
            )?),
        );

        context.globals.set_var(
            &self.committee_id(context)?,
            &ADVANCE_FUNDS_INPUT,
            VariableTypes::Utxo(utxo),
        )?;
        Ok(())
    }

    fn dispatch_advance_funds_tx(&self, context: &ProgramContext) -> Result<Txid, BitVMXError> {
        info!(
            "Dispatching {} transaction from protocol {}",
            ADVANCE_FUNDS_TX, self.ctx.id
        );

        // Get the signed transaction
        let (tx, speedup) = self.advance_funds_tx(context)?;
        let txid = tx.compute_txid();

        info!("Auto-dispatching ADVANCE_FUNDS_TX transaction: {}", txid);

        // Dispatch the transaction through the bitcoin coordinator
        context.bitcoin_coordinator.dispatch(
            tx,
            speedup,
            format!("advance_funds_{}:{}", self.ctx.id, ADVANCE_FUNDS_TX), // Context string
            None,                                                          // Dispatch immediately
        )?;

        info!(
            "ADVANCE_FUNDS_TX dispatched successfully with txid: {}",
            txid
        );

        Ok(txid)
    }

    fn advance_funds_tx(
        &self,
        context: &ProgramContext,
    ) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
        let name = ADVANCE_FUNDS_TX.to_string();
        let mut protocol = self.load_protocol()?;
        let mut input_0 = InputArgs::new_segwit_args();
        let tx = protocol.transaction_by_name(&name)?;

        let signature =
            protocol
                .clone()
                .sign_ecdsa_input(&name, 0, &context.key_chain.key_manager)?;
        input_0.push_ecdsa_signature(signature)?;
        let mut inputs: Vec<InputArgs> = vec![];
        inputs.push(input_0);

        if tx.input.len() > 1 {
            let mut input_1 = InputArgs::new_segwit_args();
            let signature = protocol.sign_ecdsa_input(&name, 1, &context.key_chain.key_manager)?;
            input_1.push_ecdsa_signature(signature)?;
            inputs.push(input_1);
        }

        let tx2send = protocol.transaction_to_send(&name, &inputs.as_slice())?;
        Ok((tx2send, None))
    }

    fn send_funds_advanced(&self, context: &ProgramContext, txid: Txid) -> Result<(), BitVMXError> {
        let request: AdvanceFundsRequest = self.advance_funds_request(context)?;

        let funds_advanced = FundsAdvanced {
            txid: txid,
            committee_id: request.committee_id,
            slot_index: request.slot_index,
            pegout_id: request.pegout_id,
        };

        let data = serde_json::to_string(&OutgoingBitVMXApiMessages::Variable(
            self.ctx.id,
            FundsAdvanced::name(),
            VariableTypes::String(serde_json::to_string(&funds_advanced)?),
        ))?;

        info!(
            id = self.ctx.my_idx,
            "Sending funds advanded data for AdvanceFunds: {}", data
        );

        // Send the funds advanced data to the broker channel
        context
            .broker_channel
            .send(&context.components_config.l2, data)?;

        Ok(())
    }
}
