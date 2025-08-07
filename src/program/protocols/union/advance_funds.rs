use std::collections::HashMap;

use bitcoin::{Amount, PublicKey, ScriptBuf, Transaction, Txid};
use bitcoin_coordinator::TransactionStatus;
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
                common::{create_transaction_reference, indexed_name},
                types::{
                    AdvanceFundsRequest, ACCEPT_PEGIN_TX, ADVANCE_FUNDS_INPUT, ADVANCE_FUNDS_TX,
                    DUST_VALUE,
                },
            },
        },
        variables::PartialUtxo,
    },
    types::ProgramContext,
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
            self.accept_pegin_utxo(context, &request.committee_id, request.slot_id)?;
        let pegin_amount = accept_pegin_utxo.2.unwrap();

        // NOTE: This is read from storage now, it will be replaced with the wallet request in the future.
        let input_utxo = self.input_utxo(context, request.slot_id)?;
        info!("Input UTXO for advance funds: {:?}", input_utxo);

        let operator_input_tx_name = indexed_name(ADVANCE_FUNDS_INPUT, request.slot_id);
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
                .operator_pubkey
                .wpubkey_hash()
                .expect("key is compressed");

            let op_script_pubkey = ScriptBuf::new_p2wpkh(&op_wpkh);

            protocol.add_transaction_output(
                ADVANCE_FUNDS_TX,
                &OutputType::SegwitPublicKey {
                    value: Amount::from_sat(op_change),
                    script_pubkey: op_script_pubkey.clone(),
                    public_key: request.operator_pubkey,
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
        _tx_id: Txid,
        _vout: Option<u32>,
        _tx_status: TransactionStatus,
        _context: String,
        _program_context: &ProgramContext,
        _participant_keys: Vec<&ParticipantKeys>,
    ) -> Result<(), BitVMXError> {
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
}
