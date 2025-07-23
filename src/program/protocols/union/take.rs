use std::collections::HashMap;

use bitcoin::{Amount, PublicKey, ScriptBuf, Transaction, Txid};
use bitcoin_coordinator::TransactionStatus;
use protocol_builder::{
    errors::ProtocolBuilderError,
    graph::graph::GraphOptions,
    scripts::SignMode,
    types::{
        connection::InputSpec,
        input::{SighashType, SpendMode},
        output::SpeedupData,
        InputArgs, OutputType,
    },
};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::{
    errors::BitVMXError,
    program::{
        participant::ParticipantKeys,
        protocols::{
            protocol_handler::{ProtocolContext, ProtocolHandler},
            union::types::{ACCEPT_PEGIN_TX, OPERATOR_TAKE_TX, OPERATOR_WON_TX, USER_TAKE_TX},
        },
        variables::PartialUtxo,
    },
    types::ProgramContext,
};

#[derive(Clone, Serialize, Deserialize)]
pub struct TakeProtocol {
    ctx: ProtocolContext,
}

impl ProtocolHandler for TakeProtocol {
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
        // Predefined aggregated keys for this protocol
        todo!()
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
        let accept_pegin_utxo = self.utxo("accept_pegin_utxo", context)?;
        let fee = self.number("fee", context)? as u64;
        let user_pubkey = self.pubkey("user_pubkey", context)?;

        //create the protocol
        let mut protocol = self.load_or_create_protocol();

        // Declare the external accept peg-in transaction
        protocol.add_external_transaction(ACCEPT_PEGIN_TX)?;
        protocol.add_transaction_output(ACCEPT_PEGIN_TX, &accept_pegin_utxo.3.unwrap())?;

        // Connect the user take transaction with the accept peg-in transaction
        protocol.add_connection(
            "user_take",
            ACCEPT_PEGIN_TX,
            (accept_pegin_utxo.1 as usize).into(),
            USER_TAKE_TX,
            InputSpec::Auto(
                SighashType::taproot_all(),
                SpendMode::KeyOnly {
                    key_path_sign: SignMode::Aggregate,
                },
            ),
            None,
            Some(accept_pegin_utxo.0),
        )?;

        // Add the user output to the user take transaction
        let mut amount = accept_pegin_utxo.2.unwrap();
        amount = self.checked_sub(amount, fee)?;

        let wpkh = user_pubkey.wpubkey_hash().expect("key is compressed");
        let script_pubkey = ScriptBuf::new_p2wpkh(&wpkh);

        protocol.add_transaction_output(
            USER_TAKE_TX,
            &OutputType::SegwitPublicKey {
                value: Amount::from_sat(amount),
                script_pubkey,
                public_key: user_pubkey,
            },
        )?;

        // TODO review if we should add an speedup output to the user take transaction
        // TODO connect the operator take transaction with the accept peg-in transaction
        // TODO connect the operator won transaction with the accept peg-in transaction

        protocol.build(&context.key_chain.key_manager, &self.ctx.protocol_name)?;
        info!("{}", protocol.visualize(GraphOptions::Default)?);
        self.save_protocol(protocol)?;
        Ok(())
    }

    fn get_transaction_by_name(
        &self,
        name: &str,
        _context: &ProgramContext,
    ) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
        // TODO include only the txs that need to be executed based on a decision from the L2
        match name {
            ACCEPT_PEGIN_TX => Ok((self.accept_pegin()?, None)),
            USER_TAKE_TX => Ok((self.user_take()?, None)),
            OPERATOR_TAKE_TX => Ok((self.operator_take()?, None)),
            OPERATOR_WON_TX => Ok((self.operator_won()?, None)),
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
            "TakeProtocol setup complete for program {}", self.ctx.id
        );
        Ok(())
    }
}

impl TakeProtocol {
    pub fn new(ctx: ProtocolContext) -> Self {
        Self { ctx }
    }

    pub fn accept_pegin(&self) -> Result<Transaction, ProtocolBuilderError> {
        let args = InputArgs::new_taproot_key_args();

        // TODO add the necessary arguments to args

        self.load_protocol()?
            .transaction_to_send(ACCEPT_PEGIN_TX, &[args])
    }

    pub fn user_take(&self) -> Result<Transaction, ProtocolBuilderError> {
        let args = InputArgs::new_taproot_key_args();

        // TODO add the necessary arguments to args

        self.load_protocol()?
            .transaction_to_send(USER_TAKE_TX, &[args])
    }

    pub fn operator_take(&self) -> Result<Transaction, ProtocolBuilderError> {
        let args = InputArgs::new_taproot_key_args();

        // TODO add the necessary arguments to args

        self.load_protocol()?
            .transaction_to_send(OPERATOR_TAKE_TX, &[args])
    }

    pub fn operator_won(&self) -> Result<Transaction, ProtocolBuilderError> {
        let args = InputArgs::new_taproot_key_args();

        // TODO add the necessary arguments to args

        self.load_protocol()?
            .transaction_to_send(OPERATOR_WON_TX, &[args])
    }

    fn utxo(&self, name: &str, context: &ProgramContext) -> Result<PartialUtxo, BitVMXError> {
        context.globals.get_var(&self.ctx.id, name)?.unwrap().utxo()
    }

    fn number(&self, name: &str, context: &ProgramContext) -> Result<u32, BitVMXError> {
        context
            .globals
            .get_var(&self.ctx.id, name)?
            .unwrap()
            .number()
    }

    fn pubkey(&self, name: &str, context: &ProgramContext) -> Result<PublicKey, BitVMXError> {
        context
            .globals
            .get_var(&self.ctx.id, name)?
            .unwrap()
            .pubkey()
    }
}
