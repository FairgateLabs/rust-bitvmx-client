use std::collections::HashMap;

use bitcoin::{PublicKey, Transaction, Txid};
use bitcoin_coordinator::TransactionStatus;
use protocol_builder::{
    scripts::SignMode,
    types::{
        connection::InputSpec,
        input::{SighashType, SpendMode},
        output::SpeedupData,
        OutputType,
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
            union::types::{PegInRequest, ACCEPT_PEG_IN_TX, REQUEST_PEG_IN_TX},
        },
    },
    types::ProgramContext,
};

#[derive(Clone, Serialize, Deserialize)]
pub struct AcceptPegInProtocol {
    ctx: ProtocolContext,
}

impl ProtocolHandler for AcceptPegInProtocol {
    fn context(&self) -> &ProtocolContext {
        &self.ctx
    }

    fn context_mut(&mut self) -> &mut ProtocolContext {
        &mut self.ctx
    }

    fn get_pregenerated_aggregated_keys(
        &self,
        context: &ProgramContext,
    ) -> Result<Vec<(String, PublicKey)>, BitVMXError> {
        let peg_in_request = self.peg_in_request(context)?;

        Ok(vec![(
            "take_aggregated".to_string(),
            peg_in_request.take_aggregated_key,
        )])
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
        let peg_in_request = self.peg_in_request(context)?;
        let txid = peg_in_request.txid;
        let amount = peg_in_request.amount;
        let take_aggregated_key = peg_in_request.take_aggregated_key;

        let mut protocol = self.load_or_create_protocol();

        // External connection from request peg-in to accept peg-in
        protocol.add_connection(
            "accept_peg_in_request",
            REQUEST_PEG_IN_TX,
            OutputType::taproot(amount, &take_aggregated_key, &[])?.into(),
            ACCEPT_PEG_IN_TX,
            InputSpec::Auto(
                SighashType::taproot_all(),
                SpendMode::KeyOnly {
                    key_path_sign: SignMode::Aggregate,
                },
            ),
            None,
            Some(txid),
        )?;

        protocol.add_transaction_output(
            ACCEPT_PEG_IN_TX,
            &OutputType::taproot(amount, &take_aggregated_key, &[])?,
        )?;

        protocol.build(&context.key_chain.key_manager, &self.ctx.protocol_name)?;
        info!("{}", protocol.visualize()?);
        self.save_protocol(protocol)?;
        Ok(())
    }

    fn get_transaction_by_name(
        &self,
        name: &str,
        _context: &ProgramContext,
    ) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
        Err(BitVMXError::InvalidTransactionName(name.to_string()))
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
}

impl AcceptPegInProtocol {
    pub fn new(ctx: ProtocolContext) -> Self {
        Self { ctx }
    }

    fn peg_in_request(&self, context: &ProgramContext) -> Result<PegInRequest, BitVMXError> {
        let peg_in_request = context
            .globals
            .get_var(&self.ctx.id, &PegInRequest::name())?
            .unwrap()
            .string()?;

        let peg_in_request: PegInRequest = serde_json::from_str(&peg_in_request)?;
        Ok(peg_in_request)
    }
}
