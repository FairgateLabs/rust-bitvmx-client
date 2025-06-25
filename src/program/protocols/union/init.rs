use crate::program::protocols::{protocol_context::ProtocolContext, protocol_handler::ProtocolHandler};
use serde::{Deserialize, Serialize};
use crate::{
    errors::BitVMXError,
    program::{
        participant::ParticipantKeys,
        protocols::protocol_handler::{ProtocolContext, ProtocolHandler},
        variables::VariableTypes,
    },
    types::ProgramContext,
};
use crate::program::protocols::union::events::events::Event;
use crate::program::protocols::union::PublicKey;
use bitcoin::{Transaction, Txid};
use bitcoin_coordinator::TransactionStatus;
use std::collections::HashMap;


#[derive(Clone, Serialize, Deserialize)]
pub struct InitProtocol {
    ctx: ProtocolContext,
}

impl ProtocolHandler for InitProtocol {
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
        todo!()
    }

    fn generate_keys(
        &self,
        program_context: &mut ProgramContext,
    ) -> Result<ParticipantKeys, BitVMXError> {
        let members_selected = program_context
            .globals
            .get_var(&self.ctx.id, Event::MembersSelected.to_string())?
            .unwrap()
            .string()?;

        let members_selected: Event::MembersSelected = serde_json::from_str(&members_selected)?;

        let take_aggregated_key = program_context.key_chain.new_musig2_session(
            members_selected.take_pubkeys.values().cloned().collect(),
            members_selected.my_take_pubkey.clone(),
        )?;

        let dispute_aggregated_key = program_context.key_chain.new_musig2_session(
            members_selected.dispute_pubkeys.values().cloned().collect(),
            members_selected.my_dispute_pubkey.clone(),
        )?;

        Ok(ParticipantKeys::new(vec![], vec![take_aggregated_key, dispute_aggregated_key]))
    }

    fn build(
        &self,
        _keys: Vec<ParticipantKeys>,
        _computed_aggregated: HashMap<String, PublicKey>,
        _context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        todo!()
    }

    fn get_transaction_name(
        &self,
        name: &str,
        context: &ProgramContext,
    ) -> Result<Transaction, BitVMXError> {
        todo!()
    }

    fn notify_news(
        &self,
        tx_id: Txid,
        vout: Option<u32>,
        tx_status: TransactionStatus,
        context: String,
        program_context: &ProgramContext,
        participant_keys: Vec<&ParticipantKeys>,
    ) -> Result<(), BitVMXError> {
        todo!()
    }
}

impl InitProtocol {
    pub fn new(ctx: ProtocolContext) -> Self {
        Self { ctx }
    }
}
