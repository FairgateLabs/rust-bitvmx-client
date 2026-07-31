use crate::ports::bitcoin_coordinator::BitcoinCoordinatorApi;
use std::collections::HashMap;

use bitcoin::{PublicKey, Transaction, Txid};
use bitcoin_coordinator::TransactionStatus;
use protocol_builder::types::output::SpeedupData;
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::{
    errors::BitVMXError,
    program::{
        participant::{ParticipantKeyDeclaration, ParticipantKeys},
        protocols::protocol_handler::{ProtocolContext, ProtocolHandler},
    },
    types::ProgramContext,
};

#[derive(Clone, Serialize, Deserialize)]
pub struct PairwisePenalizationProtocol {
    ctx: ProtocolContext,
}

impl ProtocolHandler for PairwisePenalizationProtocol {
    fn context(&self) -> &ProtocolContext {
        &self.ctx
    }

    fn context_mut(&mut self) -> &mut ProtocolContext {
        &mut self.ctx
    }

    fn get_pregenerated_aggregated_keys<BC: BitcoinCoordinatorApi>(
        &self,
        _context: &ProgramContext<BC>,
    ) -> Result<Vec<(String, PublicKey)>, BitVMXError> {
        todo!()
    }

    fn generate_keys<BC: BitcoinCoordinatorApi>(
        &self,
        _program_context: &mut ProgramContext<BC>,
    ) -> Result<ParticipantKeyDeclaration, BitVMXError> {
        todo!()
    }

    fn build<BC: BitcoinCoordinatorApi>(
        &self,
        _keys: Vec<ParticipantKeys>,
        _computed_aggregated: HashMap<String, PublicKey>,
        _context: &ProgramContext<BC>,
    ) -> Result<(), BitVMXError> {
        todo!()
    }

    fn get_transaction_by_name<BC: BitcoinCoordinatorApi>(
        &self,
        _name: &str,
        _context: &ProgramContext<BC>,
    ) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
        todo!()
    }

    fn notify_news<BC: BitcoinCoordinatorApi>(
        &self,
        _tx_id: Txid,
        _vout: Option<u32>,
        _tx_status: TransactionStatus,
        _context: String,
        _program_context: &ProgramContext<BC>,
    ) -> Result<(), BitVMXError> {
        todo!()
    }

    fn setup_complete<BC: BitcoinCoordinatorApi>(
        &self,
        _program_context: &ProgramContext<BC>,
    ) -> Result<(), BitVMXError> {
        // This is called after the protocol is built and ready to be used
        info!(
            id = self.ctx.my_idx,
            "PairwisePenalizationProtocol setup complete for program {}", self.ctx.id
        );
        Ok(())
    }
}

impl PairwisePenalizationProtocol {
    pub fn new(ctx: ProtocolContext) -> Self {
        Self { ctx }
    }
}
