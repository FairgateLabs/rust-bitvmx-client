use crate::ports::bitcoin_coordinator::BitcoinCoordinatorApi;
use bitcoin::PublicKey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::{
    errors::BitVMXError,
    program::{
        participant::ParticipantKeys,
        protocols::protocol_handler::{ProtocolContext, ProtocolHandler},
        setup::steps::SetupStepName,
    },
    types::ProgramContext,
};

#[derive(Clone, Serialize, Deserialize)]
pub struct GCGenerationProtocol {
    ctx: ProtocolContext,
}

impl GCGenerationProtocol {
    pub fn new(ctx: ProtocolContext) -> Self {
        Self { ctx }
    }
}

impl ProtocolHandler for GCGenerationProtocol {
    fn context(&self) -> &ProtocolContext {
        &self.ctx
    }

    fn context_mut(&mut self) -> &mut ProtocolContext {
        &mut self.ctx
    }

    fn generate_keys<BC: BitcoinCoordinatorApi>(
        &self,
        _program_context: &mut ProgramContext<BC>,
    ) -> Result<ParticipantKeys, BitVMXError> {
        ParticipantKeys::new(vec![], vec![])
    }

    fn build<BC: BitcoinCoordinatorApi>(
        &self,
        _keys: Vec<ParticipantKeys>,
        _computed_aggregated: HashMap<String, PublicKey>,
        _context: &ProgramContext<BC>,
    ) -> Result<(), BitVMXError> {
        tracing::info!(
            "GcGenerationProtocol::build() called for program {}",
            self.ctx.id,
        );

        Ok(())
    }

    fn send_setup_completed(&self) -> bool {
        true
    }

    // Override setup_steps to only use KeysStep
    // No Nonces or Signatures needed - we're only generating a key, not signing
    fn setup_steps(&self) -> Option<Vec<SetupStepName>> {
        Some(vec![SetupStepName::Garbler])
    }
}
