/// GarbledProtocol - Simple protocol for testing async garbled circuit setup step.
///
/// Uses [Keys, GarbledCircuits] setup steps to exercise the async generation flow.
/// The Keys step exchanges keys normally. The GarbledCircuits step sends a job
/// to the garbled-dispatcher and waits for the result asynchronously.
///
/// This protocol does NOT build Bitcoin transactions. It only tests the setup flow
/// with an async step, similar to AggregatedKeyProtocol but with a garbled step.
use bitcoin::PublicKey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::{
    errors::BitVMXError,
    program::{
        participant::ParticipantKeys,
        protocols::protocol_handler::{ProtocolContext, ProtocolHandler},
        setup::steps::SetupStepName,
        variables::VariableTypes,
    },
    types::ProgramContext,
};

#[derive(Clone, Serialize, Deserialize)]
pub struct GarbledProtocol {
    ctx: ProtocolContext,
}

impl GarbledProtocol {
    pub fn new(ctx: ProtocolContext) -> Self {
        Self { ctx }
    }
}

impl ProtocolHandler for GarbledProtocol {
    fn context(&self) -> &ProtocolContext {
        &self.ctx
    }

    fn context_mut(&mut self) -> &mut ProtocolContext {
        &mut self.ctx
    }

    fn generate_keys(
        &self,
        program_context: &mut ProgramContext,
    ) -> Result<ParticipantKeys, BitVMXError> {
        let key = program_context
            .key_manager
            .next_keypair(key_manager::key_type::BitcoinKeyType::P2tr)?;

        let key_name = format!("garbled_{}", self.ctx.id);
        Ok(ParticipantKeys::new(
            vec![(key_name.clone(), key.into())],
            vec![key_name],
        ))
    }

    fn build(
        &self,
        _keys: Vec<ParticipantKeys>,
        computed_aggregated: HashMap<String, PublicKey>,
        context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        let key_name = format!("garbled_{}", self.ctx.id);

        let aggregated_key = computed_aggregated.get(&key_name).ok_or_else(|| {
            BitVMXError::InvalidMessage(format!(
                "Pre-computed aggregated key '{}' not found",
                key_name
            ))
        })?;

        context.globals.set_var(
            &self.ctx.id,
            "garbled_aggregated_key",
            VariableTypes::PubKey(*aggregated_key),
        )?;

        tracing::info!(
            "GarbledProtocol::build() - Stored aggregated key for program {}",
            self.ctx.id
        );

        Ok(())
    }

    fn setup_steps(&self) -> Option<Vec<SetupStepName>> {
        Some(vec![SetupStepName::Keys, SetupStepName::GarbledCircuits])
    }
}
