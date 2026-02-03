/// AggregatedKeyProtocol - Simple protocol for generating an aggregated MuSig2 key
///
/// This protocol is used when multiple parties want to create a single
/// aggregated public key using MuSig2. Unlike full BitVMX protocols, this doesn't create
/// any Bitcoin transactions - it only orchestrates the key exchange.
///
/// # Use Case
///
/// - Multiple operators want to create a shared aggregated key
/// - No on-chain transactions needed
/// - Just key exchange and aggregation
/// - Result is stored in globals for later use
use bitcoin::PublicKey;
use bitvmx_broker::identification::identifier::Identifier;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use storage_backend::storage::KeyValueStore;

use crate::{
    errors::BitVMXError,
    program::{
        participant::ParticipantKeys,
        protocols::protocol_handler::{ProtocolContext, ProtocolHandler},
        setup::steps::SetupStepName,
        variables::VariableTypes,
    },
    types::{OutgoingBitVMXApiMessages, ProgramContext},
};

/// AggregatedKeyProtocol - Manages aggregated key generation
#[derive(Clone, Serialize, Deserialize)]
pub struct AggregatedKeyProtocol {
    ctx: ProtocolContext,
}

impl AggregatedKeyProtocol {
    /// Creates a new AggregatedKeyProtocol instance
    pub fn new(ctx: ProtocolContext) -> Self {
        Self { ctx }
    }
}

impl ProtocolHandler for AggregatedKeyProtocol {
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
        // Generate a single key for aggregation
        let key = program_context
            .key_chain
            .derive_keypair(key_manager::key_type::BitcoinKeyType::P2tr)?;

        // Return participant keys with a single aggregated key named after the protocol ID
        let aggregated_name = self.ctx.id.to_string();
        Ok(ParticipantKeys::new(
            vec![(aggregated_name.clone(), key.into())],
            vec![aggregated_name],
        ))
    }

    fn build(
        &self,
        _keys: Vec<ParticipantKeys>,
        computed_aggregated: HashMap<String, PublicKey>,
        context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        tracing::info!(
            "AggregatedKeyProtocol::build() called for program {}",
            self.ctx.id,
        );

        let key_name = self.ctx.id.to_string();

        // Use the pre-computed aggregated key from KeysStep
        let aggregated_key = computed_aggregated.get(&key_name).ok_or_else(|| {
            BitVMXError::InvalidMessage(format!(
                "Pre-computed aggregated key '{}' not found",
                key_name
            ))
        })?;

        // Store the aggregated key in globals for easy retrieval
        let key_str = aggregated_key.to_string();
        context.globals.set_var(
            &self.ctx.id,
            "final_aggregated_key",
            VariableTypes::String(key_str.clone()),
        )?;

        tracing::info!(
            "AggregatedKeyProtocol: Stored final aggregated key: {} (program_id: {})",
            key_str,
            self.ctx.id
        );

        // Send AggregatedPubkey message to the requester (similar to Collaboration)
        // Read the 'from' identifier from storage
        if let Some(storage) = &self.ctx.storage {
            let from_key = format!("bitvmx/aggregated_key/{}/from", self.ctx.id);
            let from: Option<Identifier> = storage.get(&from_key)?;
            if let Some(from) = from {
                tracing::info!(
                    "AggregatedKeyProtocol: Sending AggregatedPubkey to requester: {}",
                    *aggregated_key
                );
                context.broker_channel.send(
                    &from,
                    OutgoingBitVMXApiMessages::AggregatedPubkey(self.ctx.id, *aggregated_key)
                        .to_string()?,
                )?;
            } else {
                tracing::debug!(
                    "AggregatedKeyProtocol: No 'from' identifier found in storage, skipping AggregatedPubkey message"
                );
            }
        }

        Ok(())
    }

    // AggregatedKeyProtocol is used internally by SetupKey, which only expects
    // the AggregatedPubkey response. Suppress SetupCompleted to maintain backward compatibility.
    fn send_setup_completed(&self) -> bool {
        false
    }

    // Override setup_steps to only use KeysStep
    // No Nonces or Signatures needed - we're only generating a key, not signing
    fn setup_steps(&self) -> Option<Vec<SetupStepName>> {
        Some(vec![
            SetupStepName::Keys,
        ])
    }
}

