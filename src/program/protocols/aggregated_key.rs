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
        keys: Vec<ParticipantKeys>,
        _computed_aggregated: HashMap<String, PublicKey>, // ⚠️ Ignored - we compute our own
        context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        tracing::info!(
            "AggregatedKeyProtocol::build() called for program {} with {} participant keys",
            self.ctx.id,
            keys.len()
        );

        let key_name = self.ctx.id.to_string();

        // Collect all public keys from all participants for this aggregated key
        let mut aggregated_pub_keys: Vec<PublicKey> = Vec::new();

        for participant_keys in &keys {
            if let Some(agg_key) = participant_keys.mapping.get(&key_name) {
                // Extract the PublicKey from PublicKeyType
                if let Some(public_key) = agg_key.public() {
                    aggregated_pub_keys.push(*public_key);
                } else {
                    return Err(BitVMXError::InvalidMessage(format!(
                        "Key '{}' is not a PublicKey type",
                        key_name
                    )));
                }
            } else {
                return Err(BitVMXError::InvalidMessage(format!(
                    "Participant missing key '{}' for aggregation",
                    key_name
                )));
            }
        }

        // Get my public key for this aggregation session
        let my_key = keys[self.ctx.my_idx]
            .mapping
            .get(&key_name)
            .ok_or_else(|| {
                BitVMXError::InvalidMessage(format!(
                    "My key '{}' not found in participant keys",
                    key_name
                ))
            })?
            .public()
            .ok_or_else(|| {
                BitVMXError::InvalidMessage(format!(
                    "My key '{}' is not a PublicKey type",
                    key_name
                ))
            })?;

        // Compute the aggregated key
        // MuSig2 requires at least 2 participants
        if aggregated_pub_keys.len() < 2 {
            return Err(BitVMXError::InvalidMessage(format!(
                "Aggregated key requires at least 2 participants, found {}",
                aggregated_pub_keys.len()
            )));
        }

        let aggregated_key = context
            .key_chain
            .new_musig2_session(aggregated_pub_keys, *my_key)?;

        // Store the aggregated key in globals for easy retrieval
        context.globals.set_var(
            &self.ctx.id,
            "final_aggregated_key",
            VariableTypes::PubKey(aggregated_key.clone()),
        )?;

        tracing::info!(
            "AggregatedKeyProtocol: Computed and stored final aggregated key: {} (program_id: {})",
            aggregated_key,
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
                    aggregated_key
                );
                context.broker_channel.send(
                    &from,
                    OutgoingBitVMXApiMessages::AggregatedPubkey(self.ctx.id, aggregated_key)
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

