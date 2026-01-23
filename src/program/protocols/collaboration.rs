/// CollaborationProtocol - Simple protocol for generating an aggregated MuSig2 key
///
/// This protocol is used when multiple parties want to collaborate to create a single
/// aggregated public key using MuSig2. Unlike full BitVMX protocols, this doesn't create
/// any Bitcoin transactions - it only orchestrates the key exchange.
///
/// # Use Case
///
/// - Multiple operators want to create a shared aggregated key
/// - No on-chain transactions needed
/// - Just key exchange and aggregation
/// - Result is stored in globals for later use
use bitcoin::{PublicKey, Transaction, Txid};
use bitcoin_coordinator::TransactionStatus;
use protocol_builder::types::output::SpeedupData;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::{
    errors::BitVMXError,
    program::{
        participant::ParticipantKeys,
        protocols::protocol_handler::{ProtocolContext, ProtocolHandler},
        setup::{template_steps::KeysStep, SetupStep},
        variables::VariableTypes,
    },
    types::ProgramContext,
};

/// CollaborationProtocol - Manages aggregated key generation
#[derive(Clone, Serialize, Deserialize)]
pub struct CollaborationProtocol {
    ctx: ProtocolContext,
}

impl CollaborationProtocol {
    /// Creates a new CollaborationProtocol instance
    pub fn new(ctx: ProtocolContext) -> Self {
        Self { ctx }
    }
}

impl ProtocolHandler for CollaborationProtocol {
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
        // No pregenerated keys for collaboration
        Ok(vec![])
    }

    fn generate_keys(
        &self,
        program_context: &mut ProgramContext,
    ) -> Result<ParticipantKeys, BitVMXError> {
        // Generate a single key for aggregation
        let key = program_context
            .key_chain
            .derive_keypair(key_manager::key_type::BitcoinKeyType::P2tr)?;

        // Return participant keys with a single aggregated key named after the collaboration ID
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
        // CollaborationProtocol performs its own MuSig2 aggregation
        // This is the NEW pattern where protocols are responsible for aggregation

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

        // Get the local private key for this aggregation
        let my_key_type = keys[self.ctx.my_idx]
            .mapping
            .get(&key_name)
            .ok_or_else(|| {
                BitVMXError::InvalidMessage(format!(
                    "My key '{}' not found in participant keys",
                    key_name
                ))
            })?;

        let my_key = my_key_type.public().ok_or_else(|| {
            BitVMXError::InvalidMessage(format!(
                "My key '{}' is not a PublicKey type",
                key_name
            ))
        })?;

        // 🎯 THIS IS WHERE new_musig2_session IS CALLED
        // The protocol is responsible for its own MuSig2 aggregation
        let aggregated_key = context
            .key_chain
            .new_musig2_session(aggregated_pub_keys, *my_key)?;

        // Store the aggregated key in globals for easy retrieval
        context.globals.set_var(
            &self.ctx.id,
            "final_aggregated_key",
            VariableTypes::String(aggregated_key.to_string()),
        )?;

        tracing::info!(
            "CollaborationProtocol: Computed and stored final aggregated key: {}",
            aggregated_key
        );

        Ok(())
    }

    fn get_transaction_by_name(
        &self,
        _name: &str,
        _context: &ProgramContext,
    ) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
        Err(BitVMXError::InvalidTransactionName(
            "CollaborationProtocol has no transactions".to_string(),
        ))
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
        // No transactions to monitor
        Ok(())
    }

    fn setup_complete(&self, _program_context: &ProgramContext) -> Result<(), BitVMXError> {
        // No additional setup needed after keys are aggregated
        Ok(())
    }

    fn get_transactions_to_monitor(
        &self,
        _program_context: &ProgramContext,
    ) -> Result<(Vec<Txid>, Vec<(Txid, u32)>), BitVMXError> {
        // CollaborationProtocol has no Bitcoin transactions to monitor
        // It only generates an aggregated MuSig2 key
        Ok((vec![], vec![]))
    }

    // Override setup_steps to only use KeysStep
    // No Nonces or Signatures needed - we're only generating a key, not signing
    fn setup_steps(&self) -> Option<Vec<Box<dyn SetupStep>>> {
        Some(vec![
            Box::new(KeysStep::new()),
        ])
    }
}
