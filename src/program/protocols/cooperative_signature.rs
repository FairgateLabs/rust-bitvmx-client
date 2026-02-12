/// CooperativeSignatureProtocol - Protocol for complete MuSig2 signing flow
///
/// This protocol exercises all three setup steps:
/// 1. KeysStep - Generate and exchange keys, compute aggregated key
/// 2. NoncesStep - Generate and exchange nonces for signing
/// 3. SignaturesStep - Generate and exchange partial signatures
///
/// # Use Case
///
/// - Multiple participants cooperatively sign a message using MuSig2
/// - Produces a valid aggregated Schnorr signature
/// - No Bitcoin transactions needed, just key/nonce/signature exchange
///
/// # Result
///
/// The protocol stores the final results in globals:
/// - "final_aggregated_key" - The MuSig2 aggregated public key (PubKey)
/// - "final_signature" - The complete MuSig2 Schnorr signature (String, hex-encoded)
/// - "message_to_sign" - The message that was signed (String, hex-encoded)
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

/// CooperativeSignatureProtocol - Manages complete MuSig2 signing flow
#[derive(Clone, Serialize, Deserialize)]
pub struct CooperativeSignatureProtocol {
    ctx: ProtocolContext,
    /// The message that all participants will cooperatively sign
    message: Vec<u8>,
}

impl CooperativeSignatureProtocol {
    /// Creates a new CooperativeSignatureProtocol instance
    ///
    /// # Arguments
    /// * `ctx` - The protocol context
    pub fn new(ctx: ProtocolContext) -> Self {
        let message = ctx.id.to_string().into_bytes();
        Self { ctx, message }
    }

    /// Get the message being signed
    pub fn message(&self) -> &[u8] {
        &self.message
    }
}

impl ProtocolHandler for CooperativeSignatureProtocol {
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
        // Generate a single key for aggregation and signing
        let key = program_context
            .key_chain
            .derive_keypair(key_manager::key_type::BitcoinKeyType::P2tr)?;

        // Return participant keys with a single aggregated key named after the protocol ID
        let aggregated_name = self.ctx.id.to_string();

        // Note: computed_aggregated will be populated by KeysStep::on_step_complete()
        // after all participants have exchanged their keys
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
        let key_name = self.ctx.id.to_string();

        // Use the pre-computed aggregated key from KeysStep
        let aggregated_key = computed_aggregated.get(&key_name).ok_or_else(|| {
            BitVMXError::InvalidMessage(format!(
                "Pre-computed aggregated key '{}' not found",
                key_name
            ))
        })?;

        // Store the aggregated key in globals for easy retrieval
        context.globals.set_var(
            &self.ctx.id,
            "final_aggregated_key",
            VariableTypes::PubKey(*aggregated_key),
        )?;

        tracing::info!(
            "CooperativeSignatureProtocol: Stored final aggregated key: {}",
            aggregated_key
        );

        context.key_chain.key_manager.generate_nonce(
            &key_name,
            self.message.clone(),
            aggregated_key,
            &self.ctx.protocol_name,
            None,
        )?;

        // Store the message being signed (as hex string)
        context.globals.set_var(
            &self.ctx.id,
            "message_to_sign",
            VariableTypes::String(hex::encode(&self.message)),
        )?;

        tracing::info!(
            "CooperativeSignatureProtocol: Message to sign: {} bytes",
            self.message.len()
        );

        Ok(())
    }

    fn setup_complete(&self, program_context: &ProgramContext) -> Result<(), BitVMXError> {
        tracing::info!(
            "CooperativeSignatureProtocol: Completing setup, aggregating signatures..."
        );

        // 1. Get the aggregated key
        let aggregated_key = program_context
            .globals
            .get_var(&self.ctx.id, "final_aggregated_key")?
            .ok_or_else(|| {
                BitVMXError::InvalidMessage(
                    "Setup complete but no aggregated key found".to_string(),
                )
            })?
            .pubkey()?;

        // 2. Signatures have already been added to key_manager by SignaturesStep::on_step_complete()
        // We can now directly get the aggregated signature using the message_id (protocol_id as message identifier)
        let message_id = self.ctx.id.to_string();
        let final_signature = program_context.key_chain.get_aggregated_signature(
            &aggregated_key,
            &message_id,
            &self.ctx.protocol_name,
        )?;

        // 3. Store the final signature in globals
        program_context.globals.set_var(
            &self.ctx.id,
            "final_signature",
            VariableTypes::String(hex::encode(final_signature.as_ref())),
        )?;

        tracing::info!(
            "CooperativeSignatureProtocol: Setup complete! Final MuSig2 signature: {}",
            hex::encode(final_signature.as_ref())
        );

        Ok(())
    }

    /// Returns the list of setup step names for this protocol.
    ///
    /// This protocol uses all three template steps:
    /// 1. KeysStep - Exchange keys and compute aggregated key
    /// 2. NoncesStep - Exchange nonces for signing
    /// 3. SignaturesStep - Exchange partial signatures
    fn setup_steps(&self) -> Option<Vec<SetupStepName>> {
        Some(vec![
            SetupStepName::Keys,
            SetupStepName::Nonces,
            SetupStepName::Signatures,
        ])
    }
}
