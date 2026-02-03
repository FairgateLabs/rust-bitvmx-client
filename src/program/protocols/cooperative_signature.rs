/// CooperativeSignatureProtocol - Protocol for testing complete MuSig2 signing flow
///
/// This protocol exercises all three setup steps:
/// 1. KeysStep - Generate and exchange keys, compute aggregated key
/// 2. NoncesStep - Generate and exchange nonces for signing
/// 3. SignaturesStep - Generate and exchange partial signatures
///
/// # Use Case
///
/// - Test the complete MuSig2 flow with leader broadcast
/// - Verify that all participants can produce a valid aggregated signature
/// - Validate the 3-step setup process works end-to-end
/// - No Bitcoin transactions needed, just key/nonce/signature exchange
///
/// # Result
///
/// The protocol stores the final aggregated signature in globals under:
/// - "final_aggregated_key" - The MuSig2 aggregated public key
/// - "final_signature" - The complete MuSig2 signature (once implemented)
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
            VariableTypes::String(aggregated_key.to_string()),
        )?;

        tracing::info!(
            "CooperativeSignatureProtocol: Stored final aggregated key: {}",
            aggregated_key
        );

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
        // After all steps complete, verify we have everything needed

        // Verify aggregated key exists
        let _aggregated_key = program_context
            .globals
            .get_var(&self.ctx.id, "final_aggregated_key")?
            .ok_or_else(|| {
                BitVMXError::InvalidMessage(
                    "Setup complete but no aggregated key found".to_string(),
                )
            })?;

        tracing::info!(
            "CooperativeSignatureProtocol: Setup complete! All keys, nonces, and signatures exchanged."
        );

        // In a real implementation, we would:
        // 1. Collect all nonces from globals
        // 2. Collect all partial signatures from globals
        // 3. Combine them into a final MuSig2 signature
        // 4. Store the final signature in globals
        //
        // For now, we just verify the exchange completed successfully

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
