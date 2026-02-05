use crate::{
    errors::BitVMXError,
    helper::PartialSignatureMessage,
    program::{
        participant::{ParticipantData, ParticipantKeys},
        protocols::protocol_handler::{ProtocolHandler, ProtocolType},
        setup::{ExchangeConfig, SetupStep},
        variables::VariableTypes,
    },
    types::ProgramContext,
};
use tracing::{debug, warn};

/// Template step for exchanging MuSig2 partial signatures.
///
/// This step manages the signature generation and exchange process by:
/// 1. Retrieving the participant's keys from the previous KeysStep
/// 2. Generating MuSig2 partial signatures for each aggregated key via the KeyChain
/// 3. Serializing and exchanging signatures with other participants
/// 4. Verifying and storing received signatures from all participants
///
/// The signatures are stored in globals with the following conventions:
/// - Own signatures: "my_signatures"
/// - Participant i signatures: "participant_{i}_signatures"
#[derive(Default)]
pub struct SignaturesStep;

impl SignaturesStep {
    pub fn new() -> Self {
        Self
    }
}

impl SetupStep for SignaturesStep {
    fn step_name(&self) -> &str {
        "signatures"
    }

    fn generate_data(
        &self,
        protocol: &mut ProtocolType,
        context: &mut ProgramContext,
    ) -> Result<Option<Vec<u8>>, BitVMXError> {
        let protocol_id = protocol.context().id;

        debug!(
            "SignaturesStep: Generating partial signatures for protocol {}",
            protocol_id
        );

        // Get the participant's keys from the previous KeysStep
        let my_keys_json = context
            .globals
            .get_var(&protocol_id, "my_keys")?
            .ok_or_else(|| {
                BitVMXError::InvalidMessage(
                    "Keys must be exchanged before signatures (KeysStep must complete first)"
                        .to_string(),
                )
            })?
            .string()?;

        let my_keys: ParticipantKeys = serde_json::from_str(&my_keys_json)?;

        if my_keys.computed_aggregated.is_empty() {
            return Err(BitVMXError::InvalidMessage(
                "No aggregated keys found in my_keys. KeysStep must complete and compute aggregated keys before SignaturesStep can proceed.".to_string(),
            ));
        }

        debug!(
            "SignaturesStep: Generating signatures for {} aggregated keys",
            my_keys.computed_aggregated.len()
        );

        // Generate partial signatures for each aggregated key using the KeyChain
        let mut partial_sig_msg: PartialSignatureMessage = Vec::new();

        for aggregated in my_keys.computed_aggregated.values() {
            let signatures = context
                .key_chain
                .get_signatures(aggregated, &protocol.context().protocol_name);

            if let Err(e) = signatures {
                warn!(
                    "SignaturesStep: Error getting partial signatures for aggregated key {}: {}",
                    aggregated, e
                );
                continue;
            }

            let my_pub = context
                .key_chain
                .key_manager
                .get_my_public_key(aggregated)?;

            debug!(
                "SignaturesStep: Generated partial signatures for aggregated key: {}",
                aggregated
            );

            partial_sig_msg.push((aggregated.clone(), my_pub, signatures.unwrap()));
        }

        if partial_sig_msg.is_empty() {
            return Err(BitVMXError::InvalidMessage(
                "Failed to generate signatures for any aggregated key".to_string(),
            ));
        }

        // Save to globals
        context.globals.set_var(
            &protocol_id,
            "my_signatures",
            VariableTypes::String(serde_json::to_string(&partial_sig_msg)?),
        )?;

        // Serialize to send
        let serialized = serde_json::to_vec(&partial_sig_msg)?;
        debug!(
            "SignaturesStep: Serialized {} bytes to send",
            serialized.len()
        );

        Ok(Some(serialized))
    }

    fn verify_received(
        &self,
        data: &[u8],
        from_participant: &ParticipantData,
        protocol: &ProtocolType,
        participants: &[ParticipantData],
        context: &mut ProgramContext,
    ) -> Result<(), BitVMXError> {
        let protocol_id = protocol.context().id;

        debug!(
            "SignaturesStep: Verifying partial signatures from participant {}",
            from_participant.comms_address.pubkey_hash
        );

        // Deserialize the received signatures
        let signatures: PartialSignatureMessage = serde_json::from_slice(data).map_err(|e| {
            BitVMXError::InvalidMessage(format!("Failed to deserialize signatures: {}", e))
        })?;

        // Basic validation
        if signatures.is_empty() {
            return Err(BitVMXError::InvalidMessage(
                "Received empty signatures from participant".to_string(),
            ));
        }

        debug!(
            "SignaturesStep: Received {} partial signatures",
            signatures.len()
        );

        // Find participant index
        let idx = participants
            .iter()
            .position(|p| p.comms_address.pubkey_hash == from_participant.comms_address.pubkey_hash)
            .ok_or_else(|| {
                BitVMXError::InvalidMessage(format!(
                    "Unknown participant: {}",
                    from_participant.comms_address.pubkey_hash
                ))
            })?;

        // Save to globals with the convention "participant_{idx}_signatures"
        context.globals.set_var(
            &protocol_id,
            &format!("participant_{}_signatures", idx),
            VariableTypes::String(serde_json::to_string(&signatures)?),
        )?;

        debug!(
            "SignaturesStep: Stored signatures from participant {} at index {}",
            from_participant.comms_address.pubkey_hash, idx
        );

        Ok(())
    }

    fn can_advance(
        &self,
        protocol: &ProtocolType,
        participants: &[ParticipantData],
        context: &mut ProgramContext,
    ) -> Result<bool, BitVMXError> {
        let protocol_id = protocol.context().id;

        // Verify that all participants have sent their signatures
        for (idx, participant) in participants.iter().enumerate() {
            if context
                .globals
                .get_var(&protocol_id, &format!("participant_{}_signatures", idx))?
                .is_none()
            {
                debug!(
                    "SignaturesStep: Still waiting for signatures from participant {} (index {})",
                    participant.comms_address.pubkey_hash, idx
                );
                return Ok(false);
            }
        }

        debug!(
            "SignaturesStep: All {} participants have sent their signatures",
            participants.len()
        );
        Ok(true)
    }

    fn on_step_complete(
        &self,
        protocol: &ProtocolType,
        participants: &[ParticipantData],
        context: &mut ProgramContext,
    ) -> Result<(), BitVMXError> {
        let protocol_id = protocol.context().id;

        debug!("SignaturesStep: Step complete");

        // Optionally, collect all signatures for later use
        let mut all_signatures = Vec::new();

        for (idx, _) in participants.iter().enumerate() {
            let signatures_json = context
                .globals
                .get_var(&protocol_id, &format!("participant_{}_signatures", idx))?
                .ok_or_else(|| {
                    BitVMXError::InvalidMessage(format!(
                        "Missing signatures for participant {}",
                        idx
                    ))
                })?
                .string()?;

            let signatures: PartialSignatureMessage = serde_json::from_str(&signatures_json)?;
            all_signatures.push(signatures);
        }

        debug!(
            "SignaturesStep: Completed with {} participants",
            all_signatures.len()
        );
        Ok(())
    }

    fn exchange_config(&self) -> ExchangeConfig {
        ExchangeConfig {
            verify_signatures: true,
            timeout_ms: None,
            max_retries: 3,
        }
    }
}
