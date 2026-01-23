use crate::{
    errors::BitVMXError,
    helper::PubNonceMessage,
    program::{
        participant::{ParticipantData, ParticipantKeys},
        protocols::protocol_handler::{ProtocolHandler, ProtocolType},
        setup::{ExchangeConfig, SetupStep},
        variables::VariableTypes,
    },
    types::ProgramContext,
};
use tracing::{debug, warn};

/// Template step for exchanging MuSig2 public nonces.
///
/// This step manages the nonce generation and exchange process by:
/// 1. Retrieving the participant's keys from the previous KeysStep
/// 2. Generating MuSig2 nonces for each aggregated key via the KeyChain
/// 3. Serializing and exchanging nonces with other participants
/// 4. Verifying and storing received nonces from all participants
///
/// The nonces are stored in globals with the following conventions:
/// - Own nonces: "my_nonces"
/// - Participant i nonces: "participant_{i}_nonces"
pub struct NoncesStep;

impl NoncesStep {
    pub fn new() -> Self {
        Self
    }
}

impl SetupStep for NoncesStep {
    fn step_name(&self) -> &str {
        "nonces"
    }

    fn generate_data(
        &self,
        protocol: &mut ProtocolType,
        context: &mut ProgramContext,
    ) -> Result<Option<Vec<u8>>, BitVMXError> {
        let protocol_id = protocol.context().id;

        debug!("NoncesStep: Generating nonces for protocol {}", protocol_id);

        // Get the participant's keys from the previous KeysStep
        let my_keys_json = context
            .globals
            .get_var(&protocol_id, "my_keys")?
            .ok_or_else(|| {
                BitVMXError::InvalidMessage(
                    "Keys must be exchanged before nonces (KeysStep must complete first)"
                        .to_string(),
                )
            })?
            .string()?;

        let my_keys: ParticipantKeys = serde_json::from_str(&my_keys_json)?;

        if my_keys.computed_aggregated.is_empty() {
            debug!("NoncesStep: No aggregated keys found, skipping nonce generation");
            return Ok(Some(Vec::new()));
        }

        debug!(
            "NoncesStep: Generating nonces for {} aggregated keys",
            my_keys.computed_aggregated.len()
        );

        // Generate nonces for each aggregated key using the KeyChain
        let mut public_nonce_msg: PubNonceMessage = Vec::new();

        for aggregated in my_keys.computed_aggregated.values() {
            let nonces = context
                .key_chain
                .get_nonces(aggregated, &protocol.context().protocol_name);

            if let Err(e) = nonces {
                warn!(
                    "NoncesStep: Error getting nonces for aggregated key {}: {}",
                    aggregated, e
                );
                continue;
            }

            let my_pub = context
                .key_chain
                .key_manager
                .get_my_public_key(aggregated)?;

            debug!(
                "NoncesStep: Generated nonces for aggregated key: {}",
                aggregated
            );

            public_nonce_msg.push((aggregated.clone(), my_pub, nonces.unwrap()));
        }

        if public_nonce_msg.is_empty() {
            return Err(BitVMXError::InvalidMessage(
                "Failed to generate nonces for any aggregated key".to_string(),
            ));
        }

        // Save to globals
        context.globals.set_var(
            &protocol_id,
            "my_nonces",
            VariableTypes::String(serde_json::to_string(&public_nonce_msg)?),
        )?;

        // Serialize to send
        let serialized = serde_json::to_vec(&public_nonce_msg)?;
        debug!("NoncesStep: Serialized {} bytes to send", serialized.len());

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
            "NoncesStep: Verifying nonces from participant {}",
            from_participant.comms_address.pubkey_hash
        );

        // Deserialize the received nonces
        let nonces: PubNonceMessage = serde_json::from_slice(data).map_err(|e| {
            BitVMXError::InvalidMessage(format!("Failed to deserialize nonces: {}", e))
        })?;

        // Basic validation
        if nonces.is_empty() {
            return Err(BitVMXError::InvalidMessage(
                "Received empty nonces from participant".to_string(),
            ));
        }

        debug!("NoncesStep: Received {} nonces", nonces.len());

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

        // Save to globals with the convention "participant_{idx}_nonces"
        context.globals.set_var(
            &protocol_id,
            &format!("participant_{}_nonces", idx),
            VariableTypes::String(serde_json::to_string(&nonces)?),
        )?;

        debug!(
            "NoncesStep: Stored nonces from participant {} at index {}",
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

        // Verify that all participants have sent their nonces
        for (idx, participant) in participants.iter().enumerate() {
            if context
                .globals
                .get_var(&protocol_id, &format!("participant_{}_nonces", idx))?
                .is_none()
            {
                debug!(
                    "NoncesStep: Still waiting for nonces from participant {} (index {})",
                    participant.comms_address.pubkey_hash, idx
                );
                return Ok(false);
            }
        }

        debug!(
            "NoncesStep: All {} participants have sent their nonces",
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

        debug!("NoncesStep: Step complete");

        // Optionally, collect all nonces for later use
        let mut all_nonces = Vec::new();

        for (idx, _) in participants.iter().enumerate() {
            let nonces_json = context
                .globals
                .get_var(&protocol_id, &format!("participant_{}_nonces", idx))?
                .ok_or_else(|| {
                    BitVMXError::InvalidMessage(format!("Missing nonces for participant {}", idx))
                })?
                .string()?;

            let nonces: PubNonceMessage = serde_json::from_str(&nonces_json)?;
            all_nonces.push(nonces);
        }

        debug!(
            "NoncesStep: Completed with {} participants",
            all_nonces.len()
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

impl Default for NoncesStep {
    fn default() -> Self {
        Self::new()
    }
}
