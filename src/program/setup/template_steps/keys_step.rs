use crate::{
    errors::BitVMXError,
    program::{
        participant::{ParticipantData, ParticipantKeys},
        protocols::protocol_handler::{ProtocolHandler, ProtocolType},
        setup::{ExchangeConfig, SetupStep},
        variables::VariableTypes,
    },
    types::ProgramContext,
};
use tracing::debug;

/// Template step for exchanging public keys in MuSig2 protocols.
///
/// This step orchestrates the key generation and exchange process by:
/// 1. Calling the protocol's `generate_keys()` method to create protocol-specific keys
/// 2. Serializing and exchanging the keys with other participants
/// 3. Verifying and storing received keys from all participants
/// 4. Aggregating all keys when the step completes
///
/// The generated keys are stored in globals with the following conventions:
/// - Own keys: "my_keys"
/// - Participant i keys: "participant_{i}_keys"
/// - All keys aggregated: "all_participant_keys"
pub struct KeysStep;

impl KeysStep {
    pub fn new() -> Self {
        Self
    }
}

impl SetupStep for KeysStep {
    fn step_name(&self) -> &str {
        "keys"
    }

    fn generate_data(
        &self,
        protocol: &mut ProtocolType,
        context: &mut ProgramContext,
    ) -> Result<Option<Vec<u8>>, BitVMXError> {
        let protocol_id = protocol.context().id;

        debug!("KeysStep: Generating keys for protocol {}", protocol_id);

        // Call the protocol to generate its specific keys
        let keys = protocol.generate_keys(context)?;

        // Validate that keys were generated
        if keys.mapping.is_empty() && keys.aggregated.is_empty() {
            return Err(BitVMXError::InvalidMessage(
                "Protocol generated empty keys".to_string(),
            ));
        }

        debug!(
            "KeysStep: Generated {} individual keys and {} aggregated keys",
            keys.mapping.len(),
            keys.aggregated.len()
        );

        // Save to globals with the convention "my_keys"
        context.globals.set_var(
            &protocol_id,
            "my_keys",
            VariableTypes::String(serde_json::to_string(&keys)?),
        )?;

        // Serialize to send to other participants
        let serialized = serde_json::to_vec(&keys)?;
        debug!("KeysStep: Serialized {} bytes to send", serialized.len());

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
            "KeysStep: Verifying keys from participant {}",
            from_participant.comms_address.pubkey_hash
        );

        // Deserialize the received keys
        let keys: ParticipantKeys = serde_json::from_slice(data).map_err(|e| {
            BitVMXError::InvalidMessage(format!("Failed to deserialize keys: {}", e))
        })?;

        // Basic validation
        if keys.mapping.is_empty() && keys.aggregated.is_empty() {
            return Err(BitVMXError::InvalidMessage(
                "Received empty keys from participant".to_string(),
            ));
        }

        debug!(
            "KeysStep: Received {} individual keys and {} aggregated keys",
            keys.mapping.len(),
            keys.aggregated.len()
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

        // Save to globals with the convention "participant_{idx}_keys"
        context.globals.set_var(
            &protocol_id,
            &format!("participant_{}_keys", idx),
            VariableTypes::String(serde_json::to_string(&keys)?),
        )?;

        debug!(
            "KeysStep: Stored keys from participant {} at index {}",
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

        // Verify that all participants have sent their keys
        for (idx, participant) in participants.iter().enumerate() {
            if context
                .globals
                .get_var(&protocol_id, &format!("participant_{}_keys", idx))?
                .is_none()
            {
                debug!(
                    "KeysStep: Still waiting for keys from participant {} (index {})",
                    participant.comms_address.pubkey_hash, idx
                );
                return Ok(false);
            }
        }

        debug!(
            "KeysStep: All {} participants have sent their keys",
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

        debug!("KeysStep: Step complete, aggregating all participant keys");

        // Collect all participant keys
        let mut all_keys = Vec::new();

        for (idx, _) in participants.iter().enumerate() {
            let keys_json = context
                .globals
                .get_var(&protocol_id, &format!("participant_{}_keys", idx))?
                .ok_or_else(|| {
                    BitVMXError::InvalidMessage(format!("Missing keys for participant {}", idx))
                })?
                .string()?;

            let keys: ParticipantKeys = serde_json::from_str(&keys_json)?;
            all_keys.push(keys);
        }

        // Save the complete collection for later use
        context.globals.set_var(
            &protocol_id,
            "all_participant_keys",
            VariableTypes::String(serde_json::to_string(&all_keys)?),
        )?;

        debug!("KeysStep: Completed with {} participants", all_keys.len());
        Ok(())
    }

    fn exchange_config(&self) -> ExchangeConfig {
        ExchangeConfig {
            use_broadcasting: true,
            verify_signatures: true,
            timeout_ms: None,
            max_retries: 3,
        }
    }
}

impl Default for KeysStep {
    fn default() -> Self {
        Self::new()
    }
}
