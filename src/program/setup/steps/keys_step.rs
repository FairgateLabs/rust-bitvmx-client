use crate::{
    errors::BitVMXError,
    program::{
        participant::{ParticipantData, ParticipantKeys},
        protocols::protocol_handler::{ProtocolHandler, ProtocolType},
        setup::SetupStep,
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
#[derive(Default)]
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
        context: &ProgramContext,
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

        // Compute aggregated keys and update my_keys in globals
        // Get my_keys from globals
        let my_keys_json = context
            .globals
            .get_var(&protocol_id, "my_keys")?
            .ok_or_else(|| BitVMXError::InvalidMessage("my_keys not found in globals".to_string()))?
            .string()?;

        let mut my_keys: ParticipantKeys = serde_json::from_str(&my_keys_json)?;

        // Compute aggregated keys for each aggregated key name
        let mut computed_aggregated = std::collections::HashMap::new();

        for agg_name in &my_keys.aggregated {
            // Get my public key for this aggregated key
            let my_key = my_keys.get_public(agg_name).map_err(|_| {
                BitVMXError::InvalidMessage(format!(
                    "My key '{}' not found or not a PublicKey type",
                    agg_name
                ))
            })?;

            // Collect all public keys from all participants for this aggregated key
            let mut aggregated_pub_keys = Vec::new();
            for participant_keys in &all_keys {
                if let Some(key_type) = participant_keys.mapping.get(agg_name) {
                    if let Some(public_key) = key_type.public() {
                        aggregated_pub_keys.push(*public_key);
                    } else {
                        return Err(BitVMXError::InvalidMessage(format!(
                            "Participant key '{}' is not a PublicKey type",
                            agg_name
                        )));
                    }
                } else {
                    return Err(BitVMXError::InvalidMessage(format!(
                        "Participant missing key '{}' for aggregation",
                        agg_name
                    )));
                }
            }

            // Compute the aggregated key using MuSig2
            // MuSig2 requires at least 2 participants; with a single participant,
            // the aggregated key is simply that participant's own public key.
            let aggregated_key = if aggregated_pub_keys.len() == 1 {
                debug!("KeysStep: Single participant, using own key directly");
                *my_key
            } else {
                context
                    .key_chain
                    .new_musig2_session(aggregated_pub_keys, *my_key)?
            };

            computed_aggregated.insert(agg_name.clone(), aggregated_key);

            debug!(
                "KeysStep: Computed aggregated key '{}': {}",
                agg_name, aggregated_key
            );
        }

        // Update my_keys with computed_aggregated
        my_keys.computed_aggregated = computed_aggregated;

        // Save updated my_keys back to globals
        context.globals.set_var(
            &protocol_id,
            "my_keys",
            VariableTypes::String(serde_json::to_string(&my_keys)?),
        )?;

        debug!(
            "KeysStep: Completed with {} participants, computed {} aggregated keys",
            all_keys.len(),
            my_keys.computed_aggregated.len()
        );
        Ok(())
    }
}
