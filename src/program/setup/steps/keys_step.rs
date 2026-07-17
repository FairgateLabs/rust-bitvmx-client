use crate::ports::bitcoin_coordinator::BitcoinCoordinatorApi;
use crate::{
    comms_helper::CommsMessageType,
    errors::BitVMXError,
    program::{
        participant::{get_index_by_pubkey_hash, CommsAddress, ParticipantKeys},
        protocols::protocol_handler::{ProtocolHandler, ProtocolType},
        setup::SetupStep,
        variables::VariableTypes,
    },
    types::ProgramContext,
};
use serde_json::Value;
use tracing::{debug, info};

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
#[derive(Debug, Clone, Default)]
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

    fn generate_data<BC: BitcoinCoordinatorApi>(
        &self,
        protocol: &mut ProtocolType,
        context: &mut ProgramContext<BC>,
    ) -> Result<Option<(serde_json::Value, CommsMessageType)>, BitVMXError> {
        let protocol_id = protocol.context().id;

        debug!("KeysStep: Generating keys for protocol {}", protocol_id);

        // Call the protocol to generate its specific keys
        let mut keys = protocol.generate_keys(context)?;

        // Validate that keys were generated
        if keys.mapping.is_empty() && keys.aggregated.is_empty() {
            info!("KeysStep: Protocol did not generate any keys, using empty defaults");
            keys = ParticipantKeys::new(vec![], vec![]);
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
        let serialized = serde_json::to_value(&keys)?;
        debug!("KeysStep: Serialized");

        Ok(Some((serialized, CommsMessageType::Keys)))
    }

    fn verify_received<BC: BitcoinCoordinatorApi>(
        &self,
        data: Value,
        msg_type: CommsMessageType,
        from_participant: &CommsAddress,
        protocol: &ProtocolType,
        participants: &[CommsAddress],
        context: &mut ProgramContext<BC>,
        _your_data: bool,
    ) -> Result<bool, BitVMXError> {
        if !matches!(msg_type, CommsMessageType::Keys) {
            info!(
                "Received message with type {msg_type:?} in KeysStep, ignoring. Expected type: Keys"
            );
            return Ok(false);
        }
        let protocol_id = protocol.context().id;

        debug!(
            "KeysStep: Verifying keys from participant {}",
            from_participant.pubkey_hash
        );

        // Deserialize the received keys
        let keys: ParticipantKeys = serde_json::from_value(data.clone()).map_err(|e| {
            BitVMXError::InvalidMessage(format!("Failed to deserialize keys: {}", e))
        })?;

        debug!(
            "KeysStep: Received {} individual keys and {} aggregated keys",
            keys.mapping.len(),
            keys.aggregated.len()
        );

        // Find participant index
        let idx = get_index_by_pubkey_hash(participants, &from_participant.pubkey_hash)?;

        // Save to globals with the convention "participant_{idx}_keys"
        context.globals.set_var(
            &protocol_id,
            &format!("participant_{}_keys", idx),
            VariableTypes::String(serde_json::to_string(&keys)?),
        )?;

        debug!(
            "KeysStep: Stored keys from participant {} at index {}",
            from_participant.pubkey_hash, idx
        );

        Ok(true)
    }

    fn can_advance<BC: BitcoinCoordinatorApi>(
        &self,
        protocol: &ProtocolType,
        participants: &[CommsAddress],
        context: &ProgramContext<BC>,
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
                    participant.pubkey_hash, idx
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

    fn on_step_complete<BC: BitcoinCoordinatorApi>(
        &self,
        protocol: &ProtocolType,
        participants: &[CommsAddress],
        context: &mut ProgramContext<BC>,
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

            aggregated_pub_keys.sort();

            // The local key must be one of the exchanged participant keys. In
            // particular, the single-participant shortcut below bypasses the
            // key manager's MuSig2 validation, so validate membership here.
            if !aggregated_pub_keys.contains(my_key) {
                return Err(BitVMXError::InvalidMessage(format!(
                    "My key '{}' is not present in the participant keys",
                    agg_name
                )));
            }

            // Compute the aggregated key using MuSig2
            // MuSig2 requires at least 2 participants; with a single participant,
            // the aggregated key is simply that participant's own public key.
            let aggregated_key = if aggregated_pub_keys.len() == 1 {
                debug!("KeysStep: Single participant, using own key directly");
                *my_key
            } else {
                context
                    .key_manager
                    .new_musig2_session(aggregated_pub_keys, *my_key)?
            };

            computed_aggregated.insert(agg_name.clone(), aggregated_key);

            debug!(
                "KeysStep: Computed aggregated key '{}': {}",
                agg_name, aggregated_key
            );
        }

        for (name, key) in protocol.get_pregenerated_aggregated_keys(context)? {
            computed_aggregated.insert(name, key);
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

        protocol.build(all_keys, my_keys.computed_aggregated, context)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::PublicKey;
    use key_manager::key_type::BitcoinKeyType;
    use std::rc::Rc;
    use storage_backend::storage::Storage;
    use uuid::Uuid;

    use crate::program::protocols::protocol_handler::new_protocol_type;
    use crate::test_utils::{TestProgramContextEnv, TestStorageDir};
    use crate::types::{PROGRAM_TYPE_AGGREGATED_KEY, PROGRAM_TYPE_GC_GENERATION};

    fn protocol(name: &str, id: Uuid, storage: Rc<Storage>) -> ProtocolType {
        new_protocol_type(id, name, 0, storage).unwrap()
    }

    fn set_optional_generated_key<BC: BitcoinCoordinatorApi>(
        id: &Uuid,
        context: &ProgramContext<BC>,
    ) {
        context
            .globals
            .set_var(
                id,
                "optional_keys",
                VariableTypes::String(
                    serde_json::to_string(&Option::<Vec<PublicKey>>::None).unwrap(),
                ),
            )
            .unwrap();
    }

    fn stored_keys<BC: BitcoinCoordinatorApi>(
        id: &Uuid,
        name: &str,
        context: &ProgramContext<BC>,
    ) -> ParticipantKeys {
        serde_json::from_str(
            &context
                .globals
                .get_var(id, name)
                .unwrap()
                .unwrap()
                .string()
                .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn generates_verifies_and_completes_single_participant_keys() {
        let mut env = TestProgramContextEnv::new("keys-step-lifecycle").unwrap();
        let dir = TestStorageDir::new("keys-step-protocol");
        let id = Uuid::new_v4();
        let mut protocol = protocol(PROGRAM_TYPE_AGGREGATED_KEY, id, dir.storage());
        let participant = env.self_address().unwrap();
        let participants = vec![participant.clone()];
        let step = KeysStep::new();
        set_optional_generated_key(&id, &env.context);

        assert_eq!(step.step_name(), "keys");
        let (data, msg_type) = step
            .generate_data(&mut protocol, &mut env.context)
            .unwrap()
            .unwrap();
        assert_eq!(msg_type, CommsMessageType::Keys);
        let generated: ParticipantKeys = serde_json::from_value(data.clone()).unwrap();
        assert_eq!(generated.mapping.len(), 1);
        assert_eq!(generated.aggregated, vec![id.to_string()]);
        assert_eq!(stored_keys(&id, "my_keys", &env.context), generated);

        assert!(!step
            .can_advance(&protocol, &participants, &env.context)
            .unwrap());
        assert!(step
            .verify_received(
                data,
                msg_type,
                &participant,
                &protocol,
                &participants,
                &mut env.context,
                true,
            )
            .unwrap());
        assert!(step
            .can_advance(&protocol, &participants, &env.context)
            .unwrap());

        step.on_step_complete(&protocol, &participants, &mut env.context)
            .unwrap();

        let all_keys: Vec<ParticipantKeys> = serde_json::from_str(
            &env.context
                .globals
                .get_var(&id, "all_participant_keys")
                .unwrap()
                .unwrap()
                .string()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(all_keys, vec![generated.clone()]);

        let completed = stored_keys(&id, "my_keys", &env.context);
        let aggregate = completed.computed_aggregated[&id.to_string()];
        assert_eq!(aggregate, *generated.get_public(&id.to_string()).unwrap());
        assert_eq!(
            env.context
                .globals
                .get_var(&id, "final_aggregated_key")
                .unwrap()
                .unwrap()
                .pubkey()
                .unwrap(),
            aggregate
        );
    }

    #[test]
    fn handles_empty_generation_and_rejects_invalid_received_data() {
        let mut env = TestProgramContextEnv::new("keys-step-validation").unwrap();
        let dir = TestStorageDir::new("keys-step-validation-protocol");
        let step = KeysStep::new();
        let storage = dir.storage();

        let empty_id = Uuid::new_v4();
        let mut empty_protocol = protocol(PROGRAM_TYPE_GC_GENERATION, empty_id, storage.clone());
        let (empty_data, empty_type) = step
            .generate_data(&mut empty_protocol, &mut env.context)
            .unwrap()
            .unwrap();
        assert_eq!(empty_type, CommsMessageType::Keys);
        assert_eq!(
            serde_json::from_value::<ParticipantKeys>(empty_data).unwrap(),
            ParticipantKeys::new(vec![], vec![])
        );

        let id = Uuid::new_v4();
        let protocol = protocol(PROGRAM_TYPE_AGGREGATED_KEY, id, storage);
        let participant = env.self_address().unwrap();
        let participants = vec![participant.clone()];
        let valid = serde_json::to_value(ParticipantKeys::new(vec![], vec![])).unwrap();

        assert!(!step
            .verify_received(
                valid.clone(),
                CommsMessageType::PublicNonces,
                &participant,
                &protocol,
                &participants,
                &mut env.context,
                false,
            )
            .unwrap());
        assert!(env
            .context
            .globals
            .get_var(&id, "participant_0_keys")
            .unwrap()
            .is_none());

        let err = step
            .verify_received(
                serde_json::json!({"not": "participant keys"}),
                CommsMessageType::Keys,
                &participant,
                &protocol,
                &participants,
                &mut env.context,
                false,
            )
            .unwrap_err();
        assert!(matches!(err, BitVMXError::InvalidMessage(_)));

        let mut outsider = participant.clone();
        outsider.pubkey_hash = "unknown-participant".to_string();
        assert!(step
            .verify_received(
                valid,
                CommsMessageType::Keys,
                &outsider,
                &protocol,
                &participants,
                &mut env.context,
                false,
            )
            .is_err());
    }

    #[test]
    fn completion_rejects_missing_or_inconsistent_keys() {
        let mut env = TestProgramContextEnv::new("keys-step-completion-errors").unwrap();
        let dir = TestStorageDir::new("keys-step-completion-errors-protocol");
        let step = KeysStep::new();
        let storage = dir.storage();
        let participant = env.self_address().unwrap();
        let participants = vec![participant];

        let missing_id = Uuid::new_v4();
        let missing_protocol = protocol(PROGRAM_TYPE_AGGREGATED_KEY, missing_id, storage.clone());
        let err = step
            .on_step_complete(&missing_protocol, &participants, &mut env.context)
            .unwrap_err();
        assert!(
            matches!(err, BitVMXError::InvalidMessage(message) if message.contains("Missing keys"))
        );

        let id = Uuid::new_v4();
        let protocol = protocol(PROGRAM_TYPE_AGGREGATED_KEY, id, storage);
        let name = id.to_string();
        let my_key = env
            .context
            .key_manager
            .next_keypair(BitcoinKeyType::P2tr)
            .unwrap();
        let other_key = env
            .context
            .key_manager
            .next_keypair(BitcoinKeyType::P2tr)
            .unwrap();
        let my_keys = ParticipantKeys::new(vec![(name.clone(), my_key.into())], vec![name.clone()]);
        let participant_keys =
            ParticipantKeys::new(vec![(name.clone(), other_key.into())], vec![name.clone()]);
        env.context
            .globals
            .set_var(
                &id,
                "my_keys",
                VariableTypes::String(serde_json::to_string(&my_keys).unwrap()),
            )
            .unwrap();
        env.context
            .globals
            .set_var(
                &id,
                "participant_0_keys",
                VariableTypes::String(serde_json::to_string(&participant_keys).unwrap()),
            )
            .unwrap();

        let err = step
            .on_step_complete(&protocol, &participants, &mut env.context)
            .unwrap_err();
        assert!(
            matches!(err, BitVMXError::InvalidMessage(message) if message.contains("not present"))
        );
    }
}
