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
use std::collections::HashSet;
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
#[derive(Debug, Clone, Default)]
pub struct KeysStep;

impl KeysStep {
    pub fn new() -> Self {
        Self
    }

    fn collect_participant_keys<BC: BitcoinCoordinatorApi>(
        &self,
        protocol_id: &uuid::Uuid,
        participants: &[CommsAddress],
        context: &ProgramContext<BC>,
    ) -> Result<Vec<ParticipantKeys>, BitVMXError> {
        participants
            .iter()
            .enumerate()
            .map(|(idx, _)| {
                let keys_json = self.get_participant_data(&context.globals, protocol_id, idx)?;

                Ok(serde_json::from_str(&keys_json)?)
            })
            .collect()
    }

    fn compute_aggregated_keys<BC: BitcoinCoordinatorApi>(
        my_keys: &ParticipantKeys,
        all_keys: &[ParticipantKeys],
        context: &mut ProgramContext<BC>,
    ) -> Result<std::collections::HashMap<String, bitcoin::PublicKey>, BitVMXError> {
        let expected_aggregated_names = my_keys.aggregated.iter().collect::<HashSet<_>>();
        if expected_aggregated_names.len() != my_keys.aggregated.len() {
            return Err(BitVMXError::InvalidMessage(
                "My keys contain duplicate aggregated key names".to_string(),
            ));
        }

        for (idx, participant_keys) in all_keys.iter().enumerate() {
            let participant_aggregated_names =
                participant_keys.aggregated.iter().collect::<HashSet<_>>();
            if participant_aggregated_names != expected_aggregated_names {
                return Err(BitVMXError::InvalidMessage(format!(
                    "Participant {} has an inconsistent aggregated key set",
                    idx
                )));
            }
        }

        let mut computed_aggregated = std::collections::HashMap::new();

        for agg_name in &my_keys.aggregated {
            let my_key = *my_keys.get_public(agg_name).map_err(|_| {
                BitVMXError::InvalidMessage(format!(
                    "My key '{}' not found or not a PublicKey type",
                    agg_name
                ))
            })?;

            let mut aggregated_pub_keys = all_keys
                .iter()
                .map(|participant_keys| {
                    participant_keys
                        .mapping
                        .get(agg_name)
                        .ok_or_else(|| {
                            BitVMXError::InvalidMessage(format!(
                                "Participant missing key '{}' for aggregation",
                                agg_name
                            ))
                        })?
                        .public()
                        .copied()
                        .ok_or_else(|| {
                            BitVMXError::InvalidMessage(format!(
                                "Participant key '{}' is not a PublicKey type",
                                agg_name
                            ))
                        })
                })
                .collect::<Result<Vec<_>, _>>()?;

            aggregated_pub_keys.sort();

            // The single-participant shortcut bypasses the key manager's MuSig2
            // validation, so explicitly validate membership here.
            if !aggregated_pub_keys.contains(&my_key) {
                return Err(BitVMXError::InvalidMessage(format!(
                    "My key '{}' is not present in the participant keys",
                    agg_name
                )));
            }

            let aggregated_key = if aggregated_pub_keys.len() == 1 {
                debug!("KeysStep: Single participant, using own key directly");
                my_key
            } else {
                context
                    .key_manager
                    .new_musig2_session(aggregated_pub_keys, my_key)?
            };

            computed_aggregated.insert(agg_name.clone(), aggregated_key);
            debug!(
                "KeysStep: Computed aggregated key '{}': {}",
                agg_name, aggregated_key
            );
        }

        Ok(computed_aggregated)
    }

    fn store_my_keys<BC: BitcoinCoordinatorApi>(
        protocol_id: &uuid::Uuid,
        my_keys: &ParticipantKeys,
        context: &ProgramContext<BC>,
    ) -> Result<(), BitVMXError> {
        context.globals.set_var(
            protocol_id,
            "my_keys",
            VariableTypes::String(serde_json::to_string(my_keys)?),
        )
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
        let keys = protocol.generate_keys(context)?;

        // Validate that keys were generated
        if keys.mapping.is_empty() && keys.aggregated.is_empty() {
            info!("KeysStep: Protocol did not generate any keys, using empty defaults");
        }

        debug!(
            "KeysStep: Generated {} individual keys and {} aggregated keys",
            keys.mapping.len(),
            keys.aggregated.len()
        );

        // Save to globals with the convention "my_keys"
        Self::store_my_keys(&protocol_id, &keys, context)?;

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
        let keys: ParticipantKeys = serde_json::from_value(data).map_err(|e| {
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
        self.store_participant_data(
            &context.globals,
            &protocol_id,
            idx,
            &serde_json::to_string(&keys)?,
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
            if !self.has_participant_data(&context.globals, &protocol_id, idx)? {
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

        let all_keys = self.collect_participant_keys(&protocol_id, participants, context)?;
        let mut my_keys =
            super::load_my_keys(&protocol_id, context, "my_keys not found in globals")?;
        let mut computed_aggregated = Self::compute_aggregated_keys(&my_keys, &all_keys, context)?;

        computed_aggregated.extend(protocol.get_pregenerated_aggregated_keys(context)?);
        my_keys.computed_aggregated = computed_aggregated;
        Self::store_my_keys(&protocol_id, &my_keys, context)?;

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
            ParticipantKeys::empty().unwrap()
        );

        let id = Uuid::new_v4();
        let protocol = protocol(PROGRAM_TYPE_AGGREGATED_KEY, id, storage);
        let participant = env.self_address().unwrap();
        let participants = vec![participant.clone()];
        let valid = serde_json::to_value(ParticipantKeys::empty().unwrap()).unwrap();

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
        assert!(!step
            .has_participant_data(&env.context.globals, &id, 0)
            .unwrap());

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
    fn aggregation_rejects_malformed_key_sets() {
        let mut env = TestProgramContextEnv::new("keys-step-malformed-sets").unwrap();
        let name = "aggregate".to_string();
        let key = env
            .context
            .key_manager
            .next_keypair(BitcoinKeyType::P2tr)
            .unwrap();
        let valid =
            ParticipantKeys::new(vec![(name.clone(), key.into())], vec![name.clone()]).unwrap();

        let mut duplicate = valid.clone();
        duplicate.aggregated.push(name.clone());
        assert!(matches!(
            KeysStep::compute_aggregated_keys(&duplicate, &[valid.clone()], &mut env.context),
            Err(BitVMXError::InvalidMessage(message)) if message.contains("duplicate")
        ));

        let inconsistent = ParticipantKeys::empty().unwrap();
        assert!(matches!(
            KeysStep::compute_aggregated_keys(&valid, &[inconsistent], &mut env.context),
            Err(BitVMXError::InvalidMessage(message)) if message.contains("inconsistent")
        ));

        let missing_own_key = ParticipantKeys::new(vec![], vec![name.clone()]).unwrap();
        assert!(matches!(
            KeysStep::compute_aggregated_keys(
                &missing_own_key,
                &[missing_own_key.clone()],
                &mut env.context,
            ),
            Err(BitVMXError::InvalidMessage(message)) if message.contains("My key")
        ));

        let participant_missing_mapping = ParticipantKeys::new(vec![], vec![name]).unwrap();
        assert!(matches!(
            KeysStep::compute_aggregated_keys(
                &valid,
                &[participant_missing_mapping],
                &mut env.context,
            ),
            Err(BitVMXError::InvalidMessage(message)) if message.contains("missing key")
        ));
    }

    #[test]
    fn aggregation_uses_musig_for_multiple_participants() {
        let mut env = TestProgramContextEnv::new("keys-step-multisig").unwrap();
        let name = "aggregate".to_string();
        let first = env
            .context
            .key_manager
            .next_keypair(BitcoinKeyType::P2tr)
            .unwrap();
        let second = env
            .context
            .key_manager
            .next_keypair(BitcoinKeyType::P2tr)
            .unwrap();
        let my_keys =
            ParticipantKeys::new(vec![(name.clone(), first.into())], vec![name.clone()]).unwrap();
        let other_keys =
            ParticipantKeys::new(vec![(name.clone(), second.into())], vec![name.clone()]).unwrap();

        let computed = KeysStep::compute_aggregated_keys(
            &my_keys,
            &[my_keys.clone(), other_keys],
            &mut env.context,
        )
        .unwrap();
        assert!(computed.contains_key(&name));
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
        let my_keys =
            ParticipantKeys::new(vec![(name.clone(), my_key.into())], vec![name.clone()]).unwrap();
        let participant_keys =
            ParticipantKeys::new(vec![(name.clone(), other_key.into())], vec![name.clone()])
                .unwrap();
        env.context
            .globals
            .set_var(
                &id,
                "my_keys",
                VariableTypes::String(serde_json::to_string(&my_keys).unwrap()),
            )
            .unwrap();
        step.store_participant_data(
            &env.context.globals,
            &id,
            0,
            &serde_json::to_string(&participant_keys).unwrap(),
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
