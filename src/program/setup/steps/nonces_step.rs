use crate::ports::bitcoin_coordinator::BitcoinCoordinatorApi;
use crate::{
    comms_helper::CommsMessageType,
    errors::BitVMXError,
    program::{
        participant::{get_index_by_pubkey_hash, CommsAddress},
        protocols::protocol_handler::{ProtocolHandler, ProtocolType},
        setup::SetupStep,
    },
    types::ProgramContext,
};
use bitcoin::PublicKey;
use key_manager::musig2::{types::MessageId, PubNonce};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use tracing::{debug, info};

pub type PubNonceMessage = Vec<(
    bitcoin::PublicKey,
    bitcoin::PublicKey,
    Vec<(MessageId, PubNonce)>,
)>;

/// Template step for exchanging MuSig2 public nonces.
///
/// This step manages the nonce generation and exchange process by:
/// 1. Retrieving the participant's keys from the previous KeysStep
/// 2. Generating MuSig2 nonces for each aggregated key via the key manager
/// 3. Serializing and exchanging nonces with other participants
/// 4. Verifying and storing received nonces from all participants
///
/// Participant nonces are stored in globals as "participant_{i}_nonces".
#[derive(Debug, Clone, Default)]
pub struct NoncesStep;

impl NoncesStep {
    pub fn new() -> Self {
        Self
    }

    fn validate_received_nonces(
        nonces: &PubNonceMessage,
        expected_aggregated_keys: &HashSet<PublicKey>,
    ) -> Result<(), BitVMXError> {
        if nonces.is_empty() {
            return Err(BitVMXError::InvalidMessage(
                "Received empty nonces from participant".to_string(),
            ));
        }

        let mut received_aggregated_keys = HashSet::new();

        for (aggregated, _, message_nonces) in nonces {
            if !expected_aggregated_keys.contains(aggregated) {
                return Err(BitVMXError::InvalidMessage(format!(
                    "Received nonces for unexpected aggregated key {}",
                    aggregated
                )));
            }
            if !received_aggregated_keys.insert(*aggregated) {
                return Err(BitVMXError::InvalidMessage(format!(
                    "Received duplicate nonces for aggregated key {}",
                    aggregated
                )));
            }
            if message_nonces.is_empty() {
                return Err(BitVMXError::InvalidMessage(format!(
                    "Received no message nonces for aggregated key {}",
                    aggregated
                )));
            }

            let mut message_ids = HashSet::new();
            if message_nonces
                .iter()
                .any(|(message_id, _)| !message_ids.insert(message_id))
            {
                return Err(BitVMXError::InvalidMessage(format!(
                    "Received duplicate nonce message IDs for aggregated key {}",
                    aggregated
                )));
            }
        }

        Ok(())
    }
}

impl SetupStep for NoncesStep {
    fn step_name(&self) -> &str {
        "nonces"
    }

    fn generate_data<BC: BitcoinCoordinatorApi>(
        &self,
        protocol: &mut ProtocolType,
        context: &mut ProgramContext<BC>,
    ) -> Result<Option<(serde_json::Value, CommsMessageType)>, BitVMXError> {
        let protocol_id = protocol.context().id;

        debug!("NoncesStep: Generating nonces for protocol {}", protocol_id);

        // Get the participant's keys from the previous KeysStep
        let my_keys = super::load_my_keys(
            &protocol_id,
            context,
            "Keys must be exchanged before nonces (KeysStep must complete first)",
        )?;

        if my_keys.computed_aggregated.is_empty() {
            return Err(BitVMXError::InvalidMessage(
                "No aggregated keys found in my_keys. KeysStep must complete and compute aggregated keys before NoncesStep can proceed.".to_string(),
            ));
        }

        debug!(
            "NoncesStep: Generating nonces for {} aggregated keys",
            my_keys.computed_aggregated.len()
        );

        // Generate nonces for each aggregated key using the key_manager
        let mut public_nonce_msg: PubNonceMessage = Vec::new();

        for aggregated in my_keys.computed_aggregated.values() {
            let nonces = match context
                .key_manager
                .get_my_pub_nonces(aggregated, &protocol.context().protocol_name)
            {
                Ok(n) => n,
                Err(_) => {
                    debug!(
                        "NoncesStep: No nonces for aggregated key {}, skipping",
                        aggregated
                    );
                    continue;
                }
            };

            let my_pub = context.key_manager.get_my_public_key(aggregated)?;

            debug!("NoncesStep: Got nonces for aggregated key: {}", aggregated);

            public_nonce_msg.push((aggregated.clone(), my_pub, nonces));
        }

        if public_nonce_msg.is_empty() {
            return Err(BitVMXError::InvalidMessage(
                "Failed to generate nonces for any aggregated key".to_string(),
            ));
        }

        // Serialize to send
        let serialized = serde_json::to_value(&public_nonce_msg)?;
        debug!("NoncesStep: Serialized");

        Ok(Some((serialized, CommsMessageType::PublicNonces)))
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
        if !matches!(msg_type, CommsMessageType::PublicNonces) {
            info!(
                "Received message with type {msg_type:?} in NoncesStep, ignoring. Expected type: PublicNonces"
            );
            return Ok(false);
        }
        let protocol_id = protocol.context().id;

        debug!(
            "NoncesStep: Verifying nonces from participant {}",
            from_participant.pubkey_hash
        );

        // Deserialize the received nonces
        let nonces: PubNonceMessage = serde_json::from_value(data).map_err(|e| {
            BitVMXError::InvalidMessage(format!("Failed to deserialize nonces: {}", e))
        })?;

        if nonces.is_empty() {
            return Err(BitVMXError::InvalidMessage(
                "Received empty nonces from participant".to_string(),
            ));
        }

        let my_keys = super::load_my_keys(
            &protocol_id,
            context,
            "Keys must be exchanged before nonces can be verified",
        )?;
        let expected_aggregated_keys = my_keys
            .computed_aggregated
            .values()
            .copied()
            .collect::<HashSet<_>>();
        Self::validate_received_nonces(&nonces, &expected_aggregated_keys)?;

        debug!("NoncesStep: Received {} nonces", nonces.len());

        // Find participant index
        let idx = get_index_by_pubkey_hash(participants, &from_participant.pubkey_hash)?;

        // Save to globals with the convention "participant_{idx}_nonces"
        self.store_participant_data(
            &context.globals,
            &protocol_id,
            idx,
            &serde_json::to_string(&nonces)?,
        )?;

        debug!(
            "NoncesStep: Stored nonces from participant {} at index {}",
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

        // Verify that all participants have sent their nonces
        for (idx, participant) in participants.iter().enumerate() {
            if !self.has_participant_data(&context.globals, &protocol_id, idx)? {
                debug!(
                    "NoncesStep: Still waiting for nonces from participant {} (index {})",
                    participant.pubkey_hash, idx
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

    fn on_step_complete<BC: BitcoinCoordinatorApi>(
        &self,
        protocol: &ProtocolType,
        participants: &[CommsAddress],
        context: &mut ProgramContext<BC>,
    ) -> Result<(), BitVMXError> {
        let protocol_id = protocol.context().id;
        let my_idx = protocol.context().my_idx;

        debug!("NoncesStep: Step complete, adding all participant nonces to key_manager");

        // Build map_of_maps: HashMap<PublicKey, HashMap<PublicKey, Vec<(MessageId, PubNonce)>>>
        // First PublicKey is aggregated key, second is participant's public key
        let mut map_of_maps: HashMap<PublicKey, HashMap<PublicKey, Vec<(MessageId, PubNonce)>>> =
            HashMap::new();

        // Collect nonces from all participants (except ourselves)
        for (idx, _) in participants.iter().enumerate() {
            if idx == my_idx {
                continue; // Skip our own nonces
            }

            let nonces_json = self.get_participant_data(&context.globals, &protocol_id, idx)?;

            let participant_nonces: PubNonceMessage = serde_json::from_str(&nonces_json)?;

            // PubNonceMessage is Vec<(PublicKey, PublicKey, Vec<(MessageId, PubNonce)>)>
            // where first PublicKey is aggregated key, second is participant's public key
            for (aggregated, participant_pub_key, nonces) in participant_nonces {
                if map_of_maps
                    .entry(aggregated)
                    .or_default()
                    .insert(participant_pub_key, nonces)
                    .is_some()
                {
                    return Err(BitVMXError::InvalidMessage(format!(
                        "Received duplicate nonces from participant key {}",
                        participant_pub_key
                    )));
                }
            }
        }

        // Add all nonces to key_manager for each aggregated key
        for (aggregated, pubkey_nonce_map) in map_of_maps {
            context.key_manager.aggregate_nonces(
                &aggregated,
                &protocol.context().protocol_name,
                pubkey_nonce_map,
            )?;
            debug!(
                "NoncesStep: Added nonces to key_manager for aggregated key {}",
                aggregated
            );
        }

        debug!(
            "NoncesStep: Completed with {} participants, all nonces added to key_manager",
            participants.len()
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::{participant::ParticipantKeys, variables::VariableTypes};
    use key_manager::key_type::BitcoinKeyType;
    use std::rc::Rc;
    use storage_backend::storage::Storage;
    use uuid::Uuid;

    use crate::program::protocols::protocol_handler::new_protocol_type;
    use crate::test_utils::{TestProgramContextEnv, TestStorageDir};
    use crate::types::PROGRAM_TYPE_AGGREGATED_KEY;

    fn protocol(id: Uuid, my_idx: usize, storage: Rc<Storage>) -> ProtocolType {
        new_protocol_type(id, PROGRAM_TYPE_AGGREGATED_KEY, my_idx, storage).unwrap()
    }

    fn store_aggregated_key<BC: BitcoinCoordinatorApi>(
        context: &ProgramContext<BC>,
        id: Uuid,
        aggregated: PublicKey,
    ) {
        let mut keys = ParticipantKeys::empty().unwrap();
        keys.computed_aggregated
            .insert("test-aggregate".to_string(), aggregated);
        context
            .globals
            .set_var(
                &id,
                "my_keys",
                VariableTypes::String(serde_json::to_string(&keys).unwrap()),
            )
            .unwrap();
    }

    #[test]
    fn generation_requires_completed_keys_and_available_nonces() {
        let mut env = TestProgramContextEnv::new("nonces-step-generation-errors").unwrap();
        let dir = TestStorageDir::new("nonces-step-generation-errors-protocol");
        let id = Uuid::new_v4();
        let mut protocol = protocol(id, 0, dir.storage());
        let step = NoncesStep::new();

        assert_eq!(step.step_name(), "nonces");

        let err = step
            .generate_data(&mut protocol, &mut env.context)
            .unwrap_err();
        assert!(
            matches!(err, BitVMXError::InvalidMessage(message) if message.contains("Keys must be exchanged"))
        );

        let empty_keys = ParticipantKeys::empty().unwrap();
        env.context
            .globals
            .set_var(
                &id,
                "my_keys",
                VariableTypes::String(serde_json::to_string(&empty_keys).unwrap()),
            )
            .unwrap();
        let err = step
            .generate_data(&mut protocol, &mut env.context)
            .unwrap_err();
        assert!(
            matches!(err, BitVMXError::InvalidMessage(message) if message.contains("No aggregated keys"))
        );

        let key_without_session = env
            .context
            .key_manager
            .next_keypair(BitcoinKeyType::P2tr)
            .unwrap();
        store_aggregated_key(&env.context, id, key_without_session);
        let err = step
            .generate_data(&mut protocol, &mut env.context)
            .unwrap_err();
        assert!(
            matches!(err, BitVMXError::InvalidMessage(message) if message.contains("Failed to generate nonces"))
        );
    }

    #[test]
    fn generates_verifies_and_completes_nonce_exchange() {
        let mut first = TestProgramContextEnv::new("nonces-step-first").unwrap();
        let mut second = TestProgramContextEnv::new("nonces-step-second").unwrap();
        let first_dir = TestStorageDir::new("nonces-step-first-protocol");
        let second_dir = TestStorageDir::new("nonces-step-second-protocol");
        let id = Uuid::new_v4();
        let mut first_protocol = protocol(id, 0, first_dir.storage());
        let mut second_protocol = protocol(id, 1, second_dir.storage());
        let step = NoncesStep::new();

        let first_key = first
            .context
            .key_manager
            .next_keypair(BitcoinKeyType::P2tr)
            .unwrap();
        let second_key = second
            .context
            .key_manager
            .next_keypair(BitcoinKeyType::P2tr)
            .unwrap();
        let participant_keys = vec![first_key, second_key];
        let first_aggregate = first
            .context
            .key_manager
            .new_musig2_session(participant_keys.clone(), first_key)
            .unwrap();
        let second_aggregate = second
            .context
            .key_manager
            .new_musig2_session(participant_keys, second_key)
            .unwrap();
        assert_eq!(first_aggregate, second_aggregate);

        for context in [&first.context, &second.context] {
            context
                .key_manager
                .generate_nonce(
                    "message-0",
                    b"message-0".to_vec(),
                    &first_aggregate,
                    &first_protocol.context().protocol_name,
                    None,
                )
                .unwrap();
            store_aggregated_key(context, id, first_aggregate);
        }

        let (first_data, first_type) = step
            .generate_data(&mut first_protocol, &mut first.context)
            .unwrap()
            .unwrap();
        let (second_data, second_type) = step
            .generate_data(&mut second_protocol, &mut second.context)
            .unwrap()
            .unwrap();
        assert_eq!(first_type, CommsMessageType::PublicNonces);
        assert_eq!(second_type, CommsMessageType::PublicNonces);
        assert!(
            !serde_json::from_value::<PubNonceMessage>(first_data.clone())
                .unwrap()
                .is_empty()
        );

        let first_address = first.self_address().unwrap();
        let mut second_address = second.self_address().unwrap();
        // TestProgramContextEnv instances use the same development comms key;
        // give the second logical participant a distinct lookup identity.
        second_address.pubkey_hash = "second-participant".to_string();
        let participants = vec![first_address.clone(), second_address.clone()];

        assert!(!step
            .verify_received(
                first_data.clone(),
                CommsMessageType::Keys,
                &first_address,
                &first_protocol,
                &participants,
                &mut first.context,
                true,
            )
            .unwrap());
        assert!(!step
            .can_advance(&first_protocol, &participants, &first.context)
            .unwrap());

        assert!(step
            .verify_received(
                first_data,
                first_type,
                &first_address,
                &first_protocol,
                &participants,
                &mut first.context,
                true,
            )
            .unwrap());
        assert!(!step
            .can_advance(&first_protocol, &participants, &first.context)
            .unwrap());

        let mut outsider = second_address.clone();
        outsider.pubkey_hash = "unknown-participant".to_string();
        assert!(step
            .verify_received(
                second_data.clone(),
                second_type.clone(),
                &outsider,
                &first_protocol,
                &participants,
                &mut first.context,
                false,
            )
            .is_err());

        assert!(step
            .verify_received(
                second_data,
                second_type,
                &second_address,
                &first_protocol,
                &participants,
                &mut first.context,
                false,
            )
            .unwrap());
        assert!(step
            .can_advance(&first_protocol, &participants, &first.context)
            .unwrap());
        step.on_step_complete(&first_protocol, &participants, &mut first.context)
            .unwrap();
    }

    #[test]
    fn rejects_malformed_or_empty_received_nonces_and_missing_completion_data() {
        let mut env = TestProgramContextEnv::new("nonces-step-validation").unwrap();
        let dir = TestStorageDir::new("nonces-step-validation-protocol");
        let id = Uuid::new_v4();
        let protocol = protocol(id, 0, dir.storage());
        let participant = env.self_address().unwrap();
        let participants = vec![participant.clone(), participant.clone()];
        let step = NoncesStep::new();

        let err = step
            .verify_received(
                serde_json::json!({"not": "nonces"}),
                CommsMessageType::PublicNonces,
                &participant,
                &protocol,
                &participants,
                &mut env.context,
                false,
            )
            .unwrap_err();
        assert!(
            matches!(err, BitVMXError::InvalidMessage(message) if message.contains("deserialize"))
        );

        let err = step
            .verify_received(
                serde_json::to_value(PubNonceMessage::new()).unwrap(),
                CommsMessageType::PublicNonces,
                &participant,
                &protocol,
                &participants,
                &mut env.context,
                false,
            )
            .unwrap_err();
        assert!(
            matches!(err, BitVMXError::InvalidMessage(message) if message.contains("empty nonces"))
        );

        let err = step
            .on_step_complete(&protocol, &participants, &mut env.context)
            .unwrap_err();
        assert!(
            matches!(err, BitVMXError::InvalidMessage(message) if message.contains("participant 1"))
        );
    }
}
