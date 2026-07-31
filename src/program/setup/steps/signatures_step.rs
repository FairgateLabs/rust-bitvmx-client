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
use key_manager::musig2::{types::MessageId, PartialSignature};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use tracing::{debug, info, warn};

pub type PartialSignatureMessage = Vec<(
    bitcoin::PublicKey,
    bitcoin::PublicKey,
    Vec<(MessageId, PartialSignature)>,
)>;

/// Template step for exchanging MuSig2 partial signatures.
///
/// This step manages the signature generation and exchange process by:
/// 1. Retrieving the participant's keys from the previous KeysStep
/// 2. Generating MuSig2 partial signatures for each aggregated key via the key manager
/// 3. Serializing and exchanging signatures with other participants
/// 4. Verifying and storing received signatures from all participants
///
/// Participant signatures are stored in globals as "participant_{i}_signatures".
#[derive(Debug, Clone, Default)]
pub struct SignaturesStep;

impl SignaturesStep {
    pub fn new() -> Self {
        Self
    }

    fn validate_received_signatures(
        signatures: &PartialSignatureMessage,
        expected_aggregated_keys: &HashSet<PublicKey>,
    ) -> Result<(), BitVMXError> {
        if signatures.is_empty() {
            return Err(BitVMXError::InvalidMessage(
                "Received empty signatures from participant".to_string(),
            ));
        }

        let mut received_aggregated_keys = HashSet::new();

        for (aggregated, _, message_signatures) in signatures {
            if !expected_aggregated_keys.contains(aggregated) {
                return Err(BitVMXError::InvalidMessage(format!(
                    "Received signatures for unexpected aggregated key {}",
                    aggregated
                )));
            }
            if !received_aggregated_keys.insert(*aggregated) {
                return Err(BitVMXError::InvalidMessage(format!(
                    "Received duplicate signatures for aggregated key {}",
                    aggregated
                )));
            }
            if message_signatures.is_empty() {
                return Err(BitVMXError::InvalidMessage(format!(
                    "Received no message signatures for aggregated key {}",
                    aggregated
                )));
            }

            let mut message_ids = HashSet::new();
            if message_signatures
                .iter()
                .any(|(message_id, _)| !message_ids.insert(message_id))
            {
                return Err(BitVMXError::InvalidMessage(format!(
                    "Received duplicate signature message IDs for aggregated key {}",
                    aggregated
                )));
            }
        }

        Ok(())
    }
}

impl SetupStep for SignaturesStep {
    fn step_name(&self) -> &str {
        "signatures"
    }

    fn generate_data<BC: BitcoinCoordinatorApi>(
        &self,
        protocol: &mut ProtocolType,
        context: &mut ProgramContext<BC>,
    ) -> Result<Option<(serde_json::Value, CommsMessageType)>, BitVMXError> {
        let protocol_id = protocol.context().id;

        debug!(
            "SignaturesStep: Generating partial signatures for protocol {}",
            protocol_id
        );

        // Get the participant's keys from the previous KeysStep
        let my_keys = super::load_my_keys(
            &protocol_id,
            context,
            "Keys must be exchanged before signatures (KeysStep must complete first)",
        )?;

        if my_keys.computed_aggregated.is_empty() {
            return Err(BitVMXError::InvalidMessage(
                "No aggregated keys found in my_keys. KeysStep must complete and compute aggregated keys before SignaturesStep can proceed.".to_string(),
            ));
        }

        debug!(
            "SignaturesStep: Generating signatures for {} aggregated keys",
            my_keys.computed_aggregated.len()
        );

        // Generate partial signatures for each aggregated key using the key_manager
        let mut partial_sig_msg: PartialSignatureMessage = Vec::new();

        for aggregated in my_keys.computed_aggregated.values() {
            let signatures = context
                .key_manager
                .get_my_partial_signatures(aggregated, &protocol.context().protocol_name);

            if signatures.is_err() {
                warn!(
                    "SignaturesStep: Failed to generate signatures for aggregated key {}: {}",
                    aggregated,
                    signatures.as_ref().err().unwrap()
                );
                continue; // Skip this aggregated key and continue with others
            }

            let my_pub = context.key_manager.get_my_public_key(aggregated)?;

            debug!(
                "SignaturesStep: Generated partial signatures for aggregated key: {}",
                aggregated
            );

            partial_sig_msg.push((*aggregated, my_pub, signatures.unwrap()));
        }

        if partial_sig_msg.is_empty() {
            return Err(BitVMXError::InvalidMessage(
                "Failed to generate signatures for any aggregated key".to_string(),
            ));
        }

        // Serialize to send
        let serialized = serde_json::to_value(&partial_sig_msg)?;
        debug!("SignaturesStep: Serialized");

        Ok(Some((serialized, CommsMessageType::PartialSignatures)))
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
        if !matches!(msg_type, CommsMessageType::PartialSignatures) {
            info!(
                "Received message with type {msg_type:?} in SignaturesStep, ignoring. Expected type: PartialSignatures"
            );
            return Ok(false);
        }
        let protocol_id = protocol.context().id;

        debug!(
            "SignaturesStep: Verifying partial signatures from participant {}",
            from_participant.pubkey_hash
        );

        // Deserialize the received signatures
        let signatures: PartialSignatureMessage = serde_json::from_value(data).map_err(|e| {
            BitVMXError::InvalidMessage(format!("Failed to deserialize signatures: {}", e))
        })?;

        if signatures.is_empty() {
            return Err(BitVMXError::InvalidMessage(
                "Received empty signatures from participant".to_string(),
            ));
        }

        let my_keys = super::load_my_keys(
            &protocol_id,
            context,
            "Keys must be exchanged before signatures can be verified",
        )?;
        let expected_aggregated_keys = my_keys
            .computed_aggregated
            .values()
            .copied()
            .collect::<HashSet<_>>();
        Self::validate_received_signatures(&signatures, &expected_aggregated_keys)?;

        debug!(
            "SignaturesStep: Received {} partial signatures",
            signatures.len()
        );

        // Find participant index
        let idx = get_index_by_pubkey_hash(participants, &from_participant.pubkey_hash)?;

        // Save to globals with the convention "participant_{idx}_signatures"
        self.store_participant_data(
            &context.globals,
            &protocol_id,
            idx,
            &serde_json::to_string(&signatures)?,
        )?;

        debug!(
            "SignaturesStep: Stored signatures from participant {} at index {}",
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

        // Verify that all participants have sent their signatures
        for (idx, participant) in participants.iter().enumerate() {
            if !self.has_participant_data(&context.globals, &protocol_id, idx)? {
                debug!(
                    "SignaturesStep: Still waiting for signatures from participant {} (index {})",
                    participant.pubkey_hash, idx
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

    fn on_step_complete<BC: BitcoinCoordinatorApi>(
        &self,
        protocol: &ProtocolType,
        participants: &[CommsAddress],
        context: &mut ProgramContext<BC>,
    ) -> Result<(), BitVMXError> {
        let protocol_id = protocol.context().id;
        let my_idx = protocol.context().my_idx;

        debug!("SignaturesStep: Step complete, adding all participant signatures to key_manager");

        // Build map_of_maps: HashMap<PublicKey, HashMap<PublicKey, Vec<(MessageId, PartialSignature)>>>
        // First PublicKey is aggregated key, second is participant's public key
        let mut map_of_maps: HashMap<
            PublicKey,
            HashMap<PublicKey, Vec<(MessageId, PartialSignature)>>,
        > = HashMap::new();

        // Collect signatures from all participants (except ourselves)
        for (idx, _) in participants.iter().enumerate() {
            if idx == my_idx {
                continue; // Skip our own signatures
            }

            let signatures_json = self.get_participant_data(&context.globals, &protocol_id, idx)?;

            let participant_signatures: PartialSignatureMessage =
                serde_json::from_str(&signatures_json)?;

            // PartialSignatureMessage is Vec<(PublicKey, PublicKey, Vec<(MessageId, PartialSignature)>)>
            // where first PublicKey is aggregated key, second is participant's public key
            for (aggregated, participant_pub_key, signatures) in participant_signatures {
                if map_of_maps
                    .entry(aggregated)
                    .or_default()
                    .insert(participant_pub_key, signatures)
                    .is_some()
                {
                    return Err(BitVMXError::InvalidMessage(format!(
                        "Received duplicate signatures from participant key {}",
                        participant_pub_key
                    )));
                }
            }
        }

        // Add all signatures to key_manager for each aggregated key
        for (aggregated, partial_map) in map_of_maps {
            context.key_manager.save_partial_signatures_multi(
                &aggregated,
                &protocol.context().protocol_name,
                partial_map,
            )?;
            debug!(
                "SignaturesStep: Added signatures to key_manager for aggregated key {}",
                aggregated
            );
        }

        debug!(
            "SignaturesStep: Completed with {} participants, all signatures added to key_manager",
            participants.len()
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::{
        participant::ParticipantKeys, protocols::protocol_handler::new_protocol_type,
        variables::VariableTypes,
    };
    use crate::test_utils::{TestProgramContextEnv, TestStorageDir};
    use crate::types::PROGRAM_TYPE_AGGREGATED_KEY;
    use key_manager::{key_type::BitcoinKeyType, musig2::musig::MuSig2SignerApi};
    use uuid::Uuid;

    fn store_aggregated_key<BC: BitcoinCoordinatorApi>(
        context: &ProgramContext<BC>,
        id: Uuid,
        aggregated: PublicKey,
    ) {
        let mut keys = ParticipantKeys::new(vec![], vec![]).unwrap();
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
    fn generation_requires_completed_keys() {
        let mut env = TestProgramContextEnv::new("signatures-step-generation-errors").unwrap();
        let dir = TestStorageDir::new("signatures-step-generation-errors-protocol");
        let id = Uuid::new_v4();
        let mut protocol =
            new_protocol_type(id, PROGRAM_TYPE_AGGREGATED_KEY, 0, dir.storage()).unwrap();
        let step = SignaturesStep::new();

        assert_eq!(step.step_name(), "signatures");

        let err = step
            .generate_data(&mut protocol, &mut env.context)
            .unwrap_err();
        assert!(
            matches!(err, BitVMXError::InvalidMessage(message) if message.contains("Keys must be exchanged"))
        );

        let empty_keys = ParticipantKeys::new(vec![], vec![]).unwrap();
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
        let aggregate = env
            .context
            .key_manager
            .new_musig2_session(vec![my_key, other_key], my_key)
            .unwrap();
        store_aggregated_key(&env.context, id, aggregate);
        let err = step
            .generate_data(&mut protocol, &mut env.context)
            .unwrap_err();
        assert!(
            matches!(err, BitVMXError::InvalidMessage(message) if message.contains("Failed to generate signatures for any aggregated key"))
        );
    }

    #[test]
    fn exchanges_partial_signatures_and_produces_a_valid_final_signature() {
        let mut first = TestProgramContextEnv::new("signatures-step-first").unwrap();
        let mut second = TestProgramContextEnv::new("signatures-step-second").unwrap();
        let first_dir = TestStorageDir::new("signatures-step-first-protocol");
        let second_dir = TestStorageDir::new("signatures-step-second-protocol");
        let id = Uuid::new_v4();
        let mut first_protocol =
            new_protocol_type(id, PROGRAM_TYPE_AGGREGATED_KEY, 0, first_dir.storage()).unwrap();
        let mut second_protocol =
            new_protocol_type(id, PROGRAM_TYPE_AGGREGATED_KEY, 1, second_dir.storage()).unwrap();
        assert_eq!(
            first_protocol.context().protocol_name,
            second_protocol.context().protocol_name
        );
        let session_id = first_protocol.context().protocol_name.clone();
        let step = SignaturesStep::new();

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

        let message_id = "setup-transaction";
        let message = b"transaction digest covered by both participants".to_vec();
        for context in [&first.context, &second.context] {
            context
                .key_manager
                .generate_nonce(
                    message_id,
                    message.clone(),
                    &first_aggregate,
                    &session_id,
                    None,
                )
                .unwrap();
            store_aggregated_key(context, id, first_aggregate);
        }

        let first_nonces = first
            .context
            .key_manager
            .get_my_pub_nonces(&first_aggregate, &session_id)
            .unwrap();
        let second_nonces = second
            .context
            .key_manager
            .get_my_pub_nonces(&first_aggregate, &session_id)
            .unwrap();
        first
            .context
            .key_manager
            .aggregate_nonces(
                &first_aggregate,
                &session_id,
                HashMap::from([(second_key, second_nonces)]),
            )
            .unwrap();
        second
            .context
            .key_manager
            .aggregate_nonces(
                &first_aggregate,
                &session_id,
                HashMap::from([(first_key, first_nonces)]),
            )
            .unwrap();

        let (first_data, first_type) = step
            .generate_data(&mut first_protocol, &mut first.context)
            .unwrap()
            .unwrap();
        let (second_data, second_type) = step
            .generate_data(&mut second_protocol, &mut second.context)
            .unwrap()
            .unwrap();
        assert_eq!(first_type, CommsMessageType::PartialSignatures);
        assert_eq!(second_type, CommsMessageType::PartialSignatures);

        let first_signatures: PartialSignatureMessage =
            serde_json::from_value(first_data.clone()).unwrap();
        let second_signatures: PartialSignatureMessage =
            serde_json::from_value(second_data.clone()).unwrap();
        assert_eq!(first_signatures.len(), 1);
        assert_eq!(first_signatures[0].0, first_aggregate);
        assert_eq!(first_signatures[0].1, first_key);
        assert_eq!(first_signatures[0].2.len(), 1);
        assert_eq!(first_signatures[0].2[0].0, message_id);
        assert_eq!(second_signatures[0].1, second_key);

        let first_address = first.self_address().unwrap();
        let mut second_address = second.self_address().unwrap();
        second_address.pubkey_hash = "second-participant".to_string();
        let participants = vec![first_address.clone(), second_address.clone()];

        assert!(!step
            .can_advance(&first_protocol, &participants, &first.context)
            .unwrap());
        assert!(step
            .verify_received(
                first_data.clone(),
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
                second_data.clone(),
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

        let stored_second: PartialSignatureMessage = serde_json::from_str(
            &step
                .get_participant_data(&first.context.globals, &id, 1)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            serde_json::to_value(stored_second).unwrap(),
            serde_json::to_value(&second_signatures).unwrap()
        );

        step.on_step_complete(&first_protocol, &participants, &mut first.context)
            .unwrap();
        let final_signature = first
            .context
            .key_manager
            .musig2()
            .get_aggregated_signature(&first_aggregate, &session_id, message_id)
            .unwrap();
        assert!(first
            .context
            .key_manager
            .musig2()
            .verify_final_signature(message_id, final_signature, first_aggregate, &session_id)
            .unwrap());

        // A participant key may contribute only once. Reusing the second
        // participant's otherwise-valid payload under another index is rejected.
        step.store_participant_data(
            &first.context.globals,
            &id,
            2,
            &serde_json::to_string(&second_signatures).unwrap(),
        )
        .unwrap();
        let mut third_address = second_address.clone();
        third_address.pubkey_hash = "third-participant".to_string();
        let err = step
            .on_step_complete(
                &first_protocol,
                &[first_address, second_address, third_address],
                &mut first.context,
            )
            .unwrap_err();
        assert!(
            matches!(err, BitVMXError::InvalidMessage(message) if message.contains("duplicate signatures"))
        );
    }

    #[test]
    fn validates_signature_payload_structure() {
        let first = TestProgramContextEnv::new("signatures-validation-first").unwrap();
        let second = TestProgramContextEnv::new("signatures-validation-second").unwrap();
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
        let aggregated = first
            .context
            .key_manager
            .new_musig2_session(vec![first_key, second_key], first_key)
            .unwrap();
        let session_id = "signature-validation";
        first
            .context
            .key_manager
            .generate_nonce(
                "message",
                b"message".to_vec(),
                &aggregated,
                session_id,
                None,
            )
            .unwrap();
        let own_nonces = first
            .context
            .key_manager
            .get_my_pub_nonces(&aggregated, session_id)
            .unwrap();
        first
            .context
            .key_manager
            .aggregate_nonces(
                &aggregated,
                session_id,
                HashMap::from([(second_key, own_nonces)]),
            )
            .unwrap();
        let valid = vec![(
            aggregated,
            first_key,
            first
                .context
                .key_manager
                .get_my_partial_signatures(&aggregated, session_id)
                .unwrap(),
        )];
        let expected = HashSet::from([aggregated]);
        assert!(SignaturesStep::validate_received_signatures(&valid, &expected).is_ok());

        let error_message = |payload: &PartialSignatureMessage| {
            SignaturesStep::validate_received_signatures(payload, &expected)
                .unwrap_err()
                .to_string()
        };
        assert!(error_message(&vec![]).contains("empty signatures"));

        let unexpected_key = first
            .context
            .key_manager
            .next_keypair(BitcoinKeyType::P2tr)
            .unwrap();
        let mut unexpected = valid.clone();
        unexpected[0].0 = unexpected_key;
        assert!(error_message(&unexpected).contains("unexpected aggregated key"));

        let duplicate_aggregate = vec![valid[0].clone(), valid[0].clone()];
        assert!(error_message(&duplicate_aggregate).contains("duplicate signatures"));

        let mut no_messages = valid.clone();
        no_messages[0].2.clear();
        assert!(error_message(&no_messages).contains("no message signatures"));

        let mut duplicate_message = valid;
        let repeated_signature = duplicate_message[0].2[0].clone();
        duplicate_message[0].2.push(repeated_signature);
        assert!(error_message(&duplicate_message).contains("duplicate signature message IDs"));
    }

    #[test]
    fn rejects_invalid_received_signatures_and_missing_completion_data() {
        let mut env = TestProgramContextEnv::new("signatures-step-validation").unwrap();
        let dir = TestStorageDir::new("signatures-step-validation-protocol");
        let id = Uuid::new_v4();
        let protocol =
            new_protocol_type(id, PROGRAM_TYPE_AGGREGATED_KEY, 0, dir.storage()).unwrap();
        let participant = env.self_address().unwrap();
        let participants = vec![participant.clone(), participant.clone()];
        let step = SignaturesStep::new();

        assert!(!step
            .verify_received(
                Value::Null,
                CommsMessageType::PublicNonces,
                &participant,
                &protocol,
                &participants,
                &mut env.context,
                false,
            )
            .unwrap());

        let err = step
            .verify_received(
                serde_json::json!({"not": "signatures"}),
                CommsMessageType::PartialSignatures,
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
                serde_json::to_value(PartialSignatureMessage::new()).unwrap(),
                CommsMessageType::PartialSignatures,
                &participant,
                &protocol,
                &participants,
                &mut env.context,
                false,
            )
            .unwrap_err();
        assert!(
            matches!(err, BitVMXError::InvalidMessage(message) if message.contains("empty signatures"))
        );

        assert!(!step
            .can_advance(&protocol, &participants, &env.context)
            .unwrap());

        let err = step
            .on_step_complete(&protocol, &participants, &mut env.context)
            .unwrap_err();
        assert!(
            matches!(err, BitVMXError::InvalidMessage(message) if message.contains("participant 1"))
        );
    }
}
