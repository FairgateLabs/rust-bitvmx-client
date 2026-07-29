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
    use uuid::Uuid;

    #[test]
    fn generation_requires_completed_keys() {
        let mut env = TestProgramContextEnv::new("signatures-step-generation-errors").unwrap();
        let dir = TestStorageDir::new("signatures-step-generation-errors-protocol");
        let id = Uuid::new_v4();
        let mut protocol =
            new_protocol_type(id, PROGRAM_TYPE_AGGREGATED_KEY, 0, dir.storage()).unwrap();
        let step = SignaturesStep::new();

        let err = step
            .generate_data(&mut protocol, &mut env.context)
            .unwrap_err();
        assert!(
            matches!(err, BitVMXError::InvalidMessage(message) if message.contains("Keys must be exchanged"))
        );

        let empty_keys = ParticipantKeys::new(vec![], vec![]);
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
