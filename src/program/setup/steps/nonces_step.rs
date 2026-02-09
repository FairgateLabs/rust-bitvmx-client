use crate::{
    errors::BitVMXError,
    helper::PubNonceMessage,
    program::{
        participant::{ParticipantData, ParticipantKeys},
        protocols::protocol_handler::{ProtocolHandler, ProtocolType},
        setup::SetupStep,
        variables::VariableTypes,
    },
    types::ProgramContext,
};
use bitcoin::PublicKey;
use key_manager::musig2::{types::MessageId, PubNonce};
use std::collections::HashMap;
use tracing::debug;

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
#[derive(Debug, Clone, Default)]
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
            return Err(BitVMXError::InvalidMessage(
                "No aggregated keys found in my_keys. KeysStep must complete and compute aggregated keys before NoncesStep can proceed.".to_string(),
            ));
        }

        debug!(
            "NoncesStep: Generating nonces for {} aggregated keys",
            my_keys.computed_aggregated.len()
        );

        // Generate nonces for each aggregated key using the KeyChain
        let mut public_nonce_msg: PubNonceMessage = Vec::new();

        for aggregated in my_keys.computed_aggregated.values() {
            let nonces = match context
                .key_chain
                .get_nonces(aggregated, &protocol.context().protocol_name)
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

            let my_pub = context
                .key_chain
                .key_manager
                .get_my_public_key(aggregated)?;

            debug!(
                "NoncesStep: Got nonces for aggregated key: {}",
                aggregated
            );

            public_nonce_msg.push((aggregated.clone(), my_pub, nonces));
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
        context: &ProgramContext,
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
        let my_idx = protocol.context().my_idx;

        debug!("NoncesStep: Step complete, adding all participant nonces to key_manager");

        // Build map_of_maps: HashMap<PublicKey, HashMap<PublicKey, Vec<(MessageId, PubNonce)>>>
        // First PublicKey is aggregated key, second is participant's public key
        let mut map_of_maps: HashMap<
            PublicKey,
            HashMap<PublicKey, Vec<(MessageId, PubNonce)>>,
        > = HashMap::new();

        // Collect nonces from all participants (except ourselves)
        for (idx, _) in participants.iter().enumerate() {
            if idx == my_idx {
                continue; // Skip our own nonces
            }

            let nonces_json = context
                .globals
                .get_var(&protocol_id, &format!("participant_{}_nonces", idx))?
                .ok_or_else(|| {
                    BitVMXError::InvalidMessage(format!("Missing nonces for participant {}", idx))
                })?
                .string()?;

            let participant_nonces: PubNonceMessage = serde_json::from_str(&nonces_json)?;

            // PubNonceMessage is Vec<(PublicKey, PublicKey, Vec<(MessageId, PubNonce)>)>
            // where first PublicKey is aggregated key, second is participant's public key
            for (aggregated, participant_pub_key, nonces) in participant_nonces {
                map_of_maps
                    .entry(aggregated)
                    .or_insert_with(HashMap::new)
                    .insert(participant_pub_key, nonces);
            }
        }

        // Add all nonces to key_manager for each aggregated key
        for (aggregated, pubkey_nonce_map) in map_of_maps {
            context.key_chain.add_nonces(
                &aggregated,
                pubkey_nonce_map,
                &protocol.context().protocol_name,
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
