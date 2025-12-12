use std::collections::HashMap;

use bitcoin::PublicKey;
use bitvmx_broker::identification::identifier::Identifier;
use bitvmx_operator_comms::operator_comms::PubKeyHash;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{debug, error, info};
use uuid::Uuid;

use crate::{
    comms_helper::{request, response, CommsMessageType},
    errors::BitVMXError,
    helper::parse_keys,
    leader_broadcast::LeaderBroadcastHelper,
    program::participant::{CommsAddress, ParticipantKeys},
    signature_verifier::OperatorVerificationStore,
    types::{OutgoingBitVMXApiMessages, ProgramContext},
};

#[derive(Debug, Serialize, Deserialize)]
pub struct Collaboration {
    pub collaboration_id: Uuid,
    pub participants: Vec<CommsAddress>,
    pub leader: CommsAddress,
    pub im_leader: bool,
    pub keys: HashMap<PubKeyHash, PublicKey>,
    pub key_signatures: HashMap<PubKeyHash, Vec<u8>>, // Store RSA signatures for each key
    pub my_key: PublicKey,
    pub aggregated_key: Option<PublicKey>,
    pub request_from: Identifier,
    pub state: bool,
    pub completed: bool,
}

impl Collaboration {
    pub fn new(
        collaboration_id: &Uuid,
        participants: Vec<CommsAddress>,
        leader: CommsAddress,
        im_leader: bool,
        my_key: PublicKey,
        request_from: Identifier,
    ) -> Self {
        Self {
            collaboration_id: collaboration_id.clone(),
            participants,
            leader,
            im_leader,
            keys: HashMap::new(),
            key_signatures: HashMap::new(),
            my_key,
            aggregated_key: None,
            request_from,
            state: false,
            completed: false,
        }
    }

    pub fn setup_aggregated_key(
        id: &Uuid,
        peers: Vec<CommsAddress>,
        public_keys: Option<Vec<PublicKey>>,
        leader: CommsAddress,
        program_context: &mut ProgramContext,
        request_from: Identifier,
    ) -> Result<Self, BitVMXError> {
        let my_pubkey_hash = program_context.comms.get_pubk_hash()?;

        let im_leader = my_pubkey_hash == leader.pubkey_hash;
        let my_key = Self::get_or_create_my_key(program_context, peers.clone(), public_keys)?;
        let mut participant_keys =
            ParticipantKeys::new(vec![(id.to_string(), my_key.clone().into())], vec![]);

        // Sign the key with RSA signature for MITM protection
        let signature = program_context
            .key_chain
            .sign_rsa_message(my_key.to_string().as_bytes())?;
        participant_keys.add_signature(&id.to_string(), signature);

        let keys = vec![(my_pubkey_hash.clone(), participant_keys)];

        OperatorVerificationStore::store(
            &program_context.globals,
            &my_pubkey_hash,
            &program_context.key_chain.get_rsa_public_key()?,
        )?;

        OperatorVerificationStore::request_missing_verification_keys(
            &program_context.globals,
            &program_context.comms,
            &program_context.key_chain,
            id,
            &peers,
        )?;

        request(
            &program_context.comms,
            &program_context.key_chain,
            id,
            leader.clone(),
            crate::comms_helper::CommsMessageType::Keys,
            keys,
        )?;

        let mut collaboration =
            Collaboration::new(id, peers, leader, im_leader, my_key, request_from);
        if im_leader {
            collaboration
                .keys
                .insert(program_context.comms.get_pubk_hash()?, my_key);
        }
        Ok(collaboration)
    }

    pub fn tick(
        &mut self,
        program_context: &ProgramContext,
        leader_broadcast_helper: &LeaderBroadcastHelper,
    ) -> Result<bool, BitVMXError> {
        if self.state && self.im_leader {
            info!("Broadcastiing keys to peers");

            let my_pubkey_hash = program_context.comms.get_pubk_hash()?;
            let participants: Vec<_> = self
                .participants
                .iter()
                .filter(|p| p.pubkey_hash != my_pubkey_hash)
                .map(|p| p.clone())
                .collect();

            leader_broadcast_helper.broadcast_to_non_leaders(
                program_context,
                &self.collaboration_id,
                CommsMessageType::Keys,
                &participants,
            )?;

            self.state = false;
            self.completed = true;
        }
        Ok(self.completed)
    }

    pub fn process_comms_message(
        &mut self,
        comms_address: CommsAddress, //TODO: validate positions
        msg_type: CommsMessageType,
        data: Value,
        program_context: &ProgramContext,
        _timestamp: i64,
        _signature: Vec<u8>,
        _version: String,
    ) -> Result<(), BitVMXError> {
        let pubkey_hash = comms_address.pubkey_hash.clone();
        match msg_type {
            CommsMessageType::Keys => {
                // Message signature verification already done in BitVMX::process_msg
                // Only process the keys and verify individual key signatures (MITM protection)

                let keys: ParticipantKeys = parse_keys(data.clone())
                    .map_err(|_| BitVMXError::InvalidMessageFormat)?
                    .first()
                    .unwrap()
                    .1
                    .clone();

                let verification_key =
                    OperatorVerificationStore::get(&program_context.globals, &pubkey_hash)?
                        .ok_or_else(|| {
                            error!("Missing verification key for participant: {}", pubkey_hash);
                            BitVMXError::InvalidMessageFormat
                        })?;
                let key = keys.get_public(&self.collaboration_id.to_string())?;

                // Simplified MITM protection: just store the signature for redistribution
                if let Some(signature) = keys.get_signature(&self.collaboration_id.to_string()) {
                    let verified = program_context.key_chain.verify_rsa_signature(
                        &verification_key,
                        key.to_string().as_bytes(),
                        &signature,
                    )?;
                    info!(
                        "Received RSA signature from participant: {} ({})",
                        pubkey_hash, verified
                    );
                    // Store the signature for redistribution to other participants
                    self.add_key_signature(pubkey_hash.clone(), signature.clone());
                } else {
                    error!("Missing RSA signature for participant: {}", pubkey_hash);
                    return Err(BitVMXError::InvalidMessageFormat);
                }

                // Store the key and its signature
                self.keys.insert(pubkey_hash.clone(), *key);

                if self.keys.len() == self.participants.len() {
                    info!("Generating aggregated key...");
                    let aggregated = program_context.key_chain.new_musig2_session(
                        self.keys.values().cloned().collect(),
                        self.my_key.clone(),
                    )?;
                    self.aggregated_key = Some(aggregated.clone());
                    self.state = true;
                }

                if self.aggregated_key.is_some() {
                    info!("Aggregated generated ({})", self.im_leader);
                    program_context.broker_channel.send(
                        &self.request_from,
                        OutgoingBitVMXApiMessages::AggregatedPubkey(
                            self.collaboration_id,
                            self.aggregated_key.unwrap().clone(),
                        )
                        .to_string()?,
                    )?;
                }

                response(
                    &program_context.comms,
                    &program_context.key_chain,
                    &self.collaboration_id,
                    comms_address,
                    CommsMessageType::KeysAck,
                    (),
                )?;
            }
            CommsMessageType::KeysAck => {
                debug!(
                    "Collaboration id: {}: KeysAck received by {}",
                    self.collaboration_id, pubkey_hash
                );
            }
            CommsMessageType::VerificationKey | CommsMessageType::VerificationKeyRequest => {
                debug!(
                    "Collaboration id: {}: Verification key message handled upstream ({:?})",
                    self.collaboration_id, msg_type
                );
            }
            CommsMessageType::Broadcasted => {
                // Broadcasted messages are handled in BitVMX::process_msg, not here
                // This should not be reached, but we handle it gracefully
                debug!(
                    "Collaboration id: {}: Broadcasted message should be handled upstream in BitVMX::process_msg",
                    self.collaboration_id
                );
            }
            _ => {
                return Err(BitVMXError::InvalidMessageType);
            }
        }
        Ok(())
    }

    fn get_or_create_my_key(
        program_context: &mut ProgramContext,
        peers: Vec<CommsAddress>,
        public_keys: Option<Vec<PublicKey>>,
    ) -> Result<PublicKey, BitVMXError> {
        let my_key = if public_keys.is_some() {
            // find my position in the peers list
            let my_pubkey_hash = program_context.comms.get_pubk_hash()?;
            let my_position = peers
                .iter()
                .position(|p| p.pubkey_hash == my_pubkey_hash)
                .ok_or(BitVMXError::InvalidParticipant(my_pubkey_hash.to_string()))?;

            public_keys
                .unwrap()
                .get(my_position)
                .cloned()
                .ok_or(BitVMXError::InvalidParticipant(my_pubkey_hash.to_string()))?
        } else {
            program_context.key_chain.derive_keypair()?
        };

        Ok(my_key)
    }

    pub fn get_address_from_pubkey_hash(
        &self,
        pubkey_hash: &PubKeyHash,
    ) -> Result<CommsAddress, BitVMXError> {
        for participant in &self.participants {
            if &participant.pubkey_hash == pubkey_hash {
                return Ok(participant.clone());
            }
        }
        Err(BitVMXError::InvalidParticipant(pubkey_hash.to_string()))
    }

    pub fn get_key_signature(&self, pubkey_hash: &PubKeyHash) -> Option<&Vec<u8>> {
        self.key_signatures.get(pubkey_hash)
    }

    pub fn add_key_signature(&mut self, pubkey_hash: PubKeyHash, signature: Vec<u8>) {
        self.key_signatures.insert(pubkey_hash, signature);
    }
}
