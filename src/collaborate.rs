use std::collections::HashMap;

use bitcoin::PublicKey;
use bitvmx_broker::identification::identifier::{Identifier, PubkHash};
use key_manager::key_type::BitcoinKeyType;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{debug, info};
use uuid::Uuid;

use crate::{
    comms_helper::{response, CommsMessageType},
    errors::BitVMXError,
    helper::parse_keys,
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
    pub keys: HashMap<PubkHash, PublicKey>,
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
        let participant_keys =
            ParticipantKeys::new(vec![(id.to_string(), my_key.clone().into())], vec![]);

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

        program_context.leader_broadcast_helper.request_or_store(
            &program_context.comms,
            &program_context.key_chain,
            id,
            leader.clone(),
            crate::comms_helper::CommsMessageType::Keys,
            keys,
            im_leader,
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

    pub fn tick(&mut self, program_context: &ProgramContext) -> Result<bool, BitVMXError> {
        if self.state && self.im_leader {
            info!("Broadcastiing keys to peers");

            let my_pubkey_hash = program_context.comms.get_pubk_hash()?;
            let participants: Vec<_> = self
                .participants
                .iter()
                .filter(|p| p.pubkey_hash != my_pubkey_hash)
                .map(|p| p.clone())
                .collect();

            program_context
                .leader_broadcast_helper
                .broadcast_to_non_leaders(
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
                let keys: ParticipantKeys = parse_keys(data.clone())
                    .map_err(|_| BitVMXError::InvalidMessage("Invalid keys".to_string()))?
                    .first()
                    .ok_or_else(|| BitVMXError::InvalidMessage("Invalid keys".to_string()))?
                    .1
                    .clone();

                let key = keys.get_public(&self.collaboration_id.to_string())?;

                // Store the key
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

                if let Some(aggregated_key) = &self.aggregated_key {
                    info!("Aggregated generated ({})", self.im_leader);
                    program_context.broker_channel.send(
                        &self.request_from,
                        OutgoingBitVMXApiMessages::AggregatedPubkey(
                            self.collaboration_id,
                            aggregated_key.clone(),
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
        let my_key = if let Some(public_keys) = &public_keys {
            // find my position in the peers list
            let my_pubkey_hash = program_context.comms.get_pubk_hash()?;
            let my_position = peers
                .iter()
                .position(|p| p.pubkey_hash == my_pubkey_hash)
                .ok_or(BitVMXError::InvalidParticipant(my_pubkey_hash.to_string()))?;

            public_keys
                .get(my_position)
                .cloned()
                .ok_or(BitVMXError::InvalidParticipant(my_pubkey_hash.to_string()))?
        } else {
            program_context
                .key_chain
                .derive_keypair(BitcoinKeyType::P2tr)?
        };

        Ok(my_key)
    }

    pub fn get_address_from_pubkey_hash(
        &self,
        pubkey_hash: &PubkHash,
    ) -> Result<CommsAddress, BitVMXError> {
        for participant in &self.participants {
            if &participant.pubkey_hash == pubkey_hash {
                return Ok(participant.clone());
            }
        }
        Err(BitVMXError::InvalidParticipant(pubkey_hash.to_string()))
    }
}
