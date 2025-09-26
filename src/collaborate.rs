use std::collections::HashMap;

use bitcoin::PublicKey;
use bitvmx_broker::identification::identifier::Identifier;
use operator_comms::operator_comms::PubKeyHash;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::{
    comms_helper::{request, response, CommsMessageType},
    errors::BitVMXError,
    helper::parse_keys,
    program::participant::{CommsAddress, ParticipantKeys, PublicKeyType},
    types::{OutgoingBitVMXApiMessages, ProgramContext},
};

#[derive(Debug, Serialize, Deserialize)]
pub struct Collaboration {
    pub collaboration_id: Uuid,
    pub participants: Vec<CommsAddress>,
    pub leader: CommsAddress,
    pub im_leader: bool,
    pub keys: HashMap<PubKeyHash, PublicKey>,
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
        let im_leader = program_context.comms.get_pubk_hash()? == leader.pubkey_hash;
        let my_key = Self::get_or_create_my_key(program_context, peers.clone(), public_keys)?;
        let keys = vec![(
            program_context.comms.get_pubk_hash()?,
            ParticipantKeys::new(vec![(id.to_string(), my_key.clone().into())], vec![]),
        )];
        if !im_leader {
            request(
                &program_context.comms,
                id,
                leader.clone(),
                crate::comms_helper::CommsMessageType::Keys,
                keys,
            )?;
        }
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
            debug!("Send keys to peers");
            //collect all the keys from the participants in a vec (pubkey_hash, key)
            let all_keys: Vec<(PubKeyHash, PublicKeyType)> = self
                .keys
                .clone()
                .into_iter()
                .map(|(p, k)| (p, k.into()))
                .collect::<Vec<_>>();

            let pubk_hash = program_context.comms.get_pubk_hash()?;
            let keys = vec![(pubk_hash, ParticipantKeys::new(all_keys, vec![]))];
            for peer in &self.participants {
                if peer.pubkey_hash == self.leader.pubkey_hash {
                    continue;
                }
                //TODO: Serialize the rest of the keys so the other peers can use them
                //use the peerid as key
                debug!(
                    "Collaboration id: {}: Sending keys to peer: {}",
                    self.collaboration_id, peer.pubkey_hash
                );
                request(
                    &program_context.comms,
                    &self.collaboration_id,
                    peer.clone(),
                    CommsMessageType::Keys,
                    keys.clone(),
                )?;
            }
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
    ) -> Result<(), BitVMXError> {
        let pubkey_hash = comms_address.pubkey_hash.clone();
        match msg_type {
            CommsMessageType::Keys => {
                if self.im_leader {
                    let keys: ParticipantKeys = parse_keys(data)
                        .map_err(|_| BitVMXError::InvalidMessageFormat)?
                        .first()
                        .unwrap()
                        .1
                        .clone();
                    let key = keys.get_public(&self.collaboration_id.to_string())?;
                    self.keys.insert(pubkey_hash.clone(), *key);
                    debug!("Got keys {:?}", self.keys);

                    if self.keys.len() == self.participants.len() {
                        let aggregated = program_context.key_chain.new_musig2_session(
                            self.keys.values().cloned().collect(),
                            self.my_key.clone(),
                        )?;
                        self.aggregated_key = Some(aggregated.clone());

                        self.state = true;
                    }
                } else {
                    let keys: ParticipantKeys = parse_keys(data)
                        .map_err(|_| BitVMXError::InvalidMessageFormat)?
                        .first()
                        .unwrap()
                        .1
                        .clone();

                    keys.mapping.iter().for_each(|(pubkey_hash, key)| {
                        let pubkey_hash: PubKeyHash = pubkey_hash
                            .parse()
                            .unwrap_or(self.leader.pubkey_hash.clone()); //TODO: Handle the unwrap better
                        if let Some(key) = key.public() {
                            self.keys.insert(pubkey_hash, *key);
                        } else {
                            warn!("Key not found for peer: {}", pubkey_hash);
                        }
                    });

                    let aggregated = program_context.key_chain.new_musig2_session(
                        self.keys.values().cloned().collect(),
                        self.my_key.clone(),
                    )?;
                    self.aggregated_key = Some(aggregated.clone());
                    self.completed = true;
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
}
