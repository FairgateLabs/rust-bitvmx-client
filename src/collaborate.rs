use std::collections::HashMap;

use bitcoin::PublicKey;
use p2p_handler::PeerId;
use serde_json::Value;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::{
    errors::BitVMXError,
    helper::parse_keys,
    p2p_helper::{request, response, P2PMessageType},
    program::participant::{P2PAddress, ParticipantKeys, PublicKeyType},
    types::{OutgoingBitVMXApiMessages, ProgramContext},
};

pub struct Collaboration {
    pub collaboration_id: Uuid,
    pub participants: Vec<P2PAddress>,
    pub leader: P2PAddress,
    pub im_leader: bool,
    pub keys: HashMap<PeerId, PublicKey>,
    pub my_key: PublicKey,
    pub aggregated_key: Option<PublicKey>,
    pub request_from: u32,
    pub state: bool,
}

impl Collaboration {
    pub fn new(
        collaboration_id: &Uuid,
        participants: Vec<P2PAddress>,
        leader: P2PAddress,
        im_leader: bool,
        my_key: PublicKey,
        request_from: u32,
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
        }
    }

    pub fn setup_aggregated_signature(
        id: &Uuid,
        peers: Vec<P2PAddress>,
        leader: P2PAddress,
        program_context: &mut ProgramContext,
        request_from: u32,
    ) -> Result<Self, BitVMXError> {
        let im_leader = program_context.comms.get_peer_id() == leader.peer_id;
        let my_key = program_context.key_chain.derive_keypair()?;
        let keys = ParticipantKeys::new(vec![(id.to_string(), my_key.clone().into())]);
        if !im_leader {
            request(
                &program_context.comms,
                id,
                leader.clone(),
                crate::p2p_helper::P2PMessageType::Keys,
                keys,
            )?;
        }
        let mut collaboration =
            Collaboration::new(id, peers, leader, im_leader, my_key, request_from);
        if im_leader {
            collaboration
                .keys
                .insert(program_context.comms.get_peer_id(), my_key);
        }
        Ok(collaboration)
    }

    pub fn tick(&mut self, program_context: &ProgramContext) -> Result<(), BitVMXError> {
        if self.state {
            //collect all the keys from the participants in a vec (peeer_id,key)
            let all_keys: Vec<(String, PublicKeyType)> = self
                .keys
                .clone()
                .into_iter()
                .map(|(p, k)| (p.to_base58(), k.into()))
                .collect::<Vec<_>>();

            let keys = ParticipantKeys::new(all_keys);
            for peer in &self.participants {
                if peer.peer_id == self.leader.peer_id {
                    continue;
                }
                //TODO: Serialize the rest of the keys so the other peers can use them
                //use the peerid as key
                info!(
                    "Collaboration id: {}: Sending keys to peer: {}",
                    self.collaboration_id, peer.peer_id
                );
                request(
                    &program_context.comms,
                    &self.collaboration_id,
                    peer.clone(),
                    P2PMessageType::Keys,
                    keys.clone(),
                )?;
            }
            self.state = false;
        }
        Ok(())
    }

    pub fn process_p2p_message(
        &mut self,
        peer_id: PeerId, //TODO: validate positions
        msg_type: P2PMessageType,
        data: Value,
        program_context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        match msg_type {
            P2PMessageType::Keys => {
                if self.im_leader {
                    let keys: ParticipantKeys =
                        parse_keys(data).map_err(|_| BitVMXError::InvalidMessageFormat)?;
                    let key = keys.get_public(&self.collaboration_id.to_string())?;
                    self.keys.insert(peer_id, *key);
                    info!("{:?}", self.keys);

                    if self.keys.len() == self.participants.len() {
                        let aggregated = program_context.key_chain.new_musig2_session(
                            self.keys.values().cloned().collect(),
                            self.my_key.clone(),
                        )?;
                        self.aggregated_key = Some(aggregated.clone());

                        self.state = true;
                    }
                } else {
                    let keys: ParticipantKeys =
                        parse_keys(data).map_err(|_| BitVMXError::InvalidMessageFormat)?;

                    
                    keys.mapping.iter().for_each(|(peer_id, key)| {
                        let peer_id: PeerId = peer_id.parse().unwrap_or(self.leader.peer_id); //TODO: Handle the unwrap better
                        let key = key.public();
                        if let Some(key) = key {
                            self.keys.insert(peer_id, *key);
                        } else {
                            warn!("Key not found for peer: {}", peer_id);
                        }
                    });

                    let aggregated = program_context.key_chain.new_musig2_session(
                        self.keys.values().cloned().collect(),
                        self.my_key.clone(),
                    )?;
                    self.aggregated_key = Some(aggregated.clone());
                }
                program_context.broker_channel.send(
                    self.request_from,
                    OutgoingBitVMXApiMessages::AggregatedPubkey(
                        self.collaboration_id,
                        self.aggregated_key.unwrap().clone(),
                    )
                    .to_string()?,
                )?;

                response(
                    &program_context.comms,
                    &self.collaboration_id,
                    peer_id,
                    P2PMessageType::KeysAck,
                    (),
                )?;
            }
            P2PMessageType::KeysAck => {
                debug!(
                    "Collaboration id: {}: KeysAck received by {}",
                    self.collaboration_id, peer_id
                );
            }
            _ => {
                return Err(BitVMXError::InvalidMessageType);
            }
        }
        Ok(())
    }
}
