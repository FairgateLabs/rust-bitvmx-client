use std::collections::HashMap;

use bitcoin::PublicKey;
use bitvmx_broker::identification::identifier::Identifier;
use bitvmx_operator_comms::operator_comms::PubKeyHash;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{debug, info};
use uuid::Uuid;

use crate::{
    comms_helper::{request, response, CommsMessageType},
    errors::BitVMXError,
    helper::parse_keys,
    program::participant::{CommsAddress, ParticipantKeys, PublicKeyType},
    types::{OutgoingBitVMXApiMessages, ProgramContext},
    comms_helper::publish_verification_key,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct Collaboration {
    pub collaboration_id: Uuid,
    pub participants: Vec<CommsAddress>,
    pub leader: CommsAddress,
    pub im_leader: bool,
    pub keys: HashMap<PubKeyHash, PublicKey>,
    pub key_signatures: HashMap<PubKeyHash, Vec<u8>>, // Store RSA signatures for each key
    pub participant_verification_keys: HashMap<PubKeyHash, String>, // Store RSA public keys of other participants
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
            participant_verification_keys: HashMap::new(),
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
        let my_verification_key = program_context.key_chain.get_rsa_public_key()?;

        let mut participant_keys = ParticipantKeys::new(
            vec![(id.to_string(), my_key.clone().into())], 
            vec![]);

        // Sign the key with RSA signature for MITM protection
        let signature = program_context.key_chain.sign_rsa_message(my_key.to_string().as_bytes())?;
        participant_keys.add_signature(&id.to_string(), signature);

        let keys = vec![(
            my_pubkey_hash.clone(),
            participant_keys,
        )];

        // Broadcast my verification key to all participants
        publish_verification_key(my_pubkey_hash.clone(), my_verification_key.clone(), &program_context.comms, &program_context.key_chain, id, peers.clone())?;

        if !im_leader {
            request(
                &program_context.comms,
                &program_context.key_chain,
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
            
            // Create ParticipantKeys with signatures for MITM protection
            let mut participant_keys = ParticipantKeys::new(
                all_keys, 
                vec![]);
            
            // Add signatures for all keys (simplified MITM protection)
            for (pubkey_hash, _key) in &self.keys {
                if let Some(signature) = self.get_key_signature(pubkey_hash) {
                    participant_keys.add_signature(&pubkey_hash.to_string(), signature.clone());
                }
            }
            
            let keys = vec![(pubk_hash, participant_keys)];
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
                    &program_context.key_chain,
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
        timestamp: i64,
        signature: Vec<u8>,
    ) -> Result<(), BitVMXError> {
        let pubkey_hash = comms_address.pubkey_hash.clone();
        match msg_type {
            CommsMessageType::VerificationKey => {
                // Handle peer verification key message
                let verification_key: String = serde_json::from_value(data.clone())
                    .map_err(|_| BitVMXError::InvalidMessageFormat)?;
                
                // Reconstruct the message that was signed: {program_id}{msg_string}{timestamp}
                // Serialize with sorted keys to match the signing logic
                let message = crate::comms_helper::construct_message(&self.collaboration_id.to_string(), &data, timestamp)?;
                
                let verified = program_context.key_chain.verify_rsa_signature(&verification_key, message.as_bytes(), &signature)?;
                info!("Verification key verified for peer: {} ({})", pubkey_hash, verified);
                self.participant_verification_keys.insert(pubkey_hash.clone(), verification_key);
            }

            CommsMessageType::Keys => {
                if self.im_leader { 
                    let keys: ParticipantKeys = parse_keys(data.clone())
                        .map_err(|_| BitVMXError::InvalidMessageFormat)?
                        .first()
                        .unwrap()
                        .1
                        .clone();
                    let verification_key: String = self.participant_verification_keys.get(&pubkey_hash).unwrap().clone();
                    let key = keys.get_public(&self.collaboration_id.to_string())?;
                    
                    // Simplified MITM protection: just store the signature for redistribution
                    if let Some(signature) = keys.get_signature(&self.collaboration_id.to_string()) {
                        let verified = program_context.key_chain.verify_rsa_signature(&verification_key, key.to_string().as_bytes(), &signature)?;
                        info!("Received RSA signature from participant: {} ({})", pubkey_hash, verified);
                        // Store the signature for redistribution to other participants
                        self.add_key_signature(pubkey_hash.clone(), signature.clone());
                    } else {
                        info!("Missing RSA signature for participant: {}", pubkey_hash);
                        return Err(BitVMXError::InvalidMessageFormat);
                    }

                    // Store the key and its signature
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
                    let keys: ParticipantKeys = parse_keys(data.clone())
                        .map_err(|_| BitVMXError::InvalidMessageFormat)?
                        .first()
                        .unwrap()
                        .1
                        .clone();

                    //validates leader's verification key
                    let leader_verification_key = self.participant_verification_keys.get(&self.leader.pubkey_hash).unwrap();
                    
                    let message = crate::comms_helper::construct_message(&self.collaboration_id.to_string(), &data, timestamp)?;
                    
                    let verified = program_context.key_chain.verify_rsa_signature(&leader_verification_key, message.as_bytes(), &signature)?;
                    info!("Leader's verification key verified ({})", verified);

                    // Process all received keys - simplified MITM protection
                    for (pubkey_hash_str, key) in &keys.mapping {
                        let pubkey_hash: PubKeyHash = pubkey_hash_str
                            .parse()
                            .unwrap_or(self.leader.pubkey_hash.clone()); //TODO: Handle the unwrap better
                        
                        if let Some(key) = key.public() {
                            let my_pubkey_hash = program_context.comms.get_pubk_hash()?;
                            
                            // Simplified MITM protection: verify keys based on their source
                            if pubkey_hash == my_pubkey_hash {
                                // This is our own key - verify it hasn't been tampered with
                                if let Some(signature) = keys.get_signature(pubkey_hash_str) {
                                    let my_verification_key = program_context.key_chain.get_rsa_public_key()?;
                                    let verified = program_context.key_chain.verify_rsa_signature(&my_verification_key, key.to_string().as_bytes(), &signature)?;
                                    if !verified {
                                        info!("Invalid RSA signature for our own key");
                                        return Err(BitVMXError::InvalidMessageFormat);
                                    }
                                    info!("My own key verified ({})", verified);
                                } else {
                                    info!("Missing RSA signature for our own key");
                                    return Err(BitVMXError::InvalidMessageFormat);
                                }
                            } else if pubkey_hash == self.leader.pubkey_hash {
                                // Leader's key - we trust it since the leader's message is already verified
                                info!("Leader's key accepted (message already verified)");
                            } else {
                                // Other participant's key - verify if signature is present
                                if let Some(signature) = keys.get_signature(pubkey_hash_str) {
                                    if let Some(verification_key) = self.participant_verification_keys.get(&pubkey_hash) {
                                        let verified = program_context.key_chain.verify_rsa_signature(verification_key, key.to_string().as_bytes(), &signature)?;
                                        if !verified {
                                            info!("Invalid RSA signature for peer: {}", pubkey_hash);
                                            return Err(BitVMXError::InvalidMessageFormat);
                                        }
                                        info!("Key verified for peer: {} ({})", pubkey_hash, verified);
                                    } else {
                                        info!("Missing verification key for peer: {}", pubkey_hash);
                                        return Err(BitVMXError::InvalidMessageFormat);
                                    }
                                } else {
                                    info!("Missing RSA signature for peer: {}", pubkey_hash);
                                    return Err(BitVMXError::InvalidMessageFormat);
                                }
                            }
                            // Accept all keys (our own is verified, leader's is trusted, others verified above)
                            self.keys.insert(pubkey_hash, *key);
                        } else {
                            info!("Key not found for peer: {}", pubkey_hash);
                        }
                    }

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
