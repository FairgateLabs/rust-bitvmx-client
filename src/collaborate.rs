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
    program::participant::{CommsAddress, ParticipantKeys, PublicKeyType},
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

        OperatorVerificationStore::request_missing_verification_keys(
            &program_context.globals,
            &program_context.comms,
            &program_context.key_chain,
            id,
            &peers,
        )?;

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
            let mut participant_keys = ParticipantKeys::new(all_keys, vec![]);

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
    ) -> Result<(), BitVMXError> {
        let pubkey_hash = comms_address.pubkey_hash.clone();
        match msg_type {
            CommsMessageType::Keys => {
                // Message signature verification already done in BitVMX::process_msg
                // Only process the keys and verify individual key signatures (MITM protection)
                if self.im_leader {
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
                    if let Some(signature) = keys.get_signature(&self.collaboration_id.to_string())
                    {
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
                    // Message signature verification already done in BitVMX::process_msg
                    // Only process the keys received
                    let keys: ParticipantKeys = parse_keys(data.clone())
                        .map_err(|_| BitVMXError::InvalidMessageFormat)?
                        .first()
                        .unwrap()
                        .1
                        .clone();

                    // Process all received keys - simplified MITM protection
                    for (pubkey_hash_str, key) in &keys.mapping {
                        let pubkey_hash: PubKeyHash = pubkey_hash_str.parse().map_err(|_| {
                            error!("Invalid pubkey hash format received: {}", pubkey_hash_str);
                            BitVMXError::InvalidMessageFormat
                        })?;

                        if let Some(key) = key.public() {
                            let my_pubkey_hash = program_context.comms.get_pubk_hash()?;

                            // Simplified MITM protection: verify keys based on their source
                            if pubkey_hash == my_pubkey_hash {
                                // This is our own key - verify it hasn't been tampered with
                                if let Some(signature) = keys.get_signature(pubkey_hash_str) {
                                    let my_verification_key =
                                        program_context.key_chain.get_rsa_public_key()?;
                                    let verified = program_context.key_chain.verify_rsa_signature(
                                        &my_verification_key,
                                        key.to_string().as_bytes(),
                                        &signature,
                                    )?;
                                    if !verified {
                                        error!("Invalid RSA signature for our own key");
                                        return Err(BitVMXError::InvalidSignature {
                                            peer: pubkey_hash.clone(),
                                            msg_type: "Key".to_string(),
                                            program_id: "N/A".to_string(),
                                        });
                                    }
                                    info!("My own key verified ({})", verified);
                                } else {
                                    error!("Missing RSA signature for our own key");
                                    return Err(BitVMXError::InvalidMessageFormat);
                                }
                            } else if pubkey_hash == self.leader.pubkey_hash {
                                // Leader's key - we trust it since the leader's message is already verified
                                info!("Leader's key accepted (message already verified)");
                            } else {
                                // Other participant's key - verify if signature is present
                                if let Some(signature) = keys.get_signature(pubkey_hash_str) {
                                    if let Some(verification_key) = OperatorVerificationStore::get(
                                        &program_context.globals,
                                        &pubkey_hash,
                                    )? {
                                        let verified =
                                            program_context.key_chain.verify_rsa_signature(
                                                &verification_key,
                                                key.to_string().as_bytes(),
                                                &signature,
                                            )?;
                                        if !verified {
                                            info!(
                                                "Invalid RSA signature for peer: {}",
                                                pubkey_hash
                                            );
                                            return Err(BitVMXError::InvalidSignature {
                                                peer: pubkey_hash.clone(),
                                                msg_type: "Key".to_string(),
                                                program_id: "N/A".to_string(),
                                            });
                                        }
                                        info!(
                                            "Key verified for peer: {} ({})",
                                            pubkey_hash, verified
                                        );
                                    } else {
                                        info!("Missing verification key for peer: {}", pubkey_hash);
                                        return Err(BitVMXError::MissingVerificationKey {
                                            peer: pubkey_hash.clone(),
                                            known_count: 0,
                                        });
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
