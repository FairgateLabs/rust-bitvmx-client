use crate::{
    bitvmx::Context,
    config::ClientConfig,
    errors::{BitVMXError, ProgramError},
    helper::{
        parse_keys, parse_nonces, parse_signatures, PartialSignatureMessage, PubNonceMessage,
    },
    p2p_helper::{request, response, P2PMessageType},
    program::participant::ParticipantKeys,
    types::{OutgoingBitVMXApiMessages, ProgramContext, ProgramRequestInfo, L2_ID},
};
use bitcoin::{PublicKey, Transaction, Txid};
use bitcoin_coordinator::{coordinator::BitcoinCoordinatorApi, TransactionStatus, TypesToMonitor};
use chrono::Utc;
use core::panic;
use key_manager::musig2::{types::MessageId, PartialSignature, PubNonce};
use p2p_handler::PeerId;
use protocol_builder::types::Utxo;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::HashMap, rc::Rc};
use storage_backend::storage::{KeyValueStore, Storage};
use tracing::{debug, info, warn};
use uuid::Uuid;

use super::{
    dispute::{DisputeResolutionProtocol, SearchParams},
    participant::{P2PAddress, ParticipantData, ParticipantRole},
    protocol_handler::{ProtocolHandler, ProtocolType},
    slot::SlotProtocol,
    state::{ProgramState, SettingUpState},
};

#[derive(Debug, Clone)]
pub enum StoreKey {
    LastRequestKeys(Uuid),
    LastRequestNonces(Uuid),
    LastRequestSignatures(Uuid),
    Program(Uuid),
}

pub fn get_other_index_by_peer_id(peer_id: &PeerId, others: &Vec<ParticipantData>) -> usize {
    others
        .iter()
        .position(|participant| &participant.p2p_address.peer_id == peer_id)
        .unwrap() //TODO: handle
}

pub fn all_keys_ready(others: &Vec<ParticipantData>) -> bool {
    for other in others {
        if other.keys.is_none() {
            return false;
        }
    }
    true
}

pub fn all_nonces_ready(others: &Vec<ParticipantData>) -> bool {
    let mut c = 0;
    for other in others {
        if other.nonces.is_some() {
            c += 1;
        }
    }
    c >= others.len() - 1
}

pub fn all_signatures_ready(others: &Vec<ParticipantData>) -> bool {
    let mut c = 0;
    for other in others {
        if other.partial.is_some() {
            c += 1;
        }
    }
    c >= others.len() - 1
}

#[derive(Clone, Serialize, Deserialize)]
pub struct DrpParameters {
    pub role: ParticipantRole,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SlotParameters;

#[derive(Clone, Serialize, Deserialize)]
pub enum ProtocolParameters {
    DisputeResolutionProtocol(DrpParameters),
    SlotProtocol(SlotParameters),
}

impl ProtocolParameters {
    pub fn new_drp(role: ParticipantRole) -> Self {
        ProtocolParameters::DisputeResolutionProtocol(DrpParameters { role })
    }

    pub fn new_slot() -> Self {
        ProtocolParameters::SlotProtocol(SlotParameters {})
    }

    pub fn drp(&self) -> &DrpParameters {
        match self {
            ProtocolParameters::DisputeResolutionProtocol(drp) => drp,
            _ => panic!("Not a DRP protocol"),
        }
    }

    pub fn slot(&self) -> &SlotParameters {
        match self {
            ProtocolParameters::SlotProtocol(slot) => slot,
            _ => panic!("Not a Slot protocol"),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Program {
    pub program_id: Uuid,
    pub parameters: ProtocolParameters,
    pub my_idx: usize,
    pub participants: Vec<ParticipantData>,
    pub leader: usize,
    pub utxo: Option<Utxo>,
    pub protocol: ProtocolType,
    pub state: ProgramState,
    #[serde(skip)]
    storage: Option<Rc<Storage>>,
    config: ClientConfig,
}

impl Program {
    pub fn load(storage: Rc<Storage>, program_id: &Uuid) -> Result<Self, ProgramError> {
        let program = storage.get(Self::get_key(StoreKey::Program(*program_id)))?;
        let mut program: Program = program.ok_or(ProgramError::ProgramNotFound(*program_id))?;

        program.storage = Some(storage.clone());
        program.protocol.set_storage(storage);

        Ok(program)
    }

    pub fn im_leader(&self) -> bool {
        self.my_idx == self.leader
    }
    pub fn save(&self) -> Result<(), ProgramError> {
        let key = Self::get_key(StoreKey::Program(self.program_id));
        self.storage.as_ref().unwrap().set(key, self, None)?;
        Ok(())
    }

    pub fn setup_slot(
        id: &Uuid,
        peers: Vec<P2PAddress>,
        leader: usize,
        program_context: &mut ProgramContext,
        storage: Rc<Storage>,
        config: &ClientConfig,
    ) -> Result<Self, BitVMXError> {
        // Generate my keys.
        if leader >= peers.len() {
            return Err(BitVMXError::InvalidMessageFormat);
        }

        let my_keys = SlotProtocol::generate_keys(&mut program_context.key_chain)?;

        let p2p_address = P2PAddress::new(
            &program_context.comms.get_address(),
            program_context.comms.get_peer_id(),
        );

        //FIX EXCPECT WITH PROPER ERROR (invalid message as I'm not in the list)
        let my_idx = peers
            .iter()
            .position(|peer| peer.peer_id == p2p_address.peer_id)
            .expect("Peer not found in the list");

        info!("my_pos: {}", my_idx);
        info!("Leader pos: {}", leader);

        //Creates space for the participants
        let mut others = peers
            .iter()
            .map(|peer| ParticipantData::new(peer, None))
            .collect::<Vec<_>>();

        // save my pos in the others list to have the complete message ready
        others[my_idx] = ParticipantData::new(&p2p_address, Some(my_keys));

        // Create a program with the utxo information, and the dispute resolution search parameters.
        let protocol = ProtocolType::SlotProtocol(SlotProtocol::new(*id, storage.clone()));

        let program = Self {
            program_id: *id,
            parameters: ProtocolParameters::new_slot(),
            my_idx,
            participants: others,
            leader,
            utxo: None,
            protocol,
            state: ProgramState::New,
            storage: Some(storage),
            config: config.clone(),
        };

        program.save()?;

        Ok(program)
    }

    pub fn setup_program(
        id: &Uuid,
        my_role: ParticipantRole,
        peer_address: &P2PAddress,
        utxo: Utxo,
        program_context: &mut ProgramContext,
        storage: Rc<Storage>,
        config: &ClientConfig,
    ) -> Result<Self, BitVMXError> {
        // Generate my keys.
        let my_keys =
            DisputeResolutionProtocol::generate_keys(&my_role, &mut program_context.key_chain)?;

        let p2p_address = P2PAddress::new(
            &program_context.comms.get_address(),
            program_context.comms.get_peer_id(),
        );
        // Create a participant that represents me with the specified role (Prover or Verifier).
        let me = ParticipantData::new(&p2p_address, Some(my_keys));

        // Create a participant that represents the counterparty with the opposite role.
        let other = ParticipantData::new(peer_address, None);

        // Create a program with the utxo information, and the dispute resolution search parameters.
        let drp = ProtocolType::DisputeResolutionProtocol(DisputeResolutionProtocol::new(
            *id,
            storage.clone(),
        ));

        let (prover, verifier, my_idx) = if my_role == ParticipantRole::Prover {
            (me, other, 0)
        } else {
            (other, me, 1)
        };

        let others = vec![prover, verifier];

        let program = Self {
            program_id: *id,
            parameters: ProtocolParameters::new_drp(my_role),
            my_idx,
            participants: others,
            leader: 1, //verifier is the leader (because prover starts sending data)
            utxo: Some(utxo),
            protocol: drp,
            state: ProgramState::New,
            storage: Some(storage),
            config: config.clone(),
        };

        program.save()?;

        Ok(program)
    }

    pub fn prepare_aggregated_keys(
        &mut self,
        context: &ProgramContext,
    ) -> Result<HashMap<String, PublicKey>, BitVMXError> {
        // 2. Init the musig2 signer for this program

        let operatos_pub = if self.utxo.is_some() {
            self.utxo.clone().unwrap().pub_key
        } else {
            context
                .globals
                .get_var(&self.program_id, "operators_aggregated_pub")?
                .pubkey()?
        };

        let mut aggregated_keys = vec![("pregenerated".to_string(), operatos_pub)];
        let mut result = HashMap::new();

        for agg_name in &self.participants[self.my_idx]
            .keys
            .as_ref()
            .unwrap()
            .aggregated
        {
            let agg_key = self.participants[self.my_idx]
                .keys
                .as_ref()
                .unwrap()
                .get_public(agg_name)
                .map_err(|_| BitVMXError::InvalidMessageFormat)?;

            let mut aggregated_pub_keys = vec![];

            for other in &self.participants {
                let other_key = other
                    .keys
                    .as_ref()
                    .unwrap()
                    .get_public(agg_name)
                    .map_err(|_| BitVMXError::InvalidMessageFormat)?;
                aggregated_pub_keys.push(*other_key);
            }

            aggregated_pub_keys.sort();

            let aggregated_key = context
                .key_chain
                .new_musig2_session(aggregated_pub_keys, *agg_key)?;

            info!(
                "Aggregated var name {}: Aggregated key: {}",
                agg_name,
                aggregated_key.to_string()
            );
            aggregated_keys.push((agg_name.clone(), aggregated_key));
        }

        for (agg_name, aggregated_key) in aggregated_keys {
            result.insert(agg_name.to_string(), aggregated_key);
        }
        self.participants[self.my_idx]
            .keys
            .as_mut()
            .unwrap()
            .computed_aggregated = result.clone();
        Ok(result)
    }

    pub fn build_protocol(&mut self, context: &ProgramContext) -> Result<(), BitVMXError> {
        let search_params = SearchParams::new(8, 32);

        let aggregated = self.prepare_aggregated_keys(context)?;
        info!(
            "{}. Building with aggregated: {:?}",
            self.my_idx, aggregated
        );
        // 3. Build the protocol using the aggregated key as internal key for taproot

        if self.protocol.as_drp().is_some() {
            info!("Building protocol for: {:?}", self.parameters.drp().role);

            self.protocol.as_drp_mut().unwrap().build(
                self.utxo.as_ref().unwrap().clone(),
                self.participants[0].keys.as_ref().unwrap(),
                self.participants[1].keys.as_ref().unwrap(),
                aggregated,
                search_params,
                &context.key_chain,
            )?;
            info!("Protocol built for role: {:?}", self.parameters.drp().role);
        } else {
            let keys: Vec<ParticipantKeys> = self
                .participants
                .iter()
                .map(|p| p.keys.as_ref().unwrap().clone())
                .collect();
            self.protocol
                .as_slot_mut()
                .unwrap()
                .build(keys, aggregated, &context)?;
        }

        // 6. Move the program to the next state
        self.move_program_to_next_state()?;
        Ok(())
    }

    pub fn get_address_from_peer_id(&self, peer_id: &PeerId) -> Result<P2PAddress, BitVMXError> {
        for p in &self.participants {
            if &p.p2p_address.peer_id == peer_id {
                return Ok(p.p2p_address.clone());
            }
        }
        return Err(BitVMXError::P2PCommunicationError);
    }

    pub fn request_helper<T>(
        &mut self,
        program_context: &ProgramContext,
        to_send: Vec<(PeerId, T)>,
        msg_type: P2PMessageType,
    ) -> Result<(), BitVMXError>
    where
        T: Serialize + Clone,
    {
        let my_peer_id = &program_context.comms.get_peer_id();
        for (other, _) in to_send.iter() {
            if self.leader != self.my_idx || other != my_peer_id {
                let dest = if self.leader != self.my_idx {
                    self.participants[self.leader].p2p_address.clone()
                } else {
                    self.get_address_from_peer_id(other)?
                };

                info!(
                    "Sending message {:?} from {} to {}",
                    &msg_type, self.my_idx, dest.peer_id
                );

                request(
                    &program_context.comms,
                    &self.program_id,
                    dest,
                    msg_type.clone(),
                    to_send.clone(),
                )?;
            }
        }
        Ok(())
    }

    pub fn send_keys(&mut self, program_context: &ProgramContext) -> Result<(), BitVMXError> {
        let should_send_request =
            self.should_send_request(StoreKey::LastRequestKeys(self.program_id))?;

        if !should_send_request {
            return Ok(());
        }

        info!("{:?}: Sending keys", self.my_idx);
        let keys = if self.my_idx == self.leader {
            let mut keys = vec![];
            for other in &self.participants {
                keys.push((
                    other.p2p_address.peer_id.clone(),
                    other.keys.clone().unwrap(),
                ));
            }
            keys
        } else {
            vec![(
                self.participants[self.my_idx].p2p_address.peer_id.clone(),
                self.participants[self.my_idx].keys.clone().unwrap(),
            )]
        };
        self.request_helper(program_context, keys, P2PMessageType::Keys)?;

        self.save_retry(StoreKey::LastRequestKeys(self.program_id))?;
        Ok(())
    }

    pub fn receive_keys(
        &mut self,
        peer_id: PeerId,
        msg_type: P2PMessageType,
        data: Value,
        program_context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        if !self.state.should_handle_msg(&msg_type) {
            if self.state.should_answer_ack(self.im_leader(), &msg_type) {
                self.send_ack(program_context, &peer_id, P2PMessageType::KeysAck)?;
            }
            return Ok(());
        }

        // Parse the keys received
        for (peer_id, keys) in parse_keys(data).map_err(|_| BitVMXError::InvalidMessageFormat)? {
            let other_pos = get_other_index_by_peer_id(&peer_id, &self.participants);
            self.participants[other_pos].keys = Some(keys);
        }

        self.save()?;

        // Send ack to the other party
        self.send_ack(program_context, &peer_id, P2PMessageType::KeysAck)?;

        if all_keys_ready(&self.participants) {
            // Build the protocol
            self.build_protocol(program_context)?;
        }
        Ok(())
    }

    pub fn send_nonces(&mut self, program_context: &ProgramContext) -> Result<(), BitVMXError> {
        let should_send_request =
            self.should_send_request(StoreKey::LastRequestNonces(self.program_id))?;

        if !should_send_request {
            return Ok(());
        }

        info!("{}. Sending nonces", self.my_idx);

        let mut public_nonce_msg: PubNonceMessage = Vec::new();
        for aggregated in self.participants[self.my_idx]
            .keys
            .as_ref()
            .unwrap()
            .computed_aggregated
            .values()
        {
            let nonces = program_context.key_chain.get_nonces(aggregated);
            if nonces.is_err() {
                warn!(
                    "{}. Error geting nonces for aggregated key: {:?}",
                    self.my_idx, aggregated
                );
                continue;
            }
            let my_pub = program_context
                .key_chain
                .key_manager
                .get_my_public_key(aggregated)?;
            info!(
                "{}. Sending nonces for aggregated key: {} {:?} {:?}",
                self.my_idx, aggregated, my_pub, nonces
            );
            public_nonce_msg.push((aggregated.clone(), my_pub, nonces.unwrap()));
        }

        self.participants[self.my_idx].nonces = Some(public_nonce_msg);
        info!("I'm {} and I'm setting my nonces", self.my_idx);

        let mut nonces = vec![];
        for other in &self.participants {
            if other.nonces.is_some() {
                nonces.push((
                    other.p2p_address.peer_id.clone(),
                    other.nonces.clone().unwrap(),
                ));
            }
        }
        self.request_helper(program_context, nonces, P2PMessageType::PublicNonces)?;

        self.save_retry(StoreKey::LastRequestNonces(self.program_id))?;
        self.save()?;
        Ok(())
    }

    pub fn receive_nonces(
        &mut self,
        peer_id: PeerId,
        msg_type: P2PMessageType,
        data: Value,
        program_context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        if !self.state.should_handle_msg(&msg_type) {
            if self.state.should_answer_ack(self.im_leader(), &msg_type) {
                self.send_ack(program_context, &peer_id, P2PMessageType::PublicNoncesAck)?;
            }
            return Ok(());
        }

        //TODO: Santitize pariticipant_pub_key with message origin
        let nonces_msg = parse_nonces(data).map_err(|_| BitVMXError::InvalidMessageFormat)?;

        for (peer_id, particpant_nonces) in nonces_msg {
            let other_pos = get_other_index_by_peer_id(&peer_id, &self.participants);
            info!("{}. Got nonces for pos: {}", self.my_idx, other_pos);
            self.participants[other_pos].nonces = Some(particpant_nonces);
        }
        self.save()?;

        if all_nonces_ready(&self.participants) {
            let mut map_of_maps: HashMap<
                PublicKey,
                HashMap<PublicKey, Vec<(MessageId, PubNonce)>>,
            > = HashMap::new();

            for (idx, participant) in self.participants.iter().enumerate() {
                if idx != self.my_idx {
                    for (aggregated, participant_pub_key, nonces) in
                        participant.nonces.as_ref().unwrap()
                    {
                        info!(
                            "will do nonces for: {} {:?} {:?} {:?} ",
                            idx, aggregated, participant_pub_key, nonces
                        );
                        map_of_maps
                            .entry(aggregated.clone())
                            .or_insert_with(HashMap::new)
                            .insert(*participant_pub_key, nonces.clone());
                    }
                }
            }
            for (aggregated, pubkey_nonce_map) in map_of_maps {
                program_context
                    .key_chain
                    .add_nonces(&aggregated, pubkey_nonce_map)?;
            }

            self.move_program_to_next_state()?;
        } else {
            info!("{}. Not all nonces ready", self.my_idx);
        }

        self.send_ack(&program_context, &peer_id, P2PMessageType::PublicNoncesAck)?;
        Ok(())
    }

    pub fn send_signatures(&mut self, program_context: &ProgramContext) -> Result<(), BitVMXError> {
        let should_send_request =
            self.should_send_request(StoreKey::LastRequestSignatures(self.program_id))?;

        if !should_send_request {
            return Ok(());
        }

        info!("{}. Sending PartialSignatures", self.my_idx);
        let mut partial_sig_msg: PartialSignatureMessage = Vec::new();
        for aggregated in self.participants[self.my_idx]
            .keys
            .as_ref()
            .unwrap()
            .computed_aggregated
            .values()
        {
            let signatures = program_context.key_chain.get_signatures(aggregated);
            if signatures.is_err() {
                warn!(
                    "{}. Error geting partial signature for aggregated key: {:?}",
                    self.my_idx, aggregated
                );
                continue;
            }
            let my_pub = program_context
                .key_chain
                .key_manager
                .get_my_public_key(aggregated)?;
            info!(
                "{}. Sending partial signatures for aggregated key: {} {:?} {:?}",
                self.my_idx, aggregated, my_pub, signatures
            );
            partial_sig_msg.push((aggregated.clone(), my_pub, signatures.unwrap()));
        }

        self.participants[self.my_idx].partial = Some(partial_sig_msg);
        info!("I'm {} and I'm setting my partial", self.my_idx);

        let mut partials = vec![];
        for other in &self.participants {
            if other.partial.is_some() {
                partials.push((
                    other.p2p_address.peer_id.clone(),
                    other.partial.clone().unwrap(),
                ));
            }
        }
        self.request_helper(program_context, partials, P2PMessageType::PartialSignatures)?;

        self.save_retry(StoreKey::LastRequestSignatures(self.program_id))?;
        self.save()?;
        Ok(())
    }

    pub fn receive_signatures(
        &mut self,
        peer_id: PeerId,
        msg_type: P2PMessageType,
        data: Value,
        program_context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        if !self.state.should_handle_msg(&msg_type) {
            if self.state.should_answer_ack(self.im_leader(), &msg_type) {
                self.send_ack(
                    program_context,
                    &peer_id,
                    P2PMessageType::PartialSignaturesAck,
                )?;
            }
            return Ok(());
        }

        let partial_msg = parse_signatures(data).map_err(|_| BitVMXError::InvalidMessageFormat)?;
        for (peer_id, particpant_partials) in partial_msg {
            let other_pos = get_other_index_by_peer_id(&peer_id, &self.participants);
            info!("{}. Got partials for pos: {}", self.my_idx, other_pos);
            self.participants[other_pos].partial = Some(particpant_partials);
        }
        self.save()?;

        if all_signatures_ready(&self.participants) {
            let mut map_of_maps: HashMap<
                PublicKey,
                HashMap<PublicKey, Vec<(MessageId, PartialSignature)>>,
            > = HashMap::new();

            for (idx, participant) in self.participants.iter().enumerate() {
                if idx != self.my_idx {
                    for (aggregated, other_pub_key, signatures) in
                        participant.partial.as_ref().unwrap()
                    {
                        info!(
                            "Program {}: agg: {}, other: {} Received signatures: {:#?}",
                            self.program_id, aggregated, other_pub_key, signatures
                        );

                        map_of_maps
                            .entry(aggregated.clone())
                            .or_insert_with(HashMap::new)
                            .insert(*other_pub_key, signatures.clone());
                    }
                }
            }

            for (aggregated, partial_map) in map_of_maps {
                program_context
                    .key_chain
                    .add_signatures(&aggregated, partial_map)?;
            }

            self.protocol.sign(&program_context.key_chain)?;
            self.move_program_to_next_state()?;
        }

        self.send_ack(
            program_context,
            &peer_id,
            P2PMessageType::PartialSignaturesAck,
        )?;
        Ok(())
    }

    pub fn tick(&mut self, program_context: &ProgramContext) -> Result<(), BitVMXError> {
        match &self.state {
            ProgramState::New => {
                self.move_program_to_next_state()?;
            }

            ProgramState::SettingUp(SettingUpState::SendingKeys) => {
                self.send_keys(program_context)?;
            }
            ProgramState::SettingUp(SettingUpState::SendingNonces) => {
                self.send_nonces(program_context)?;
            }
            ProgramState::SettingUp(SettingUpState::SendingSignatures) => {
                self.send_signatures(program_context)?;
            }
            ProgramState::Monitoring => {
                // After the program is ready, we need to monitor the transactions
                let txns_to_monitor = self.get_txs_to_monitor()?;

                let context = Context::ProgramId(self.program_id);
                let txs_to_monitor =
                    TypesToMonitor::Transactions(txns_to_monitor.clone(), context.to_string()?);

                program_context
                    .bitcoin_coordinator
                    .monitor(txs_to_monitor)?;

                let utox_to_monitor = TypesToMonitor::SpendingUTXOTransaction(
                    txns_to_monitor[0],
                    0,
                    "HELLO UTXO TRANSACTION".to_string(),
                );

                program_context
                    .bitcoin_coordinator
                    .monitor(utox_to_monitor)?;

                debug!("Monitoring best block");
                // Monitor when the best block changes
                program_context
                    .bitcoin_coordinator
                    .monitor(TypesToMonitor::NewBlock)?;

                self.move_program_to_next_state()?;

                let result = program_context.broker_channel.send(
                    L2_ID,
                    OutgoingBitVMXApiMessages::SetupCompleted(self.program_id).to_string()?,
                );
                if let Err(e) = result {
                    warn!("Error sending setup completed message: {:?}", e);
                    //TODO: Handle error and rollback
                }
            }
            _ => {}
        }

        Ok(())
    }

    pub fn process_p2p_message(
        &mut self,
        peer_id: PeerId,
        msg_type: P2PMessageType,
        data: Value,
        program_context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        info!("{}: Message received: {:?} ", self.my_idx, msg_type);

        match msg_type {
            P2PMessageType::Keys => {
                self.receive_keys(peer_id, msg_type, data, program_context)?;
            }
            P2PMessageType::PublicNonces => {
                self.receive_nonces(peer_id, msg_type, data, program_context)?;
            }
            P2PMessageType::PartialSignatures => {
                self.receive_signatures(peer_id, msg_type, data, program_context)?;
            }
            P2PMessageType::KeysAck
            | P2PMessageType::PublicNoncesAck
            | P2PMessageType::PartialSignaturesAck => {
                if !self.state.should_handle_msg(&msg_type) {
                    info!(
                        "{}. Ignoring message {:?} {:?}",
                        self.my_idx, msg_type, self.state
                    );
                    return Ok(());
                }

                self.move_program_to_next_state()?;
            }
        }

        Ok(())
    }

    pub fn send_ack(
        &self,
        program_context: &ProgramContext,
        peer_id: &PeerId,
        msg_type: P2PMessageType,
    ) -> Result<(), BitVMXError> {
        info!("{}. Sending {:?}", self.my_idx, msg_type);

        response(
            &program_context.comms,
            &self.program_id,
            //self.others[0].p2p_address.peer_id.clone(),
            peer_id.clone(),
            msg_type,
            (),
        )?;

        Ok(())
    }

    pub fn dispatch_transaction_name(
        &self,
        program_context: &ProgramContext,
        name: &str,
    ) -> Result<(), BitVMXError> {
        //TODO: Get transactions by identification
        let tx_to_dispatch = self.protocol.get_transaction_name(name, program_context)?;

        let context = Context::ProgramId(self.program_id);

        program_context
            .bitcoin_coordinator
            .dispatch(tx_to_dispatch, context.to_string()?)?;
        Ok(())
    }

    pub fn notify_news(
        &self,
        tx_id: Txid,
        tx_status: TransactionStatus,
        context: String,
        program_context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        self.protocol.notify_news(
            tx_id,
            tx_status.clone(),
            context,
            program_context,
            &self.parameters,
        )?;

        if tx_status.confirmations == 6 {
            let name = self.protocol.get_transaction_name_by_id(tx_id)?;
            program_context.broker_channel.send(
                L2_ID,
                OutgoingBitVMXApiMessages::Transaction(self.program_id, tx_status, Some(name))
                    .to_string()?,
            )?;
        }

        Ok(())
    }

    pub fn get_txs_to_monitor(&self) -> Result<Vec<Txid>, BitVMXError> {
        self.protocol
            .get_transaction_ids()
            .map_err(BitVMXError::from)
    }

    fn get_key(key: StoreKey) -> String {
        let prefix = "program";
        match key {
            StoreKey::LastRequestKeys(id) => format!("{prefix}/{id}/last_request_keys"),
            StoreKey::LastRequestNonces(id) => {
                format!("{prefix}/{id}/last_request_nonces")
            }
            StoreKey::LastRequestSignatures(id) => {
                format!("{prefix}/{id}/last_request_signatures")
            }
            StoreKey::Program(id) => format!("{prefix}/{id}"),
        }
    }

    fn save_retry(&mut self, key: StoreKey) -> Result<(), BitVMXError> {
        let retries = self
            .storage
            .as_ref()
            .unwrap()
            .get(Self::get_key(key.clone()))?
            .unwrap_or(ProgramRequestInfo::default())
            .retries
            + 1;

        let last_request = ProgramRequestInfo {
            retries,
            last_request_time: Utc::now(),
        };

        self.storage
            .as_ref()
            .unwrap()
            .set(Self::get_key(key), last_request, None)?;

        Ok(())
    }

    fn should_send_request(&self, key: StoreKey) -> Result<bool, BitVMXError> {
        let retry_delay = self.config.retry_delay;
        let last_request: ProgramRequestInfo = self
            .storage
            .as_ref()
            .unwrap()
            .get(Self::get_key(key.clone()))?
            .unwrap_or(ProgramRequestInfo::default());

        if last_request.retries >= self.config.retry {
            return Ok(false);
        }

        if last_request.retries >= self.config.retry {
            return Ok(false);
        }

        if last_request.retries == 0 {
            return Ok(true);
        }

        let now = Utc::now();
        let diff = now.signed_duration_since(last_request.last_request_time);
        if diff.num_milliseconds() < retry_delay as i64 {
            return Ok(false);
        }

        Ok(true)
    }

    /// This function should only be called when the program is in the correct state,
    /// otherwise it will transition to the next state at the wrong time and break
    /// the program's flow
    pub fn move_program_to_next_state(&mut self) -> Result<(), BitVMXError> {
        self.state = self.state.next_state(self.im_leader());
        self.save()?;
        Ok(())
    }

    pub fn get_tx_by_id(&self, txid: Txid) -> Result<Transaction, BitVMXError> {
        if self.state.is_setting_up() {
            return Err(BitVMXError::ProgramNotReady(self.program_id));
        }

        self.protocol
            .get_transaction_by_id(&txid)
            .map_err(BitVMXError::from)
            .map_err(BitVMXError::from)
    }
}
