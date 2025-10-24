use crate::{
    bitvmx::Context,
    comms_helper::{request, response, CommsMessageType},
    config::ClientConfig,
    errors::{BitVMXError, ProgramError},
    helper::{
        parse_keys, parse_nonces, parse_signatures, PartialSignatureMessage, PubNonceMessage,
    },
    program::{participant::ParticipantKeys, protocols::protocol_handler::new_protocol_type},
    types::{OutgoingBitVMXApiMessages, ProgramContext, ProgramRequestInfo},
};
use bitcoin::{PublicKey, Transaction, Txid};
use bitcoin_coordinator::{coordinator::BitcoinCoordinatorApi, TransactionStatus, TypesToMonitor};
use bitvmx_operator_comms::operator_comms::PubKeyHash;
use chrono::Utc;
use console::style;
use key_manager::musig2::{types::MessageId, PartialSignature, PubNonce};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::HashMap, rc::Rc};
use storage_backend::storage::{KeyValueStore, Storage};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use super::{
    participant::{CommsAddress, ParticipantData, ParticipantRole},
    protocols::protocol_handler::{ProtocolHandler, ProtocolType},
    state::{ProgramState, SettingUpState},
};

#[derive(Debug, Clone)]
pub enum StoreKey {
    LastRequestKeys(Uuid),
    LastRequestNonces(Uuid),
    LastRequestSignatures(Uuid),
    Program(Uuid),
}

pub fn get_other_index_by_pubkey_hash(
    pubkey_hash: &PubKeyHash,
    others: &Vec<ParticipantData>,
) -> Option<usize> {
    others
        .iter()
        .position(|participant| &participant.comms_address.pubkey_hash == pubkey_hash)
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DrpParameters {
    pub role: ParticipantRole,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LockParameters {
    pub my_id: u32,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Program {
    pub program_id: Uuid,
    pub my_idx: usize,
    pub participants: Vec<ParticipantData>,
    pub leader: usize,
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

    //TODO UNIFY SETUPS WITH NAMES
    pub fn setup(
        id: &Uuid,
        protocol_type: &str,
        peers: Vec<CommsAddress>,
        leader: usize,
        program_context: &mut ProgramContext,
        storage: Rc<Storage>,
        config: &ClientConfig,
    ) -> Result<Self, BitVMXError> {
        // Generate my keys.
        if leader >= peers.len() {
            return Err(BitVMXError::InvalidMessageFormat);
        }

        let comms_address = CommsAddress::new(
            program_context.comms.get_address(),
            program_context.comms.get_pubk_hash()?,
        );

        //FIX EXCPECT WITH PROPER ERROR (invalid message as I'm not in the list)
        let my_idx = peers
            .iter()
            .position(|peer| peer.pubkey_hash == comms_address.pubkey_hash)
            .expect("Peer not found in the list");

        info!("my_pos: {}", my_idx);
        info!("Leader pos: {}", leader);

        let protocol = new_protocol_type(*id, protocol_type, my_idx, storage.clone())?;
        let my_keys = protocol.generate_keys(program_context)?;

        //Creates space for the participants
        let mut others = peers
            .iter()
            .map(|peer| ParticipantData::new(peer, None))
            .collect::<Vec<_>>();

        // save my pos in the others list to have the complete message ready
        others[my_idx] = ParticipantData::new(&comms_address, Some(my_keys));

        let mut program = Self {
            program_id: *id,
            my_idx,
            participants: others,
            leader,
            protocol,
            state: ProgramState::New,
            storage: Some(storage),
            config: config.clone(),
        };

        // This is for those protocols that only has one participant
        if peers.len() == 1 {
            program.build_protocol(program_context)?;
            program.protocol.sign(&program_context.key_chain)?;
            program.state = ProgramState::Monitoring
        }
        program.save()?;

        Ok(program)
    }

    pub fn prepare_aggregated_keys(
        &mut self,
        context: &ProgramContext,
    ) -> Result<HashMap<String, PublicKey>, BitVMXError> {
        let mut aggregated_keys = self.protocol.get_pregenerated_aggregated_keys(context)?;

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

            debug!(
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
        let aggregated = self.prepare_aggregated_keys(context)?;
        info!(
            "{}. Building with aggregated: {:?}",
            self.my_idx, aggregated
        );

        let keys: Vec<ParticipantKeys> = self
            .participants
            .iter()
            .map(|p| p.keys.as_ref().unwrap().clone())
            .collect();

        info!("Building protocol for: {} {}", self.program_id, self.my_idx);
        self.protocol.build(keys, aggregated, &context)?;

        // 6. Move the program to the next state
        self.move_program_to_next_state()?;
        Ok(())
    }

    pub fn get_address_from_pubkey_hash(
        &self,
        pubkey_hash: &PubKeyHash,
    ) -> Result<CommsAddress, BitVMXError> {
        for p in &self.participants {
            if &p.comms_address.pubkey_hash == pubkey_hash {
                return Ok(p.comms_address.clone());
            }
        }
        return Err(BitVMXError::CommsCommunicationError);
    }

    pub fn request_helper<T>(
        &mut self,
        program_context: &ProgramContext,
        to_send: Vec<(PubKeyHash, T)>,
        msg_type: CommsMessageType,
    ) -> Result<(), BitVMXError>
    where
        T: Serialize + Clone,
    {
        let my_pubkey_hash = &program_context.comms.get_pubk_hash()?;
        for (other, _) in to_send.iter() {
            if self.leader != self.my_idx || other != my_pubkey_hash {
                let dest = if self.leader != self.my_idx {
                    self.participants[self.leader].comms_address.clone()
                } else {
                    self.get_address_from_pubkey_hash(other)?
                };

                debug!(
                    "Sending message {:?} from {} to {}",
                    &msg_type, self.my_idx, dest.pubkey_hash
                );

                request(
                    &program_context.comms,
                    &program_context.key_chain,
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

        debug!("{:?}: Sending keys", self.my_idx);
        let keys = if self.my_idx == self.leader {
            let mut keys = vec![];
            for other in &self.participants {
                keys.push((
                    other.comms_address.pubkey_hash.clone(),
                    other.keys.clone().unwrap(),
                ));
            }
            keys
        } else {
            vec![(
                self.participants[self.my_idx]
                    .comms_address
                    .pubkey_hash
                    .clone(),
                self.participants[self.my_idx].keys.clone().unwrap(),
            )]
        };
        self.request_helper(program_context, keys, CommsMessageType::Keys)?;

        self.save_retry(StoreKey::LastRequestKeys(self.program_id))?;
        Ok(())
    }

    pub fn receive_keys(
        &mut self,
        comms_address: CommsAddress,
        msg_type: CommsMessageType,
        data: Value,
        program_context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        // TODO: review state logic. quickfix. before this if I get a message before moving from new to receivingkeys it got stuck
        if self.state == ProgramState::New {
            self.move_program_to_next_state()?;
        }
        if !self.state.should_handle_msg(&msg_type) {
            error!(
                "{}. Ignoring message {:?} {:?}",
                self.my_idx, msg_type, self.state
            );
            if self.state.should_answer_ack(self.im_leader(), &msg_type) {
                self.send_ack(program_context, comms_address, CommsMessageType::KeysAck)?;
            }
            return Ok(());
        }

        // Parse the keys received
        for (pubkey_hash, keys) in
            parse_keys(data).map_err(|_| BitVMXError::InvalidMessageFormat)?
        {
            let other_pos = get_other_index_by_pubkey_hash(&pubkey_hash, &self.participants)
                .ok_or(BitVMXError::InvalidParticipant(pubkey_hash))?;
            self.participants[other_pos].keys = Some(keys);
        }

        self.save()?;

        // Send ack to the other party
        self.send_ack(program_context, comms_address, CommsMessageType::KeysAck)?;

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

        debug!("{}. Sending nonces", self.my_idx);

        let mut public_nonce_msg: PubNonceMessage = Vec::new();
        for aggregated in self.participants[self.my_idx]
            .keys
            .as_ref()
            .unwrap()
            .computed_aggregated
            .values()
        {
            let nonces = program_context
                .key_chain
                .get_nonces(aggregated, &self.protocol.context().protocol_name);
            if nonces.is_err() {
                warn!(
                    "{}. Error getting nonces for aggregated key: {}",
                    self.my_idx,
                    aggregated.to_string()
                );
                continue;
            }
            let my_pub = program_context
                .key_chain
                .key_manager
                .get_my_public_key(aggregated)?;
            debug!(
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
                    other.comms_address.pubkey_hash.clone(),
                    other.nonces.clone().unwrap(),
                ));
            }
        }
        self.request_helper(program_context, nonces, CommsMessageType::PublicNonces)?;

        self.save_retry(StoreKey::LastRequestNonces(self.program_id))?;
        self.save()?;
        Ok(())
    }

    pub fn receive_nonces(
        &mut self,
        comms_address: CommsAddress,
        msg_type: CommsMessageType,
        data: Value,
        program_context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        if !self.state.should_handle_msg(&msg_type) {
            if self.state.should_answer_ack(self.im_leader(), &msg_type) {
                self.send_ack(
                    program_context,
                    comms_address,
                    CommsMessageType::PublicNoncesAck,
                )?;
            }
            return Ok(());
        }

        //TODO: Santitize pariticipant_pub_key with message origin
        let nonces_msg = parse_nonces(data).map_err(|_| BitVMXError::InvalidMessageFormat)?;

        for (pubkey_hash, particpant_nonces) in nonces_msg {
            let other_pos = get_other_index_by_pubkey_hash(&pubkey_hash, &self.participants)
                .ok_or(BitVMXError::InvalidParticipant(pubkey_hash))?;
            debug!("{}. Got nonces for pos: {}", self.my_idx, other_pos);
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
                        debug!(
                            "will get nonces for: {} {:?} {:?} {:?} ",
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
                program_context.key_chain.add_nonces(
                    &aggregated,
                    pubkey_nonce_map,
                    &self.protocol.context().protocol_name,
                )?;
            }

            self.move_program_to_next_state()?;
            info!("{}. All nonces ready", self.my_idx);
        } else {
            info!("{}. Not all nonces ready", self.my_idx);
        }

        self.send_ack(
            &program_context,
            comms_address,
            CommsMessageType::PublicNoncesAck,
        )?;
        Ok(())
    }

    pub fn send_signatures(&mut self, program_context: &ProgramContext) -> Result<(), BitVMXError> {
        let should_send_request =
            self.should_send_request(StoreKey::LastRequestSignatures(self.program_id))?;

        if !should_send_request {
            return Ok(());
        }

        debug!("{}. Sending PartialSignatures", self.my_idx);
        let mut partial_sig_msg: PartialSignatureMessage = Vec::new();
        for aggregated in self.participants[self.my_idx]
            .keys
            .as_ref()
            .unwrap()
            .computed_aggregated
            .values()
        {
            let signatures = program_context
                .key_chain
                .get_signatures(aggregated, &self.protocol.context().protocol_name);
            if signatures.is_err() {
                warn!(
                    "{}. Error getting partial signature for aggregated key: {}",
                    self.my_idx,
                    aggregated.to_string()
                );
                continue;
            }

            let my_pub = program_context
                .key_chain
                .key_manager
                .get_my_public_key(aggregated)?;
            debug!(
                "{}. Sending partial signatures for aggregated key: {} {:?} {:?}",
                self.my_idx, aggregated, my_pub, signatures
            );
            partial_sig_msg.push((aggregated.clone(), my_pub, signatures.unwrap()));
        }

        self.participants[self.my_idx].partial = Some(partial_sig_msg);
        debug!("I'm {} and I'm setting my partial", self.my_idx);

        let mut partials = vec![];
        for other in &self.participants {
            if other.partial.is_some() {
                partials.push((
                    other.comms_address.pubkey_hash.clone(),
                    other.partial.clone().unwrap(),
                ));
            }
        }
        self.request_helper(
            program_context,
            partials,
            CommsMessageType::PartialSignatures,
        )?;

        self.save_retry(StoreKey::LastRequestSignatures(self.program_id))?;
        self.save()?;
        Ok(())
    }

    pub fn receive_signatures(
        &mut self,
        comms_address: CommsAddress,
        msg_type: CommsMessageType,
        data: Value,
        program_context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        if !self.state.should_handle_msg(&msg_type) {
            if self.state.should_answer_ack(self.im_leader(), &msg_type) {
                self.send_ack(
                    program_context,
                    comms_address,
                    CommsMessageType::PartialSignaturesAck,
                )?;
            }
            return Ok(());
        }

        let partial_msg = parse_signatures(data).map_err(|_| BitVMXError::InvalidMessageFormat)?;
        for (pubkey_hash, particpant_partials) in partial_msg {
            let other_pos = get_other_index_by_pubkey_hash(&pubkey_hash, &self.participants)
                .ok_or(BitVMXError::InvalidParticipant(pubkey_hash))?;
            debug!("{}. Got partials for pos: {}", self.my_idx, other_pos);
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
                        debug!(
                            "Program {}: agg: {}, other: {} Received signatures: {:?}",
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
                program_context.key_chain.add_signatures(
                    &aggregated,
                    partial_map,
                    &self.protocol.context().protocol_name,
                )?;
            }

            self.protocol.sign(&program_context.key_chain)?;
            self.move_program_to_next_state()?;
            info!("{}. All signatures received", self.my_idx);
        }

        self.send_ack(
            program_context,
            comms_address,
            CommsMessageType::PartialSignaturesAck,
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
                let (txns_to_monitor, vouts_to_monitor) =
                    self.get_transactions_to_monitor(program_context)?;

                let context = Context::ProgramId(self.program_id);
                let txs_to_monitor =
                    TypesToMonitor::Transactions(txns_to_monitor.clone(), context.to_string()?);

                program_context
                    .bitcoin_coordinator
                    .monitor(txs_to_monitor)?;

                for (txid, vout) in vouts_to_monitor {
                    info!(
                        "Monitoring vout {} of txid {} for program {}",
                        vout, txid, self.program_id
                    );
                    let vout_to_monitor =
                        TypesToMonitor::SpendingUTXOTransaction(txid, vout, context.to_string()?);

                    program_context
                        .bitcoin_coordinator
                        .monitor(vout_to_monitor)?;
                }

                self.move_program_to_next_state()?;

                self.protocol.setup_complete(&program_context)?;

                let result = program_context.broker_channel.send(
                    &program_context.components_config.l2,
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

    pub fn process_comms_message(
        &mut self,
        comms_address: CommsAddress,
        msg_type: CommsMessageType,
        data: Value,
        program_context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        debug!("{}: Message received: {:?} ", self.my_idx, msg_type);

        match msg_type {
            CommsMessageType::VerificationKey => {
                //HPR: TO IMPLEMENT
                todo!()
            }
            CommsMessageType::Keys => {
                self.receive_keys(comms_address, msg_type, data, program_context)?;
            }
            CommsMessageType::PublicNonces => {
                self.receive_nonces(comms_address, msg_type, data, program_context)?;
            }
            CommsMessageType::PartialSignatures => {
                self.receive_signatures(comms_address, msg_type, data, program_context)?;
            }
            CommsMessageType::KeysAck
            | CommsMessageType::PublicNoncesAck
            | CommsMessageType::PartialSignaturesAck => {
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
        comms_address: CommsAddress,
        msg_type: CommsMessageType,
    ) -> Result<(), BitVMXError> {
        debug!("{}. Sending {:?}", self.my_idx, msg_type);

        response(
            &program_context.comms,
            &program_context.key_chain,
            &self.program_id,
            comms_address,
            msg_type,
            (),
        )?;

        Ok(())
    }

    pub fn get_transaction_by_name(
        &self,
        program_context: &ProgramContext,
        name: &str,
    ) -> Result<Transaction, BitVMXError> {
        Ok(self
            .protocol
            .get_transaction_by_name(name, program_context)?
            .0)
    }

    pub fn dispatch_transaction_name(
        &self,
        program_context: &ProgramContext,
        name: &str,
    ) -> Result<(), BitVMXError> {
        //TODO: Get transactions by identification
        let (tx_to_dispatch, speedup) = self
            .protocol
            .get_transaction_by_name(name, program_context)?;

        let context = Context::ProgramId(self.program_id);

        info!(
            "Dispatching transaction: {} and speedup: {:?}",
            style(tx_to_dispatch.compute_txid()).green(),
            style(speedup.is_some()).yellow(),
        );

        program_context.bitcoin_coordinator.dispatch(
            tx_to_dispatch,
            speedup,
            context.to_string()?,
            None,
        )?;

        Ok(())
    }

    pub fn notify_news(
        &self,
        tx_id: Txid,
        vout: Option<u32>,
        tx_status: TransactionStatus,
        context: String,
        program_context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        let participant_keys = self
            .participants
            .iter()
            .map(|p| p.keys.as_ref().unwrap())
            .collect::<Vec<_>>();

        self.protocol.notify_news(
            tx_id,
            vout,
            tx_status.clone(),
            context,
            program_context,
            participant_keys,
        )?;

        let name = self.protocol.get_transaction_name_by_id(tx_id)?;
        if vout.is_some() {
            /* DON'T SEND AUTOMATICALLY FOR NOW
            program_context.broker_channel.send(
                L2_ID,
                OutgoingBitVMXApiMessages::SpendingUTXOTransactionFound(
                    self.program_id,
                    tx_id,
                    vout.unwrap(),
                    tx_status.clone(),
                )
                .to_string()?,
            )?;*/
        } else {
            program_context.broker_channel.send(
                &program_context.components_config.l2,
                OutgoingBitVMXApiMessages::Transaction(self.program_id, tx_status, Some(name))
                    .to_string()?,
            )?;
        }

        Ok(())
    }

    pub fn get_transactions_to_monitor(
        &self,
        program_context: &ProgramContext,
    ) -> Result<(Vec<Txid>, Vec<(Txid, u32)>), BitVMXError> {
        self.protocol.get_transactions_to_monitor(program_context)
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
