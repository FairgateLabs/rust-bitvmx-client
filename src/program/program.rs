use crate::{
    bitvmx::Context,
    config::ClientConfig,
    errors::{BitVMXError, ProgramError},
    helper::{
        parse_keys, parse_nonces, parse_signatures, PartialSignatureMessage, PubNonceMessage,
    },
    p2p_helper::{request, response, P2PMessageType},
    program::dispute,
    types::{OutgoingBitVMXApiMessages, ProgramContext, ProgramRequestInfo, L2_ID},
};
use bitcoin::{PublicKey, Transaction, Txid};
use bitcoin_coordinator::{coordinator::BitcoinCoordinatorApi, TransactionStatus, TypesToMonitor};
use chrono::Utc;
use key_manager::{
    musig2::{types::MessageId, PartialSignature, PubNonce},
    winternitz::{self, WinternitzSignature, WinternitzType},
};
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
    witness,
};

#[derive(Clone, Serialize, Deserialize)]
pub struct WitnessData {
    values: HashMap<String, WinternitzSignature>,
}

impl Default for WitnessData {
    fn default() -> Self {
        Self::new()
    }
}

impl WitnessData {
    pub fn new() -> Self {
        Self {
            values: HashMap::new(),
        }
    }

    pub fn insert(&mut self, name: String, value: WinternitzSignature) {
        self.values.insert(name, value);
    }

    pub fn get(&self, name: &str) -> Option<&WinternitzSignature> {
        self.values.get(name)
    }
}

//use crate::program::protocol_handler::ProtocolHandler;

//#[derive(Clone, Serialize, Deserialize)]

#[derive(Debug, Clone)]
pub enum StoreKey {
    LastRequestKeys(Uuid),
    LastRequestNonces(Uuid),
    LastRequestSignatures(Uuid),
    Program(Uuid),
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Program {
    pub program_id: Uuid,
    pub my_role: ParticipantRole,
    pub me: ParticipantData,
    pub others: Vec<ParticipantData>,
    pub utxo: Utxo,
    pub drp: ProtocolType, //TODO: this might be generic
    pub state: ProgramState,
    witness_data: HashMap<Txid, WitnessData>,
    #[serde(skip)]
    storage: Option<Rc<Storage>>,
    config: ClientConfig,
}

impl Program {
    pub fn load(storage: Rc<Storage>, program_id: &Uuid) -> Result<Self, ProgramError> {
        let program = storage.get(Self::get_key(StoreKey::Program(*program_id)))?;
        let mut program: Program = program.ok_or(ProgramError::ProgramNotFound(*program_id))?;

        program.storage = Some(storage.clone());
        program.drp.set_storage(storage);

        Ok(program)
    }

    pub fn save(&self) -> Result<(), ProgramError> {
        let key = Self::get_key(StoreKey::Program(self.program_id));
        self.storage.as_ref().unwrap().set(key, self, None)?;
        Ok(())
    }

    pub fn setup_slot(
        id: &Uuid,
        peers: Vec<P2PAddress>,
        _leader: u16,
        utxo: Utxo,
        program_context: &mut ProgramContext,
        storage: Rc<Storage>,
        config: &ClientConfig,
    ) -> Result<Self, BitVMXError> {
        // Generate my keys.
        let my_keys = SlotProtocol::generate_keys(&mut program_context.key_chain)?;

        let p2p_address = P2PAddress::new(
            &program_context.comms.get_address(),
            program_context.comms.get_peer_id(),
        );
        // Create a participant that represents me with the specified role (Prover or Verifier).
        let me = ParticipantData::new(&p2p_address, Some(my_keys));

        //Creates space for the participants
        let others = peers
            .iter()
            .map(|peer| ParticipantData::new(peer, None))
            .collect::<Vec<_>>();

        // Create a program with the utxo information, and the dispute resolution search parameters.
        let drp = ProtocolType::SlotProtocol(SlotProtocol::new(*id, storage.clone()));

        let program = Self {
            program_id: *id,
            my_role: ParticipantRole::Prover, //TODO: This should be part of the protocol context and generic
            me,
            others,
            utxo,
            drp,
            state: ProgramState::New,
            witness_data: HashMap::new(),
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

        let program = Self {
            program_id: *id,
            my_role,
            me,
            others: vec![other],
            utxo,
            drp,
            state: ProgramState::New,
            witness_data: HashMap::new(),
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
        let mut aggregated_keys = vec![("pregenerated".to_string(), self.utxo.pub_key)];
        let mut result = HashMap::new();

        for agg_name in &self.me.keys.as_ref().unwrap().aggregated {
            let agg_key = self
                .me
                .keys
                .as_ref()
                .unwrap()
                .get_public(agg_name)
                .map_err(|_| BitVMXError::InvalidMessageFormat)?;

            let mut aggregated_pub_keys = vec![agg_key.clone()];

            for other in &self.others {
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
        self.me.keys.as_mut().unwrap().computed_aggregated = result.clone();
        Ok(result)
    }

    pub fn build_protocol(&mut self, context: &ProgramContext) -> Result<(), BitVMXError> {
        let search_params = SearchParams::new(8, 32);

        let aggregated = self.prepare_aggregated_keys(context)?;

        // 3. Build the protocol using the aggregated key as internal key for taproot
        info!("Building protocol for: {:?}", self.my_role);

        let (prover_key, verifier_key) = match self.my_role {
            ParticipantRole::Prover => (&self.me, &self.others[0]),
            ParticipantRole::Verifier => (&self.others[0], &self.me),
        };

        self.drp.as_drp_mut().unwrap().build(
            self.utxo.clone(),
            prover_key.keys.as_ref().unwrap(),
            verifier_key.keys.as_ref().unwrap(),
            aggregated,
            search_params,
            &context.key_chain,
        )?;
        info!("Protocol built for role: {:?}", self.my_role);

        // 6. Move the program to the next state
        self.move_program_to_next_state()?;

        Ok(())
    }

    pub fn receive_participant_nonces(
        &mut self,
        nonces: Vec<(MessageId, PubNonce)>,
        aggregated: &PublicKey,
        participant_pubkey: &PublicKey,
        context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        //the participant key is WRONG NEEDS TO BE THE ONE FROM THE AGGREGATED
        context
            .key_chain
            .add_nonces(aggregated, Some(participant_pubkey), nonces)?;

        Ok(())
    }

    pub fn sign_protocol(
        &mut self,
        signatures: Vec<(MessageId, PartialSignature)>,
        context: &ProgramContext,
        aggreagted: &PublicKey,
        other_pubkey: &PublicKey,
    ) -> Result<(), BitVMXError> {
        //let other_pubkey = self.other.keys.as_ref().unwrap().protocol();
        context
            .key_chain
            .add_signatures(aggreagted, signatures, other_pubkey)?;

        Ok(())
    }

    pub fn prekickoff_transaction(&self) -> Result<Transaction, BitVMXError> {
        self.drp
            .as_drp()
            .unwrap()
            .prekickoff_transaction()
            .map_err(BitVMXError::from)
    }

    pub fn push_witness_value(&mut self, txid: Txid, name: &str, value: WinternitzSignature) {
        self.witness_data
            .entry(txid)
            .or_default()
            .insert(name.to_string(), value);
    }

    pub fn witness(&self, txid: Txid) -> Option<&WitnessData> {
        self.witness_data.get(&txid)
    }

    pub fn tick(&mut self, program_context: &ProgramContext) -> Result<(), BitVMXError> {
        match &self.state {
            ProgramState::New => {
                self.move_program_to_next_state()?;
            }

            ProgramState::SettingUp(SettingUpState::SendingKeys) => {
                let my_keys = self.me.keys.clone().unwrap();

                let should_send_request =
                    self.should_send_request(StoreKey::LastRequestKeys(self.program_id))?;

                if !should_send_request {
                    return Ok(());
                }

                info!("{:?}: Sending keys", self.my_role);

                request(
                    &program_context.comms,
                    &self.program_id,
                    self.others[0].p2p_address.clone(),
                    P2PMessageType::Keys,
                    my_keys,
                )?;

                self.save_retry(StoreKey::LastRequestKeys(self.program_id))?;
            }
            ProgramState::SettingUp(SettingUpState::SendingNonces) => {
                let should_send_request =
                    self.should_send_request(StoreKey::LastRequestNonces(self.program_id))?;

                if !should_send_request {
                    return Ok(());
                }

                info!("{:?}: Sending nonces", self.my_role);

                let mut public_nonce_msg: PubNonceMessage = Vec::new();
                for aggregated in self.me.keys.as_ref().unwrap().computed_aggregated.values() {
                    let nonces = program_context.key_chain.get_nonces(aggregated)?;
                    let my_pub = program_context
                        .key_chain
                        .key_manager
                        .get_my_public_key(aggregated)?;
                    public_nonce_msg.push((aggregated.clone(), my_pub, nonces));
                }

                request(
                    &program_context.comms,
                    &self.program_id,
                    self.others[0].p2p_address.clone(),
                    P2PMessageType::PublicNonces,
                    public_nonce_msg,
                )?;

                self.save_retry(StoreKey::LastRequestNonces(self.program_id))?;
            }
            ProgramState::SettingUp(SettingUpState::SendingSignatures) => {
                let should_send_request =
                    self.should_send_request(StoreKey::LastRequestSignatures(self.program_id))?;

                if !should_send_request {
                    return Ok(());
                }

                info!("{:?}: Sending PartialSignatures", self.my_role);
                let mut partial_sig_msg: PartialSignatureMessage = Vec::new();
                for aggregated in self.me.keys.as_ref().unwrap().computed_aggregated.values() {
                    debug!(
                        "Program {}: Sending partial signatures for aggregated key: {}",
                        self.program_id, aggregated
                    );
                    let signatures = program_context.key_chain.get_signatures(aggregated)?;
                    let my_pub = program_context
                        .key_chain
                        .key_manager
                        .get_my_public_key(aggregated)?;
                    partial_sig_msg.push((aggregated.clone(), my_pub, signatures));
                }

                request(
                    &program_context.comms,
                    &self.program_id,
                    self.others[0].p2p_address.clone(),
                    P2PMessageType::PartialSignatures,
                    partial_sig_msg,
                )?;

                self.save_retry(StoreKey::LastRequestSignatures(self.program_id))?;
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
        msg_type: P2PMessageType,
        data: Value,
        program_context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        info!("{}: Message received: {:?} ", self.my_role, msg_type);

        match msg_type {
            P2PMessageType::Keys => {
                if !self.state.should_handle_msg(&msg_type) {
                    if self.state.should_answer_ack(&self.my_role, &msg_type) {
                        self.send_ack(program_context, P2PMessageType::KeysAck)?;
                    }
                    return Ok(());
                }

                // Parse the keys received
                let keys = parse_keys(data).map_err(|_| BitVMXError::InvalidMessageFormat)?;
                //save others key
                self.others[0].keys = Some(keys);
                self.save()?;

                //TODO :if all the keys ready
                // Build the protocol
                self.build_protocol(program_context)?;

                // Send ack to the other party
                self.send_ack(program_context, P2PMessageType::KeysAck)?;
            }
            P2PMessageType::PublicNonces => {
                // TODO: Review this condition
                if !self.state.should_handle_msg(&msg_type) {
                    if self.state.should_answer_ack(&self.my_role, &msg_type) {
                        self.send_ack(program_context, P2PMessageType::PublicNoncesAck)?;
                    }
                    return Ok(());
                }

                //TODO: Santitize pariticipant_pub_key with message origin
                let nonces_msg =
                    parse_nonces(data).map_err(|_| BitVMXError::InvalidMessageFormat)?;
                debug!(
                    "Program {}: Received nonces: {:#?}",
                    self.program_id, nonces_msg
                );
                for (aggregated, participant_pub_key, nonces) in nonces_msg {
                    self.receive_participant_nonces(
                        nonces,
                        &aggregated,
                        &participant_pub_key,
                        program_context,
                    )?;
                }

                self.move_program_to_next_state()?;
                self.send_ack(&program_context, P2PMessageType::PublicNoncesAck)?;
            }
            P2PMessageType::PartialSignatures => {
                // TODO: Review this condition
                if !self.state.should_handle_msg(&msg_type) {
                    if self.state.should_answer_ack(&self.my_role, &msg_type) {
                        self.send_ack(program_context, P2PMessageType::PartialSignaturesAck)?;
                    }
                    return Ok(());
                }

                let partial =
                    parse_signatures(data).map_err(|_| BitVMXError::InvalidMessageFormat)?;
                for (aggregated, other_pub_key, signatures) in partial {
                    debug!(
                        "Program {}: agg: {}, other: {} Received signatures: {:#?}",
                        self.program_id, aggregated, other_pub_key, signatures
                    );
                    self.sign_protocol(signatures, program_context, &aggregated, &other_pub_key)?;
                }

                self.drp.sign(&program_context.key_chain)?;
                self.move_program_to_next_state()?;

                self.send_ack(program_context, P2PMessageType::PartialSignaturesAck)?;
            }
            P2PMessageType::KeysAck
            | P2PMessageType::PublicNoncesAck
            | P2PMessageType::PartialSignaturesAck => {
                if !self.state.should_handle_msg(&msg_type) {
                    info!(
                        "Ignoring message {} {:?} {:?}",
                        self.my_role, msg_type, self.state
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
        msg_type: P2PMessageType,
    ) -> Result<(), BitVMXError> {
        info!("{:?}: Sending {:?}", self.my_role, msg_type);

        response(
            &program_context.comms,
            &self.program_id,
            self.others[0].p2p_address.peer_id.clone(),
            msg_type,
            (),
        )?;

        Ok(())
    }

    pub fn dispatch_transaction_name(
        &self,
        program_context: &ProgramContext,
        _name: &str,
    ) -> Result<(), BitVMXError> {
        //TODO: Get transactions by identification
        let tx_to_dispatch = self.drp.as_drp().unwrap().prekickoff_transaction()?;

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
        _context: String,
        program_context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        //TODO: for each tx the protocol should decide something to do
        let name = self.drp.get_transaction_name_by_id(tx_id)?;
        info!(
            "Program {}: Transaction {} has been seen on-chain",
            self.program_id, name
        );

        if name == dispute::START_CH
            && tx_status.confirmations == 5
            && self.my_role == ParticipantRole::Prover
        {
            //TODO: inform whoever is needed
            // now act here to test

            let tx_to_dispatch = self
                .drp
                .as_drp()
                .unwrap()
                .input_1_tx(0x1234_4444, &program_context.key_chain)?;

            let context = Context::ProgramId(self.program_id);
            program_context
                .bitcoin_coordinator
                .dispatch(tx_to_dispatch, context.to_string()?)?;
        }

        if name == dispute::INPUT_1
            && tx_status.confirmations == 5
            && self.my_role == ParticipantRole::Verifier
        {
            //self.drp.
            //size is from def

            //let wpub = self .get_prover() .keys .as_ref() .unwrap() .get_winternitz("program_input") .unwrap();
            let witness = tx_status.tx.input[0].witness.clone();
            let data = self.decode_witness_data(vec![4], WinternitzType::HASH160, witness)?;
            //info!("message bytes {:?}", data[0].message_bytes());
            //from vec<u8> be bytes to u32
            let message = u32::from_be_bytes(data[0].message_bytes().try_into().unwrap());
            warn!(
                "Program {}:{} Witness data decoded: {:0x}",
                self.program_id, name, message
            );
        }

        Ok(())
    }

    fn decode_witness_data(
        &self,
        winternitz_message_sizes: Vec<usize>,
        winternitz_type: winternitz::WinternitzType,
        witness: bitcoin::Witness,
    ) -> Result<Vec<winternitz::WinternitzSignature>, BitVMXError> {
        witness::decode_witness(winternitz_message_sizes, winternitz_type, witness)
    }

    pub fn get_txs_to_monitor(&self) -> Result<Vec<Txid>, BitVMXError> {
        self.drp.get_transaction_ids().map_err(BitVMXError::from)
    }

    /*pub fn get_tx_to_dispatch(&self) -> Result<Option<Transaction>, BitVMXError> {
        if self.my_role == ParticipantRole::Prover {
            return Ok(Some(self.drp.prekickoff_transaction()?));
        } else {
            return Ok(None);
        }
    }*/
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
        self.state = self.state.next_state(&self.my_role);
        self.save()?;
        Ok(())
    }

    pub fn get_tx_by_id(&self, txid: Txid) -> Result<Transaction, BitVMXError> {
        if self.state.is_setting_up() {
            return Err(BitVMXError::ProgramNotReady(self.program_id));
        }

        self.drp
            .get_transaction_by_id(&txid)
            .map_err(BitVMXError::from)
            .map_err(BitVMXError::from)
    }
}
