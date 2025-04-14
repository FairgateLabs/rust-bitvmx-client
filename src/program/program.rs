use crate::{
    bitvmx::Context, config::ClientConfig, errors::{BitVMXError, ProgramError}, helper::{parse_keys, parse_nonces, parse_signatures}, p2p_helper::{request, response, P2PMessageType}, program::dispute, types::{OutgoingBitVMXApiMessages, ProgramContext, ProgramRequestInfo, L2_ID}
};
use bitcoin::{PublicKey, Transaction, Txid};
use bitcoin_coordinator::{
    coordinator::BitcoinCoordinatorApi, TransactionMonitor, TransactionStatus,
};
use chrono::Utc;
use key_manager::{
    musig2::{types::MessageId, PartialSignature, PubNonce},
    winternitz::{self, WinternitzSignature, WinternitzType},
};
use protocol_builder::builder::Utxo;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::HashMap, rc::Rc};
use storage_backend::storage::{KeyValueStore, Storage};
use tracing::{info, warn};
use uuid::Uuid;

use super::{
    dispute::{DisputeResolutionProtocol, SearchParams},
    participant::{P2PAddress, ParticipantData, ParticipantKeys, ParticipantRole},
    witness,
};

#[derive(PartialEq, Clone, Serialize, Deserialize, Debug)]
pub enum ProgramState {
    /// Initial state when a program is first created
    New,

    /// Program is in setup phase, exchanging keys, nonces and signatures with counterparty.
    /// Contains a SettingUpState enum specifying the exact setup step.
    SettingUp(SettingUpState),

    /// Program setup is complete and is ready to send transactions monitor
    Monitoring,

    /// Program is dispatching transactions to the blockchain to complete the protocol
    /// TODO: Dispatching should have (Claimed, Challenged) inside it
    //Dispatching,

    /// Ready state after setup is completed and the transactions are being monitored
    Ready,
    // Program has been claimed by one party
    //Claimed,

    // Program has been challenged
    //Challenged,

    // Program encountered an error and cannot continue
    //Error,

    // Program has completed successfully
    //Completed,
}

#[derive(PartialEq, Clone, Serialize, Deserialize, Debug)]
pub enum SettingUpState {
    WaitingKeys,
    SendingKeys,
    WaitingNonces,
    SendingNonces,
    WaitingSignatures,
    SendingSignatures,
}

#[derive(Debug, Clone)]
enum StoreKey {
    LastRequestKeys(Uuid),
    LastRequestNonces(Uuid),
    LastRequestSignatures(Uuid),
    Program(Uuid),
}

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

#[derive(Clone, Serialize, Deserialize)]
pub struct Program {
    pub program_id: Uuid,
    pub my_role: ParticipantRole,
    pub me: ParticipantData,
    pub other: ParticipantData,
    pub utxo: Utxo,
    pub drp: DisputeResolutionProtocol, //TODO: this might be generic
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

    pub fn save_other_keys(&mut self, keys: ParticipantKeys) -> Result<(), BitVMXError> {
        self.other.keys = Some(keys);
        self.move_program_to_next_state()?;

        Ok(())
    }

    pub fn get_prover(&self) -> &ParticipantData {
        if self.my_role == ParticipantRole::Prover {
            &self.me
        } else {
            &self.other
        }
    }

    pub fn get_verifier(&self) -> &ParticipantData {
        if self.my_role == ParticipantRole::Verifier {
            &self.me
        } else {
            &self.other
        }
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
        let drp = DisputeResolutionProtocol::new(*id, storage.clone())?;

        let program = Self {
            program_id: *id,
            my_role,
            me,
            other,
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

    pub fn build_protocol(
        &mut self,
        context: &ProgramContext,
        keys: ParticipantKeys,
    ) -> Result<(), BitVMXError> {
        let search_params = SearchParams::new(8, 32);

        // 1. Save the received keys
        self.other.keys = Some(keys);

        //let my_protocol_key = self.me.keys.as_ref().unwrap().protocol();
        //let other_protocol_key = self.other.keys.as_ref().unwrap().protocol();

        /*let mut participant_keys = vec![my_protocol_key, other_protocol_key];
        participant_keys.sort();

        // 2. Init the musig2 signer for this program
        let aggregated_key = context.key_chain.new_musig2_session(
            self.program_id,
            participant_keys,
            my_protocol_key,
        )?;

        warn!(
            "Program {}: Aggregated key: {}",
            self.program_id,
            aggregated_key.to_string()
        );*/

        // 3. Build the protocol using the aggregated key as internal key for taproot
        info!("Building protocol for: {:?}", self.my_role);
        self.drp.build(
            self.utxo.clone(),
            //&aggregated_key,
            self.get_prover().keys.as_ref().unwrap(),
            self.get_verifier().keys.as_ref().unwrap(),
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
        participant_pubkey: &PublicKey,
        context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        //the participant key is WRONG NEEDS TO BE THE ONE FROM THE AGGREGATED
        context
            .key_chain
            .add_nonces(&self.utxo.pub_key, Some(participant_pubkey), nonces)?;
        self.move_program_to_next_state()?;

        Ok(())
    }

    pub fn sign_protocol(
        &mut self,
        signatures: Vec<(MessageId, PartialSignature)>,
        context: &ProgramContext,
        other_pubkey: &PublicKey,
    ) -> Result<(), BitVMXError> {
        //let other_pubkey = self.other.keys.as_ref().unwrap().protocol();
        context
            .key_chain
            .add_signatures(&self.utxo.pub_key, signatures, other_pubkey)?;

        self.drp.sign(&context.key_chain)?;

        self.move_program_to_next_state()?;

        Ok(())
    }

    pub fn prekickoff_transaction(&self) -> Result<Transaction, BitVMXError> {
        self.drp.prekickoff_transaction().map_err(BitVMXError::from)
    }

    /*pub fn kickoff_transaction(&self) -> Result<Transaction, BitVMXError> {
        self.drp.kickoff_transaction().map_err(BitVMXError::from)
    }*/

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
                    self.other.p2p_address.clone(),
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

                //TODO: support multiple keys
                let nonces = program_context.key_chain.get_nonces(&self.utxo.pub_key)?;
                let my_pub = program_context
                    .key_chain
                    .key_manager
                    .get_my_public_key(&self.utxo.pub_key)?;

                request(
                    &program_context.comms,
                    &self.program_id,
                    self.other.p2p_address.clone(),
                    P2PMessageType::PublicNonces,
                    (my_pub, nonces),
                )?;

                self.save_retry(StoreKey::LastRequestNonces(self.program_id))?;
            }
            ProgramState::SettingUp(SettingUpState::SendingSignatures) => {
                let should_send_request =
                    self.should_send_request(StoreKey::LastRequestSignatures(self.program_id))?;

                if !should_send_request {
                    return Ok(());
                }

                //TODO: support multiple keys
                info!("{:?}: Sending PartialSignatures", self.my_role);
                let signatures = program_context
                    .key_chain
                    .get_signatures(&self.utxo.pub_key)?;
                let my_pub = program_context
                    .key_chain
                    .key_manager
                    .get_my_public_key(&self.utxo.pub_key)?;

                request(
                    &program_context.comms,
                    &self.program_id,
                    self.other.p2p_address.clone(),
                    P2PMessageType::PartialSignatures,
                    (my_pub, signatures),
                )?;

                self.save_retry(StoreKey::LastRequestSignatures(self.program_id))?;
            }
            ProgramState::Monitoring => {
                // After the program is ready, we need to monitor the transactions
                let txns_to_monitor = self.get_txs_to_monitor()?;

                // TODO : COMPLETE THE FUNDING TX FOR SPEED UP
                let txs_to_monitor = TransactionMonitor::Transactions(
                    txns_to_monitor.clone(),
                    self.program_id.to_string(),
                );

                program_context
                    .bitcoin_coordinator
                    .monitor(txs_to_monitor)?;

                let utox_to_monitor = TransactionMonitor::SpendingUTXOTransaction(
                    txns_to_monitor[0],
                    0,
                    "HELLO UTXO TRANSACTION".to_string(),
                );

                program_context
                    .bitcoin_coordinator
                    .monitor(utox_to_monitor)?;

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

    fn should_send_request(&mut self, key: StoreKey) -> Result<bool, BitVMXError> {
        let retry_delay = self.config.retry_delay;
        let last_request: ProgramRequestInfo = self
            .storage
            .as_ref()
            .unwrap()
            .get(Self::get_key(key.clone()))?
            .unwrap_or(ProgramRequestInfo::default());

        // info!(
        //     "Last request retries: {}, time: {:?}, key: {:?}",
        //     last_request.retries, last_request.last_request_time, key
        // );

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
        let next_state = match self.my_role {
            ParticipantRole::Prover => match self.state {
                ProgramState::New => ProgramState::SettingUp(SettingUpState::SendingKeys),
                ProgramState::SettingUp(SettingUpState::SendingKeys) => {
                    ProgramState::SettingUp(SettingUpState::WaitingKeys)
                }
                ProgramState::SettingUp(SettingUpState::WaitingKeys) => {
                    ProgramState::SettingUp(SettingUpState::SendingNonces)
                }
                ProgramState::SettingUp(SettingUpState::SendingNonces) => {
                    ProgramState::SettingUp(SettingUpState::WaitingNonces)
                }
                ProgramState::SettingUp(SettingUpState::WaitingNonces) => {
                    ProgramState::SettingUp(SettingUpState::SendingSignatures)
                }
                ProgramState::SettingUp(SettingUpState::SendingSignatures) => {
                    ProgramState::SettingUp(SettingUpState::WaitingSignatures)
                }
                ProgramState::SettingUp(SettingUpState::WaitingSignatures) => {
                    ProgramState::Monitoring
                }

                ProgramState::Monitoring => ProgramState::Ready,
                ProgramState::Ready => ProgramState::Ready,
                /*ProgramState::Claimed => ProgramState::Claimed,
                ProgramState::Challenged => ProgramState::Challenged,
                ProgramState::Error => ProgramState::Error,
                ProgramState::Completed => ProgramState::Completed,
                //TODO: This should change to Claimed or Challenged , there is 2 options .
                ProgramState::Dispatching => ProgramState::Dispatching,*/
            },
            ParticipantRole::Verifier => match self.state {
                ProgramState::New => ProgramState::SettingUp(SettingUpState::WaitingKeys),
                ProgramState::SettingUp(SettingUpState::WaitingKeys) => {
                    ProgramState::SettingUp(SettingUpState::SendingKeys)
                }
                ProgramState::SettingUp(SettingUpState::SendingKeys) => {
                    ProgramState::SettingUp(SettingUpState::WaitingNonces)
                }
                ProgramState::SettingUp(SettingUpState::WaitingNonces) => {
                    ProgramState::SettingUp(SettingUpState::SendingNonces)
                }
                ProgramState::SettingUp(SettingUpState::SendingNonces) => {
                    ProgramState::SettingUp(SettingUpState::WaitingSignatures)
                }
                ProgramState::SettingUp(SettingUpState::WaitingSignatures) => {
                    ProgramState::SettingUp(SettingUpState::SendingSignatures)
                }
                ProgramState::SettingUp(SettingUpState::SendingSignatures) => {
                    ProgramState::Monitoring
                }

                ProgramState::Monitoring => ProgramState::Ready,
                ProgramState::Ready => ProgramState::Ready,
                /*ProgramState::Claimed => ProgramState::Claimed,
                ProgramState::Challenged => ProgramState::Challenged,
                ProgramState::Error => ProgramState::Error,
                ProgramState::Completed => ProgramState::Completed,
                ProgramState::Dispatching => ProgramState::Dispatching,*/
            },
        };

        self.state = next_state;

        self.save()?;

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
                if !self.should_handle_msg(&msg_type) {
                    if self.should_answer_ack(&msg_type) {
                        self.send_ack(program_context, P2PMessageType::KeysAck)?;
                    }
                    return Ok(());
                }

                // Parse the keys received
                let keys = parse_keys(data).map_err(|_| BitVMXError::InvalidMessageFormat)?;

                // Build the protocol
                self.build_protocol(program_context, keys)?;

                // Send ack to the other party
                self.send_ack(program_context, P2PMessageType::KeysAck)?;
            }
            P2PMessageType::PublicNonces => {
                // TODO: Review this condition
                if !self.should_handle_msg(&msg_type) {
                    if self.should_answer_ack(&msg_type) {
                        self.send_ack(program_context, P2PMessageType::PublicNoncesAck)?;
                    }
                    return Ok(());
                }

                //TODO: Santitize pariticipant_pub_key with message origin
                let (participant_pub_key, nonces) =
                    parse_nonces(data).map_err(|_| BitVMXError::InvalidMessageFormat)?;

                self.receive_participant_nonces(nonces, &participant_pub_key, program_context)?;

                self.send_ack(&program_context, P2PMessageType::PublicNoncesAck)?;
            }
            P2PMessageType::PartialSignatures => {
                // TODO: Review this condition
                if !self.should_handle_msg(&msg_type) {
                    if self.should_answer_ack(&msg_type) {
                        self.send_ack(program_context, P2PMessageType::PartialSignaturesAck)?;
                    }
                    return Ok(());
                }

                let (other_pub_key, signatures) =
                    parse_signatures(data).map_err(|_| BitVMXError::InvalidMessageFormat)?;

                self.sign_protocol(signatures, program_context, &other_pub_key)?;

                //TODO Integration.
                //let signatures = program.get_aggregated_signatures();
                //self.program.save_signatures(signatures)?;

                self.send_ack(program_context, P2PMessageType::PartialSignaturesAck)?;
            }
            P2PMessageType::KeysAck
            | P2PMessageType::PublicNoncesAck
            | P2PMessageType::PartialSignaturesAck => {
                if !self.should_handle_msg(&msg_type) {
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

    pub fn should_answer_ack(&self, msg_type: &P2PMessageType) -> bool {
        if &self.my_role == &ParticipantRole::Prover {
            // Prover flow:
            // 1. Sends keys and waits for KeysAck
            // 2. Waits for Keys from verifier
            // 3. Sends nonces and waits for NoncesAck
            // 4. Waits for nonces from verifier
            // 5. Sends signatures and waits for SignaturesAck
            // 6. Waits for signatures from verifier
            match (&self.state, msg_type) {
                (ProgramState::SettingUp(SettingUpState::SendingNonces), P2PMessageType::Keys) => {
                    true
                }
                (
                    ProgramState::SettingUp(SettingUpState::SendingSignatures),
                    P2PMessageType::PublicNonces,
                ) => true,
                _ => false,
            }
        } else {
            // Verifier flow:
            // 1. Waits for keys from prover
            // 2. Sends keys and waits for KeysAck
            // 3. Waits for nonces from prover
            // 4. Sends nonces and waits for NoncesAck
            // 5. Waits for signatures from prover
            // 6. Sends signatures and waits for SignaturesAck
            match (&self.state, msg_type) {
                (ProgramState::SettingUp(SettingUpState::SendingKeys), P2PMessageType::Keys) => {
                    true
                }
                (
                    ProgramState::SettingUp(SettingUpState::SendingNonces),
                    P2PMessageType::PublicNonces,
                ) => true,
                (
                    ProgramState::SettingUp(SettingUpState::SendingSignatures),
                    P2PMessageType::PartialSignatures,
                ) => true,
                _ => false,
            }
        }
    }

    pub fn should_handle_msg(&self, msg_type: &P2PMessageType) -> bool {
        match (&self.state, msg_type) {
            (ProgramState::SettingUp(SettingUpState::WaitingKeys), P2PMessageType::Keys) => true,
            (
                ProgramState::SettingUp(SettingUpState::WaitingNonces),
                P2PMessageType::PublicNonces,
            ) => true,
            (
                ProgramState::SettingUp(SettingUpState::WaitingSignatures),
                P2PMessageType::PartialSignatures,
            ) => true,
            (ProgramState::SettingUp(SettingUpState::SendingKeys), P2PMessageType::KeysAck) => true,
            (
                ProgramState::SettingUp(SettingUpState::SendingNonces),
                P2PMessageType::PublicNoncesAck,
            ) => true,
            (
                ProgramState::SettingUp(SettingUpState::SendingSignatures),
                P2PMessageType::PartialSignaturesAck,
            ) => true,
            _ => false,
        }
    }
    pub fn is_active(&self) -> bool {
        let is_setting_up = self.is_setting_up();
        let is_monitoring = self.is_monitoring();
        //let is_dispatching = self.is_dispatching();
        is_setting_up || is_monitoring //|| is_dispatching
    }

    pub fn is_setting_up(&self) -> bool {
        matches!(self.state, ProgramState::New | ProgramState::SettingUp(_))
    }

    /*pub fn is_dispatching(&self) -> bool {
        matches!(self.state, ProgramState::Dispatching)
    }*/

    pub fn is_monitoring(&self) -> bool {
        self.state == ProgramState::Monitoring
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
            self.other.p2p_address.peer_id.clone(),
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
        let tx_to_dispatch = self.drp.prekickoff_transaction()?;

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
                .input_1_tx(0x1234_4444, &program_context.key_chain)?;

            program_context
                .bitcoin_coordinator
                .dispatch(tx_to_dispatch, self.program_id.to_string())?;
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

    pub fn get_tx_by_id(&self, txid: Txid) -> Result<Transaction, BitVMXError> {
        if self.is_setting_up() {
            return Err(BitVMXError::ProgramNotReady(self.program_id));
        }

        self.drp
            .get_transaction_by_id(txid)
            .map_err(BitVMXError::from)
            .map_err(BitVMXError::from)
    }
}
