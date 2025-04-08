use crate::{
    config::ClientConfig,
    errors::{BitVMXError, ProgramError},
    helper::{parse_keys, parse_nonces, parse_signatures},
    p2p_helper::{request, response, P2PMessageType},
    types::{OutgoingBitVMXApiMessages, ProgramContext, ProgramRequestInfo, L2_ID},
};
use bitcoin::{Transaction, Txid};
use bitcoin_coordinator::coordinator::BitcoinCoordinatorApi;
use bitcoin_coordinator::types::{BitvmxInstance, TransactionNew, TransactionPartialInfo};
use chrono::Utc;
use key_manager::{
    musig2::{types::MessageId, PartialSignature, PubNonce},
    winternitz::WinternitzSignature,
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
    participant::{ParticipantData, ParticipantKeys, ParticipantRole},
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
    Dispatching,

    /// Program has been claimed by one party
    Claimed,

    /// Program has been challenged
    Challenged,

    /// Program encountered an error and cannot continue
    Error,

    /// Program has completed successfully
    Completed,
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
    pub drp: DisputeResolutionProtocol,
    pub state: ProgramState,
    witness_data: HashMap<Txid, WitnessData>,
    #[serde(skip)]
    storage: Option<Rc<Storage>>,
    config: ClientConfig,
}

impl Program {
    pub fn new(
        program_id: Uuid,
        my_role: ParticipantRole,
        me: ParticipantData,
        other: ParticipantData,
        utxo: Utxo,
        storage: Rc<Storage>,
        config: ClientConfig,
    ) -> Result<Self, ProgramError> {
        let drp = DisputeResolutionProtocol::new(program_id, storage.clone())?;

        let program = Program {
            program_id,
            my_role,
            me,
            other,
            utxo,
            drp,
            state: ProgramState::New,
            witness_data: HashMap::new(),
            storage: Some(storage),
            config,
        };

        program.save()?;

        Ok(program)
    }

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

    pub fn build_protocol(
        &mut self,
        context: &ProgramContext,
        keys: ParticipantKeys,
    ) -> Result<(), BitVMXError> {
        let search_params = SearchParams::new(8, 32);

        // 1. Save the received keys
        self.other.keys = Some(keys);

        let my_protocol_key = self.me.keys.as_ref().unwrap().protocol;
        let other_protocol_key = self.other.keys.as_ref().unwrap().protocol;

        let mut participant_keys = vec![my_protocol_key, other_protocol_key];
        participant_keys.sort();

        // 2. Init the musig2 signer for this program
        let aggregated_key = context.key_chain.new_musig2_session(
            self.program_id,
            participant_keys,
            my_protocol_key,
        )?;

        // 3. Build the protocol using the aggregated key as internal key for taproot
        info!("Building protocol for: {:?}", self.my_role);
        self.drp.build(
            &self.program_id.to_string(),
            self.utxo.clone(),
            &aggregated_key,
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
        context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        let participant_key = self.other.keys.as_ref().unwrap().protocol;
        context
            .key_chain
            .add_nonces(self.program_id, nonces, participant_key)?;
        self.move_program_to_next_state()?;

        Ok(())
    }

    pub fn sign_protocol(
        &mut self,
        signatures: Vec<(MessageId, PartialSignature)>,
        context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        let other_pubkey = self.other.keys.as_ref().unwrap().protocol;
        context
            .key_chain
            .add_signatures(self.program_id, signatures, other_pubkey)?;

        self.drp
            .sign(&self.program_id.to_string(), &context.key_chain)?;

        self.move_program_to_next_state()?;

        Ok(())
    }

    pub fn prekickoff_transaction(&self) -> Result<Transaction, BitVMXError> {
        self.drp.prekickoff_transaction().map_err(BitVMXError::from)
    }

    pub fn kickoff_transaction(&self) -> Result<Transaction, BitVMXError> {
        self.drp.kickoff_transaction().map_err(BitVMXError::from)
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

    //TODO: Check if this shouldnt be part of the tick
    pub fn process_program(&mut self, program_context: &ProgramContext) -> Result<(), BitVMXError> {
        // info!("Program state: {:?}", program.state);
        if self.is_setting_up() {
            // info!("Program state is_setting_up: {:?}", program.state);
            // TODO: Improvement, I think this tick function we should have different name.
            // I think a better name could be proceed_with_setting_up
            // Besides that I think tick only exist as a function for a library to use it outside of the library.
            self.tick(program_context)?;

            return Ok(());
        }

        if self.is_monitoring() {
            // info!("Program state is_monitoring: {:?}", program.state);
            // After the program is ready, we need to monitor the transactions
            let txns_to_monitor = self.get_txs_to_monitor()?;

            // TODO : COMPLETE THE FUNDING TX FOR SPEED UP
            let txs_to_monitor: BitvmxInstance<TransactionPartialInfo> = BitvmxInstance::new(
                self.program_id,
                txns_to_monitor
                    .iter()
                    .map(|tx| TransactionPartialInfo::from(*tx))
                    .collect(),
                None,
            );

            program_context
                .bitcoin_coordinator
                .monitor_instance(&txs_to_monitor)?;

            self.move_program_to_next_state()?;

            let result = program_context.broker_channel.send(
                L2_ID,
                OutgoingBitVMXApiMessages::SetupCompleted(self.program_id).to_string()?,
            );
            if let Err(e) = result {
                warn!("Error sending setup completed message: {:?}", e);
                //TODO: Handle error and rollback
            }

            return Ok(());
        }

        if self.is_dispatching() {
            // info!("Program state is_dispatching: {:?}", program.state);
            let tx_to_dispatch: Option<Transaction> = self.get_tx_to_dispatch()?;

            if let Some(tx) = tx_to_dispatch {
                program_context
                    .bitcoin_coordinator
                    .send_tx_instance(self.program_id, &tx)?;
            }
            return Ok(());
        }
        Ok(())
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

                let nonces = program_context.key_chain.get_nonces(self.program_id)?;

                request(
                    &program_context.comms,
                    &self.program_id,
                    self.other.p2p_address.clone(),
                    P2PMessageType::PublicNonces,
                    nonces,
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
                let signatures = program_context.key_chain.get_signatures(self.program_id)?;

                request(
                    &program_context.comms,
                    &self.program_id,
                    self.other.p2p_address.clone(),
                    P2PMessageType::PartialSignatures,
                    signatures,
                )?;

                self.save_retry(StoreKey::LastRequestSignatures(self.program_id))?;
            }
            _ => {
                //self.state = ProgramState::Error;
            }
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

                ProgramState::Monitoring => ProgramState::Dispatching,
                ProgramState::Claimed => ProgramState::Claimed,
                ProgramState::Challenged => ProgramState::Challenged,
                ProgramState::Error => ProgramState::Error,
                ProgramState::Completed => ProgramState::Completed,
                //TODO: This should change to Claimed or Challenged , there is 2 options .
                ProgramState::Dispatching => ProgramState::Dispatching,
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

                ProgramState::Monitoring => ProgramState::Dispatching,
                ProgramState::Claimed => ProgramState::Claimed,
                ProgramState::Challenged => ProgramState::Challenged,
                ProgramState::Error => ProgramState::Error,
                ProgramState::Completed => ProgramState::Completed,
                ProgramState::Dispatching => ProgramState::Dispatching,
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

                let nonces = parse_nonces(data).map_err(|_| BitVMXError::InvalidMessageFormat)?;

                self.receive_participant_nonces(nonces, program_context)?;

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

                let signatures =
                    parse_signatures(data).map_err(|_| BitVMXError::InvalidMessageFormat)?;

                self.sign_protocol(signatures, program_context)?;

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
        let is_dispatching = self.is_dispatching();
        is_setting_up || is_monitoring || is_dispatching
    }

    pub fn is_setting_up(&self) -> bool {
        matches!(self.state, ProgramState::New | ProgramState::SettingUp(_))
    }

    pub fn is_dispatching(&self) -> bool {
        matches!(self.state, ProgramState::Dispatching)
    }

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
            self.other.p2p_address.peer_id,
            msg_type,
            (),
        )?;

        Ok(())
    }

    pub fn notify_news(&self, _txs: Vec<TransactionNew>) -> Result<(), BitVMXError> {
        //TODO: for each tx the protocol should decide something to do
        Ok(())
    }

    pub fn get_txs_to_monitor(&self) -> Result<Vec<Txid>, BitVMXError> {
        self.drp.get_transaction_ids().map_err(BitVMXError::from)
    }

    pub fn get_tx_to_dispatch(&self) -> Result<Option<Transaction>, BitVMXError> {
        if self.my_role == ParticipantRole::Prover {
            return Ok(Some(self.drp.prekickoff_transaction()?));
        } else {
            return Ok(None);
        }
    }

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
