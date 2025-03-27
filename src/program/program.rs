use crate::{
    config::ClientConfig,
    errors::{BitVMXError, ProgramError},
    p2p_helper::{request, response, P2PMessageType},
    types::{ProgramContext, ProgramRequestInfo},
};
use bitcoin::{absolute::LockTime, transaction::Version, Transaction, Txid};
use bitcoin_coordinator::types::TransactionNew;
use chrono::Utc;
use key_manager::{
    musig2::{types::MessageId, PartialSignature, PubNonce},
    winternitz::WinternitzSignature,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, rc::Rc};
use storage_backend::storage::{KeyValueStore, Storage};
use tracing::info;
use uuid::Uuid;

use super::{
    dispute::{DisputeResolutionProtocol, Funding, SearchParams},
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
        funding: Funding,
        storage: Rc<Storage>,
        config: ClientConfig,
    ) -> Result<Self, ProgramError> {
        let drp = DisputeResolutionProtocol::new(funding, program_id, storage.clone())?;

        let program = Program {
            program_id,
            my_role,
            me,
            other,
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

        let participant_keys = vec![my_protocol_key, other_protocol_key];

        // 2. Init the musig2 signer for this program
        context
            .key_chain
            .init_musig2(self.program_id, participant_keys, my_protocol_key)?;

        // 3. Aggregate the participants public keys
        let aggregated_key = context.key_chain.get_aggregated_pubkey(self.program_id)?;

        // 4. Build the protocol using the aggregated key as internal key for taproot
        self.drp.build(
            &self.program_id.to_string(),
            &aggregated_key,
            self.get_prover().keys.as_ref().unwrap(),
            self.get_verifier().keys.as_ref().unwrap(),
            search_params,
            &context.key_chain,
        )?;

        // 5. Get all the protocol sighashes
        // let sighashes: Vec<(MessageId, Message)> = self.drp.protocol_sighashes()?
        //     .into_iter()
        //     .map(|(id, msg)| (MessageId::from(id.to_string()), msg))
        //     .collect();

        // 6. Generate the pubnonces for each sighash
        // for (id, msg) in sighashes {
        //     context.key_chain.generate_pub_nonce(self.program_id, &id, msg)?;
        // }

        // 7. Move the program to the next state
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

        //key_chain.get_aggregated_signature(self.program_id, &id.to_string())?;

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
        //TODO: get the full DAG of the protocol and remove the hardcoded txs

        let txs = vec![
            "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
                .parse::<Txid>()
                .unwrap(),
            "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
                .parse::<Txid>()
                .unwrap(),
            "9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba"
                .parse::<Txid>()
                .unwrap(),
        ];

        Ok(txs)
    }

    pub fn get_tx_to_dispatch(&self) -> Result<Option<Transaction>, BitVMXError> {
        //TODO: This is hardcoded for now, this should return None or the answer of the protocol with a transaction to dispatch.
        let _tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![],
        };

        Ok(None)
    }
}
