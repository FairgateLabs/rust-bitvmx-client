use bitcoin::{Transaction, Txid};
use key_manager::winternitz::WinternitzSignature;
use p2p_handler::P2pHandler;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fmt, rc::Rc};
use storage_backend::storage::{KeyValueStore, Storage};
use tracing::info;
use uuid::Uuid;

use crate::{
    errors::{BitVMXError, ProgramError},
    p2p::p2p_manager::{send_keys, send_nonces, send_signatures},
};

use super::{
    dispute::{DisputeResolutionProtocol, Funding, SearchParams},
    participant::{Participant, ParticipantKeys, ParticipantRole},
};

#[derive(PartialEq, Clone, Serialize, Deserialize, Debug)]
pub enum ProgramState {
    Inactive,
    Ready,
    Claimed,
    Challenged,
    KeySent,
    NonceSent,
    SignSent,
    DeployProgram,
    Error, //TODO: check somewhere
}

impl fmt::Display for ProgramState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ProgramState::Inactive => write!(f, "Inactive"),
            ProgramState::Ready => write!(f, "Ready"),
            ProgramState::Claimed => write!(f, "Claimed"),
            ProgramState::Challenged => write!(f, "Challenged"),
            ProgramState::KeySent => write!(f, "KeySent"),
            ProgramState::NonceSent => write!(f, "NonceSent"),
            ProgramState::SignSent => write!(f, "SignSent"),
            ProgramState::DeployProgram => write!(f, "DeployProgram"),
            ProgramState::Error => write!(f, "Error"),
        }
    }
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
    id: Uuid,
    my_role: ParticipantRole,
    prover: Participant,
    verifier: Participant,
    drp: DisputeResolutionProtocol,
    state: ProgramState,
    _trace: Trace,
    _ending_state: u8,
    _ending_step_number: u32,
    witness_data: HashMap<Txid, WitnessData>,
    #[serde(skip)]
    storage: Option<Rc<Storage>>,
}

impl Program {
    pub fn new(
        id: Uuid,
        my_role: ParticipantRole,
        prover: Participant,
        verifier: Participant,
        funding: Funding,
        storage: Rc<Storage>,
    ) -> Result<Self, ProgramError> {
        let drp = DisputeResolutionProtocol::new(funding, id, storage.clone())?;

        let program = Program {
            id,
            my_role,
            prover,
            verifier,
            drp,
            state: ProgramState::Inactive,
            _trace: Trace {},
            _ending_state: 0,
            _ending_step_number: 0,
            witness_data: HashMap::new(),
            storage: Some(storage),
        };

        program.save()?;

        Ok(program)
    }

    pub fn load(storage: Rc<Storage>, program_id: &Uuid) -> Result<Self, ProgramError> {
        let mut program: Program = match storage.get(&format!("program_{}", program_id))? {
            Some(program) => program,
            None => return Err(ProgramError::ProgramNotFound(*program_id)),
        };

        program.storage = Some(storage.clone());
        program.drp.set_storage(storage);

        Ok(program)
    }

    pub fn save(&self) -> Result<Uuid, ProgramError> {
        let key = format!("program_{}", self.id);
        self.storage.clone().unwrap().set(key, self, None)?;
        Ok(self.id)
    }

    pub fn setup_counterparty_keys(&mut self, keys: ParticipantKeys) -> Result<(), BitVMXError> {
        match self.my_role {
            ParticipantRole::Prover => self.verifier.set_keys(keys),
            ParticipantRole::Verifier => self.prover.set_keys(keys),
        }

        let search_params = SearchParams::new(8, 32);

        self.drp.build_protocol(
            self.prover.keys().as_ref().unwrap(),
            self.verifier.keys().as_ref().unwrap(),
            search_params,
        )?;

        Ok(())
    }

    pub fn prekickoff_transaction(&self) -> Result<Transaction, BitVMXError> {
        self.dispute_resolution_protocol()
            .prekickoff_transaction()
            .map_err(BitVMXError::from)
    }

    pub fn kickoff_transaction(&self) -> Result<Transaction, BitVMXError> {
        self.dispute_resolution_protocol()
            .kickoff_transaction()
            .map_err(BitVMXError::from)
    }

    pub fn id(&self) -> Uuid {
        self.id
    }

    pub fn prover(&self) -> &Participant {
        &self.prover
    }

    pub fn verifier(&self) -> &Participant {
        &self.verifier
    }

    pub fn deploy(&mut self) {
        if self.state == ProgramState::Inactive {
            self.state = ProgramState::Ready;
        }
    }

    pub fn claim(&mut self) {
        if self.state == ProgramState::Ready {
            self.state = ProgramState::Claimed;
        }
    }

    pub fn challenge(&mut self) {
        if self.state == ProgramState::Claimed {
            self.state = ProgramState::Challenged;
        }
    }

    pub fn is_claimed(&self) -> bool {
        self.state == ProgramState::Claimed
    }

    pub fn is_ready(&self) -> bool {
        self.state == ProgramState::Ready
    }

    pub fn state(&self) -> &ProgramState {
        &self.state
    }

    pub fn funding_txid(&self) -> Txid {
        self.dispute_resolution_protocol().funding().txid()
    }

    pub fn funding_vout(&self) -> u32 {
        self.dispute_resolution_protocol().funding().vout()
    }

    pub fn funding_amount(&self) -> u64 {
        self.dispute_resolution_protocol()
            .funding()
            .amount()
            .to_sat()
    }

    pub fn protocol_amount(&self) -> u64 {
        self.dispute_resolution_protocol().funding().protocol()
    }

    pub fn timelock_amount(&self) -> u64 {
        self.dispute_resolution_protocol().funding().timelock()
    }

    pub fn speedup_amount(&self) -> u64 {
        self.dispute_resolution_protocol().funding().speedup()
    }

    pub fn dispute_resolution_protocol(&self) -> &DisputeResolutionProtocol {
        &self.drp
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

    fn send_keys(&mut self, comms: &mut P2pHandler) -> Result<(), BitVMXError> {
        //TODO: Ready = IDLE?
        if self.state == ProgramState::Ready {
            send_keys(
                comms,
                self.get_participant_me(),
                &self.id,
                *self.get_participant_other().address().peer_id(),
                self.get_address_if_prover(),
            )?;
            self.state = ProgramState::KeySent;
        } else {
            self.state = ProgramState::Error;
        }
        Ok(())
    }

    fn send_nonces(&mut self, comms: &mut P2pHandler) -> Result<(), BitVMXError> {
        if self.state == ProgramState::KeySent {
            send_nonces(
                comms,
                self.get_participant_me(),
                &self.id,
                *self.get_participant_other().address().peer_id(),
                self.get_address_if_prover(),
            )?;
            self.state = ProgramState::NonceSent;
        } else {
            self.state = ProgramState::Error;
        }
        Ok(())
    }

    fn send_signatures(&mut self, comms: &mut P2pHandler) -> Result<(), BitVMXError> {
        if self.state == ProgramState::NonceSent {
            match self.my_role {
                ParticipantRole::Prover => info!("Prover is signing program"),
                ParticipantRole::Verifier => info!("Verifier is signing program"),
            }
            //sign_program(); //TODO: add function to sign program
            send_signatures(
                comms,
                self.get_participant_me(),
                &self.id,
                *self.get_participant_other().address().peer_id(),
                self.get_address_if_prover(),
            )?;
            match self.my_role {
                ParticipantRole::Prover => self.state = ProgramState::SignSent,
                ParticipantRole::Verifier => {
                    self.state = ProgramState::DeployProgram;
                    self.deploy_program();
                }
            }
        } else {
            self.state = ProgramState::Error;
        }
        Ok(())
    }

    fn deploy_program(&mut self) {
        match self.my_role {
            ParticipantRole::Prover => info!("Deploying the prover program"),
            ParticipantRole::Verifier => info!("Deploying the verifier program"),
        }
        //deploy_program //TODO: add function to deploy program
    }

    pub fn get_participant_me(&self) -> &Participant {
        match self.my_role {
            ParticipantRole::Prover => &self.prover,
            ParticipantRole::Verifier => &self.verifier,
        }
    }

    pub fn get_participant_other(&self) -> &Participant {
        match self.my_role {
            ParticipantRole::Verifier => &self.prover,
            ParticipantRole::Prover => &self.verifier,
        }
    }

    fn get_address_if_prover(&self) -> Option<String> {
        match self.my_role {
            ParticipantRole::Prover => Some(self.verifier.address().address().to_string()),
            ParticipantRole::Verifier => None,
        }
    }

    pub fn tick(&mut self, comms: &mut P2pHandler) -> Result<(), BitVMXError> {
        match (&self.state, &self.my_role) {
            (ProgramState::Inactive, _) => {
                //TODO: take out, only for testing
                self.state = ProgramState::Ready;
                self.tick(comms)?;
            }

            (ProgramState::Ready, _) => self.send_keys(comms)?,
            (ProgramState::KeySent, _) => self.send_nonces(comms)?,
            (ProgramState::NonceSent, _) => self.send_signatures(comms)?, // Sign program and send signature
            (ProgramState::SignSent, ParticipantRole::Prover) => self.deploy_program(),

            _ => {
                self.state = ProgramState::Error;
            }
        }

        self.save()?;

        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Trace {}
