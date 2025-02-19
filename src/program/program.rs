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
    participant::{ParticipantData, ParticipantKeys, ParticipantRole},
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
    pub id: Uuid,
    pub my_role: ParticipantRole,
    // TODO:  We need to find a better name here
    pub party_data: ParticipantData,
    pub counterparty_data: ParticipantData,
    pub drp: DisputeResolutionProtocol,
    pub state: ProgramState,
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
        prover: ParticipantData,
        verifier: ParticipantData,
        funding: Funding,
        storage: Rc<Storage>,
    ) -> Result<Self, ProgramError> {
        let drp = DisputeResolutionProtocol::new(funding, id, storage.clone())?;

        let program = Program {
            id,
            my_role,
            party_data: prover,
            counterparty_data: verifier,
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
        self.counterparty_data.keys = Some(keys);

        let search_params = SearchParams::new(8, 32);

        self.drp.build_protocol(
            self.party_data.keys.as_ref().unwrap(),
            self.counterparty_data.keys.as_ref().unwrap(),
            search_params,
        )?;

        Ok(())
    }

    pub fn prekickoff_transaction(&self) -> Result<Transaction, BitVMXError> {
        self.drp.prekickoff_transaction().map_err(BitVMXError::from)
    }

    pub fn kickoff_transaction(&self) -> Result<Transaction, BitVMXError> {
        self.drp.kickoff_transaction().map_err(BitVMXError::from)
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

    pub fn funding_txid(&self) -> Txid {
        self.drp.funding().txid()
    }

    pub fn funding_vout(&self) -> u32 {
        self.drp.funding().vout()
    }

    pub fn funding_amount(&self) -> u64 {
        self.drp.funding().amount().to_sat()
    }

    pub fn protocol_amount(&self) -> u64 {
        self.drp.funding().protocol()
    }

    pub fn timelock_amount(&self) -> u64 {
        self.drp.funding().timelock()
    }

    pub fn speedup_amount(&self) -> u64 {
        self.drp.funding().speedup()
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
                &self.party_data,
                &self.id,
                self.counterparty_data.address.peer_id,
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
                &self.party_data,
                &self.id,
                self.counterparty_data.address.peer_id,
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
                &self.party_data,
                &self.id,
                self.counterparty_data.address.peer_id,
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

    fn get_address_if_prover(&self) -> Option<String> {
        match self.my_role {
            ParticipantRole::Prover => Some(self.counterparty_data.address.address.clone()),
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

    pub fn get_prover_participant(&self) -> &ParticipantData {
        match self.my_role {
            ParticipantRole::Prover => &self.party_data,
            ParticipantRole::Verifier => &self.counterparty_data,
        }
    }

    pub fn get_verifier_participant(&self) -> &ParticipantData {
        match self.my_role {
            ParticipantRole::Prover => &self.counterparty_data,
            ParticipantRole::Verifier => &self.party_data,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Trace {}
