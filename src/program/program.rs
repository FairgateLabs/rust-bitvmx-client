use crate::{
    errors::{BitVMXError, ProgramError},
    p2p_helper::{send_keys, send_nonces, send_signatures},
};
use bitcoin::{Transaction, Txid};
use key_manager::winternitz::WinternitzSignature;
use p2p_handler::P2pHandler;
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
    Inactive,
    Ready,
    Claimed,
    Challenged,
    DeployProgram,
    Error, //TODO: check somewhere

    KeysSent,
    NoncesSent,
    SignaturesSent,
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
}

impl Program {
    pub fn new(
        program_id: Uuid,
        my_role: ParticipantRole,
        me: ParticipantData,
        other: ParticipantData,
        funding: Funding,
        storage: Rc<Storage>,
    ) -> Result<Self, ProgramError> {
        let drp = DisputeResolutionProtocol::new(funding, program_id, storage.clone())?;

        let program = Program {
            program_id,
            my_role,
            me,
            other,
            drp,
            state: ProgramState::Inactive,
            witness_data: HashMap::new(),
            storage: Some(storage),
        };

        program.save()?;

        Ok(program)
    }

    pub fn load(storage: Rc<Storage>, program_id: &Uuid) -> Result<Self, ProgramError> {
        let mut program: Program = match storage.get(format!("program_{}", program_id))? {
            Some(program) => program,
            None => {
                return Err(ProgramError::ProgramNotFound(*program_id));
            }
        };

        program.storage = Some(storage.clone());
        program.drp.set_storage(storage);

        Ok(program)
    }

    pub fn save(&self) -> Result<Uuid, ProgramError> {
        let key = format!("program_{}", self.program_id);
        self.storage.as_ref().unwrap().set(key, self, None)?;
        Ok(self.program_id)
    }

    pub fn set_other_keys(&mut self, keys: ParticipantKeys) -> Result<(), BitVMXError> {
        self.other.keys = Some(keys);

        let search_params = SearchParams::new(8, 32);

        self.drp.build_protocol(
            self.me.keys.as_ref().unwrap(),
            self.other.keys.as_ref().unwrap(),
            search_params,
        )?;

        self.save()?;

        Ok(())
    }

    pub fn prekickoff_transaction(&self) -> Result<Transaction, BitVMXError> {
        self.drp.prekickoff_transaction().map_err(BitVMXError::from)
    }

    pub fn kickoff_transaction(&self) -> Result<Transaction, BitVMXError> {
        self.drp.kickoff_transaction().map_err(BitVMXError::from)
    }

    pub fn funding_txid(&self) -> Txid {
        self.drp.funding.txid
    }

    pub fn funding_vout(&self) -> u32 {
        self.drp.funding.vout
    }

    pub fn funding_amount(&self) -> u64 {
        self.drp.funding.amount.to_sat()
    }

    pub fn protocol_amount(&self) -> u64 {
        self.drp.funding.protocol
    }

    pub fn timelock_amount(&self) -> u64 {
        self.drp.funding.timelock
    }

    pub fn speedup_amount(&self) -> u64 {
        self.drp.funding.speedup
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
            let keys = self.me.keys.clone().unwrap();

            send_keys(
                comms,
                &self.program_id,
                self.other.p2p_address.peer_id,
                self.other.p2p_address.address.clone(),
                keys,
            )?;
            self.state = ProgramState::KeysSent;
        } else {
            self.state = ProgramState::Error;
        }
        Ok(())
    }

    fn send_nonces(&mut self, comms: &mut P2pHandler) -> Result<(), BitVMXError> {
        if self.state == ProgramState::KeysSent {
            let nonces: Vec<u8> = vec![0, 1, 2, 3];
            send_nonces(
                comms,
                &self.program_id,
                self.other.p2p_address.peer_id,
                self.other.p2p_address.address.clone(),
                nonces,
            )?;
            self.state = ProgramState::NoncesSent;
        } else {
            self.state = ProgramState::Error;
        }

        self.save()?;

        Ok(())
    }

    fn send_signatures(&mut self, comms: &mut P2pHandler) -> Result<(), BitVMXError> {
        if self.state == ProgramState::NoncesSent {
            let signatures: Vec<u8> = vec![0, 1, 2, 3];

            send_signatures(
                comms,
                &self.program_id,
                self.other.p2p_address.peer_id,
                self.other.p2p_address.address.clone(),
                signatures,
            )?;
            match self.my_role {
                ParticipantRole::Prover => self.state = ProgramState::SignaturesSent,
                ParticipantRole::Verifier => {
                    self.state = ProgramState::DeployProgram;
                    self.deploy_program();
                }
            }
        } else {
            self.state = ProgramState::Error;
        }

        self.save()?;
        Ok(())
    }

    fn deploy_program(&mut self) {
        match self.my_role {
            ParticipantRole::Prover => info!("Deploying the prover program"),
            ParticipantRole::Verifier => info!("Deploying the verifier program"),
        }
        //deploy_program //TODO: add function to deploy program
    }

    pub fn is_ready(&self) -> bool {
        self.state == ProgramState::Ready
    }

    pub fn tick(&mut self, comms: &mut P2pHandler) -> Result<(), BitVMXError> {
        match (&self.state, &self.my_role) {
            (ProgramState::Inactive, _) => {
                //TODO: take out, only for testing
                self.state = ProgramState::Ready;
                self.tick(comms)?;
            }

            (ProgramState::Ready, _) => self.send_keys(comms)?,
            (ProgramState::KeysSent, _) => self.send_nonces(comms)?,
            (ProgramState::NoncesSent, _) => self.send_signatures(comms)?, // Sign program and send signature
            (ProgramState::SignaturesSent, ParticipantRole::Prover) => self.deploy_program(),

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
