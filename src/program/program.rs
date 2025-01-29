use std::{collections::HashMap, fmt, rc::Rc};

use bitcoin::{Transaction, Txid};
use key_manager::winternitz::WinternitzSignature;
use serde::{Deserialize, Serialize};
use storage_backend::storage::{Storage, KeyValueStore};
use uuid::Uuid;

use crate::errors::{BitVMXError, ProgramError};

use super::{
    dispute::{DisputeResolutionProtocol, Funding, SearchParams},
    participant::{Participant, ParticipantKeys, ParticipantRole},
};

#[derive(PartialEq, Clone, Serialize, Deserialize)]
pub enum ProgramState {
    Inactive,
    Ready,
    Claimed,
    Challenged,
    KeySent,
    ExchangedKeys,
    NonceSent,
    ExchangedNonces,
    SignSent,
    ExchangedSignatures,
    Error, //TODO: check somewhere
}

impl fmt::Display for ProgramState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ProgramState::Inactive => write!(f, "Inactive"),
            ProgramState::Ready => write!(f, "Ready"),
            ProgramState::Claimed => write!(f, "Claimed"),
            ProgramState::Challenged => write!(f, "Challenged"),
            ProgramState::ExchangedKeys => write!(f, "ExchangdeKeys"),
            ProgramState::ExchangedSignatures => write!(f, "ExchangedSignatures"),
            ProgramState::ExchangedNonces => write!(f, "ExchangedNonces"),
            ProgramState::KeySent => write!(f, "KeySent"),
            ProgramState::NonceSent => write!(f, "NonceSent"),
            ProgramState::SignSent => write!(f, "SignSent"),
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
    pub my_role: ParticipantRole,
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
        storage: Rc<Storage>
    ) -> Result<Self, ProgramError> {
        let drp = DisputeResolutionProtocol::new(funding, id, storage.clone())?;

        Ok(Program {
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
        })
    }

    pub fn load(storage: Rc<Storage>, program_id: &Uuid) -> Result<Self, ProgramError> {
        let mut program: Program = match storage.get(&format!("program_{}", program_id))? {
            Some(program) => program,
            None => return Err(ProgramError::ProgramNotFound(*program_id))
        };

        program.storage = Some(storage.clone());
        program.drp.load_storage(storage);

        Ok(program)
    }

    pub fn setup_counterparty_keys(&mut self, keys: ParticipantKeys, storage: Rc<Storage>) -> Result<(), BitVMXError> {
        match self.my_role {
            ParticipantRole::Prover => self.verifier.set_keys(keys),
            ParticipantRole::Verifier => self.prover.set_keys(keys),
        }

        let search_params = SearchParams::new(8, 32);

        self.drp.build_protocol(
            storage,
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

    pub fn send_keys(&mut self) {
        //TODO: Ready = IDLE?
        if self.state == ProgramState::Ready && self.my_role == ParticipantRole::Prover {
            self.state = ProgramState::KeySent;
        } else {
            self.state = ProgramState::Error;
        }
    }
    pub fn exchange_keys(&mut self) {
        //TODO: Ready = IDLE?
        if (self.state == ProgramState::Ready && self.my_role == ParticipantRole::Verifier)
            || (self.state == ProgramState::KeySent && self.my_role == ParticipantRole::Prover)
        {
            self.state = ProgramState::ExchangedKeys;
        } else {
            self.state = ProgramState::Error;
        }
    }

    
    pub fn exchange_nonces(&mut self) {
        if (self.state == ProgramState::ExchangedKeys && self.my_role == ParticipantRole::Verifier)
            || (self.state == ProgramState::NonceSent && self.my_role == ParticipantRole::Prover)
        {
            self.state = ProgramState::ExchangedNonces;
        } else {
            self.state = ProgramState::Error;
        }
    }

    pub fn send_nonces(&mut self) {
        if self.state == ProgramState::ExchangedKeys && self.my_role == ParticipantRole::Prover {
            self.state = ProgramState::NonceSent;
        } else {
            self.state = ProgramState::Error;
        }
    }

}

#[derive(Clone, Serialize, Deserialize)]
pub struct Trace {}
