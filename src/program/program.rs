use std::{collections::HashMap, fmt, path::PathBuf};

use bitcoin::{Transaction, Txid};
use key_manager::winternitz::WinternitzSignature;
use uuid::Uuid;

use crate::{
    config::Config,
    errors::{BitVMXError, ProgramError},
};

use super::{
    dispute::{DisputeResolutionProtocol, Funding, SearchParams},
    participant::{Participant, ParticipantKeys, ParticipantRole},
};

#[derive(PartialEq, Clone)]
pub enum ProgramState {
    Inactive,
    Ready,
    Claimed,
    Challenged,
}

impl fmt::Display for ProgramState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ProgramState::Inactive => write!(f, "Inactive"),
            ProgramState::Ready => write!(f, "Ready"),
            ProgramState::Claimed => write!(f, "Claimed"),
            ProgramState::Challenged => write!(f, "Challenged"),
        }
    }
}

#[derive(Clone)]
pub struct WitnessData {
    values: HashMap<String, WinternitzSignature>,
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

#[derive(Clone)]
pub struct Program {
    id: Uuid,
    my_role: ParticipantRole,
    prover: Participant,
    verifier: Participant,
    drp: Option<DisputeResolutionProtocol>,
    funding: Funding,
    state: ProgramState,
    _trace: Trace,
    _ending_state: u8,
    _ending_step_number: u32,
    witness_data: HashMap<Txid, WitnessData>,
    protocol_storage: PathBuf,
}

impl Program {
    pub fn new(
        config: &Config,
        id: Uuid,
        my_role: ParticipantRole,
        prover: Participant,
        verifier: Participant,
        funding: Funding,
    ) -> Result<Self, ProgramError> {
        let protocol_name = "drp";
        let program_path = config.program_storage_path(id);
        let protocol_storage = program_path.join(protocol_name);

        Ok(Program {
            id,
            my_role,
            prover,
            verifier,
            drp: None,
            funding,
            state: ProgramState::Inactive,
            _trace: Trace {},
            _ending_state: 0,
            _ending_step_number: 0,
            witness_data: HashMap::new(),
            protocol_storage,
        })
    }

    pub fn setup_counterparty_keys(&mut self, keys: ParticipantKeys) -> Result<(), BitVMXError> {
        match self.my_role {
            ParticipantRole::Prover => self.verifier.set_keys(keys),
            ParticipantRole::Verifier => self.prover.set_keys(keys),
        }

        let search_params = SearchParams::new(8, 32);

        let drp = DisputeResolutionProtocol::new(
            "drp",
            self.protocol_storage.clone(),
            self.funding.clone(),
            self.prover.keys().as_ref().unwrap(),
            self.verifier.keys().as_ref().unwrap(),
            search_params,
        )?;

        self.drp = Some(drp);
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

    pub fn dispute_resolution_protocol_mut(&mut self) -> &mut DisputeResolutionProtocol {
        self.drp.as_mut().expect("DRP is not set")
    }

    pub fn dispute_resolution_protocol(&self) -> &DisputeResolutionProtocol {
        self.drp.as_ref().unwrap()
    }

    pub fn push_witness_value(&mut self, txid: Txid, name: &str, value: WinternitzSignature) {
        self.witness_data
            .entry(txid)
            .or_insert(WitnessData::new())
            .insert(name.to_string(), value);
    }

    pub fn witness(&self, txid: Txid) -> Option<&WitnessData> {
        self.witness_data.get(&txid)
    }
}

#[derive(Clone)]
pub struct Trace {}
