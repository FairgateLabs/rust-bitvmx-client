use std::{collections::HashMap, fmt};

use bitcoin::{Transaction, Txid};
use key_manager::winternitz::WinternitzSignature;
use uuid::Uuid;

use crate::{config::Config, errors::{BitVMXError, ProgramError}};

use super::{dispute::{DisputeResolutionProtocol, Funding, SearchParams}, participant::{P2PAddress, Participant, ParticipantKeys}};

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
    creator: P2PAddress,
    prover: Participant,
    verifier: Participant,
    drp: Option<DisputeResolutionProtocol>,
    funding: Funding,
    state: ProgramState,
    trace: Trace,
    ending_state: u8,
    ending_step_number: u32,
    witness_data: HashMap<Txid, WitnessData>
}

impl Program {
    pub fn new(creator: &P2PAddress, config: &Config, prover: Participant, verifier: Participant, funding: Funding) -> Result<Self, ProgramError> {
        let id = Uuid::new_v4();
        let protocol_name = "drp";
        let program_path = config.program_storage_path(id);
        let protocol_storage = program_path.join(protocol_name);
        let search_params = SearchParams::new(8,32);



        let drp = Some(DisputeResolutionProtocol::new(
            &protocol_name,
            protocol_storage,
            funding.clone(),
            &prover.keys().unwrap(),
            search_params
        )?);

        Ok(Program {
            id,
            creator: creator.clone(),
            prover,
            verifier,
            drp,
            funding,
            state: ProgramState::Inactive,
            trace: Trace {},
            ending_state: 0,
            ending_step_number: 0,
            witness_data: HashMap::new(),
        })
    }

    pub fn prekickoff_transaction(&self) -> Result<Transaction, BitVMXError> {
        self.dispute_resolution_protocol().prekickoff_transaction().map_err(BitVMXError::from)
    }

    pub fn kickoff_transaction(&self) -> Result<Transaction, BitVMXError> {
        self.dispute_resolution_protocol().kickoff_transaction().map_err(BitVMXError::from)
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

    pub fn creator(&self) -> &Participant {
        if *self.prover().address() == self.creator {
            &self.prover()
        } else {
            &self.verifier()
        }   
    }

    pub fn funding_txid(&self) -> Txid {
        self.dispute_resolution_protocol().funding().txid()
    }

    pub fn funding_vout(&self) -> u32 {
        self.dispute_resolution_protocol().funding().vout()
    }

    pub fn funding_amount(&self) -> u64 {
        self.dispute_resolution_protocol().funding().amount().to_sat()
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
        &self.drp.as_ref().unwrap()
    }

    pub fn push_witness_value(&mut self, txid: Txid, name: &str, value: WinternitzSignature) {
        self.witness_data.entry(txid).or_insert(WitnessData::new()).insert(name.to_string(), value);
    }

    pub fn witness(&self, txid: Txid) -> Option<&WitnessData> {
        self.witness_data.get(&txid)
    }
}

#[derive(Clone)]
pub struct Trace {
}