use crate::{
    errors::{BitVMXError, ProgramError},
    keychain::KeyChain,
    p2p_helper::{send, P2PMessageType},
    types::ProgramContext,
};
use bitcoin::{Transaction, Txid};
use key_manager::winternitz::WinternitzSignature;
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
    New,
    Claimed,
    Challenged,
    Ready,
    Error,

    // Exchange messages
    WaitingKeys,
    SendingKeys,
    WaitingNonces,
    SendingNonces,
    WaitingSignatures,
    SendingSignatures,

    Completed,
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
            state: ProgramState::New,
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

    pub fn recieve_participant_keys(&mut self, keys: ParticipantKeys) -> Result<(), BitVMXError> {
        self.other.keys = Some(keys);

        let search_params = SearchParams::new(8, 32);

        self.drp.build_protocol(
            self.me.keys.as_ref().unwrap(),
            self.other.keys.as_ref().unwrap(),
            search_params,
        )?;

        self.move_to_next_state()?;

        Ok(())
    }

    pub fn recieve_participant_nonces(
        &mut self,
        nonces: Vec<bitvmx_musig2::PubNonce>,
        key_chain: &KeyChain,
    ) -> Result<(), BitVMXError> {
        let participant_key = self.other.keys.as_ref().unwrap().protocol;
        let my_pubkey = self.me.keys.as_ref().unwrap().protocol;
        key_chain.add_nonces(self.program_id, nonces, participant_key, my_pubkey)?;
        self.move_to_next_state()?;

        Ok(())
    }

    pub fn recieve_participant_partial_signatures(
        &mut self,
        signatures: Vec<bitvmx_musig2::PartialSignature>,
        key_chain: &KeyChain,
    ) -> Result<(), BitVMXError> {
        let other_pubkey = self.other.keys.as_ref().unwrap().protocol;
        key_chain.add_signatures(self.program_id, signatures, other_pubkey)?;
        self.move_to_next_state()?;

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

    fn deploy_program(&mut self) {
        match self.my_role {
            ParticipantRole::Prover => info!("Deploying the prover program"),
            ParticipantRole::Verifier => info!("Deploying the verifier program"),
        }
        //deploy_program //TODO: add function to deploy program
    }

    pub fn is_ready(&self) -> bool {
        self.state == ProgramState::New
    }

    pub fn tick(&mut self, program_context: &ProgramContext) -> Result<(), BitVMXError> {
        info!("I am {:?} and I'm being ticked to advance", self.my_role);

        match &self.state {
            ProgramState::New => {
                self.move_to_next_state()?;
            }

            ProgramState::SendingKeys => {
                let my_keys = self.me.keys.clone().unwrap();

                send(
                    &program_context.comms,
                    &self.program_id,
                    self.other.p2p_address.clone(),
                    P2PMessageType::Keys,
                    my_keys,
                )
                .unwrap();
            }
            ProgramState::SendingNonces => {
                //TODO: get dag messages from the drp
                let dag_messages = vec![];
                let nonces = program_context
                    .key_chain
                    .get_nonces(self.program_id, dag_messages)?;
                send(
                    &program_context.comms,
                    &self.program_id,
                    self.other.p2p_address.clone(),
                    P2PMessageType::PublicNonces,
                    nonces,
                )?;
            }
            ProgramState::SendingSignatures => {
                let dag_messages_count = 10;
                let signatures = program_context
                    .key_chain
                    .get_signatures(self.program_id, dag_messages_count)?;
                send(
                    &program_context.comms,
                    &self.program_id,
                    self.other.p2p_address.clone(),
                    P2PMessageType::PartialSignatures,
                    signatures,
                )?;
            }
            _ => {
                self.state = ProgramState::Error;
            }
        }

        self.save()?;

        Ok(())
    }

    pub fn move_to_next_state(&mut self) -> Result<(), BitVMXError> {
        let next_state = match self.my_role {
            ParticipantRole::Prover => match self.state {
                ProgramState::New => ProgramState::SendingKeys,
                ProgramState::SendingKeys => ProgramState::WaitingKeys,
                ProgramState::WaitingKeys => ProgramState::SendingNonces,
                ProgramState::SendingNonces => ProgramState::WaitingSignatures,
                ProgramState::WaitingNonces => ProgramState::SendingSignatures,
                ProgramState::SendingSignatures => ProgramState::WaitingSignatures,
                ProgramState::WaitingSignatures => ProgramState::Ready,
                ProgramState::Claimed => ProgramState::Claimed,
                ProgramState::Challenged => ProgramState::Challenged,
                ProgramState::Ready => ProgramState::Ready,
                ProgramState::Error => ProgramState::Error,
                ProgramState::Completed => ProgramState::Completed,
            },
            ParticipantRole::Verifier => match self.state {
                ProgramState::New => ProgramState::WaitingKeys,
                ProgramState::WaitingKeys => ProgramState::SendingKeys,
                ProgramState::SendingKeys => ProgramState::WaitingNonces,
                ProgramState::WaitingNonces => ProgramState::SendingNonces,
                ProgramState::SendingNonces => ProgramState::WaitingSignatures,
                ProgramState::WaitingSignatures => ProgramState::SendingSignatures,
                ProgramState::SendingSignatures => ProgramState::Ready,
                ProgramState::Claimed => ProgramState::Claimed,
                ProgramState::Challenged => ProgramState::Challenged,
                ProgramState::Ready => ProgramState::Ready,
                ProgramState::Error => ProgramState::Error,
                ProgramState::Completed => ProgramState::Completed,
            },
        };

        self.state = next_state;

        self.save()?;

        Ok(())
    }

    pub fn is_active(&self) -> bool {
        matches!(
            self.state,
            ProgramState::WaitingKeys
                | ProgramState::SendingKeys
                | ProgramState::WaitingNonces
                | ProgramState::SendingNonces
                | ProgramState::WaitingSignatures
                | ProgramState::SendingSignatures
        )
    }
}
