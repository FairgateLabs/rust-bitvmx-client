use std::rc::Rc;

use bitcoin::PublicKey;
use p2p_handler::PeerId;
use protocol_builder::builder::Utxo;
use serde::{Deserialize, Serialize};
use storage_backend::storage::Storage;

type SessionId = String;
type ParticipantId = PeerId;

#[derive(Clone, Serialize, Deserialize)]
pub enum SessionState {
    Created,
    Pending,
    InChallenge,
    Finalized,
    Aborted,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Session {
    id: SessionId,
    session_key: PublicKey,
    utxo: Utxo,
    participants: Vec<ParticipantId>,
    state: SessionState,
    #[serde(skip)]
    _storage: Option<Rc<Storage>>,
}

impl Session {
    pub fn new(
        id: SessionId,
        session_key: PublicKey,
        utxo: Utxo,
        participants: Vec<ParticipantId>,
        storage: Rc<Storage>,
    ) -> Self {
        Self {
            id,
            session_key,
            utxo,
            participants,
            state: SessionState::Created,
            _storage: Some(storage),
        }
    }

    pub fn get_id(&self) -> &SessionId {
        &self.id
    }

    pub fn get_utxo(&self) -> &Utxo {
        &self.utxo
    }

    pub fn get_participants(&self) -> &Vec<ParticipantId> {
        &self.participants
    }

    pub fn get_state(&self) -> &SessionState {
        &self.state
    }
}
