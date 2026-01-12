use crate::errors::BitVMXError;
use bitvmx_broker::identification::identifier::Identifier;
use serde::{Deserialize, Serialize};
use std::rc::Rc;
use storage_backend::storage::{KeyValueStore, Storage};
use tracing::warn;
use uuid::Uuid;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct QueuedMessage {
    pub identifier: Identifier,
    pub data: Vec<u8>,
    pub retries: u8,
}

impl QueuedMessage {
    pub fn new(identifier: Identifier, data: Vec<u8>) -> Self {
        Self {
            identifier,
            data,
            retries: 0,
        }
    }
}

const QUEUE_IDS_KEY: &str = "bitvmx/message_queue/ids";
const MSG_KEY_PREFIX: &str = "bitvmx/message_queue/msg/";
pub const MAX_MESSAGE_RETRIES: u8 = 3; // Maximum number of retries for sending messages
                                       // until message is dropped from pending queue

pub struct MessageQueue {
    storage: Rc<Storage>,
}

impl MessageQueue {
    pub fn new(storage: Rc<Storage>) -> Self {
        Self { storage }
    }

    fn get_queue_ids(&self) -> Result<Vec<Uuid>, BitVMXError> {
        let ids: Option<Vec<Uuid>> = self.storage.get(QUEUE_IDS_KEY)?;
        Ok(ids.unwrap_or_default())
    }

    fn save_queue_ids(&self, ids: Vec<Uuid>) -> Result<(), BitVMXError> {
        self.storage
            .set(QUEUE_IDS_KEY, ids, None)
            .map_err(BitVMXError::StorageError)?;
        Ok(())
    }

    pub fn push_back(&self, mut queued_msg: QueuedMessage) -> Result<(), BitVMXError> {
        queued_msg.retries += 1;

        if queued_msg.retries > MAX_MESSAGE_RETRIES {
            // TODO: Notify about dropped message
            warn!("Dropping message after {} retries", queued_msg.retries);
            return Ok(());
        }

        self.push(queued_msg)
    }

    pub fn push_new(&self, identifier: Identifier, msg: Vec<u8>) -> Result<(), BitVMXError> {
        let queued_msg = QueuedMessage::new(identifier, msg);
        self.push(queued_msg)
    }

    fn push(&self, queued_msg: QueuedMessage) -> Result<(), BitVMXError> {
        let id = Uuid::new_v4();

        // Save message content
        self.storage
            .set(&format!("{}{}", MSG_KEY_PREFIX, id), queued_msg, None)
            .map_err(BitVMXError::StorageError)?;

        // Update queue
        let mut ids = self.get_queue_ids()?;
        ids.push(id);
        self.save_queue_ids(ids)?;

        Ok(())
    }

    pub fn pop_front(&self) -> Result<Option<QueuedMessage>, BitVMXError> {
        let mut ids = self.get_queue_ids()?;
        if ids.is_empty() {
            return Ok(None);
        }

        let id = ids.remove(0);
        self.save_queue_ids(ids)?;

        let key = format!("{}{}", MSG_KEY_PREFIX, id);
        let queued_msg: Option<QueuedMessage> = self.storage.get(&key)?;

        // Clean up message content
        self.storage
            .delete(&key)
            .map_err(BitVMXError::StorageError)?;

        Ok(queued_msg)
    }

    pub fn is_empty(&self) -> Result<bool, BitVMXError> {
        let ids = self.get_queue_ids()?;
        Ok(ids.is_empty())
    }
}
