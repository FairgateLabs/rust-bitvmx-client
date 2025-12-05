use crate::errors::BitVMXError;
use serde::{Deserialize, Serialize};
use std::rc::Rc;
use storage_backend::storage::{KeyValueStore, Storage};
use uuid::Uuid;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct QueuedMessage {
    pub identifier: String,
    pub msg: Vec<u8>,
}

const QUEUE_IDS_KEY: &str = "bitvmx/message_queue/ids";
const MSG_KEY_PREFIX: &str = "bitvmx/message_queue/msg/";

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

    pub fn push_back(&self, identifier: String, msg: Vec<u8>) -> Result<(), BitVMXError> {
        let id = Uuid::new_v4();
        let queued_msg = QueuedMessage { identifier, msg };

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

    pub fn pop_front(&self) -> Result<Option<(String, Vec<u8>)>, BitVMXError> {
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

        match queued_msg {
            Some(m) => Ok(Some((m.identifier, m.msg))),
            None => Ok(None), // Should not happen if consistency is maintained
        }
    }

    pub fn is_empty(&self) -> Result<bool, BitVMXError> {
        let ids = self.get_queue_ids()?;
        Ok(ids.is_empty())
    }
}
