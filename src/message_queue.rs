use crate::errors::BitVMXError;
use bitvmx_broker::{
    channel::retry_helper::{now_ms, RetryPolicy, RetryState},
    identification::identifier::Identifier,
};
use serde::{Deserialize, Serialize};
use std::rc::Rc;
use storage_backend::storage::{KeyValueStore, Storage};
use tracing::warn;
use uuid::Uuid;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct QueuedMessage {
    pub identifier: Identifier,
    pub data: Vec<u8>,
    pub retry_state: RetryState,
}

impl QueuedMessage {
    pub fn new(identifier: Identifier, data: Vec<u8>) -> Result<Self, BitVMXError> {
        Ok(Self {
            identifier,
            data,
            retry_state: RetryState::new(now_ms()?),
        })
    }
}

const QUEUE_IDS_KEY: &str = "bitvmx/message_queue/ids";
const MSG_KEY_PREFIX: &str = "bitvmx/message_queue/msg/";

pub struct MessageQueue {
    storage: Rc<Storage>,
    retry_policy: RetryPolicy,
}

impl MessageQueue {
    pub fn new(storage: Rc<Storage>, retry_policy: RetryPolicy) -> Self {
        Self {
            storage,
            retry_policy,
        }
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
        queued_msg
            .retry_state
            .record_attempt(&self.retry_policy, now_ms()?);

        if self.retry_policy.is_exhausted(&queued_msg.retry_state) {
            warn!(
                "Dropping message after {} attempts: {:?}",
                queued_msg.retry_state.get_attempts(),
                queued_msg.identifier
            );
            return Ok(());
        }

        self.push(queued_msg)
    }

    pub fn push_new(&self, identifier: Identifier, msg: Vec<u8>) -> Result<(), BitVMXError> {
        let queued_msg = QueuedMessage::new(identifier, msg)?;
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

        let now = now_ms()?;
        let original_len = ids.len();

        for _ in 0..original_len {
            let id = ids.remove(0);
            let key = format!("{}{}", MSG_KEY_PREFIX, id);

            let queued_msg: Option<QueuedMessage> = self.storage.get(&key)?;
            let Some(msg) = queued_msg else {
                continue; // Empty message, skip //TODO: Is this possible?
            };

            // If not ready, rotate to back of queue
            if !msg.retry_state.is_ready(now) {
                ids.push(id);
                continue;
            }

            // If ready, return message
            self.save_queue_ids(ids)?;
            self.storage
                .delete(&key)
                .map_err(BitVMXError::StorageError)?;

            return Ok(Some(msg));
        }

        // If we reach here, no messages were ready
        self.save_queue_ids(ids)?;
        Ok(None)
    }

    pub fn is_empty(&self) -> Result<bool, BitVMXError> {
        let ids = self.get_queue_ids()?;
        Ok(ids.is_empty())
    }
}
