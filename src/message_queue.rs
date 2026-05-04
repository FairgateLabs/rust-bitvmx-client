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
        let ids: Option<Vec<Uuid>> = self.storage.get(QUEUE_IDS_KEY, None)?;
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

            let queued_msg: Option<QueuedMessage> = self.storage.get(&key, None)?;
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
                .remove(&key, None)
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

#[cfg(test)]
mod tests {
    use super::*;
    use bitvmx_broker::rpc::config::QueueChannelConfig;
    use std::{env, fs};
    use storage_backend::storage::{KeyValueStore, Storage};
    use storage_backend::storage_config::StorageConfig;
    use uuid::Uuid;

    struct TestStorageDir {
        path: String,
    }

    impl TestStorageDir {
        fn new() -> Self {
            Self {
                path: env::temp_dir()
                    .join(format!("bitvmx-message-queue-test-{}", Uuid::new_v4()))
                    .to_string_lossy()
                    .into_owned(),
            }
        }

        fn config(&self) -> StorageConfig {
            StorageConfig {
                path: self.path.clone(),
                password: None,
            }
        }

        fn storage(&self) -> Rc<Storage> {
            Rc::new(Storage::new(&self.config()).unwrap())
        }
    }

    impl Drop for TestStorageDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn test_retry_policy() -> RetryPolicy {
        RetryPolicy::new(&QueueChannelConfig {
            max_msgs_per_tick_utilization: 1.0,
            max_send_attempts: 3,
            retry_min_delay_msecs: 1,
            retry_max_delay_msecs: 3,
        })
        .unwrap()
    }

    fn test_identifier(name: &str) -> Identifier {
        Identifier::new(name.to_string(), 0)
    }

    #[test]
    fn push_new_and_pop_front_are_fifo() {
        let test_dir = TestStorageDir::new();
        let storage = test_dir.storage();
        let queue = MessageQueue::new(storage, test_retry_policy());

        let id1 = test_identifier("first");
        let id2 = test_identifier("second");
        let msg1 = vec![1, 2, 3];
        let msg2 = vec![4, 5, 6];

        assert!(queue.is_empty().unwrap());

        queue.push_new(id1.clone(), msg1.clone()).unwrap();
        queue.push_new(id2.clone(), msg2.clone()).unwrap();

        assert!(!queue.is_empty().unwrap());

        let popped = queue.pop_front().unwrap().unwrap();
        assert_eq!(popped.identifier, id1);
        assert_eq!(popped.data, msg1);

        let popped = queue.pop_front().unwrap().unwrap();
        assert_eq!(popped.identifier, id2);
        assert_eq!(popped.data, msg2);

        assert!(queue.pop_front().unwrap().is_none());
        assert!(queue.is_empty().unwrap());
    }

    #[test]
    fn pop_front_rotates_not_ready_messages() {
        let test_dir = TestStorageDir::new();
        let storage = test_dir.storage();
        let retry_policy = test_retry_policy();
        let queue = MessageQueue::new(storage.clone(), retry_policy.clone());

        let delayed_id = test_identifier("delayed");
        let ready_id = test_identifier("ready");

        let mut delayed_msg = QueuedMessage::new(delayed_id.clone(), vec![1]).unwrap();
        delayed_msg
            .retry_state
            .record_attempt(&retry_policy, now_ms().unwrap());
        let ready_msg = QueuedMessage::new(ready_id.clone(), vec![2]).unwrap();

        queue.push(delayed_msg).unwrap();
        queue.push(ready_msg).unwrap();

        let popped = queue.pop_front().unwrap().unwrap();
        assert_eq!(popped.identifier, ready_id);
        assert_eq!(popped.data, vec![2]);

        let remaining_ids = queue.get_queue_ids().unwrap();
        assert_eq!(remaining_ids.len(), 1);

        let remaining: Option<QueuedMessage> = storage
            .get(&format!("{}{}", MSG_KEY_PREFIX, remaining_ids[0]), None)
            .unwrap();
        let remaining = remaining.unwrap();

        assert_eq!(remaining.identifier, delayed_id);
        assert!(!remaining.retry_state.is_ready(now_ms().unwrap()));
    }

    #[test]
    fn push_back_increments_attempts_and_drops_exhausted_messages() {
        let test_dir = TestStorageDir::new();
        let storage = test_dir.storage();
        let retry_policy = test_retry_policy();
        let queue = MessageQueue::new(storage.clone(), retry_policy.clone());

        let msg = QueuedMessage::new(test_identifier("retry"), vec![9, 9, 9]).unwrap();
        queue.push_back(msg).unwrap();

        let queued_ids = queue.get_queue_ids().unwrap();
        assert_eq!(queued_ids.len(), 1);

        let stored: Option<QueuedMessage> = storage
            .get(&format!("{}{}", MSG_KEY_PREFIX, queued_ids[0]), None)
            .unwrap();
        let stored = stored.unwrap();
        assert_eq!(stored.retry_state.get_attempts(), 1);
        assert!(queue.pop_front().unwrap().is_none());

        let mut exhausted = QueuedMessage::new(test_identifier("exhausted"), vec![7]).unwrap();
        for _ in 0..retry_policy.max_attempts - 1 {
            exhausted
                .retry_state
                .record_attempt(&retry_policy, now_ms().unwrap());
        }

        queue.push_back(exhausted).unwrap();

        assert_eq!(queue.get_queue_ids().unwrap().len(), 1);
        assert!(!queue.is_empty().unwrap());
    }

    #[test]
    fn pop_front_skips_missing_message_entries() {
        let test_dir = TestStorageDir::new();
        let storage = test_dir.storage();
        let queue = MessageQueue::new(storage.clone(), test_retry_policy());

        let missing_id = Uuid::new_v4();
        let valid_id = Uuid::new_v4();
        let valid_msg = QueuedMessage::new(test_identifier("valid"), vec![4, 2]).unwrap();

        storage
            .set(
                &format!("{}{}", MSG_KEY_PREFIX, valid_id),
                valid_msg.clone(),
                None,
            )
            .unwrap();
        queue.save_queue_ids(vec![missing_id, valid_id]).unwrap();

        let popped = queue.pop_front().unwrap().unwrap();
        assert_eq!(popped.identifier, valid_msg.identifier);
        assert_eq!(popped.data, valid_msg.data);
        assert!(queue.get_queue_ids().unwrap().is_empty());
        assert!(queue.is_empty().unwrap());
    }

    #[test]
    fn queue_persists_across_storage_reopen() {
        let test_dir = TestStorageDir::new();
        let retry_policy = test_retry_policy();

        let id1 = test_identifier("persisted-1");
        let id2 = test_identifier("persisted-2");
        let msg1 = vec![1, 1, 1];
        let msg2 = vec![2, 2, 2];

        {
            let storage = test_dir.storage();
            let queue = MessageQueue::new(storage, retry_policy.clone());

            queue.push_new(id1.clone(), msg1.clone()).unwrap();
            queue.push_new(id2.clone(), msg2.clone()).unwrap();

            let popped = queue.pop_front().unwrap().unwrap();
            assert_eq!(popped.identifier, id1);
            assert_eq!(popped.data, msg1);
        }

        {
            let storage = test_dir.storage();
            let queue = MessageQueue::new(storage, retry_policy);

            let popped = queue.pop_front().unwrap().unwrap();
            assert_eq!(popped.identifier, id2);
            assert_eq!(popped.data, msg2);
            assert!(queue.pop_front().unwrap().is_none());
        }
    }
}
