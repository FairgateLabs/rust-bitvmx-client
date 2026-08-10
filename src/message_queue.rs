use crate::errors::BitVMXError;
use bitvmx_broker::{
    identification::identifier::Identifier,
    retry::{now_ms, RetryPolicy, RetryState},
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

/// Result of returning a message to the queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushOutcome {
    /// Queued for another attempt.
    Queued,
    /// Retry budget exhausted. The message was discarded and will not arrive again:
    /// the sender already delivered it successfully and does not resend.
    Dropped,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct StoredMessage {
    identifier: Identifier,
    data: Vec<u8>,
}

const QUEUE_IDS_KEY: &str = "bitvmx/message_queue/ids";
const MSG_KEY_PREFIX: &str = "bitvmx/message_queue/msg/";
const RETRY_STATE_KEY_PREFIX: &str = "bitvmx/message_queue/retry_state/";

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

    fn msg_key(id: &Uuid) -> String {
        format!("{}{}", MSG_KEY_PREFIX, id)
    }

    fn retry_state_key(id: &Uuid) -> String {
        format!("{}{}", RETRY_STATE_KEY_PREFIX, id)
    }

    fn get_stored_message(&self, id: &Uuid) -> Result<Option<StoredMessage>, BitVMXError> {
        self.storage
            .get(&Self::msg_key(id), None)
            .map_err(BitVMXError::StorageError)
    }

    fn save_stored_message(&self, id: &Uuid, msg: &StoredMessage) -> Result<(), BitVMXError> {
        self.storage
            .set(&Self::msg_key(id), msg, None)
            .map_err(BitVMXError::StorageError)?;
        Ok(())
    }

    fn get_retry_state(&self, id: &Uuid) -> Result<Option<RetryState>, BitVMXError> {
        self.storage
            .get(&Self::retry_state_key(id), None)
            .map_err(BitVMXError::StorageError)
    }

    fn save_retry_state(&self, id: &Uuid, retry_state: &RetryState) -> Result<(), BitVMXError> {
        self.storage
            .set(&Self::retry_state_key(id), retry_state, None)
            .map_err(BitVMXError::StorageError)?;
        Ok(())
    }

    fn remove_stored_message(&self, id: &Uuid) -> Result<(), BitVMXError> {
        self.storage
            .remove(&Self::msg_key(id), None)
            .map_err(BitVMXError::StorageError)?;
        Ok(())
    }

    fn remove_retry_state(&self, id: &Uuid) -> Result<(), BitVMXError> {
        self.storage
            .remove(&Self::retry_state_key(id), None)
            .map_err(BitVMXError::StorageError)?;
        Ok(())
    }

    fn remove_entry(&self, id: &Uuid) -> Result<(), BitVMXError> {
        self.remove_stored_message(id)?;
        self.remove_retry_state(id)?;
        Ok(())
    }

    pub fn push_back(&self, mut queued_msg: QueuedMessage) -> Result<PushOutcome, BitVMXError> {
        queued_msg
            .retry_state
            .record_attempt(&self.retry_policy, now_ms()?);

        if self.retry_policy.is_exhausted(&queued_msg.retry_state) {
            warn!(
                "Dropping message after {} attempts: {:?}",
                queued_msg.retry_state.get_attempts(),
                queued_msg.identifier
            );
            return Ok(PushOutcome::Dropped);
        }

        self.push(queued_msg)?;
        Ok(PushOutcome::Queued)
    }

    pub fn push_new(&self, identifier: Identifier, msg: Vec<u8>) -> Result<(), BitVMXError> {
        let queued_msg = QueuedMessage::new(identifier, msg)?;
        self.push(queued_msg)
    }

    fn push(&self, queued_msg: QueuedMessage) -> Result<(), BitVMXError> {
        let id = Uuid::new_v4();
        let stored_message = StoredMessage {
            identifier: queued_msg.identifier,
            data: queued_msg.data,
        };

        self.save_stored_message(&id, &stored_message)?;
        self.save_retry_state(&id, &queued_msg.retry_state)?;

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

            let Some(retry_state) = self.get_retry_state(&id)? else {
                self.remove_stored_message(&id)?;
                continue;
            };

            if !retry_state.is_ready(now) {
                ids.push(id);
                continue;
            }

            let Some(stored_msg) = self.get_stored_message(&id)? else {
                self.remove_retry_state(&id)?;
                continue;
            };

            self.save_queue_ids(ids)?;
            self.remove_entry(&id)?;

            return Ok(Some(QueuedMessage {
                identifier: stored_msg.identifier,
                data: stored_msg.data,
                retry_state,
            }));
        }

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
    use crate::test_utils::TestStorageDir;
    use bitvmx_broker::rpc::config::BrokerNodeConfig;

    fn test_storage_dir() -> TestStorageDir {
        TestStorageDir::new("bitvmx-message-queue-test")
    }

    fn test_retry_policy() -> RetryPolicy {
        RetryPolicy::new(&BrokerNodeConfig {
            max_msgs_per_tick_utilization: 1.0,
            max_send_attempts: 3,
            retry_min_delay_msecs: 1_000,
            retry_max_delay_msecs: 1_002,
        })
        .unwrap()
    }

    fn test_identifier(name: &str) -> Identifier {
        Identifier::new(name.to_string(), 0)
    }

    #[test]
    fn push_new_and_pop_front_are_fifo() {
        let test_dir = test_storage_dir();
        let storage = test_dir.storage();
        let queue = MessageQueue::new(storage, test_retry_policy());

        let id1 = test_identifier("first");
        let id2 = test_identifier("second");
        let msg1 = vec![1, 2, 3];
        let msg2 = vec![4, 5, 6];

        assert!(queue.is_empty().unwrap());

        queue.push_new(id1.clone(), msg1.clone()).unwrap();
        queue.push_new(id2.clone(), msg2.clone()).unwrap();

        let popped = queue.pop_front().unwrap().unwrap();
        assert_eq!(popped.identifier, id1);
        assert_eq!(popped.data, msg1);
        assert_eq!(popped.retry_state.get_attempts(), 0);

        let popped = queue.pop_front().unwrap().unwrap();
        assert_eq!(popped.identifier, id2);
        assert_eq!(popped.data, msg2);
        assert_eq!(popped.retry_state.get_attempts(), 0);

        assert!(queue.pop_front().unwrap().is_none());
        assert!(queue.is_empty().unwrap());
    }

    #[test]
    fn message_and_retry_state_are_stored_separately() {
        let test_dir = test_storage_dir();
        let storage = test_dir.storage();
        let queue = MessageQueue::new(storage.clone(), test_retry_policy());

        let identifier = test_identifier("separate-storage");
        let data = vec![7, 8, 9];
        queue.push_new(identifier.clone(), data.clone()).unwrap();

        let queue_ids = queue.get_queue_ids().unwrap();
        assert_eq!(queue_ids.len(), 1);

        let id = queue_ids[0];
        let stored_msg = queue.get_stored_message(&id).unwrap().unwrap();
        let retry_state = queue.get_retry_state(&id).unwrap().unwrap();

        assert_eq!(stored_msg.identifier, identifier);
        assert_eq!(stored_msg.data, data);
        assert_eq!(retry_state.get_attempts(), 0);
    }

    #[test]
    fn pop_front_rotates_not_ready_messages() {
        let test_dir = test_storage_dir();
        let storage = test_dir.storage();
        let retry_policy = test_retry_policy();
        let queue = MessageQueue::new(storage, retry_policy.clone());

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

        let remaining_id = remaining_ids[0];
        let remaining_msg = queue.get_stored_message(&remaining_id).unwrap().unwrap();
        let remaining_retry_state = queue.get_retry_state(&remaining_id).unwrap().unwrap();

        assert_eq!(remaining_msg.identifier, delayed_id);
        assert_eq!(remaining_msg.data, vec![1]);
        assert!(!remaining_retry_state.is_ready(now_ms().unwrap()));
    }

    #[test]
    fn push_back_increments_attempts_and_drops_exhausted_messages() {
        let test_dir = test_storage_dir();
        let storage = test_dir.storage();
        let retry_policy = test_retry_policy();
        let queue = MessageQueue::new(storage, retry_policy.clone());

        let msg = QueuedMessage::new(test_identifier("retry"), vec![9, 9, 9]).unwrap();
        assert_eq!(queue.push_back(msg).unwrap(), PushOutcome::Queued);

        let queued_ids = queue.get_queue_ids().unwrap();
        assert_eq!(queued_ids.len(), 1);

        let retry_state = queue.get_retry_state(&queued_ids[0]).unwrap().unwrap();
        assert_eq!(retry_state.get_attempts(), 1);
        assert!(queue.pop_front().unwrap().is_none());

        let mut exhausted = QueuedMessage::new(test_identifier("exhausted"), vec![7]).unwrap();
        for _ in 0..retry_policy.max_attempts - 1 {
            exhausted
                .retry_state
                .record_attempt(&retry_policy, now_ms().unwrap());
        }

        assert_eq!(queue.push_back(exhausted).unwrap(), PushOutcome::Dropped);

        assert_eq!(queue.get_queue_ids().unwrap().len(), 1);
        assert!(!queue.is_empty().unwrap());
    }

    #[test]
    fn pop_front_skips_incomplete_entries() {
        let test_dir = test_storage_dir();
        let storage = test_dir.storage();
        let queue = MessageQueue::new(storage.clone(), test_retry_policy());

        let missing_retry_state_id = Uuid::new_v4();
        let missing_message_id = Uuid::new_v4();
        let valid_id = Uuid::new_v4();

        let message_without_retry_state = StoredMessage {
            identifier: test_identifier("missing-retry-state"),
            data: vec![1],
        };
        let retry_state_without_message = RetryState::new(now_ms().unwrap());
        let valid_msg = StoredMessage {
            identifier: test_identifier("valid"),
            data: vec![4, 2],
        };
        let valid_retry_state = RetryState::new(now_ms().unwrap());

        queue
            .save_stored_message(&missing_retry_state_id, &message_without_retry_state)
            .unwrap();
        queue
            .save_retry_state(&missing_message_id, &retry_state_without_message)
            .unwrap();
        queue.save_stored_message(&valid_id, &valid_msg).unwrap();
        queue
            .save_retry_state(&valid_id, &valid_retry_state)
            .unwrap();
        queue
            .save_queue_ids(vec![missing_retry_state_id, missing_message_id, valid_id])
            .unwrap();

        let popped = queue.pop_front().unwrap().unwrap();
        assert_eq!(popped.identifier, valid_msg.identifier);
        assert_eq!(popped.data, valid_msg.data);

        assert!(queue
            .get_stored_message(&missing_retry_state_id)
            .unwrap()
            .is_none());
        assert!(queue
            .get_retry_state(&missing_message_id)
            .unwrap()
            .is_none());
        assert!(queue.get_queue_ids().unwrap().is_empty());
        assert!(queue.is_empty().unwrap());
    }

    #[test]
    fn queue_persists_across_storage_reopen() {
        let test_dir = test_storage_dir();
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
