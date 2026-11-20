//! Persistent queue of monitor news whose reaction asked to be retried later.
//!
//! A news is only queued after it was acked in the coordinator, in the same transaction, so the monitor never waits for
//! it and the rest of the news keeps flowing. Entries live in the client store, so they survive a restart.

use crate::errors::BitVMXError;
use bitcoin_coordinator::MonitorNews;
use serde::{Deserialize, Serialize};
use std::{
    rc::Rc,
    sync::LazyLock,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use storage_backend::key::StorageKey;
use storage_backend::storage::{KeyValueStore, Storage};
use uuid::Uuid;

static QUEUE_IDS_KEY: LazyLock<StorageKey> = LazyLock::new(|| {
    StorageKey::new(["bitvmx", "news_retry", "ids"])
        .expect("the fixed news retry IDs storage key is valid")
});

/// A queued news and when to hand it to its owner again.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct NewsRetryEntry {
    pub news: MonitorNews,
    /// Unix time in milliseconds from which the news can be retried.
    pub ready_at_ms: u64,
    /// How many times the reaction asked to retry, only used in logs.
    pub attempts: u32,
}

pub struct NewsRetryQueue {
    storage: Rc<Storage>,
}

impl NewsRetryQueue {
    pub fn new(storage: Rc<Storage>) -> Self {
        Self { storage }
    }

    /// Current Unix time in milliseconds.
    pub fn now_ms() -> Result<u64, BitVMXError> {
        Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64)
    }

    fn entry_key(id: &Uuid) -> Result<StorageKey, BitVMXError> {
        Ok(StorageKey::new([
            "bitvmx",
            "news_retry",
            "entry",
            &id.to_string(),
        ])?)
    }

    fn get_ids(&self) -> Result<Vec<Uuid>, BitVMXError> {
        let ids: Option<Vec<Uuid>> = self.storage.get(QUEUE_IDS_KEY.as_ref(), None)?;
        Ok(ids.unwrap_or_default())
    }

    fn save_ids(&self, ids: Vec<Uuid>) -> Result<(), BitVMXError> {
        self.storage.set(QUEUE_IDS_KEY.as_ref(), ids, None)?;
        Ok(())
    }

    /// Queues a news for the first time, to be retried after `delay`.
    pub fn push(&self, news: MonitorNews, delay: Duration) -> Result<(), BitVMXError> {
        let id = Uuid::new_v4();
        let entry = NewsRetryEntry {
            news,
            ready_at_ms: Self::now_ms()? + delay.as_millis() as u64,
            attempts: 1,
        };
        self.storage.set(Self::entry_key(&id)?, &entry, None)?;
        let mut ids = self.get_ids()?;
        ids.push(id);
        self.save_ids(ids)
    }

    /// The entries whose delay has passed at `now_ms`, oldest first.
    pub fn due(&self, now_ms: u64) -> Result<Vec<(Uuid, NewsRetryEntry)>, BitVMXError> {
        let mut due = Vec::new();
        for id in self.get_ids()? {
            let entry: Option<NewsRetryEntry> = self.storage.get(Self::entry_key(&id)?, None)?;
            if let Some(entry) = entry {
                if entry.ready_at_ms <= now_ms {
                    due.push((id, entry));
                }
            }
        }
        Ok(due)
    }

    /// Schedules an entry that asked to retry again, after `delay`. It keeps its place in the queue.
    pub fn reschedule(&self, id: &Uuid, delay: Duration) -> Result<(), BitVMXError> {
        let key = Self::entry_key(id)?;
        let entry: Option<NewsRetryEntry> = self.storage.get(&key, None)?;
        let Some(mut entry) = entry else {
            return Err(BitVMXError::InvalidState(format!(
                "news retry entry {id} not found"
            )));
        };
        entry.ready_at_ms = Self::now_ms()? + delay.as_millis() as u64;
        entry.attempts += 1;
        self.storage.set(&key, &entry, None)?;
        Ok(())
    }

    /// Removes an entry once its news was handled.
    pub fn remove(&self, id: &Uuid) -> Result<(), BitVMXError> {
        self.storage.remove(Self::entry_key(id)?, None)?;
        let mut ids = self.get_ids()?;
        ids.retain(|queued| queued != id);
        self.save_ids(ids)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TestStorageDir;
    use bitcoin::{hashes::Hash, Txid};
    use bitcoin_coordinator::{MonitorTarget, NewsKind};

    fn news(n: u8) -> MonitorNews {
        MonitorNews {
            target: MonitorTarget::Transaction(Txid::from_byte_array([n; 32])),
            context: format!("context-{n}"),
            kind: NewsKind::UnreachableTx,
        }
    }

    #[test]
    fn entries_are_due_only_after_their_delay() {
        let dir = TestStorageDir::new("news-retry-due");
        let queue = NewsRetryQueue::new(dir.storage());
        queue.push(news(1), Duration::ZERO).unwrap();
        queue.push(news(2), Duration::from_secs(3600)).unwrap();
        queue.push(news(3), Duration::ZERO).unwrap();

        let now = NewsRetryQueue::now_ms().unwrap();
        let due: Vec<MonitorNews> = queue
            .due(now)
            .unwrap()
            .into_iter()
            .map(|(_, entry)| entry.news)
            .collect();
        assert_eq!(due, vec![news(1), news(3)]);

        // An hour later the delayed one is due as well, still in queue order.
        let later = queue.due(now + 3_600_000).unwrap();
        assert_eq!(later.len(), 3);
        assert_eq!(later[1].1.news, news(2));
    }

    #[test]
    fn reschedule_counts_attempts_and_remove_drops_the_entry() {
        let dir = TestStorageDir::new("news-retry-reschedule");
        let queue = NewsRetryQueue::new(dir.storage());
        queue.push(news(1), Duration::ZERO).unwrap();
        let now = NewsRetryQueue::now_ms().unwrap();
        let (id, entry) = queue.due(now).unwrap().remove(0);
        assert_eq!(entry.attempts, 1);

        queue.reschedule(&id, Duration::from_secs(3600)).unwrap();
        assert!(queue.due(now).unwrap().is_empty());
        let (_, entry) = queue.due(now + 3_600_000).unwrap().remove(0);
        assert_eq!(entry.attempts, 2);

        queue.remove(&id).unwrap();
        assert!(queue.due(u64::MAX).unwrap().is_empty());
        assert!(queue.reschedule(&id, Duration::ZERO).is_err());
    }

    #[test]
    fn entries_survive_reopening_the_store() {
        let dir = TestStorageDir::new("news-retry-reopen");
        NewsRetryQueue::new(dir.storage())
            .push(news(7), Duration::ZERO)
            .unwrap();

        let queue = NewsRetryQueue::new(dir.storage());
        let due = queue.due(u64::MAX).unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].1.news, news(7));
    }
}
