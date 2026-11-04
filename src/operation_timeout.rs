use crate::errors::BitVMXError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{rc::Rc, sync::LazyLock, time::Duration};
use storage_backend::{
    key::StorageKey,
    storage::{KeyValueStore, Storage},
};
use uuid::Uuid;

static OPERATION_TIMEOUT_IDS_KEY: LazyLock<StorageKey> = LazyLock::new(|| {
    StorageKey::new(["bitvmx", "operation_timeout", "ids"])
        .expect("the fixed operation-timeout IDs storage key is valid")
});

pub(crate) const DEFAULT_SETUP_TIMEOUT: Duration = Duration::from_secs(3_600);
pub(crate) const DEFAULT_JOB_TIMEOUT: Duration = Duration::from_secs(900);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(crate) enum OperationTimeoutId {
    SetupProcess(Uuid),
    DispatcherJob(String),
}

/// What happens on expiry follows from the id: a setup process fails its setup, and a
/// dispatcher job is handled according to its `ExpectedJob::target`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct OperationTimeout {
    pub id: OperationTimeoutId,
    pub deadline_ms: u64,
}

/// Whole milliseconds in `duration`, saturating at `u64::MAX`.
pub(crate) fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[derive(Clone)]
pub(crate) struct OperationTimeouts {
    storage: Rc<Storage>,
}

impl OperationTimeouts {
    pub fn new(storage: Rc<Storage>) -> Self {
        Self { storage }
    }

    fn key(id: &OperationTimeoutId) -> Result<StorageKey, BitVMXError> {
        let encoded = serde_json::to_vec(id)?;
        let digest = hex::encode(Sha256::digest(encoded));
        Ok(StorageKey::new(["bitvmx", "operation_timeout", &digest])?)
    }

    fn deadline(duration: Duration) -> Result<u64, BitVMXError> {
        Ok(bitvmx_broker::retry::now_ms()?.saturating_add(duration_ms(duration)))
    }

    fn load_ids(&self) -> Result<Vec<OperationTimeoutId>, BitVMXError> {
        Ok(self
            .storage
            .get(OPERATION_TIMEOUT_IDS_KEY.as_ref(), None)?
            .unwrap_or_default())
    }

    fn register(
        &self,
        id: OperationTimeoutId,
        duration: Duration,
        renew: bool,
    ) -> Result<(), BitVMXError> {
        let key = Self::key(&id)?;
        let existing: Option<OperationTimeout> = self.storage.get(&key, None)?;
        if existing.is_some() && !renew {
            return Ok(());
        }
        if existing.is_none() {
            let mut ids = self.load_ids()?;
            ids.push(id.clone());
            self.storage
                .set(OPERATION_TIMEOUT_IDS_KEY.as_ref(), ids, None)?;
        }

        self.storage.set(
            key,
            OperationTimeout {
                id,
                deadline_ms: Self::deadline(duration)?,
            },
            None,
        )?;
        Ok(())
    }

    pub fn register_setup(
        &self,
        program_id: Uuid,
        timeout: Option<Duration>,
    ) -> Result<(), BitVMXError> {
        self.register(
            OperationTimeoutId::SetupProcess(program_id),
            timeout.unwrap_or(DEFAULT_SETUP_TIMEOUT),
            false,
        )
    }

    pub fn register_job(
        &self,
        job_id: String,
        timeout: Option<Duration>,
        renew: bool,
    ) -> Result<(), BitVMXError> {
        self.register(
            OperationTimeoutId::DispatcherJob(job_id),
            timeout.unwrap_or(DEFAULT_JOB_TIMEOUT),
            renew,
        )
    }

    pub fn cancel(&self, id: &OperationTimeoutId) -> Result<(), BitVMXError> {
        let key = Self::key(id)?;
        if self.storage.get::<OperationTimeout>(&key, None)?.is_none() {
            return Ok(());
        }
        self.storage.remove(key, None)?;
        let mut ids = self.load_ids()?;
        ids.retain(|candidate| candidate != id);
        self.storage
            .set(OPERATION_TIMEOUT_IDS_KEY.as_ref(), ids, None)?;
        Ok(())
    }

    pub fn cancel_setup(&self, program_id: Uuid) -> Result<(), BitVMXError> {
        self.cancel(&OperationTimeoutId::SetupProcess(program_id))
    }

    pub fn cancel_job(&self, job_id: &str) -> Result<(), BitVMXError> {
        self.cancel(&OperationTimeoutId::DispatcherJob(job_id.to_string()))
    }

    pub fn get(&self, id: &OperationTimeoutId) -> Result<Option<OperationTimeout>, BitVMXError> {
        Ok(self.storage.get(Self::key(id)?, None)?)
    }

    /// Returns a bounded snapshot. Callers must re-read each item in its own transaction.
    pub fn expired(&self, limit: usize) -> Result<Vec<OperationTimeoutId>, BitVMXError> {
        let now = bitvmx_broker::retry::now_ms()?;
        let mut expired = Vec::new();
        for id in self.load_ids()? {
            if expired.len() == limit {
                break;
            }
            if self
                .get(&id)?
                .is_some_and(|timeout| timeout.deadline_ms <= now)
            {
                expired.push(id);
            }
        }
        Ok(expired)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TestStorageDir;

    #[test]
    fn setup_registration_is_idempotent_and_does_not_renew() {
        let dir = TestStorageDir::new("operation-timeout-idempotent");
        let timeouts = OperationTimeouts::new(dir.storage());
        let program_id = Uuid::new_v4();
        timeouts
            .register_setup(program_id, Some(Duration::from_secs(60)))
            .unwrap();
        let id = OperationTimeoutId::SetupProcess(program_id);
        let first = timeouts.get(&id).unwrap().unwrap();
        timeouts
            .register_setup(program_id, Some(Duration::from_secs(120)))
            .unwrap();
        assert_eq!(timeouts.get(&id).unwrap(), Some(first));
    }

    #[test]
    fn job_renewal_moves_the_deadline_without_duplicating_the_id() {
        let dir = TestStorageDir::new("operation-timeout-renew");
        let timeouts = OperationTimeouts::new(dir.storage());
        let job_id = "job".to_string();
        timeouts
            .register_job(job_id.clone(), Some(Duration::from_secs(3_600)), false)
            .unwrap();
        assert!(timeouts.expired(10).unwrap().is_empty());

        timeouts
            .register_job(job_id.clone(), Some(Duration::ZERO), true)
            .unwrap();
        assert_eq!(
            timeouts.expired(10).unwrap(),
            vec![OperationTimeoutId::DispatcherJob(job_id)]
        );
    }

    #[test]
    fn cancellation_is_idempotent() {
        let dir = TestStorageDir::new("operation-timeout-cancel");
        let timeouts = OperationTimeouts::new(dir.storage());
        let program_id = Uuid::new_v4();
        timeouts.register_setup(program_id, None).unwrap();
        timeouts.cancel_setup(program_id).unwrap();
        timeouts.cancel_setup(program_id).unwrap();
        assert!(timeouts.expired(10).unwrap().is_empty());
    }

    #[test]
    fn elapsed_deadline_survives_reconstruction() {
        let dir = TestStorageDir::new("operation-timeout-restart");
        let program_id = Uuid::new_v4();
        OperationTimeouts::new(dir.storage())
            .register_setup(program_id, Some(Duration::ZERO))
            .unwrap();

        // Constructing the facility again models a client restart: the persisted
        // absolute deadline is reused rather than granting a fresh setup budget.
        let restarted = OperationTimeouts::new(dir.storage());
        assert_eq!(
            restarted.expired(10).unwrap(),
            vec![OperationTimeoutId::SetupProcess(program_id)]
        );
    }

    #[test]
    fn expiration_scan_is_bounded() {
        let dir = TestStorageDir::new("operation-timeout-bounded");
        let timeouts = OperationTimeouts::new(dir.storage());
        for _ in 0..3 {
            timeouts
                .register_setup(Uuid::new_v4(), Some(Duration::ZERO))
                .unwrap();
        }
        assert_eq!(timeouts.expired(2).unwrap().len(), 2);
    }
}
