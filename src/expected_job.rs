use crate::{
    bitvmx::Context,
    errors::BitVMXError,
    operation_timeout::{OperationTimeouts, DEFAULT_JOB_TIMEOUT},
    types::JobDispatcherType,
};
use bitvmx_broker::{identification::identifier::Identifier, BrokerNode};
use bitvmx_job_dispatcher::{dispatcher_job::DispatcherJob, dispatcher_message::DispatcherMessage};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{rc::Rc, sync::LazyLock, time::Duration};
use storage_backend::{
    key::StorageKey,
    storage::{KeyValueStore, Storage},
};
use tracing::{error, warn};
use uuid::Uuid;

static EXPECTED_JOB_IDS_KEY: LazyLock<StorageKey> = LazyLock::new(|| {
    StorageKey::new(["bitvmx", "expected_job", "ids"])
        .expect("the fixed expected-job IDs storage key is valid")
});

const RETRY_MIN_DELAY_MS: u64 = 1_000;
const RETRY_MAX_DELAY_MS: u64 = 300_000;

/// Durable description of a job issued to an authenticated dispatcher.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ExpectedJob {
    pub job_id: String,
    pub dispatcher: JobDispatcherType,
    pub owner: ExpectedJobOwner,
    pub kind: ExpectedJobKind,
    pub status: ExpectedJobStatus,
    /// Exact outbound envelope and destination, retained so retries reuse the same wire id.
    #[serde(default)]
    dispatch: Option<ExpectedJobDispatch>,
    #[serde(default)]
    retry_attempts: u32,
    #[serde(default)]
    retry_not_before_ms: Option<u64>,
    /// Per-attempt timeout selected by the dispatching protocol or API caller.
    #[serde(default)]
    execution_timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ExpectedJobDispatch {
    destination: Identifier,
    message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum ExpectedJobOwner {
    Program(Uuid),
    Request(Uuid),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum ExpectedJobKind {
    Setup,
    Program,
    Zkp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum ExpectedJobStatus {
    Pending,
    RetryPending(String),
    Completed,
    Discarded(String),
    Failed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ExpectedJobRegistration {
    Registered,
    AlreadyExists(ExpectedJobStatus),
}

pub(crate) struct ExpectedJobs {
    storage: Rc<Storage>,
}

impl ExpectedJobs {
    pub fn new(storage: Rc<Storage>) -> Self {
        Self { storage }
    }

    fn key(job_id: &str) -> Result<StorageKey, BitVMXError> {
        let digest = hex::encode(Sha256::digest(job_id.as_bytes()));
        Ok(StorageKey::new(["bitvmx", "expected_job", &digest])?)
    }

    /// Registers the wire job id and derives its owner and kind using the same
    /// source-specific contract that ingress validates.
    #[cfg(test)]
    pub fn register(
        &self,
        job_id: String,
        dispatcher: JobDispatcherType,
    ) -> Result<ExpectedJobRegistration, BitVMXError> {
        self.register_with_dispatch(
            &OperationTimeouts::new(self.storage.clone()),
            job_id,
            dispatcher,
            None,
            None,
        )
    }

    fn register_with_dispatch(
        &self,
        timeouts: &OperationTimeouts,
        job_id: String,
        dispatcher: JobDispatcherType,
        dispatch: Option<ExpectedJobDispatch>,
        execution_timeout: Option<Duration>,
    ) -> Result<ExpectedJobRegistration, BitVMXError> {
        let (owner, kind) = match dispatcher {
            JobDispatcherType::ZKP => (
                ExpectedJobOwner::Request(Uuid::parse_str(&job_id).map_err(|error| {
                    BitVMXError::InvalidMessage(format!("invalid ZKP job id '{job_id}': {error}"))
                })?),
                ExpectedJobKind::Zkp,
            ),
            JobDispatcherType::Garbler | JobDispatcherType::Emulator => {
                match Context::from_string(&job_id)? {
                    Context::SetupStep(program_id, _, _, _)
                        if dispatcher == JobDispatcherType::Garbler =>
                    {
                        (
                            ExpectedJobOwner::Program(program_id),
                            ExpectedJobKind::Setup,
                        )
                    }
                    Context::ProgramStep(program_id, _) => (
                        ExpectedJobOwner::Program(program_id),
                        ExpectedJobKind::Program,
                    ),
                    context => {
                        return Err(BitVMXError::InvalidMessage(format!(
                            "unsupported {dispatcher:?} job context: {context:?}"
                        )))
                    }
                }
            }
        };
        let timeout = execution_timeout.unwrap_or(DEFAULT_JOB_TIMEOUT);
        let execution_timeout_ms = Some(u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX));
        let job = ExpectedJob {
            job_id,
            dispatcher,
            owner,
            kind,
            status: ExpectedJobStatus::Pending,
            dispatch,
            retry_attempts: 0,
            retry_not_before_ms: None,
            execution_timeout_ms,
        };

        if let Some(existing) = self.get(&job.job_id)? {
            if existing.dispatcher == job.dispatcher
                && existing.owner == job.owner
                && existing.kind == job.kind
                && existing.execution_timeout_ms == job.execution_timeout_ms
            {
                return Ok(ExpectedJobRegistration::AlreadyExists(existing.status));
            }
            return Err(BitVMXError::InvalidState(format!(
                "dispatcher job id '{}' is registered with incompatible metadata",
                job.job_id
            )));
        }
        let mut ids: Vec<String> = self
            .storage
            .get(EXPECTED_JOB_IDS_KEY.as_ref(), None)?
            .unwrap_or_default();
        ids.push(job.job_id.clone());
        self.storage.set(Self::key(&job.job_id)?, &job, None)?;
        self.storage.set(EXPECTED_JOB_IDS_KEY.as_ref(), ids, None)?;
        match (&job.owner, &job.kind) {
            (ExpectedJobOwner::Program(program_id), ExpectedJobKind::Setup) => {
                timeouts.register_setup_job(
                    *program_id,
                    job.job_id.clone(),
                    job.execution_timeout_ms.map(Duration::from_millis),
                    false,
                )?;
            }
            (ExpectedJobOwner::Program(program_id), ExpectedJobKind::Program) => {
                timeouts.register_runtime_job(
                    *program_id,
                    job.job_id.clone(),
                    job.execution_timeout_ms.map(Duration::from_millis),
                    false,
                )?;
            }
            (ExpectedJobOwner::Request(request_id), ExpectedJobKind::Zkp) => {
                timeouts.register_request_job(
                    *request_id,
                    job.job_id.clone(),
                    job.execution_timeout_ms.map(Duration::from_millis),
                    false,
                )?;
            }
            _ => {
                return Err(BitVMXError::InvalidState(
                    "dispatcher job owner and kind are incompatible".to_string(),
                ));
            }
        }
        Ok(ExpectedJobRegistration::Registered)
    }

    /// Registers and sends a job in the current storage transaction, so an outbox
    /// entry can never commit without its matching expected-result record.
    pub fn send_dispatcher_job<J: Serialize + DispatcherMessage>(
        &self,
        timeouts: &OperationTimeouts,
        broker_channel: &BrokerNode,
        dispatcher: JobDispatcherType,
        destination: &Identifier,
        job_id: String,
        job_type: J,
        execution_timeout: Option<Duration>,
    ) -> Result<ExpectedJobRegistration, BitVMXError> {
        let message = serde_json::to_string(&DispatcherJob {
            job_id: job_id.clone(),
            job_type,
        })?;
        let registration = self.register_with_dispatch(
            timeouts,
            job_id,
            dispatcher,
            Some(ExpectedJobDispatch {
                destination: destination.clone(),
                message: message.clone(),
            }),
            execution_timeout,
        )?;
        if matches!(registration, ExpectedJobRegistration::AlreadyExists(_)) {
            return Ok(registration);
        }
        broker_channel.send_service(destination, message)?;
        Ok(registration)
    }

    pub fn get(&self, job_id: &str) -> Result<Option<ExpectedJob>, BitVMXError> {
        Ok(self.storage.get(Self::key(job_id)?, None)?)
    }

    pub fn complete(&self, timeouts: &OperationTimeouts, job_id: &str) -> Result<(), BitVMXError> {
        self.set_status(timeouts, job_id, ExpectedJobStatus::Completed)
    }

    /// Keeps a runtime job unresolved after a dispatcher failure and schedules the
    /// same serialized job for redispatch with durable exponential backoff.
    pub fn retry_pending(
        &self,
        timeouts: &OperationTimeouts,
        job_id: &str,
        reason: String,
    ) -> Result<(), BitVMXError> {
        let Some(mut job) = self.get(job_id)? else {
            return Err(BitVMXError::InvalidState(format!(
                "dispatcher job '{}' is not registered",
                job_id
            )));
        };
        timeouts.cancel_job(job_id)?;
        job.retry_attempts = job.retry_attempts.saturating_add(1);
        let exponent = job.retry_attempts.saturating_sub(1).min(31);
        let delay = RETRY_MIN_DELAY_MS
            .saturating_mul(1_u64 << exponent)
            .min(RETRY_MAX_DELAY_MS);
        // Records created before durable dispatch payloads were introduced cannot be
        // redispatched, but must still settle the failed input without poisoning inbox.
        job.retry_not_before_ms = job
            .dispatch
            .as_ref()
            .map(|_| bitvmx_broker::retry::now_ms().map(|now| now.saturating_add(delay)))
            .transpose()?;
        error!(
            "Dispatcher job '{}' failed and will be retried: {}",
            job_id, reason
        );
        match job.retry_not_before_ms {
            Some(not_before) => warn!(
                "Dispatcher job '{}' will be retried in {} ms (not before Unix epoch {} ms)",
                job_id, delay, not_before
            ),
            None => warn!(
                "Dispatcher job '{}' cannot be automatically retried because its durable dispatch payload is unavailable",
                job_id
            ),
        }
        job.status = ExpectedJobStatus::RetryPending(reason);
        self.storage.set(Self::key(job_id)?, job, None)?;
        Ok(())
    }

    /// Redispatches due runtime jobs. Status and broker outbox writes share the caller's
    /// transaction, so a failed commit cannot lose the retry intent.
    pub fn redispatch_due(
        &self,
        timeouts: &OperationTimeouts,
        broker_channel: &BrokerNode,
    ) -> Result<usize, BitVMXError> {
        let now = bitvmx_broker::retry::now_ms()?;
        let ids: Vec<String> = self
            .storage
            .get(EXPECTED_JOB_IDS_KEY.as_ref(), None)?
            .unwrap_or_default();
        let mut dispatched = 0;
        for job_id in ids {
            let Some(mut job) = self.get(&job_id)? else {
                continue;
            };
            if !matches!(job.status, ExpectedJobStatus::RetryPending(_))
                || job
                    .retry_not_before_ms
                    .is_none_or(|not_before| not_before > now)
            {
                continue;
            }
            let Some(dispatch) = job.dispatch.clone() else {
                return Err(BitVMXError::InvalidState(format!(
                    "retry-pending dispatcher job '{}' has no durable dispatch payload",
                    job_id
                )));
            };
            warn!(
                "Retrying dispatcher job '{}' now (attempt {})",
                job_id, job.retry_attempts
            );
            broker_channel.send_service(&dispatch.destination, dispatch.message)?;
            let ExpectedJobOwner::Program(program_id) = &job.owner else {
                return Err(BitVMXError::InvalidState(format!(
                    "retryable dispatcher job '{}' is not program-owned",
                    job_id
                )));
            };
            timeouts.register_runtime_job(
                *program_id,
                job_id.clone(),
                job.execution_timeout_ms.map(Duration::from_millis),
                true,
            )?;
            job.status = ExpectedJobStatus::Pending;
            job.retry_not_before_ms = None;
            self.storage.set(Self::key(&job_id)?, job, None)?;
            dispatched += 1;
        }
        Ok(dispatched)
    }

    pub fn discard(
        &self,
        timeouts: &OperationTimeouts,
        job_id: &str,
        reason: String,
    ) -> Result<(), BitVMXError> {
        self.set_status(timeouts, job_id, ExpectedJobStatus::Discarded(reason))
    }

    pub fn fail(
        &self,
        timeouts: &OperationTimeouts,
        job_id: &str,
        reason: String,
    ) -> Result<(), BitVMXError> {
        self.set_status(timeouts, job_id, ExpectedJobStatus::Failed(reason))
    }

    fn set_status(
        &self,
        timeouts: &OperationTimeouts,
        job_id: &str,
        status: ExpectedJobStatus,
    ) -> Result<(), BitVMXError> {
        let Some(mut job) = self.get(job_id)? else {
            return Err(BitVMXError::InvalidState(format!(
                "dispatcher job '{}' is not registered",
                job_id
            )));
        };
        timeouts.cancel_job(job_id)?;
        job.status = status;
        self.storage.set(Self::key(job_id)?, job, None)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{TestProgramContextEnv, TestStorageDir};

    fn expected_jobs(storage: Rc<Storage>) -> ExpectedJobs {
        ExpectedJobs::new(storage)
    }

    #[test]
    fn registration_is_idempotent_for_every_existing_status() {
        let dir = TestStorageDir::new("expected-job-registration");
        let storage = dir.storage();
        let jobs = expected_jobs(storage.clone());
        let job_id = Uuid::new_v4().to_string();

        assert_eq!(
            jobs.register(job_id.clone(), JobDispatcherType::ZKP)
                .unwrap(),
            ExpectedJobRegistration::Registered
        );
        assert_eq!(
            jobs.register(job_id.clone(), JobDispatcherType::ZKP)
                .unwrap(),
            ExpectedJobRegistration::AlreadyExists(ExpectedJobStatus::Pending)
        );

        jobs.complete(&OperationTimeouts::new(storage), &job_id)
            .unwrap();
        assert_eq!(
            jobs.register(job_id.clone(), JobDispatcherType::ZKP)
                .unwrap(),
            ExpectedJobRegistration::AlreadyExists(ExpectedJobStatus::Completed)
        );
    }

    #[test]
    fn updating_an_unknown_job_is_an_error() {
        let dir = TestStorageDir::new("unknown-expected-job");
        let storage = dir.storage();
        let jobs = expected_jobs(storage.clone());
        assert!(matches!(
            jobs.complete(
                &OperationTimeouts::new(storage),
                &Uuid::new_v4().to_string(),
            ),
            Err(BitVMXError::InvalidState(_))
        ));
    }

    #[test]
    fn runtime_failure_durably_schedules_the_same_envelope_with_backoff() {
        let dir = TestStorageDir::new("expected-job-retry");
        let storage = dir.storage();
        let jobs = expected_jobs(storage.clone());
        let job_id = Context::ProgramStep(Uuid::new_v4(), "execute-round-1".to_string())
            .to_string()
            .unwrap();
        let destination = Identifier::new("dispatcher".to_string(), 0);
        let message = format!(r#"{{"job_id":"{job_id}"}}"#);

        jobs.register_with_dispatch(
            &OperationTimeouts::new(storage.clone()),
            job_id.clone(),
            JobDispatcherType::Emulator,
            Some(ExpectedJobDispatch {
                destination: destination.clone(),
                message: message.clone(),
            }),
            Some(Duration::from_secs(42)),
        )
        .unwrap();
        let before = bitvmx_broker::retry::now_ms().unwrap();
        jobs.retry_pending(
            &OperationTimeouts::new(storage),
            &job_id,
            "dispatcher failed".to_string(),
        )
        .unwrap();

        let job = jobs.get(&job_id).unwrap().unwrap();
        assert!(matches!(
            job.status,
            ExpectedJobStatus::RetryPending(ref reason) if reason == "dispatcher failed"
        ));
        assert_eq!(job.retry_attempts, 1);
        assert_eq!(job.execution_timeout_ms, Some(42_000));
        assert!(job.retry_not_before_ms.unwrap() >= before + RETRY_MIN_DELAY_MS);
        assert_eq!(
            job.dispatch,
            Some(ExpectedJobDispatch {
                destination,
                message
            })
        );
    }

    #[test]
    fn due_retry_is_requeued_and_returns_to_pending() {
        let env = TestProgramContextEnv::new("expected-job-redispatch").unwrap();
        let jobs = &env.context.expected_jobs;
        let job_id = Context::ProgramStep(Uuid::new_v4(), "execute-round-1".to_string())
            .to_string()
            .unwrap();
        jobs.register_with_dispatch(
            &env.context.operation_timeouts,
            job_id.clone(),
            JobDispatcherType::Emulator,
            Some(ExpectedJobDispatch {
                destination: Identifier::new("dispatcher".to_string(), 0),
                message: format!(r#"{{"job_id":"{job_id}"}}"#),
            }),
            None,
        )
        .unwrap();
        jobs.retry_pending(
            &env.context.operation_timeouts,
            &job_id,
            "retry me".to_string(),
        )
        .unwrap();

        let mut job = jobs.get(&job_id).unwrap().unwrap();
        job.retry_not_before_ms = Some(0);
        jobs.storage
            .set(ExpectedJobs::key(&job_id).unwrap(), job, None)
            .unwrap();

        assert_eq!(
            jobs.redispatch_due(&env.context.operation_timeouts, &env.context.broker_channel)
                .unwrap(),
            1
        );
        let job = jobs.get(&job_id).unwrap().unwrap();
        assert_eq!(job.status, ExpectedJobStatus::Pending);
        assert_eq!(job.retry_attempts, 1);
        assert_eq!(job.retry_not_before_ms, None);
        assert_eq!(
            jobs.redispatch_due(&env.context.operation_timeouts, &env.context.broker_channel)
                .unwrap(),
            0
        );
    }
}
