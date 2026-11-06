use crate::{
    bitvmx::Context,
    errors::BitVMXError,
    operation_timeout::{duration_ms, OperationTimeouts, DEFAULT_JOB_TIMEOUT},
    types::JobDispatcherType,
};
use bitvmx_broker::{identification::identifier::Identifier, BrokerNode};
use bitvmx_job_dispatcher::{dispatcher_job::DispatcherJob, dispatcher_message::DispatcherMessage};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{rc::Rc, time::Duration};
use storage_backend::{
    key::StorageKey,
    storage::{KeyValueStore, Storage},
};
use tracing::{error, warn};
use uuid::Uuid;

/// Records live under `active` while a result is still expected, and move to `finished` once
/// terminal, so the per-tick retry scan only reads in-flight jobs.
const ACTIVE: &str = "active";
const FINISHED: &str = "finished";

const RETRY_MIN_DELAY_MS: u64 = 1_000;
const RETRY_MAX_DELAY_MS: u64 = 300_000;

/// Failure reason recorded when a dispatcher job exceeds its execution timeout.
pub(crate) const JOB_TIMEOUT_REASON: &str = "dispatcher job execution timed out";

/// What a dispatcher job id refers to. Derived from the wire id, so registration and
/// result ingress apply the same source-specific contract.
#[derive(Debug)]
pub(crate) enum JobTarget {
    Request(Uuid),
    Setup(Uuid, Context),
    Program(Uuid, Context),
}

impl JobTarget {
    pub fn derive(dispatcher: JobDispatcherType, job_id: &str) -> Result<Self, BitVMXError> {
        match dispatcher {
            JobDispatcherType::ZKP => {
                Ok(Self::Request(Uuid::parse_str(job_id).map_err(|error| {
                    BitVMXError::InvalidMessage(format!("invalid ZKP job id '{job_id}': {error}"))
                })?))
            }
            JobDispatcherType::Garbler | JobDispatcherType::Emulator => {
                match Context::from_string(job_id)? {
                    context @ Context::SetupStep(program_id, _, _, _)
                        if dispatcher == JobDispatcherType::Garbler =>
                    {
                        Ok(Self::Setup(program_id, context))
                    }
                    context @ Context::ProgramStep(program_id, _) => {
                        Ok(Self::Program(program_id, context))
                    }
                    context => Err(BitVMXError::InvalidMessage(format!(
                        "unsupported {dispatcher:?} job context: {context:?}"
                    ))),
                }
            }
        }
    }

    pub fn expected_target(&self) -> ExpectedJobTarget {
        match self {
            Self::Request(id) => ExpectedJobTarget::Request(*id),
            Self::Setup(program_id, _) => ExpectedJobTarget::Setup(*program_id),
            Self::Program(program_id, _) => ExpectedJobTarget::Program(*program_id),
        }
    }
}

/// Durable description of a job issued to an authenticated dispatcher.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ExpectedJob {
    pub job_id: String,
    pub dispatcher: JobDispatcherType,
    pub target: ExpectedJobTarget,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum ExpectedJobTarget {
    Setup(Uuid),
    Program(Uuid),
    Request(Uuid),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum ExpectedJobStatus {
    Pending,
    RetryPending(String),
    Completed,
    Discarded(String),
    Failed(String),
}

impl ExpectedJobStatus {
    fn is_finished(&self) -> bool {
        matches!(self, Self::Completed | Self::Discarded(_) | Self::Failed(_))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ExpectedJobRegistration {
    Registered,
    AlreadyExists(ExpectedJobStatus),
}

pub(crate) struct ExpectedJobs {
    storage: Rc<Storage>,
    timeouts: OperationTimeouts,
}

impl ExpectedJobs {
    pub fn new(storage: Rc<Storage>) -> Self {
        Self {
            timeouts: OperationTimeouts::new(storage.clone()),
            storage,
        }
    }

    fn key(state: &str, job_id: &str) -> Result<StorageKey, BitVMXError> {
        let digest = hex::encode(Sha256::digest(job_id.as_bytes()));
        Ok(StorageKey::new(["bitvmx", "expected_job", state, &digest])?)
    }

    /// Writes the record under the key for its status and removes it from the other one.
    fn save(&self, job: &ExpectedJob) -> Result<(), BitVMXError> {
        let (state, other) = if job.status.is_finished() {
            (FINISHED, ACTIVE)
        } else {
            (ACTIVE, FINISHED)
        };
        self.storage
            .set(Self::key(state, &job.job_id)?, job, None)?;
        self.storage.remove(Self::key(other, &job.job_id)?, None)?;
        Ok(())
    }

    /// Registers the wire job id and derives its target using the same
    /// source-specific contract that ingress validates.
    #[cfg(test)]
    pub fn register(
        &self,
        job_id: String,
        dispatcher: JobDispatcherType,
    ) -> Result<ExpectedJobRegistration, BitVMXError> {
        self.register_with_dispatch(job_id, dispatcher, None, None)
    }

    fn register_with_dispatch(
        &self,
        job_id: String,
        dispatcher: JobDispatcherType,
        dispatch: Option<ExpectedJobDispatch>,
        execution_timeout: Option<Duration>,
    ) -> Result<ExpectedJobRegistration, BitVMXError> {
        let target = JobTarget::derive(dispatcher, &job_id)?.expected_target();
        let timeout = execution_timeout.unwrap_or(DEFAULT_JOB_TIMEOUT);
        let execution_timeout_ms = Some(duration_ms(timeout));

        if let Some(existing) = self.get(&job_id)? {
            if existing.dispatcher == dispatcher
                && existing.target == target
                && existing.execution_timeout_ms == execution_timeout_ms
            {
                return Ok(ExpectedJobRegistration::AlreadyExists(existing.status));
            }
            return Err(BitVMXError::DispatcherJobConflict(job_id));
        }
        let job = ExpectedJob {
            job_id,
            dispatcher,
            target,
            status: ExpectedJobStatus::Pending,
            dispatch,
            retry_attempts: 0,
            retry_not_before_ms: None,
            execution_timeout_ms,
        };
        self.storage
            .set(Self::key(ACTIVE, &job.job_id)?, &job, None)?;
        self.timeouts
            .register_job(job.job_id, Some(timeout), false)?;
        Ok(ExpectedJobRegistration::Registered)
    }

    /// Registers and sends a job in the current storage transaction, so an outbox
    /// entry can never commit without its matching expected-result record.
    pub fn send_dispatcher_job<J: Serialize + DispatcherMessage>(
        &self,
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
        if let Some(job) = self.storage.get(Self::key(ACTIVE, job_id)?, None)? {
            return Ok(Some(job));
        }
        Ok(self.storage.get(Self::key(FINISHED, job_id)?, None)?)
    }

    fn active_jobs(&self) -> Result<Vec<ExpectedJob>, BitVMXError> {
        let prefix = StorageKey::new(["bitvmx", "expected_job", ACTIVE])?.to_scan_prefix();
        self.storage
            .partial_compare(&prefix, None)?
            .into_iter()
            .map(|(_, job)| Ok(serde_json::from_str(&job)?))
            .collect()
    }

    pub fn get_registered(&self, job_id: &str) -> Result<ExpectedJob, BitVMXError> {
        self.get(job_id)?.ok_or_else(|| {
            BitVMXError::InvalidState(format!("dispatcher job '{job_id}' is not registered"))
        })
    }

    pub fn complete(&self, job_id: &str) -> Result<(), BitVMXError> {
        self.set_status(job_id, ExpectedJobStatus::Completed)
    }

    /// Keeps a runtime job unresolved after a dispatcher failure and schedules the
    /// same serialized job for redispatch with durable exponential backoff.
    pub fn retry_pending(&self, job_id: &str, reason: String) -> Result<(), BitVMXError> {
        let mut job = self.get_registered(job_id)?;
        self.timeouts.cancel_job(job_id)?;
        job.retry_attempts = job.retry_attempts.saturating_add(1);
        let delay = retry_delay_ms(job.retry_attempts);
        // Records created before durable dispatch payloads were introduced cannot be
        // redispatched, but must still settle the failed input without poisoning inbox.
        job.retry_not_before_ms = if job.dispatch.is_some() {
            Some(bitvmx_broker::retry::now_ms()?.saturating_add(delay))
        } else {
            None
        };
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
        self.save(&job)?;
        Ok(())
    }

    /// Redispatches due runtime jobs. Status and broker outbox writes share the caller's
    /// transaction, so a failed commit cannot lose the retry intent.
    ///
    /// A due record with no dispatch payload or a non-program target is corrupt, since
    /// normal flows never produce one. It fails the whole pass on purpose rather than being
    /// skipped or marked failed: the error repeats every tick and halts all redispatches
    /// until an operator inspects the record and decides what happened.
    pub fn redispatch_due(&self, broker_channel: &BrokerNode) -> Result<usize, BitVMXError> {
        let now = bitvmx_broker::retry::now_ms()?;
        let mut dispatched = 0;
        for mut job in self.active_jobs()? {
            let job_id = job.job_id.clone();
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
            if !matches!(job.target, ExpectedJobTarget::Program(_)) {
                return Err(BitVMXError::InvalidState(format!(
                    "retryable dispatcher job '{}' is not a runtime program job",
                    job_id
                )));
            }
            broker_channel.send_service(&dispatch.destination, dispatch.message)?;
            self.timeouts.register_job(
                job_id.clone(),
                job.execution_timeout_ms.map(Duration::from_millis),
                true,
            )?;
            job.status = ExpectedJobStatus::Pending;
            job.retry_not_before_ms = None;
            self.save(&job)?;
            dispatched += 1;
        }
        Ok(dispatched)
    }

    pub fn discard(&self, job_id: &str, reason: String) -> Result<(), BitVMXError> {
        self.set_status(job_id, ExpectedJobStatus::Discarded(reason))
    }

    pub fn fail(&self, job_id: &str, reason: String) -> Result<(), BitVMXError> {
        self.set_status(job_id, ExpectedJobStatus::Failed(reason))
    }

    fn set_status(&self, job_id: &str, status: ExpectedJobStatus) -> Result<(), BitVMXError> {
        let mut job = self.get_registered(job_id)?;
        self.timeouts.cancel_job(job_id)?;
        job.status = status;
        self.save(&job)?;
        Ok(())
    }
}

fn retry_delay_ms(attempts: u32) -> u64 {
    let exponent = attempts.saturating_sub(1).min(31);
    RETRY_MIN_DELAY_MS
        .saturating_mul(1_u64 << exponent)
        .min(RETRY_MAX_DELAY_MS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{TestProgramContextEnv, TestStorageDir};

    #[test]
    fn expected_job_target_variants_round_trip() {
        let id = Uuid::new_v4();
        let variants = [
            (ExpectedJobTarget::Setup(id), JobDispatcherType::Garbler),
            (ExpectedJobTarget::Program(id), JobDispatcherType::Emulator),
            (ExpectedJobTarget::Request(id), JobDispatcherType::ZKP),
        ];

        for (target, dispatcher) in variants {
            let job = ExpectedJob {
                job_id: "job".to_string(),
                dispatcher,
                target,
                status: ExpectedJobStatus::Pending,
                dispatch: None,
                retry_attempts: 0,
                retry_not_before_ms: None,
                execution_timeout_ms: None,
            };
            let serialized = serde_json::to_value(&job).unwrap();
            let expected_target = match target {
                ExpectedJobTarget::Setup(id) => serde_json::json!({"Setup": id}),
                ExpectedJobTarget::Program(id) => serde_json::json!({"Program": id}),
                ExpectedJobTarget::Request(id) => serde_json::json!({"Request": id}),
            };
            assert_eq!(serialized["target"], expected_target);
            assert_eq!(
                serde_json::from_value::<ExpectedJob>(serialized).unwrap(),
                job
            );
        }
    }

    #[test]
    fn registration_is_idempotent_for_every_existing_status() {
        let dir = TestStorageDir::new("expected-job-registration");
        let jobs = ExpectedJobs::new(dir.storage());
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

        jobs.complete(&job_id).unwrap();
        assert_eq!(
            jobs.register(job_id.clone(), JobDispatcherType::ZKP)
                .unwrap(),
            ExpectedJobRegistration::AlreadyExists(ExpectedJobStatus::Completed)
        );
    }

    #[test]
    fn terminal_job_history_survives_facility_reconstruction() {
        let dir = TestStorageDir::new("expected-job-terminal-history");
        let storage = dir.storage();
        let jobs = ExpectedJobs::new(storage.clone());
        let completed = Uuid::new_v4().to_string();
        let failed = Uuid::new_v4().to_string();
        let discarded = Context::ProgramStep(Uuid::new_v4(), "execute-round-1".to_string())
            .to_string()
            .unwrap();

        jobs.register(completed.clone(), JobDispatcherType::ZKP)
            .unwrap();
        jobs.register(failed.clone(), JobDispatcherType::ZKP)
            .unwrap();
        jobs.register(discarded.clone(), JobDispatcherType::Emulator)
            .unwrap();
        assert_eq!(jobs.active_jobs().unwrap().len(), 3);
        jobs.complete(&completed).unwrap();
        jobs.fail(&failed, "prover failed".to_string()).unwrap();
        jobs.discard(&discarded, "operator discarded".to_string())
            .unwrap();
        // Terminal records leave the active set, so the retry scan no longer reads them.
        assert!(jobs.active_jobs().unwrap().is_empty());

        // Reconstructing the online facility models a restart. Terminal records
        // remain the durable deduplication and diagnostic history; no online
        // maintenance path removes them.
        let restarted = ExpectedJobs::new(storage);
        assert!(matches!(
            restarted.get(&completed).unwrap().unwrap().status,
            ExpectedJobStatus::Completed
        ));
        assert!(matches!(
            restarted.get(&failed).unwrap().unwrap().status,
            ExpectedJobStatus::Failed(ref reason) if reason == "prover failed"
        ));
        assert!(matches!(
            restarted.get(&discarded).unwrap().unwrap().status,
            ExpectedJobStatus::Discarded(ref reason) if reason == "operator discarded"
        ));
    }

    #[test]
    fn updating_an_unknown_job_is_an_error() {
        let dir = TestStorageDir::new("unknown-expected-job");
        let jobs = ExpectedJobs::new(dir.storage());
        assert!(matches!(
            jobs.complete(&Uuid::new_v4().to_string()),
            Err(BitVMXError::InvalidState(_))
        ));
    }

    #[test]
    fn runtime_failure_durably_schedules_the_same_envelope_with_backoff() {
        let dir = TestStorageDir::new("expected-job-retry");
        let jobs = ExpectedJobs::new(dir.storage());
        let job_id = Context::ProgramStep(Uuid::new_v4(), "execute-round-1".to_string())
            .to_string()
            .unwrap();
        let destination = Identifier::new("dispatcher".to_string(), 0);
        let message = format!(r#"{{"job_id":"{job_id}"}}"#);

        jobs.register_with_dispatch(
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
        jobs.retry_pending(&job_id, "dispatcher failed".to_string())
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
            job_id.clone(),
            JobDispatcherType::Emulator,
            Some(ExpectedJobDispatch {
                destination: Identifier::new("dispatcher".to_string(), 0),
                message: format!(r#"{{"job_id":"{job_id}"}}"#),
            }),
            None,
        )
        .unwrap();
        jobs.retry_pending(&job_id, "retry me".to_string()).unwrap();

        let mut job = jobs.get(&job_id).unwrap().unwrap();
        job.retry_not_before_ms = Some(0);
        jobs.save(&job).unwrap();

        assert_eq!(jobs.redispatch_due(&env.context.broker_channel).unwrap(), 1);
        let job = jobs.get(&job_id).unwrap().unwrap();
        assert_eq!(job.status, ExpectedJobStatus::Pending);
        assert_eq!(job.retry_attempts, 1);
        assert_eq!(job.retry_not_before_ms, None);
        assert_eq!(jobs.redispatch_due(&env.context.broker_channel).unwrap(), 0);
    }

    fn stored_under(jobs: &ExpectedJobs, job_id: &str) -> (bool, bool) {
        let has = |state| {
            jobs.storage
                .has_key(ExpectedJobs::key(state, job_id).unwrap(), None)
                .unwrap()
        };
        (has(ACTIVE), has(FINISHED))
    }

    #[test]
    fn each_transition_keeps_the_record_under_exactly_one_state_key() {
        let env = TestProgramContextEnv::new("expected-job-transitions").unwrap();
        let jobs = &env.context.expected_jobs;
        let job_id = Context::ProgramStep(Uuid::new_v4(), "execute-round-1".to_string())
            .to_string()
            .unwrap();
        let active = (true, false);
        let finished = (false, true);

        jobs.register_with_dispatch(
            job_id.clone(),
            JobDispatcherType::Emulator,
            Some(ExpectedJobDispatch {
                destination: Identifier::new("dispatcher".to_string(), 0),
                message: format!(r#"{{"job_id":"{job_id}"}}"#),
            }),
            None,
        )
        .unwrap();
        assert_eq!(stored_under(jobs, &job_id), active);

        jobs.retry_pending(&job_id, "retry me".to_string()).unwrap();
        assert_eq!(stored_under(jobs, &job_id), active);

        let mut job = jobs.get(&job_id).unwrap().unwrap();
        job.retry_not_before_ms = Some(0);
        jobs.save(&job).unwrap();
        assert_eq!(jobs.redispatch_due(&env.context.broker_channel).unwrap(), 1);
        assert_eq!(stored_under(jobs, &job_id), active);

        // A due retry that is discarded leaves the active set, so the scan no longer redispatches it.
        jobs.retry_pending(&job_id, "retry again".to_string())
            .unwrap();
        let mut job = jobs.get(&job_id).unwrap().unwrap();
        job.retry_not_before_ms = Some(0);
        jobs.save(&job).unwrap();
        jobs.discard(&job_id, "operator discarded".to_string())
            .unwrap();
        assert_eq!(stored_under(jobs, &job_id), finished);
        assert_eq!(jobs.redispatch_due(&env.context.broker_channel).unwrap(), 0);
        assert!(matches!(
            jobs.get(&job_id).unwrap().unwrap().status,
            ExpectedJobStatus::Discarded(_)
        ));
    }
}
