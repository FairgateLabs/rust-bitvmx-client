use crate::{bitvmx::Context, errors::BitVMXError, types::JobDispatcherType};
use bitvmx_broker::{identification::identifier::Identifier, BrokerNode};
use bitvmx_job_dispatcher::{dispatcher_job::DispatcherJob, dispatcher_message::DispatcherMessage};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::rc::Rc;
use storage_backend::{
    key::StorageKey,
    storage::{KeyValueStore, Storage},
};
use uuid::Uuid;

/// Durable description of a job issued to an authenticated dispatcher.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ExpectedJob {
    pub job_id: String,
    pub dispatcher: JobDispatcherType,
    pub owner: ExpectedJobOwner,
    pub kind: ExpectedJobKind,
    pub status: ExpectedJobStatus,
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
    pub fn register(
        &self,
        job_id: String,
        dispatcher: JobDispatcherType,
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
        let job = ExpectedJob {
            job_id,
            dispatcher,
            owner,
            kind,
            status: ExpectedJobStatus::Pending,
        };

        if let Some(existing) = self.get(&job.job_id)? {
            if existing.dispatcher == job.dispatcher
                && existing.owner == job.owner
                && existing.kind == job.kind
            {
                return Ok(ExpectedJobRegistration::AlreadyExists(existing.status));
            }
            return Err(BitVMXError::InvalidState(format!(
                "dispatcher job id '{}' is registered with incompatible metadata",
                job.job_id
            )));
        }
        self.storage.set(Self::key(&job.job_id)?, job, None)?;
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
    ) -> Result<ExpectedJobRegistration, BitVMXError> {
        let registration = self.register(job_id.clone(), dispatcher)?;
        if matches!(registration, ExpectedJobRegistration::AlreadyExists(_)) {
            return Ok(registration);
        }
        let message = serde_json::to_string(&DispatcherJob { job_id, job_type })?;
        broker_channel.send_service(destination, message)?;
        Ok(registration)
    }

    pub fn get(&self, job_id: &str) -> Result<Option<ExpectedJob>, BitVMXError> {
        Ok(self.storage.get(Self::key(job_id)?, None)?)
    }

    pub fn complete(&self, job_id: &str) -> Result<(), BitVMXError> {
        self.set_status(job_id, ExpectedJobStatus::Completed)
    }

    /// Keeps a runtime job unresolved after a dispatcher failure. A future retry
    /// scheduler will redispatch this same job id until success or manual discard.
    pub fn retry_pending(&self, job_id: &str, reason: String) -> Result<(), BitVMXError> {
        self.set_status(job_id, ExpectedJobStatus::RetryPending(reason))
    }

    pub fn discard(&self, job_id: &str, reason: String) -> Result<(), BitVMXError> {
        self.set_status(job_id, ExpectedJobStatus::Discarded(reason))
    }

    pub fn fail(&self, job_id: &str, reason: String) -> Result<(), BitVMXError> {
        self.set_status(job_id, ExpectedJobStatus::Failed(reason))
    }

    fn set_status(&self, job_id: &str, status: ExpectedJobStatus) -> Result<(), BitVMXError> {
        let Some(mut job) = self.get(job_id)? else {
            return Err(BitVMXError::InvalidState(format!(
                "dispatcher job '{}' is not registered",
                job_id
            )));
        };
        job.status = status;
        self.storage.set(Self::key(job_id)?, job, None)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TestStorageDir;

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
    fn updating_an_unknown_job_is_an_error() {
        let dir = TestStorageDir::new("unknown-expected-job");
        let jobs = ExpectedJobs::new(dir.storage());
        assert!(matches!(
            jobs.complete(&Uuid::new_v4().to_string()),
            Err(BitVMXError::InvalidState(_))
        ));
    }
}
