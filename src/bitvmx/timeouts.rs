//! Operation timeouts for setups and dispatcher jobs.

use super::BitVMX;
use crate::{
    errors::BitVMXError,
    expected_job::{ExpectedJobStatus, ExpectedJobTarget, JOB_TIMEOUT_REASON},
    operation_timeout::OperationTimeoutId,
    ports::bitcoin_coordinator::BitcoinCoordinatorApi,
    types::{DispatcherJobFailure, JobDispatcherType, ResultDisposition, SetupFailureReason},
};
use uuid::Uuid;

/// How many expired timeouts one tick settles, so a backlog can't stall the other phases.
const MAX_TIMEOUTS_PER_TICK: usize = 32;

impl<BC: BitcoinCoordinatorApi> BitVMX<BC> {
    /// Applies a bounded timeout snapshot, settling every expiration in its own
    /// transaction so one broken operation cannot roll back unrelated deadlines.
    pub(super) fn process_operation_timeouts(&mut self) -> Result<bool, BitVMXError> {
        let ids = self
            .program_context
            .operation_timeouts
            .expired(MAX_TIMEOUTS_PER_TICK)?;
        let had_work = !ids.is_empty();

        for id in ids {
            self.run_tx_step(&format!("operation timeout {id:?}"), |this| {
                this.apply_operation_timeout(&id)
            })?;
        }
        Ok(had_work)
    }

    fn apply_operation_timeout(&mut self, id: &OperationTimeoutId) -> Result<(), BitVMXError> {
        let Some(timeout) = self.program_context.operation_timeouts.get(id)? else {
            return Ok(());
        };
        if timeout.deadline_ms > bitvmx_broker::retry::now_ms()? {
            return Ok(());
        }

        match id {
            OperationTimeoutId::SetupProcess(program_id) => {
                self.apply_setup_timeout(id, *program_id, None)
            }
            OperationTimeoutId::DispatcherJob(job_id) => self.apply_job_timeout(id, job_id),
        }
    }

    fn apply_job_timeout(
        &mut self,
        id: &OperationTimeoutId,
        job_id: &str,
    ) -> Result<(), BitVMXError> {
        let Some(job) = self.program_context.expected_jobs.get(job_id)? else {
            return self.program_context.operation_timeouts.cancel(id);
        };
        if !matches!(job.status, ExpectedJobStatus::Pending) {
            return self.program_context.operation_timeouts.cancel(id);
        }
        match job.target {
            ExpectedJobTarget::Setup(program_id) => {
                self.apply_setup_timeout(id, program_id, Some(job_id))
            }
            ExpectedJobTarget::Request(request_id) => self.fail_zkp_timeout(request_id, job_id),
            ExpectedJobTarget::Program(program_id) => {
                self.apply_program_job_timeout(id, job_id, program_id, job.dispatcher)
            }
        }
    }

    fn apply_program_job_timeout(
        &mut self,
        id: &OperationTimeoutId,
        job_id: &str,
        program_id: Uuid,
        dispatcher: JobDispatcherType,
    ) -> Result<(), BitVMXError> {
        let Some(program) = self.load_program(&program_id)? else {
            return self.program_context.operation_timeouts.cancel(id);
        };
        if program.is_failed() {
            return self.program_context.operation_timeouts.cancel(id);
        }
        self.apply_dispatcher_result_disposition(
            dispatcher,
            ResultDisposition::fail_dispatcher(DispatcherJobFailure {
                program_id,
                expected_job_id: job_id.to_string(),
                job_id: job_id.to_string(),
                reason: JOB_TIMEOUT_REASON.to_string(),
            }),
        )
    }

    /// Fails an unfinished setup, settling `job_id` first when a dispatcher job timed out.
    fn apply_setup_timeout(
        &mut self,
        id: &OperationTimeoutId,
        program_id: Uuid,
        job_id: Option<&str>,
    ) -> Result<(), BitVMXError> {
        let Some(program) = self.load_program(&program_id)? else {
            return self.program_context.operation_timeouts.cancel(id);
        };
        if program.peer_message_lifecycle_disposition().is_some() {
            return self.program_context.operation_timeouts.cancel(id);
        }
        if let Some(job_id) = job_id {
            self.program_context.expected_jobs.fail(
                &self.program_context.operation_timeouts,
                job_id,
                JOB_TIMEOUT_REASON.to_string(),
            )?;
        }
        self.fail_program_setup(
            &program_id,
            None,
            SetupFailureReason::StepError("setup operation timed out".to_string()),
        )
    }
}
