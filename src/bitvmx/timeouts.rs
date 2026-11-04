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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bitvmx::{test_support::create_single_participant_program, Context},
        comms_helper::CommsMessageType,
        operation_timeout::OperationTimeouts,
        program::{program::Program, variables::VariableTypes},
        test_utils::TestBitVMXEnv,
    };
    use std::time::Duration;

    #[test]
    fn setup_timeout_fails_a_setup_waiting_without_input() {
        let mut env = TestBitVMXEnv::new("setup-operation-timeout").unwrap();
        let program_id = Uuid::new_v4();
        let store = create_single_participant_program(&mut env, program_id);
        env.bitvmx
            .program_context
            .operation_timeouts
            .cancel_setup(program_id)
            .unwrap();
        OperationTimeouts::new(store.clone())
            .register_setup(program_id, Some(Duration::ZERO))
            .unwrap();

        assert!(env.bitvmx.process_operation_timeouts().unwrap());
        assert!(Program::load(store, &program_id)
            .unwrap()
            .unwrap()
            .is_failed());
        assert!(!env.bitvmx.process_operation_timeouts().unwrap());
    }

    #[test]
    fn setup_job_timeout_fails_the_job_and_its_setup() {
        let mut env = TestBitVMXEnv::new("setup-job-operation-timeout").unwrap();
        let program_id = Uuid::new_v4();
        let store = create_single_participant_program(&mut env, program_id);
        let job_id = Context::SetupStep(
            program_id,
            "garbler".to_string(),
            String::new(),
            CommsMessageType::GarbledCircuit,
        )
        .to_string()
        .unwrap();
        let context = &env.bitvmx.program_context;
        context
            .expected_jobs
            .register(job_id.clone(), crate::types::JobDispatcherType::Garbler)
            .unwrap();
        context.operation_timeouts.cancel_job(&job_id).unwrap();
        context
            .operation_timeouts
            .register_job(job_id.clone(), Some(Duration::ZERO), false)
            .unwrap();

        assert!(env.bitvmx.process_operation_timeouts().unwrap());
        assert!(matches!(
            env.bitvmx
                .program_context
                .expected_jobs
                .get(&job_id)
                .unwrap()
                .unwrap()
                .status,
            ExpectedJobStatus::Failed(ref reason) if reason == JOB_TIMEOUT_REASON
        ));
        assert!(Program::load(store, &program_id)
            .unwrap()
            .unwrap()
            .is_failed());
        assert!(!env.bitvmx.process_operation_timeouts().unwrap());
    }

    #[test]
    fn settled_job_timeout_is_cancelled_without_touching_the_program() {
        let mut env = TestBitVMXEnv::new("settled-job-operation-timeout").unwrap();
        let program_id = Uuid::new_v4();
        let store = create_single_participant_program(&mut env, program_id);
        let job_id = Context::SetupStep(
            program_id,
            "garbler".to_string(),
            String::new(),
            CommsMessageType::GarbledCircuit,
        )
        .to_string()
        .unwrap();
        let context = &env.bitvmx.program_context;
        context
            .expected_jobs
            .register(job_id.clone(), crate::types::JobDispatcherType::Garbler)
            .unwrap();
        context
            .expected_jobs
            .complete(&context.operation_timeouts, &job_id)
            .unwrap();
        context
            .operation_timeouts
            .register_job(job_id.clone(), Some(Duration::ZERO), false)
            .unwrap();

        assert!(env.bitvmx.process_operation_timeouts().unwrap());
        assert!(!Program::load(store, &program_id)
            .unwrap()
            .unwrap()
            .is_failed());
        assert!(env
            .bitvmx
            .program_context
            .operation_timeouts
            .get(&OperationTimeoutId::DispatcherJob(job_id))
            .unwrap()
            .is_none());
    }

    #[test]
    fn runtime_job_timeout_enters_retry_without_failing_program() {
        let mut env = TestBitVMXEnv::new("runtime-operation-timeout").unwrap();
        let program_id = Uuid::new_v4();
        let store = create_single_participant_program(&mut env, program_id);
        env.bitvmx
            .program_context
            .globals
            .set_var(
                &program_id,
                "optional_keys",
                VariableTypes::String("null".to_string()),
            )
            .unwrap();
        let mut program = Program::load(store.clone(), &program_id).unwrap().unwrap();
        program.tick(&mut env.bitvmx.program_context).unwrap();
        program.tick(&mut env.bitvmx.program_context).unwrap();

        let job_id = Context::ProgramStep(program_id, "execute-round-1".to_string())
            .to_string()
            .unwrap();
        env.bitvmx
            .program_context
            .expected_jobs
            .register(job_id.clone(), crate::types::JobDispatcherType::Emulator)
            .unwrap();
        let timeout_id = OperationTimeoutId::DispatcherJob(job_id.clone());
        env.bitvmx
            .program_context
            .operation_timeouts
            .cancel(&timeout_id)
            .unwrap();
        OperationTimeouts::new(store.clone())
            .register_job(job_id.clone(), Some(Duration::ZERO), false)
            .unwrap();

        assert!(env.bitvmx.process_operation_timeouts().unwrap());
        assert!(matches!(
            env.bitvmx
                .program_context
                .expected_jobs
                .get(&job_id)
                .unwrap()
                .unwrap()
                .status,
            ExpectedJobStatus::RetryPending(_)
        ));
        assert!(!Program::load(store, &program_id)
            .unwrap()
            .unwrap()
            .is_failed());
    }
}
