use super::{BitVMX, Context, StoreKey};
use crate::{
    error_handling::try_send_error_report,
    errors::BitVMXError,
    expected_job::{ExpectedJob, ExpectedJobStatus, JobTarget, JOB_TIMEOUT_REASON},
    ports::bitcoin_coordinator::BitcoinCoordinatorApi,
    types::{
        DispatcherJobFailure, ErrorReport, ErrorReportKind, ErrorScope, FailureDetail,
        JobDispatcherType, NoOpReason, OutgoingBitVMXApiMessages, ResultDisposition, SuccessDetail,
        ZKPExecution,
    },
};
use bitvmx_broker::{identification::identifier::Identifier, ReceivedMessage};
use bitvmx_dispatcher_utils::PingMessage;
use bitvmx_job_dispatcher::dispatcher_job::ResultMessage;
use std::str::FromStr;
use storage_backend::storage::KeyValueStore;
use tracing::{debug, error, info, warn};
use uuid::Uuid;
use zk_result::ResultType as ProverResultType;

/// Outcome of decoding a message from an authenticated dispatcher route. Result
/// payloads remain encoded until the target-specific handler validates them.
#[derive(Debug)]
enum DispatcherIngress {
    Result(ResultMessage, JobTarget),
    Settled(ResultDisposition),
}

/// Checks correlation shared by all result handlers: the result must come from the
/// dispatcher the job was issued to and the job must still be awaiting a result.
fn rejection(expected: &ExpectedJob, dispatcher: JobDispatcherType) -> Option<NoOpReason> {
    if expected.dispatcher != dispatcher {
        warn!(
            "Ignoring result for job '{}' from {dispatcher:?}; expected {:?}",
            expected.job_id, expected.dispatcher
        );
        return Some(NoOpReason::Uncorrelatable);
    }
    match &expected.status {
        ExpectedJobStatus::Pending => None,
        status => {
            if let ExpectedJobStatus::Failed(reason) = status {
                if reason.contains(JOB_TIMEOUT_REASON) {
                    error!(
                        "Discarding late result from {dispatcher:?} for timed-out job '{}': {}",
                        expected.job_id, reason
                    );
                }
            }
            Some(NoOpReason::Duplicate)
        }
    }
}

/// Validates a prover result, returning the seal and journal or the failure reason
/// reported to the requester.
fn parse_zkp_output(message: &ResultMessage) -> Result<(Vec<u8>, Vec<u8>), String> {
    if message.is_error {
        return Err(message.result.clone());
    }
    let ProverResultType::ProveResult {
        seal,
        journal,
        status,
    } = serde_json::from_str::<ProverResultType>(&message.result).map_err(|error| {
        warn!(
            "Invalid ZKP result payload. Raw result: {}; error: {error}",
            message.result
        );
        format!("invalid successful result payload: {error}")
    })?;
    if status != "OK" {
        return Err(format!("prover returned unsuccessful status: {status}"));
    }
    Ok((seal, journal))
}

/// Dispatcher-declared failures contain plain text, while labelled successes must
/// contain JSON. Both are attributable output failures.
fn parse_program_payload(message: &ResultMessage) -> Result<serde_json::Value, String> {
    if message.is_error {
        return Err(message.result.clone());
    }
    message
        .result_as_value()
        .map_err(|error| format!("invalid successful result payload: {error}"))
}

impl<BC: BitcoinCoordinatorApi> BitVMX<BC> {
    fn complete_job(&self, job_id: &str) -> Result<(), BitVMXError> {
        self.program_context
            .expected_jobs
            .complete(&self.program_context.operation_timeouts, job_id)
    }

    fn fail_job(&self, job_id: &str, reason: String) -> Result<(), BitVMXError> {
        self.program_context.expected_jobs.fail(
            &self.program_context.operation_timeouts,
            job_id,
            reason,
        )
    }

    fn discard_job(&self, job_id: &str, reason: String) -> Result<(), BitVMXError> {
        self.program_context.expected_jobs.discard(
            &self.program_context.operation_timeouts,
            job_id,
            reason,
        )
    }

    fn retry_job(&self, job_id: &str, reason: String) -> Result<(), BitVMXError> {
        self.program_context.expected_jobs.retry_pending(
            &self.program_context.operation_timeouts,
            job_id,
            reason,
        )
    }

    /// Maps an authenticated sender to the dispatcher route it owns, if any.
    fn dispatcher_for(&self, from: &Identifier) -> Option<JobDispatcherType> {
        let components = &self.config.components;
        if *from == components.garbler {
            Some(JobDispatcherType::Garbler)
        } else if *from == components.emulator {
            Some(JobDispatcherType::Emulator)
        } else if *from == components.prover {
            Some(JobDispatcherType::ZKP)
        } else {
            None
        }
    }

    /// Applies common envelope and control-message handling for every authenticated
    /// dispatcher route, leaving only encoded result payloads to target-specific handlers.
    fn decode_dispatcher_message(
        &mut self,
        dispatcher: JobDispatcherType,
        msg: &str,
    ) -> Result<DispatcherIngress, BitVMXError> {
        if let Ok(message) = serde_json::from_str::<PingMessage>(msg) {
            self.ping_helper.received_message(
                dispatcher,
                &message,
                &self.program_context,
                &self.config.components,
            );
            return Ok(DispatcherIngress::Settled(ResultDisposition::Success(
                SuccessDetail::Processed,
            )));
        }

        let message = match ResultMessage::from_str(msg) {
            Ok(message) => message,
            Err(error) => {
                warn!("Rejecting malformed dispatcher envelope: {}", error);
                return Ok(DispatcherIngress::Settled(ResultDisposition::NoOp(
                    NoOpReason::MalformedEnvelope,
                )));
            }
        };
        let Some(expected) = self.program_context.expected_jobs.get(&message.job_id)? else {
            warn!(
                "Ignoring result for job that was not issued locally: {}",
                message.job_id
            );
            return Ok(DispatcherIngress::Settled(ResultDisposition::NoOp(
                NoOpReason::Orphaned,
            )));
        };
        if let Some(reason) = rejection(&expected, dispatcher) {
            return Ok(DispatcherIngress::Settled(ResultDisposition::NoOp(reason)));
        }
        let target = match JobTarget::derive(dispatcher, &message.job_id) {
            Ok(target) => target,
            Err(error) => {
                warn!(
                    "Ignoring {dispatcher:?} result with uncorrelatable job id '{}': {error}",
                    message.job_id
                );
                return Ok(DispatcherIngress::Settled(ResultDisposition::NoOp(
                    NoOpReason::Uncorrelatable,
                )));
            }
        };
        if expected.owner != target.owner() || expected.kind != target.kind() {
            warn!(
                "Expected-job metadata does not match result '{}'",
                message.job_id
            );
            return Ok(DispatcherIngress::Settled(ResultDisposition::NoOp(
                NoOpReason::Uncorrelatable,
            )));
        }
        Ok(DispatcherIngress::Result(message, target))
    }

    /// Decodes one dispatcher message and routes its result to the owning request or program.
    fn handle_job_result(
        &mut self,
        dispatcher: JobDispatcherType,
        msg: &str,
    ) -> Result<ResultDisposition, BitVMXError> {
        let (message, target) = match self.decode_dispatcher_message(dispatcher, msg)? {
            DispatcherIngress::Result(message, target) => (message, target),
            DispatcherIngress::Settled(disposition) => return Ok(disposition),
        };
        match target {
            JobTarget::Request(id) => self.handle_zkp_result(id, message),
            JobTarget::Setup(program_id, context) | JobTarget::Program(program_id, context) => {
                self.handle_program_result(dispatcher, program_id, context, message)
            }
        }
    }

    pub(super) fn fail_zkp_result(
        &mut self,
        id: Uuid,
        job_id: &str,
        requester: Identifier,
        reason: String,
    ) -> Result<ResultDisposition, BitVMXError> {
        let status = format!("FAILED: {reason}");
        self.reply(
            requester,
            OutgoingBitVMXApiMessages::ProofGenerationError(id, status.clone()),
        )?;
        self.fail_job(job_id, status)?;
        Ok(ResultDisposition::Success(SuccessDetail::Processed))
    }

    fn handle_zkp_result(
        &mut self,
        id: Uuid,
        message: ResultMessage,
    ) -> Result<ResultDisposition, BitVMXError> {
        // Correlate before recording either success or failure. An unknown request
        // cannot be answered and must not poison the shared inbox.
        let execution: Option<ZKPExecution> = self
            .store
            .get(StoreKey::ZKPExecution(id).get_key()?, None)?;
        let Some(execution) = execution else {
            let reason = format!("Missing requester correlation for ZKP job {id}");
            warn!("{reason}");
            self.fail_job(&message.job_id, reason)?;
            return Ok(ResultDisposition::NoOp(NoOpReason::Orphaned));
        };
        let requester = execution.requester().clone();

        let (seal, journal) = match parse_zkp_output(&message) {
            Ok(output) => output,
            Err(reason) => return self.fail_zkp_result(id, &message.job_id, requester, reason),
        };
        self.store.set(
            StoreKey::ZKPExecution(id).get_key()?,
            ZKPExecution::with_output(requester.clone(), seal, journal),
            None,
        )?;
        self.complete_job(&message.job_id)?;
        let response = self.proof_ready(id)?;
        self.reply(requester, response)?;
        Ok(ResultDisposition::Success(SuccessDetail::Processed))
    }

    fn handle_program_result(
        &mut self,
        dispatcher: JobDispatcherType,
        program_id: Uuid,
        context: Context,
        message: ResultMessage,
    ) -> Result<ResultDisposition, BitVMXError> {
        let Some(mut program) = self.load_program(&program_id)? else {
            let reason = format!("Program {program_id} not found for dispatcher result");
            error!("{reason}");
            self.fail_job(&message.job_id, reason)?;
            return Ok(ResultDisposition::NoOp(NoOpReason::Orphaned));
        };

        let disposition = match parse_program_payload(&message) {
            Ok(parsed) => {
                info!("Received result from dispatcher {}", parsed);
                program.receive_dispatcher_result(
                    parsed,
                    context,
                    dispatcher,
                    &mut self.program_context,
                )?
            }
            Err(reason) => program.receive_dispatcher_failure(&context, dispatcher, reason)?,
        };
        self.settle_program_job(&message.job_id, &disposition)?;
        Ok(disposition)
    }

    /// Records the expected-job outcome implied by a program's result disposition.
    fn settle_program_job(
        &self,
        job_id: &str,
        disposition: &ResultDisposition,
    ) -> Result<(), BitVMXError> {
        match disposition {
            ResultDisposition::Success(SuccessDetail::Processed) => self.complete_job(job_id),
            ResultDisposition::NoOp(NoOpReason::Stale) => {
                self.discard_job(job_id, "stale dispatcher result".to_string())
            }
            ResultDisposition::NoOp(NoOpReason::SetupAlreadyFailed) => self.fail_job(
                job_id,
                "owning setup failed before the dispatcher result settled".to_string(),
            ),
            _ => Ok(()),
        }
    }

    /// Applies service-result control flow at the inbox transaction boundary.
    pub(super) fn apply_dispatcher_result_disposition(
        &mut self,
        dispatcher: JobDispatcherType,
        disposition: ResultDisposition,
    ) -> Result<(), BitVMXError> {
        match disposition {
            ResultDisposition::Success(SuccessDetail::Processed) => Ok(()),
            ResultDisposition::NoOp(reason) => {
                debug!(
                    "Consuming no-op result from {:?} dispatcher: {:?}",
                    dispatcher, reason
                );
                Ok(())
            }
            ResultDisposition::Fail(FailureDetail::DispatcherJob(DispatcherJobFailure {
                program_id,
                expected_job_id,
                job_id,
                reason,
            })) => {
                self.retry_job(&expected_job_id, reason.clone())?;
                try_send_error_report(
                    &self.program_context.broker_channel,
                    &self.program_context.components_config.l2,
                    ErrorReport::new(
                        ErrorScope::Program(program_id),
                        ErrorReportKind::JobFailed { job_id, dispatcher },
                        Some(reason),
                    ),
                )
            }
            _ => unreachable!("invalid dispatcher result disposition"),
        }
    }

    /// Processes a bounded number of service/API inputs, committing each independently.
    /// Must be called without an active global transaction.
    pub fn process_api_messages(&mut self) -> Result<bool, BitVMXError> {
        const MAX_MESSAGES_PER_TICK: usize = 20;

        let store = self.store.clone();
        let mut processed = false;
        for _ in 0..MAX_MESSAGES_PER_TICK {
            if !Self::run_transaction(&store, || self.process_one_api_message())? {
                break;
            }
            processed = true;
        }
        Ok(processed)
    }

    fn process_one_api_message(&mut self) -> Result<bool, BitVMXError> {
        // Receive one input so rollback restores it without consuming unvisited messages.
        let messages = self.program_context.broker_channel.check_receive(Some(1))?;
        let Some(ReceivedMessage::Msg(from, msg)) = messages.into_iter().next() else {
            return Ok(false);
        };

        match self.dispatcher_for(&from) {
            Some(dispatcher) => {
                let disposition = self.handle_job_result(dispatcher, &msg)?;
                self.apply_dispatcher_result_disposition(dispatcher, disposition)?;
            }
            None => self.handle_api_message(msg, from)?,
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        comms_helper::CommsMessageType,
        program::{participant::CommsAddress, program::Program},
        test_utils::TestBitVMXEnv,
        types::{
            ErrorReport, ErrorReportKind, ErrorScope, IncomingBitVMXApiMessages,
            SetupFailureReason, ZKPOutput, PROGRAM_TYPE_AGGREGATED_KEY,
        },
    };
    fn test_l2_messages(
        env: &TestBitVMXEnv,
    ) -> Result<Vec<OutgoingBitVMXApiMessages>, BitVMXError> {
        env.bitvmx.program_context.broker_channel.tick()?;
        let l2 = env
            .bitvmx
            .program_context
            .broker_channel
            .create_local_channel(env.bitvmx.program_context.components_config.l2.clone())?;
        l2.get_all()?
            .into_iter()
            .map(|message| OutgoingBitVMXApiMessages::from_string(&message.msg))
            .collect()
    }

    #[test]
    fn dispatcher_ingress_does_not_parse_result_payload() {
        let mut env = TestBitVMXEnv::new("dispatcher-envelope-decoder").unwrap();
        let id = Uuid::new_v4();
        env.bitvmx
            .program_context
            .expected_jobs
            .register(id.to_string(), JobDispatcherType::ZKP)
            .unwrap();
        let result = ResultMessage::new(
            id.to_string(),
            "plain-text dispatcher failure".to_string(),
            true,
        )
        .to_string()
        .unwrap();

        match env
            .bitvmx
            .decode_dispatcher_message(JobDispatcherType::ZKP, &result)
        {
            Ok(DispatcherIngress::Result(result, JobTarget::Request(context_id))) => {
                assert_eq!(context_id, id);
                assert_eq!(result.job_id, id.to_string());
                assert_eq!(result.result, "plain-text dispatcher failure");
                assert!(result.is_error);
            }
            other => panic!("expected result envelope, got {other:?}"),
        }
        assert!(matches!(
            env.bitvmx.decode_dispatcher_message(
                JobDispatcherType::Emulator,
                &serde_json::to_string(&PingMessage::Pong).unwrap(),
            ),
            Ok(DispatcherIngress::Settled(ResultDisposition::Success(
                SuccessDetail::Processed
            )))
        ));
        assert!(matches!(
            env.bitvmx
                .decode_dispatcher_message(JobDispatcherType::Emulator, "not JSON"),
            Ok(DispatcherIngress::Settled(ResultDisposition::NoOp(
                NoOpReason::MalformedEnvelope
            )))
        ));
    }

    #[test]
    fn malformed_dispatcher_input_does_not_block_following_api_message() {
        let mut env = TestBitVMXEnv::new("malformed-dispatcher-envelope").unwrap();
        let destination = env.bitvmx.config.components.bitvmx.clone();
        let garbler = env
            .bitvmx
            .program_context
            .broker_channel
            .create_local_channel(env.bitvmx.config.components.garbler.clone())
            .unwrap();
        let l2 = env
            .bitvmx
            .program_context
            .broker_channel
            .create_local_channel(env.bitvmx.config.components.l2.clone())
            .unwrap();
        let ping_id = Uuid::new_v4();

        garbler.send(&destination, "not JSON".to_string()).unwrap();
        l2.send(
            &destination,
            IncomingBitVMXApiMessages::Ping(ping_id)
                .to_string()
                .unwrap(),
        )
        .unwrap();
        env.bitvmx.program_context.broker_channel.tick().unwrap();

        assert!(env.bitvmx.process_api_messages().unwrap());
        assert!(env
            .bitvmx
            .program_context
            .broker_channel
            .check_receive(None)
            .unwrap()
            .is_empty());
        env.bitvmx.program_context.broker_channel.tick().unwrap();
        let replies = l2.get_all().unwrap();
        assert!(replies.iter().any(|message| matches!(
            OutgoingBitVMXApiMessages::from_string(&message.msg),
            Ok(OutgoingBitVMXApiMessages::Pong(id)) if id == ping_id
        )));
    }

    #[test]
    fn cross_dispatcher_result_does_not_change_the_expected_job() {
        let mut env = TestBitVMXEnv::new("dispatcher-route-before-payload").unwrap();
        let store = env.bitvmx.get_store();
        let self_address = CommsAddress::new(
            env.bitvmx.program_context.comms.get_address(),
            env.bitvmx.program_context.comms.get_pubk_hash(),
        );
        let program_id = Uuid::new_v4();
        Program::new(
            program_id,
            PROGRAM_TYPE_AGGREGATED_KEY,
            vec![self_address],
            0,
            None,
            &mut env.bitvmx.program_context,
            store,
        )
        .unwrap();
        let context = Context::SetupStep(
            program_id,
            "garbler".to_string(),
            String::new(),
            CommsMessageType::GarbledCircuit,
        );
        env.bitvmx
            .program_context
            .expected_jobs
            .register(context.to_string().unwrap(), JobDispatcherType::Garbler)
            .unwrap();
        let message = ResultMessage::new(
            context.to_string().unwrap(),
            "not a JSON result payload".to_string(),
            false,
        )
        .to_string()
        .unwrap();

        assert_eq!(
            env.bitvmx
                .handle_job_result(JobDispatcherType::Emulator, &message)
                .unwrap(),
            ResultDisposition::NoOp(NoOpReason::Uncorrelatable)
        );
        assert!(matches!(
            env.bitvmx
                .program_context
                .expected_jobs
                .get(&context.to_string().unwrap())
                .unwrap()
                .unwrap()
                .status,
            ExpectedJobStatus::Pending
        ));
    }

    #[test]
    fn zkp_plain_text_dispatcher_error_is_stored_and_notified() {
        let mut env = TestBitVMXEnv::new("zkp-dispatcher-error").unwrap();
        let id = Uuid::new_v4();
        let requester_id = env.bitvmx.config.components.l2.clone();
        let requester = env
            .bitvmx
            .program_context
            .broker_channel
            .create_local_channel(requester_id.clone())
            .unwrap();
        env.bitvmx
            .store
            .set(
                StoreKey::ZKPExecution(id).get_key().unwrap(),
                ZKPExecution::new(requester_id),
                None,
            )
            .unwrap();
        env.bitvmx
            .program_context
            .expected_jobs
            .register(id.to_string(), JobDispatcherType::ZKP)
            .unwrap();
        let message = ResultMessage::new(
            id.to_string(),
            "prover process exited with status 1".to_string(),
            true,
        )
        .to_string()
        .unwrap();

        assert_eq!(
            env.bitvmx
                .handle_job_result(JobDispatcherType::ZKP, &message)
                .unwrap(),
            ResultDisposition::Success(SuccessDetail::Processed)
        );
        let expected = env
            .bitvmx
            .program_context
            .expected_jobs
            .get(&id.to_string())
            .unwrap()
            .unwrap();
        let ExpectedJobStatus::Failed(status) = expected.status else {
            panic!("expected failed ZKP job");
        };
        assert_eq!(status, "FAILED: prover process exited with status 1");
        assert_eq!(
            env.bitvmx
                .handle_job_result(JobDispatcherType::ZKP, &message)
                .unwrap(),
            ResultDisposition::NoOp(NoOpReason::Duplicate)
        );

        env.bitvmx.program_context.broker_channel.tick().unwrap();
        let replies = requester.get_all().unwrap();
        assert!(matches!(
            replies.as_slice(),
            [message] if matches!(
                OutgoingBitVMXApiMessages::from_string(&message.msg),
                Ok(OutgoingBitVMXApiMessages::ProofGenerationError(response_id, reason))
                    if response_id == id && reason == status
            )
        ));
    }

    #[test]
    fn late_zkp_result_after_timeout_matches_the_persisted_timeout_reason() {
        let mut env = TestBitVMXEnv::new("zkp-late-after-timeout").unwrap();
        let id = Uuid::new_v4();
        let job_id = id.to_string();
        let requester = env.bitvmx.config.components.l2.clone();
        env.bitvmx
            .store
            .set(
                StoreKey::ZKPExecution(id).get_key().unwrap(),
                ZKPExecution::new(requester),
                None,
            )
            .unwrap();
        env.bitvmx
            .program_context
            .expected_jobs
            .register(job_id.clone(), JobDispatcherType::ZKP)
            .unwrap();

        env.bitvmx.fail_zkp_timeout(id, &job_id).unwrap();
        let expected = env
            .bitvmx
            .program_context
            .expected_jobs
            .get(&job_id)
            .unwrap()
            .unwrap();
        assert_eq!(
            expected.status,
            ExpectedJobStatus::Failed("FAILED: dispatcher job execution timed out".to_string())
        );

        let late_result = ResultMessage::new(job_id, "{}".to_string(), false)
            .to_string()
            .unwrap();
        assert_eq!(
            env.bitvmx
                .handle_job_result(JobDispatcherType::ZKP, &late_result)
                .unwrap(),
            ResultDisposition::NoOp(NoOpReason::Duplicate)
        );
    }

    #[test]
    fn successful_zkp_result_completes_job_and_stores_domain_output() {
        let mut env = TestBitVMXEnv::new("zkp-success").unwrap();
        let id = Uuid::new_v4();
        let requester_id = env.bitvmx.config.components.l2.clone();
        let requester = env
            .bitvmx
            .program_context
            .broker_channel
            .create_local_channel(requester_id.clone())
            .unwrap();
        env.bitvmx
            .store
            .set(
                StoreKey::ZKPExecution(id).get_key().unwrap(),
                ZKPExecution::new(requester_id),
                None,
            )
            .unwrap();
        env.bitvmx
            .program_context
            .expected_jobs
            .register(id.to_string(), JobDispatcherType::ZKP)
            .unwrap();
        let payload = serde_json::json!({
            "type": "ProveResult",
            "data": { "seal": [1, 2], "journal": [3, 4], "status": "OK" }
        });
        let message = ResultMessage::new(id.to_string(), payload.to_string(), false)
            .to_string()
            .unwrap();

        assert_eq!(
            env.bitvmx
                .handle_job_result(JobDispatcherType::ZKP, &message)
                .unwrap(),
            ResultDisposition::Success(SuccessDetail::Processed)
        );
        let expected = env
            .bitvmx
            .program_context
            .expected_jobs
            .get(&id.to_string())
            .unwrap()
            .unwrap();
        assert!(matches!(expected.status, ExpectedJobStatus::Completed));
        let execution: ZKPExecution = env
            .bitvmx
            .store
            .get(StoreKey::ZKPExecution(id).get_key().unwrap(), None)
            .unwrap()
            .unwrap();
        assert_eq!(
            execution.into_output(),
            Some(ZKPOutput::new(vec![1, 2], vec![3, 4]))
        );

        env.bitvmx.program_context.broker_channel.tick().unwrap();
        let replies = requester.get_all().unwrap();
        assert!(matches!(
            replies.as_slice(),
            [message] if matches!(
                OutgoingBitVMXApiMessages::from_string(&message.msg),
                Ok(OutgoingBitVMXApiMessages::ProofReady(response_id)) if response_id == id
            )
        ));
    }

    #[test]
    fn invalid_zkp_bytes_are_rejected_without_blocking_the_inbox() {
        let mut env = TestBitVMXEnv::new("zkp-invalid-bytes").unwrap();
        let id = Uuid::new_v4();
        let requester_id = env.bitvmx.config.components.l2.clone();
        env.bitvmx
            .store
            .set(
                StoreKey::ZKPExecution(id).get_key().unwrap(),
                ZKPExecution::new(requester_id),
                None,
            )
            .unwrap();
        env.bitvmx
            .program_context
            .expected_jobs
            .register(id.to_string(), JobDispatcherType::ZKP)
            .unwrap();
        let payload = serde_json::json!({
            "type": "ProveResult",
            "data": { "seal": [256], "journal": [1], "status": "OK" }
        });
        let message = ResultMessage::new(id.to_string(), payload.to_string(), false)
            .to_string()
            .unwrap();

        assert_eq!(
            env.bitvmx
                .handle_job_result(JobDispatcherType::ZKP, &message)
                .unwrap(),
            ResultDisposition::Success(SuccessDetail::Processed)
        );
        assert!(matches!(
            env.bitvmx
                .program_context
                .expected_jobs
                .get(&id.to_string())
                .unwrap()
                .unwrap()
                .status,
            ExpectedJobStatus::Failed(ref reason)
                if reason.contains("invalid successful result payload")
        ));
    }

    #[test]
    fn missing_zkp_requester_fails_expected_job_without_retry() {
        let mut env = TestBitVMXEnv::new("zkp-missing-requester").unwrap();
        let id = Uuid::new_v4();
        env.bitvmx
            .program_context
            .expected_jobs
            .register(id.to_string(), JobDispatcherType::ZKP)
            .unwrap();
        let message = ResultMessage::new(id.to_string(), "{}".to_string(), false)
            .to_string()
            .unwrap();

        assert_eq!(
            env.bitvmx
                .handle_job_result(JobDispatcherType::ZKP, &message)
                .unwrap(),
            ResultDisposition::NoOp(NoOpReason::Orphaned)
        );
        let execution: Option<ZKPExecution> = env
            .bitvmx
            .store
            .get(StoreKey::ZKPExecution(id).get_key().unwrap(), None)
            .unwrap();
        assert!(execution.is_none());
        assert!(matches!(
            env.bitvmx
                .program_context
                .expected_jobs
                .get(&id.to_string())
                .unwrap()
                .unwrap()
                .status,
            ExpectedJobStatus::Failed(ref reason)
                if reason.contains("Missing requester correlation")
        ));
    }

    #[test]
    fn setup_plain_text_dispatcher_error_is_settled_then_consumed() {
        let mut env = TestBitVMXEnv::new("setup-dispatcher-error").unwrap();
        let store = env.bitvmx.get_store();
        let self_address = CommsAddress::new(
            env.bitvmx.program_context.comms.get_address(),
            env.bitvmx.program_context.comms.get_pubk_hash(),
        );
        let program_id = Uuid::new_v4();
        Program::new(
            program_id,
            PROGRAM_TYPE_AGGREGATED_KEY,
            vec![self_address],
            0,
            None,
            &mut env.bitvmx.program_context,
            store.clone(),
        )
        .unwrap();
        let context = Context::SetupStep(
            program_id,
            "garbler".to_string(),
            String::new(),
            CommsMessageType::GarbledCircuit,
        );
        env.bitvmx
            .program_context
            .expected_jobs
            .register(context.to_string().unwrap(), JobDispatcherType::Garbler)
            .unwrap();
        let message = ResultMessage::new(
            context.to_string().unwrap(),
            "garbler failed before producing JSON".to_string(),
            true,
        )
        .to_string()
        .unwrap();
        let destination = env.bitvmx.config.components.bitvmx.clone();
        let garbler = env
            .bitvmx
            .program_context
            .broker_channel
            .create_local_channel(env.bitvmx.config.components.garbler.clone())
            .unwrap();
        garbler.send(&destination, message).unwrap();
        env.bitvmx.program_context.broker_channel.tick().unwrap();

        assert!(env
            .bitvmx
            .run_step("test dispatcher error", |bitvmx| {
                bitvmx.process_api_messages()
            })
            .unwrap()
            .is_none());
        assert!(Program::load(store, &program_id)
            .unwrap()
            .unwrap()
            .is_failed());

        assert!(env.bitvmx.process_api_messages().unwrap());
        assert!(env
            .bitvmx
            .program_context
            .broker_channel
            .check_receive(None)
            .unwrap()
            .is_empty());
        assert!(matches!(
            env.bitvmx
                .program_context
                .expected_jobs
                .get(&context.to_string().unwrap())
                .unwrap()
                .unwrap()
                .status,
            ExpectedJobStatus::Failed(_)
        ));
        let reports = test_l2_messages(&env).unwrap();
        assert!(matches!(
            reports.as_slice(),
            [OutgoingBitVMXApiMessages::Error(ErrorReport {
                scope: ErrorScope::Program(id),
                kind: ErrorReportKind::SetupFailed { reason: SetupFailureReason::StepError(reason), .. },
                ..
            })] if *id == program_id && reason.contains("garbler failed before producing JSON")
        ));
    }

    #[test]
    fn runtime_plain_text_dispatcher_errors_do_not_fail_program() {
        for (prefix, dispatcher, reason) in [
            (
                "runtime-emulator-error",
                JobDispatcherType::Emulator,
                "emulator crashed",
            ),
            (
                "runtime-garbler-evaluate-error",
                JobDispatcherType::Garbler,
                "garbler evaluate crashed",
            ),
        ] {
            let mut env = TestBitVMXEnv::new(prefix).unwrap();
            let store = env.bitvmx.get_store();
            let self_address = CommsAddress::new(
                env.bitvmx.program_context.comms.get_address(),
                env.bitvmx.program_context.comms.get_pubk_hash(),
            );
            let program_id = Uuid::new_v4();
            Program::new(
                program_id,
                PROGRAM_TYPE_AGGREGATED_KEY,
                vec![self_address],
                0,
                None,
                &mut env.bitvmx.program_context,
                store.clone(),
            )
            .unwrap();
            let context = Context::ProgramStep(program_id, "execute-round-1".to_string());
            env.bitvmx
                .program_context
                .expected_jobs
                .register(context.to_string().unwrap(), dispatcher)
                .unwrap();
            let message =
                ResultMessage::new(context.to_string().unwrap(), reason.to_string(), true)
                    .to_string()
                    .unwrap();

            let disposition = env.bitvmx.handle_job_result(dispatcher, &message).unwrap();
            env.bitvmx
                .apply_dispatcher_result_disposition(dispatcher, disposition)
                .unwrap();

            let program = Program::load(store, &program_id).unwrap().unwrap();
            assert!(!program.is_failed());
            assert!(matches!(
                env.bitvmx
                    .program_context
                    .expected_jobs
                    .get(&context.to_string().unwrap())
                    .unwrap()
                    .unwrap()
                    .status,
                ExpectedJobStatus::RetryPending(ref stored_reason) if stored_reason == reason
            ));
            let reports = test_l2_messages(&env).unwrap();
            assert!(matches!(
                reports.as_slice(),
                [OutgoingBitVMXApiMessages::Error(ErrorReport {
                    scope: ErrorScope::Program(id),
                    kind: ErrorReportKind::JobFailed { job_id, dispatcher: reported_dispatcher },
                    detail: Some(reported_reason),
                })] if *id == program_id
                    && job_id == "execute-round-1"
                    && *reported_dispatcher == dispatcher
                    && reported_reason == reason
            ));
        }
    }
}
