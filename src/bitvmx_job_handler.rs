use super::{BitVMX, Context, StoreKey};
use crate::{
    errors::BitVMXError,
    ports::bitcoin_coordinator::BitcoinCoordinatorApi,
    types::{
        DispatcherNoOpReason, DispatcherResultDisposition, JobDispatcherType,
        OutgoingBitVMXApiMessages,
    },
};
use bitvmx_broker::{identification::identifier::Identifier, ReceivedMessage};
use bitvmx_dispatcher_utils::PingMessage;
use bitvmx_job_dispatcher::dispatcher_job::ResultMessage;
use std::str::FromStr;
use storage_backend::storage::KeyValueStore;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// A decoded message from an authenticated job-dispatcher route. Result payloads
/// deliberately remain encoded until the dispatcher-specific handler validates them.
#[derive(Debug)]
enum DispatcherEnvelope {
    Control(PingMessage),
    Result(ResultMessage),
}

impl<BC: BitcoinCoordinatorApi> BitVMX<BC> {
    /// Decodes only the service envelope. A malformed frame has no trustworthy job
    /// correlation, so callers consume it rather than retrying it indefinitely.
    fn decode_dispatcher_envelope(msg: &str) -> Option<DispatcherEnvelope> {
        if let Ok(message) = serde_json::from_str::<PingMessage>(msg) {
            return Some(DispatcherEnvelope::Control(message));
        }

        match ResultMessage::from_str(msg) {
            Ok(message) => Some(DispatcherEnvelope::Result(message)),
            Err(error) => {
                warn!("Rejecting malformed dispatcher envelope: {}", error);
                None
            }
        }
    }

    fn handle_prover_message(
        &mut self,
        msg: &str,
    ) -> Result<DispatcherResultDisposition, BitVMXError> {
        let Some(envelope) = Self::decode_dispatcher_envelope(msg) else {
            return Ok(DispatcherResultDisposition::DiscardNoOp(
                DispatcherNoOpReason::MalformedEnvelope,
            ));
        };

        match envelope {
            DispatcherEnvelope::Control(message) => {
                self.ping_helper.received_message(
                    JobDispatcherType::ZKP,
                    &message,
                    &self.program_context,
                    &self.config.components,
                );
            }
            DispatcherEnvelope::Result(result_message) => {
                let id = match Uuid::parse_str(&result_message.job_id) {
                    Ok(id) => id,
                    Err(_) => {
                        warn!(
                            "Ignoring ZKP result with uncorrelatable job id: {}",
                            result_message.job_id
                        );
                        return Ok(DispatcherResultDisposition::DiscardNoOp(
                            DispatcherNoOpReason::Uncorrelatable,
                        ));
                    }
                };

                // Correlate before recording either success or failure. An unknown request
                // cannot be answered and must not poison the shared inbox.
                let Some(from): Option<Identifier> =
                    self.store.get(StoreKey::ZKPFrom(id).get_key()?, None)?
                else {
                    warn!("Missing 'from' parameter for ZKP request: {}", id);
                    return Ok(DispatcherResultDisposition::DiscardNoOp(
                        DispatcherNoOpReason::Orphaned,
                    ));
                };

                if result_message.is_error {
                    let reason = format!("FAILED: {}", result_message.result);
                    self.store
                        .set(StoreKey::ZKPStatus(id).get_key()?, reason.clone(), None)?;
                    self.reply(
                        from,
                        OutgoingBitVMXApiMessages::ProofGenerationError(id, reason),
                    )?;
                    return Ok(DispatcherResultDisposition::Processed);
                }

                let parsed: serde_json::Value = result_message.result_as_value()?;
                let data = parsed.get("data").ok_or_else(|| {
                    warn!("Missing data field in result. Raw message: {}", msg);
                    BitVMXError::InvalidMessageFormat
                })?;

                let status = data["status"].as_str().ok_or_else(|| {
                    warn!("Missing status field in data. Raw message: {}", msg);
                    BitVMXError::InvalidMessageFormat
                })?;
                let journal = data["journal"].as_array().ok_or_else(|| {
                    warn!("Missing journal field in data. Raw message: {}", msg);
                    BitVMXError::InvalidMessageFormat
                })?;
                let seal = data["seal"].as_array().ok_or_else(|| {
                    warn!("Missing seal field in data. Raw message: {}", msg);
                    BitVMXError::InvalidMessageFormat
                })?;

                let seal: Vec<u8> = seal
                    .iter()
                    .filter_map(|value| value.as_u64())
                    .map(|value| value as u8)
                    .collect();

                self.store
                    .set(StoreKey::ZKPProof(id).get_key()?, seal, None)?;
                self.store
                    .set(StoreKey::ZKPJournal(id).get_key()?, journal, None)?;
                self.store
                    .set(StoreKey::ZKPStatus(id).get_key()?, status.to_string(), None)?;

                let response = self.proof_ready(id)?;
                self.reply(from, response)?;
            }
        }
        Ok(DispatcherResultDisposition::Processed)
    }

    fn handle_dispatcher_message(
        &mut self,
        dispatcher: JobDispatcherType,
        msg: &str,
    ) -> Result<DispatcherResultDisposition, BitVMXError> {
        let Some(envelope) = Self::decode_dispatcher_envelope(msg) else {
            return Ok(DispatcherResultDisposition::DiscardNoOp(
                DispatcherNoOpReason::MalformedEnvelope,
            ));
        };

        match envelope {
            DispatcherEnvelope::Control(message) => {
                self.ping_helper.received_message(
                    dispatcher,
                    &message,
                    &self.program_context,
                    &self.config.components,
                );
            }
            DispatcherEnvelope::Result(result_message) => {
                let context = match Context::from_string(&result_message.job_id) {
                    Ok(context) => context,
                    Err(error) => {
                        warn!(
                            "Ignoring dispatcher result with uncorrelatable job id '{}': {}",
                            result_message.job_id, error
                        );
                        return Ok(DispatcherResultDisposition::DiscardNoOp(
                            DispatcherNoOpReason::Uncorrelatable,
                        ));
                    }
                };
                let program_id = match &context {
                    Context::ProgramId(program_id) => *program_id,
                    Context::SetupStep(program_id, _, _, _) => *program_id,
                    Context::ProgramStep(program_id, _) => *program_id,
                    _ => {
                        warn!("Uncorrelatable dispatcher result context: {:?}", context);
                        return Ok(DispatcherResultDisposition::DiscardNoOp(
                            DispatcherNoOpReason::Uncorrelatable,
                        ));
                    }
                };

                if let Some(mut program) = self.load_program(&program_id)? {
                    if result_message.is_error {
                        return program.receive_dispatcher_failure(&context, result_message.result);
                    }

                    let parsed: serde_json::Value = result_message.result_as_value()?;
                    info!("Received result from dispatcher {}", parsed);
                    return program.receive_dispatcher_result(
                        parsed,
                        context,
                        dispatcher,
                        &mut self.program_context,
                    );
                } else {
                    error!("Program {} not found for dispatcher result", program_id);
                    return Ok(DispatcherResultDisposition::DiscardNoOp(
                        DispatcherNoOpReason::Orphaned,
                    ));
                }
            }
        }
        Ok(DispatcherResultDisposition::Processed)
    }

    /// Applies service-result control flow at the inbox transaction boundary.
    fn apply_dispatcher_result_disposition(
        &mut self,
        dispatcher: JobDispatcherType,
        disposition: DispatcherResultDisposition,
    ) -> Result<(), BitVMXError> {
        match disposition {
            DispatcherResultDisposition::Processed => Ok(()),
            DispatcherResultDisposition::DiscardNoOp(reason) => {
                debug!(
                    "Consuming no-op result from {:?} dispatcher: {:?}",
                    dispatcher, reason
                );
                Ok(())
            }
            DispatcherResultDisposition::FailJob {
                program_id,
                job_id,
                reason,
            } => {
                let Some(mut program) = self.load_program(&program_id)? else {
                    warn!(
                        "Program {} disappeared while applying failed dispatcher job {}",
                        program_id, job_id
                    );
                    return Ok(());
                };
                program.fail_job(job_id, dispatcher, reason, &mut self.program_context)
            }
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
        let processed = !messages.is_empty();
        for message in messages {
            let (from, msg) = match message {
                ReceivedMessage::Msg(identifier, msg) => (identifier, msg),
            };

            match from {
                identifier if identifier == self.config.components.garbler => {
                    let disposition =
                        self.handle_dispatcher_message(JobDispatcherType::Garbler, &msg)?;
                    self.apply_dispatcher_result_disposition(
                        JobDispatcherType::Garbler,
                        disposition,
                    )?;
                }
                identifier if identifier == self.config.components.emulator => {
                    let disposition =
                        self.handle_dispatcher_message(JobDispatcherType::Emulator, &msg)?;
                    self.apply_dispatcher_result_disposition(
                        JobDispatcherType::Emulator,
                        disposition,
                    )?;
                }
                identifier if identifier == self.config.components.prover => {
                    let disposition = self.handle_prover_message(&msg)?;
                    self.apply_dispatcher_result_disposition(JobDispatcherType::ZKP, disposition)?;
                }
                _ => self.handle_api_message(msg, from)?,
            };
        }
        Ok(processed)
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
            SetupFailureReason, PROGRAM_TYPE_AGGREGATED_KEY,
        },
    };
    use bitcoin_coordinator::coordinator::BitcoinCoordinator;

    type TestBitVMX = BitVMX<BitcoinCoordinator>;

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
    fn dispatcher_envelope_decoder_does_not_parse_result_payload() {
        let result = ResultMessage::new(
            "job-id".to_string(),
            "plain-text dispatcher failure".to_string(),
            true,
        )
        .to_string()
        .unwrap();

        match TestBitVMX::decode_dispatcher_envelope(&result) {
            Some(DispatcherEnvelope::Result(result)) => {
                assert_eq!(result.job_id, "job-id");
                assert_eq!(result.result, "plain-text dispatcher failure");
                assert!(result.is_error);
            }
            other => panic!("expected result envelope, got {other:?}"),
        }
        assert!(matches!(
            TestBitVMX::decode_dispatcher_envelope(
                &serde_json::to_string(&PingMessage::Pong).unwrap()
            ),
            Some(DispatcherEnvelope::Control(PingMessage::Pong))
        ));
        assert!(TestBitVMX::decode_dispatcher_envelope("not JSON").is_none());
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
            .set(StoreKey::ZKPFrom(id).get_key().unwrap(), requester_id, None)
            .unwrap();
        let message = ResultMessage::new(
            id.to_string(),
            "prover process exited with status 1".to_string(),
            true,
        )
        .to_string()
        .unwrap();

        assert_eq!(
            env.bitvmx.handle_prover_message(&message).unwrap(),
            DispatcherResultDisposition::Processed
        );
        let status: String = env
            .bitvmx
            .store
            .get(StoreKey::ZKPStatus(id).get_key().unwrap(), None)
            .unwrap()
            .unwrap();
        assert_eq!(status, "FAILED: prover process exited with status 1");

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
    fn runtime_plain_text_dispatcher_error_fails_program() {
        let mut env = TestBitVMXEnv::new("runtime-dispatcher-error").unwrap();
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
            &mut env.bitvmx.program_context,
            store.clone(),
        )
        .unwrap();
        let context = Context::ProgramStep(program_id, "execute-round-1".to_string());
        let message = ResultMessage::new(
            context.to_string().unwrap(),
            "emulator crashed".to_string(),
            true,
        )
        .to_string()
        .unwrap();

        let disposition = env
            .bitvmx
            .handle_dispatcher_message(JobDispatcherType::Emulator, &message)
            .unwrap();
        env.bitvmx
            .apply_dispatcher_result_disposition(JobDispatcherType::Emulator, disposition)
            .unwrap();

        let failed_program = Program::load(store, &program_id).unwrap().unwrap();
        assert!(failed_program.is_failed());
        assert_eq!(
            failed_program.runtime_failure(),
            Some((
                "execute-round-1",
                JobDispatcherType::Emulator,
                "emulator crashed"
            ))
        );
        let reports = test_l2_messages(&env).unwrap();
        assert!(matches!(
            reports.as_slice(),
            [OutgoingBitVMXApiMessages::Error(ErrorReport {
                scope: ErrorScope::Program(id),
                kind: ErrorReportKind::JobFailed { job_id, dispatcher: JobDispatcherType::Emulator },
                detail: Some(reason),
            })] if *id == program_id && job_id == "execute-round-1" && reason == "emulator crashed"
        ));
    }
}
