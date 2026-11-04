use super::*;
use crate::{
    comms_helper::{deserialize_msg, prepare_message, serialize_msg, VerificationKeyAnnouncement},
    expected_job::{ExpectedJobStatus, JOB_TIMEOUT_REASON},
    leader_broadcast::{BroadcastedMessage, OriginalMessage},
    message_queue::QueuedMessage,
    operation_timeout::OperationTimeoutId,
    program::{participant::CommsAddress, variables::VariableTypes},
    signature_verifier::OperatorVerificationStore,
    test_utils::{TestBitVMXEnv, TestStorageDir},
    types::{
        ErrorReportKind, NoOpReason, ResultDisposition, SetupFailureReason,
        PROGRAM_TYPE_AGGREGATED_KEY,
    },
};

type BitVMX = super::BitVMX<BitcoinCoordinator>;
use crate::types::{ErrorReport, ErrorScope, IncomingBitVMXApiMessages};
use storage_backend::error::StorageError;

impl super::BitVMX<crate::test_utils::BitcoinCoordinatorMock> {
    /// Builds the complete runtime without a wallet or a Bitcoin node.
    pub(crate) fn new_mock(config: Config) -> Result<Self, BitVMXError> {
        Self::new_with_coordinator_factory(config, false, |_, _, _| {
            Ok(crate::test_utils::BitcoinCoordinatorMock::new())
        })
    }

    pub(crate) fn coordinator_mock(&self) -> &crate::test_utils::BitcoinCoordinatorMock {
        &self.program_context.bitcoin_coordinator
    }
}

macro_rules! test_key {
    ($name:expr) => {
        StorageKey::new(["bitvmx", "test", $name]).unwrap()
    };
}

fn test_l2_messages(env: &TestBitVMXEnv) -> Result<Vec<OutgoingBitVMXApiMessages>, BitVMXError> {
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

fn create_single_participant_program(env: &mut TestBitVMXEnv, program_id: Uuid) -> Rc<Storage> {
    let store = env.bitvmx.get_store();
    let self_address = CommsAddress::new(
        env.bitvmx.program_context.comms.get_address(),
        env.bitvmx.program_context.comms.get_pubk_hash(),
    );
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
    store
}

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

#[test]
fn runtime_dispatcher_failure_rolls_back_attempt_before_scheduling_retry() {
    let mut env = TestBitVMXEnv::new("runtime-dispatcher-rollback-settlement").unwrap();
    let program_id = Uuid::new_v4();
    let store = create_single_participant_program(&mut env, program_id);
    let context = Context::ProgramStep(program_id, "execute-round-1".to_string());
    let expected_job_id = context.to_string().unwrap();
    env.bitvmx
        .program_context
        .expected_jobs
        .register(
            expected_job_id.clone(),
            crate::types::JobDispatcherType::Emulator,
        )
        .unwrap();
    let staged_key = test_key!("runtime-dispatcher-staged-effect");

    let outcome = env
        .bitvmx
        .run_step(
            "runtime dispatcher result",
            |_this| -> Result<(), BitVMXError> {
                BitVMX::run_transaction(&store, || {
                    store.set(&staged_key, "must roll back".to_string(), None)?;
                    Err(BitVMXError::RuntimeJobAttemptFailed {
                        program_id,
                        expected_job_id: expected_job_id.clone(),
                        job_id: "execute-round-1".to_string(),
                        reason: "invalid emulator output".to_string(),
                    })
                })
            },
        )
        .unwrap();

    assert!(outcome.is_none());
    assert_eq!(store.get::<String>(&staged_key, None).unwrap(), None);
    assert!(matches!(
        env.bitvmx
            .program_context
            .expected_jobs
            .get(&expected_job_id)
            .unwrap()
            .unwrap()
            .status,
        ExpectedJobStatus::RetryPending(ref reason) if reason == "invalid emulator output"
    ));
    assert!(!Program::load(store, &program_id)
        .unwrap()
        .unwrap()
        .is_failed());
}

#[test]
fn terminal_programs_discard_peer_messages_before_payload_processing() {
    let mut env = TestBitVMXEnv::new("peer-lifecycle-gate").unwrap();
    let store = env.bitvmx.get_store();
    let self_hash = env.bitvmx.program_context.comms.get_pubk_hash();
    let self_address = CommsAddress::new(
        env.bitvmx.program_context.comms.get_address(),
        self_hash.clone(),
    );

    let ready_id = Uuid::new_v4();
    Program::new(
        ready_id,
        PROGRAM_TYPE_AGGREGATED_KEY,
        vec![self_address.clone()],
        0,
        None,
        &mut env.bitvmx.program_context,
        store.clone(),
    )
    .unwrap();
    env.bitvmx
        .program_context
        .globals
        .set_var(
            &ready_id,
            "optional_keys",
            VariableTypes::String("null".to_string()),
        )
        .unwrap();
    let mut ready_program = Program::load(store.clone(), &ready_id).unwrap().unwrap();
    ready_program.tick(&mut env.bitvmx.program_context).unwrap();
    ready_program.tick(&mut env.bitvmx.program_context).unwrap();
    assert_eq!(
        ready_program.peer_message_lifecycle_disposition(),
        Some(ResultDisposition::NoOp(NoOpReason::SetupAlreadyComplete))
    );

    // The invalid RSA signature would be rejected if authentication ran.
    let stale_direct = serialize_msg(
        "1.0",
        CommsMessageType::Keys,
        &ready_id,
        serde_json::json!({"stale": true}),
        0,
        vec![1],
    )
    .unwrap();
    env.bitvmx
        .process_msg(
            QueuedMessage::new(Identifier::new(self_hash.clone(), 0), stale_direct).unwrap(),
        )
        .unwrap();

    let failed_id = Uuid::new_v4();
    Program::new(
        failed_id,
        PROGRAM_TYPE_AGGREGATED_KEY,
        vec![self_address],
        0,
        None,
        &mut env.bitvmx.program_context,
        store.clone(),
    )
    .unwrap();
    let mut failed_program = Program::load(store, &failed_id).unwrap().unwrap();
    failed_program
        .fail_setup(
            None,
            SetupFailureReason::StepError("test failure".to_string()),
            &mut env.bitvmx.program_context,
        )
        .unwrap();

    // This is not a BroadcastedMessage. The lifecycle gate must consume it
    // before the special broadcast path attempts to deserialize the payload.
    let stale_broadcast = serialize_msg(
        "1.0",
        CommsMessageType::Broadcasted,
        &failed_id,
        serde_json::json!({"malformed": true}),
        0,
        vec![1],
    )
    .unwrap();
    env.bitvmx
        .process_msg(QueuedMessage::new(Identifier::new(self_hash, 0), stale_broadcast).unwrap())
        .unwrap();
}

#[test]
fn attributable_peer_fault_is_terminal_and_notified_once() {
    let mut env = TestBitVMXEnv::new("peer-fault-terminal").unwrap();
    let store = env.bitvmx.get_store();
    let self_hash = env.bitvmx.program_context.comms.get_pubk_hash();
    let program_id = Uuid::new_v4();
    Program::new(
        program_id,
        PROGRAM_TYPE_AGGREGATED_KEY,
        vec![CommsAddress::new(
            env.bitvmx.program_context.comms.get_address(),
            self_hash.clone(),
        )],
        0,
        None,
        &mut env.bitvmx.program_context,
        store.clone(),
    )
    .unwrap();

    // The sender is an expected participant and its current contribution is
    // pending, so malformed signature bytes are an attributable peer fault.
    let invalid = serialize_msg(
        "1.0",
        CommsMessageType::Keys,
        &program_id,
        serde_json::json!({"malformed": true}),
        0,
        vec![1],
    )
    .unwrap();
    let queued = QueuedMessage::new(Identifier::new(self_hash.clone(), 0), invalid).unwrap();
    env.bitvmx.process_msg(queued.clone()).unwrap();

    let program = Program::load(store.clone(), &program_id)
        .unwrap()
        .expect("program must remain persisted");
    assert!(program.is_failed());
    assert!(env.bitvmx.message_queue.is_empty().unwrap());

    let reports = test_l2_messages(&env).unwrap();
    assert_eq!(reports.len(), 1);
    match &reports[0] {
        OutgoingBitVMXApiMessages::Error(ErrorReport {
            scope: ErrorScope::Program(id),
            kind: ErrorReportKind::SetupFailed { peer, .. },
            ..
        }) => {
            assert_eq!(*id, program_id);
            assert_eq!(peer.as_ref(), Some(&self_hash));
        }
        other => panic!("expected scoped SetupFailed report, got {other:?}"),
    }

    // Redelivery is stale after the terminal transition. It must neither
    // enter the retry queue nor produce another setup-failure report.
    env.bitvmx.process_msg(queued).unwrap();
    assert!(env.bitvmx.message_queue.is_empty().unwrap());
    assert_eq!(test_l2_messages(&env).unwrap().len(), 1);
}

#[test]
fn malformed_verification_announcement_fails_active_setup() {
    let mut env = TestBitVMXEnv::new("verification-bootstrap-rejection").unwrap();
    let store = env.bitvmx.get_store();
    let self_hash = env.bitvmx.program_context.comms.get_pubk_hash();
    let self_address = CommsAddress::new(
        env.bitvmx.program_context.comms.get_address(),
        self_hash.clone(),
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

    let malformed = serialize_msg(
        "1.0",
        CommsMessageType::VerificationKey,
        &program_id,
        serde_json::json!({"wrong_field": true}),
        0,
        vec![1],
    )
    .unwrap();
    env.bitvmx
        .process_msg(QueuedMessage::new(Identifier::new(self_hash, 0), malformed).unwrap())
        .unwrap();

    let program = Program::load(store, &program_id).unwrap().unwrap();
    assert!(program.is_failed());
}

#[test]
fn verification_key_fingerprint_mismatch_fails_setup_without_storing_key() {
    let mut env = TestBitVMXEnv::new("verification-bootstrap-fingerprint-mismatch").unwrap();
    let store = env.bitvmx.get_store();
    let self_address = CommsAddress::new(
        env.bitvmx.program_context.comms.get_address(),
        env.bitvmx.program_context.comms.get_pubk_hash(),
    );
    let peer_hash = "ab".repeat(32);
    let peer = CommsAddress::new("127.0.0.1:1".parse().unwrap(), peer_hash.clone());
    let program_id = Uuid::new_v4();
    Program::new(
        program_id,
        PROGRAM_TYPE_AGGREGATED_KEY,
        vec![self_address, peer],
        0,
        None,
        &mut env.bitvmx.program_context,
        store.clone(),
    )
    .unwrap();

    // This is a valid RSA public key, but it belongs to this node rather
    // than to the TLS-authenticated peer fingerprint in `peer_hash`.
    let announcement = VerificationKeyAnnouncement {
        verification_key: env.bitvmx.program_context.rsa_public_key.clone(),
    }
    .to_value()
    .unwrap();
    let message = serialize_msg(
        "1.0",
        CommsMessageType::VerificationKey,
        &program_id,
        announcement,
        0,
        vec![1],
    )
    .unwrap();
    env.bitvmx
        .process_msg(QueuedMessage::new(Identifier::new(peer_hash.clone(), 0), message).unwrap())
        .unwrap();

    assert!(Program::load(store, &program_id)
        .unwrap()
        .unwrap()
        .is_failed());
    assert!(
        !OperatorVerificationStore::has(&env.bitvmx.program_context.globals, &peer_hash,).unwrap()
    );
    let reports = test_l2_messages(&env).unwrap();
    assert!(matches!(
        reports.as_slice(),
        [OutgoingBitVMXApiMessages::Error(ErrorReport {
            scope: ErrorScope::Program(id),
            kind: ErrorReportKind::SetupFailed { peer: Some(failed_peer), .. },
            ..
        })] if *id == program_id && failed_peer == &peer_hash
    ));
}

#[test]
fn broadcast_from_non_leader_participant_fails_active_setup() {
    let mut env = TestBitVMXEnv::new("non-leader-broadcast").unwrap();
    let store = env.bitvmx.get_store();
    let self_address = CommsAddress::new(
        env.bitvmx.program_context.comms.get_address(),
        env.bitvmx.program_context.comms.get_pubk_hash(),
    );
    let non_leader = CommsAddress::new("127.0.0.1:1".parse().unwrap(), "11".repeat(32));
    let program_id = Uuid::new_v4();
    Program::new(
        program_id,
        PROGRAM_TYPE_AGGREGATED_KEY,
        vec![self_address, non_leader.clone()],
        0,
        None,
        &mut env.bitvmx.program_context,
        store.clone(),
    )
    .unwrap();

    // Authorization precedes broadcast payload parsing, so even this
    // malformed envelope is an attributable leader-role violation.
    let broadcast = serialize_msg(
        "1.0",
        CommsMessageType::Broadcasted,
        &program_id,
        serde_json::json!({"malformed": true}),
        0,
        vec![1],
    )
    .unwrap();
    env.bitvmx
        .process_msg(
            QueuedMessage::new(Identifier::new(non_leader.pubkey_hash, 0), broadcast).unwrap(),
        )
        .unwrap();

    let program = Program::load(store, &program_id).unwrap().unwrap();
    assert!(program.is_failed());
}

#[test]
fn broadcast_from_configured_leader_is_authorized() {
    let mut env = TestBitVMXEnv::new("leader-broadcast-authorization").unwrap();
    let store = env.bitvmx.get_store();
    let leader_hash = env.bitvmx.program_context.comms.get_pubk_hash();
    let leader_address = CommsAddress::new(
        env.bitvmx.program_context.comms.get_address(),
        leader_hash.clone(),
    );
    let program_id = Uuid::new_v4();
    Program::new(
        program_id,
        PROGRAM_TYPE_AGGREGATED_KEY,
        vec![leader_address],
        0,
        None,
        &mut env.bitvmx.program_context,
        store.clone(),
    )
    .unwrap();

    let original_data = serde_json::json!({"declaration": "test"});
    let (version, data, timestamp, signature) = prepare_message(
        &env.bitvmx.program_context.key_manager,
        &env.bitvmx.program_context.rsa_public_key,
        &program_id,
        CommsMessageType::Keys,
        original_data,
    )
    .unwrap();
    let broadcast_data = BroadcastedMessage {
        original_msg_type: CommsMessageType::Keys,
        original_messages: vec![OriginalMessage {
            sender_pubkey_hash: leader_hash.clone(),
            msg_type: CommsMessageType::Keys,
            data,
            original_timestamp: timestamp,
            original_signature: signature,
            version,
        }],
    };
    let (outer_version, outer_data, outer_timestamp, outer_signature) = prepare_message(
        &env.bitvmx.program_context.key_manager,
        &env.bitvmx.program_context.rsa_public_key,
        &program_id,
        CommsMessageType::Broadcasted,
        serde_json::to_value(broadcast_data).unwrap(),
    )
    .unwrap();
    let broadcast = serialize_msg(
        &outer_version,
        CommsMessageType::Broadcasted,
        &program_id,
        outer_data,
        outer_timestamp,
        outer_signature,
    )
    .unwrap();

    env.bitvmx
        .process_msg(QueuedMessage::new(Identifier::new(leader_hash, 0), broadcast).unwrap())
        .unwrap();

    let program = Program::load(store, &program_id).unwrap().unwrap();
    assert!(!program.is_failed());
}

#[test]
fn invalid_outer_broadcast_signature_from_leader_fails_setup() {
    let mut env = TestBitVMXEnv::new("leader-broadcast-invalid-outer-signature").unwrap();
    let store = env.bitvmx.get_store();
    let leader_hash = env.bitvmx.program_context.comms.get_pubk_hash();
    let program_id = Uuid::new_v4();
    Program::new(
        program_id,
        PROGRAM_TYPE_AGGREGATED_KEY,
        vec![CommsAddress::new(
            env.bitvmx.program_context.comms.get_address(),
            leader_hash.clone(),
        )],
        0,
        None,
        &mut env.bitvmx.program_context,
        store.clone(),
    )
    .unwrap();

    let broadcast = serialize_msg(
        "1.0",
        CommsMessageType::Broadcasted,
        &program_id,
        serde_json::json!({"malformed": true}),
        0,
        vec![1],
    )
    .unwrap();
    env.bitvmx
        .process_msg(QueuedMessage::new(Identifier::new(leader_hash, 0), broadcast).unwrap())
        .unwrap();

    let program = Program::load(store, &program_id).unwrap().unwrap();
    assert!(program.is_failed());
    assert!(env.bitvmx.message_queue.is_empty().unwrap());
}

#[test]
fn broadcast_with_missing_leader_key_is_retried() {
    let mut env = TestBitVMXEnv::new("leader-broadcast-missing-outer-key").unwrap();
    let store = env.bitvmx.get_store();
    let remote_leader = CommsAddress::new("127.0.0.1:1".parse().unwrap(), "22".repeat(32));
    let self_address = CommsAddress::new(
        env.bitvmx.program_context.comms.get_address(),
        env.bitvmx.program_context.comms.get_pubk_hash(),
    );
    let program_id = Uuid::new_v4();
    Program::new(
        program_id,
        PROGRAM_TYPE_AGGREGATED_KEY,
        vec![remote_leader.clone(), self_address],
        0,
        None,
        &mut env.bitvmx.program_context,
        store.clone(),
    )
    .unwrap();

    let broadcast = serialize_msg(
        "1.0",
        CommsMessageType::Broadcasted,
        &program_id,
        serde_json::json!({"not_processed_without_the_key": true}),
        0,
        vec![1],
    )
    .unwrap();
    env.bitvmx
        .process_msg(
            QueuedMessage::new(Identifier::new(remote_leader.pubkey_hash, 0), broadcast).unwrap(),
        )
        .unwrap();

    let program = Program::load(store, &program_id).unwrap().unwrap();
    assert!(!program.is_failed());
    assert!(!env.bitvmx.message_queue.is_empty().unwrap());
}

#[test]
fn non_participant_message_does_not_fail_active_setup() {
    let mut env = TestBitVMXEnv::new("non-participant-message").unwrap();
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

    let unauthorized = serialize_msg(
        "1.0",
        CommsMessageType::Keys,
        &program_id,
        serde_json::json!({"malformed": true}),
        0,
        vec![1],
    )
    .unwrap();
    env.bitvmx
        .process_msg(
            QueuedMessage::new(
                Identifier::new("non-participant".to_string(), 0),
                unauthorized,
            )
            .unwrap(),
        )
        .unwrap();

    let program = Program::load(store, &program_id).unwrap().unwrap();
    assert_eq!(program.peer_message_lifecycle_disposition(), None);
    assert!(env.bitvmx.message_queue.is_empty().unwrap());
    assert!(test_l2_messages(&env).unwrap().is_empty());
}

#[test]
fn news_handler_and_acknowledgement_commit_independently_per_item() {
    let dir = TestStorageDir::new("news-independent-transactions");
    let store = dir.storage();
    let result: Result<(), BitVMXError> = BitVMX::run_transaction(&store, || {
        store.set(test_key!("handler-first"), true, None)?;
        store.set(test_key!("ack-first"), true, None)?;
        Err(BitVMXError::InvalidMessageFormat)
    });
    assert!(result.is_err());
    BitVMX::run_transaction(&store, || {
        store.set(test_key!("handler-second"), true, None)?;
        store.set(test_key!("ack-second"), true, None)?;
        Ok(())
    })
    .unwrap();

    drop(store);
    let store = dir.storage();
    assert_eq!(
        store.get::<bool>(test_key!("handler-first"), None).unwrap(),
        None
    );
    assert_eq!(
        store.get::<bool>(test_key!("ack-first"), None).unwrap(),
        None
    );
    assert_eq!(
        store
            .get::<bool>(test_key!("handler-second"), None)
            .unwrap(),
        Some(true)
    );
    assert_eq!(
        store.get::<bool>(test_key!("ack-second"), None).unwrap(),
        Some(true)
    );
}

#[test]
fn malformed_input_is_consumed_and_the_next_input_can_commit() {
    let dir = TestStorageDir::new("reject-malformed-input");
    let store = dir.storage();
    let valid = serde_json::to_string(&IncomingBitVMXApiMessages::Ping(Uuid::new_v4())).unwrap();
    store.set(test_key!("bad-input"), "not JSON", None).unwrap();
    store.set(test_key!("next-input"), &valid, None).unwrap();

    for key in ["bad-input", "next-input"] {
        BitVMX::run_transaction(&store, || {
            let payload: String = store.get(test_key!(key), None)?.unwrap();
            store.remove(test_key!(key), None)?;
            if BitVMX::discard_if_malformed(serde_json::from_str::<IncomingBitVMXApiMessages>(
                &payload,
            ))
            .is_some()
            {
                store.set(test_key!("handled"), true, None)?;
            }
            Ok(())
        })
        .unwrap();
    }

    assert_eq!(
        store.get::<String>(test_key!("bad-input"), None).unwrap(),
        None
    );
    assert_eq!(
        store.get::<String>(test_key!("next-input"), None).unwrap(),
        None
    );
    assert_eq!(
        store.get::<bool>(test_key!("handled"), None).unwrap(),
        Some(true)
    );
}

#[test]
fn malformed_input_consumption_rolls_back_with_transaction() {
    let dir = TestStorageDir::new("reject-rollback");
    let store = dir.storage();
    store.set(test_key!("input"), "[]", None).unwrap();
    let result: Result<(), BitVMXError> = BitVMX::run_transaction(&store, || {
        store.remove(test_key!("input"), None)?;
        assert!(BitVMX::discard_if_malformed(deserialize_msg("[]".into(), 1024)).is_none());
        Err(BitVMXError::StorageError(StorageError::WriteError))
    });
    assert!(result.is_err());
    assert_eq!(
        store.get::<String>(test_key!("input"), None).unwrap(),
        Some("[]".into())
    );
}

#[test]
fn nonfatal_step_reports_after_rollback_and_allows_independent_work() {
    let env = crate::test_utils::TestProgramContextEnv::new("nonfatal-step").unwrap();
    let mut reporter = Reporter::new(env.context.components_config.l2.clone());
    let dir = TestStorageDir::new("nonfatal-step-storage");
    let store = dir.storage();
    store.set(test_key!("input"), true, None).unwrap();

    let failed: Result<(), BitVMXError> = BitVMX::run_transaction(&store, || {
        store.remove(test_key!("input"), None)?;
        store.set(test_key!("partial"), true, None)?;
        Err(BitVMXError::InvalidMessageFormat)
    });
    assert_eq!(
        BitVMX::finish_step("input", failed, &mut reporter, &env.context.broker_channel).unwrap(),
        None
    );
    assert_eq!(
        store.get::<bool>(test_key!("input"), None).unwrap(),
        Some(true)
    );
    assert_eq!(store.get::<bool>(test_key!("partial"), None).unwrap(), None);
    assert_eq!(env.l2_messages().unwrap().len(), 1);

    let next = BitVMX::run_transaction(&store, || {
        store.set(test_key!("independent"), true, None)?;
        Ok(true)
    });
    assert_eq!(
        BitVMX::finish_step("next", next, &mut reporter, &env.context.broker_channel).unwrap(),
        Some(true)
    );
    assert_eq!(
        store.get::<bool>(test_key!("independent"), None).unwrap(),
        Some(true)
    );
    assert_eq!(env.l2_messages().unwrap().len(), 1);
}

#[test]
fn fatal_step_propagates_without_reporting_twice() {
    let env = crate::test_utils::TestProgramContextEnv::new("fatal-step").unwrap();
    let mut reporter = Reporter::new(env.context.components_config.l2.clone());
    let result = BitVMX::finish_step::<()>(
        "storage",
        Err(BitVMXError::StorageError(StorageError::WriteError)),
        &mut reporter,
        &env.context.broker_channel,
    );
    assert!(matches!(
        result,
        Err(BitVMXError::StorageError(StorageError::WriteError))
    ));
    // Fatal reporting belongs to tick, not the individual step.
    assert!(env.l2_messages().unwrap().is_empty());
}

#[test]
fn broker_commit_survives_application_rollback() {
    let dir = TestStorageDir::new("broker-tick-commit");
    let store = dir.storage();
    BitVMX::run_transaction(&store, || {
        store.set(test_key!("broker"), true, None)?;
        Ok(())
    })
    .unwrap();

    store.begin_global_transaction().unwrap();
    store.set(test_key!("application"), true, None).unwrap();
    store.rollback_global_transaction().unwrap();
    assert_eq!(
        store.get::<bool>(test_key!("broker"), None).unwrap(),
        Some(true)
    );
    assert_eq!(
        store.get::<bool>(test_key!("application"), None).unwrap(),
        None
    );
}

#[test]
fn failed_second_broker_does_not_undo_first_broker() {
    let dir = TestStorageDir::new("broker-tick-independent");
    let store = dir.storage();
    BitVMX::run_transaction(&store, || {
        store.set(test_key!("comms"), true, None)?;
        Ok(())
    })
    .unwrap();

    let result: Result<(), BitVMXError> = BitVMX::run_transaction(&store, || {
        store.set(test_key!("services"), true, None)?;
        Err(BitVMXError::InvalidMessageFormat)
    });
    assert!(matches!(result, Err(BitVMXError::InvalidMessageFormat)));
    assert_eq!(
        store.get::<bool>(test_key!("comms"), None).unwrap(),
        Some(true)
    );
    assert_eq!(
        store.get::<bool>(test_key!("services"), None).unwrap(),
        None
    );
    // No leaked transaction blocks the next phase.
    store.begin_global_transaction().unwrap();
    store.rollback_global_transaction().unwrap();
}

#[test]
fn failed_item_preserves_previous_commit_and_unvisited_input() {
    let dir = TestStorageDir::new("application-item-transactions");
    let store = dir.storage();
    for key in ["input-a", "input-b", "input-c"] {
        store.set(test_key!(key), true, None).unwrap();
    }

    let value = BitVMX::run_transaction(&store, || {
        store.remove(test_key!("input-a"), None)?;
        store.set(test_key!("state-a"), true, None)?;
        Ok(42)
    })
    .unwrap();
    assert_eq!(value, 42);

    let result: Result<(), BitVMXError> = BitVMX::run_transaction(&store, || {
        store.remove(test_key!("input-b"), None)?;
        store.set(test_key!("partial-b"), true, None)?;
        Err(BitVMXError::InvalidMessageFormat)
    });
    assert!(matches!(result, Err(BitVMXError::InvalidMessageFormat)));
    assert_eq!(store.get::<bool>(test_key!("input-a"), None).unwrap(), None);
    assert_eq!(
        store.get::<bool>(test_key!("state-a"), None).unwrap(),
        Some(true)
    );
    assert_eq!(
        store.get::<bool>(test_key!("partial-b"), None).unwrap(),
        None
    );
    assert_eq!(
        store.get::<bool>(test_key!("input-b"), None).unwrap(),
        Some(true)
    );
    assert_eq!(
        store.get::<bool>(test_key!("input-c"), None).unwrap(),
        Some(true)
    );

    // The next step can open its own transaction after the failure.
    BitVMX::run_transaction(&store, || {
        store.set(test_key!("next-step"), true, None)?;
        Ok(())
    })
    .unwrap();
    assert_eq!(
        store.get::<bool>(test_key!("next-step"), None).unwrap(),
        Some(true)
    );
}

#[test]
fn rollback_failure_is_fatal_even_if_the_original_error_was_not() {
    let dir = TestStorageDir::new("transaction-rollback-failure");
    let store = dir.storage();
    let result: Result<(), BitVMXError> = BitVMX::run_transaction(&store, || {
        // Simulate a handler incorrectly consuming its owner's transaction.
        store.rollback_global_transaction()?;
        Err(BitVMXError::InvalidMessageFormat)
    });
    let error = result.unwrap_err();
    assert!(matches!(
        error,
        BitVMXError::StorageError(StorageError::TransactionRollbackFailed)
    ));
    assert!(matches!(classify(&error), Severity::Fatal));
}

#[test]
fn fatal_broker_error_also_rolls_back() {
    let dir = TestStorageDir::new("broker-tick-fatal");
    let store = dir.storage();
    store.set(test_key!("incoming"), true, None).unwrap();
    let result: Result<(), BitVMXError> = BitVMX::run_transaction(&store, || {
        store.remove(test_key!("incoming"), None)?;
        Err(BitVMXError::StorageError(StorageError::WriteError))
    });
    assert!(matches!(
        result,
        Err(BitVMXError::StorageError(StorageError::WriteError))
    ));
    assert_eq!(
        store.get::<bool>(test_key!("incoming"), None).unwrap(),
        Some(true)
    );
    store.begin_global_transaction().unwrap();
    store.rollback_global_transaction().unwrap();
}
