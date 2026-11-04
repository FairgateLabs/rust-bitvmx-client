//! Peer message handling: decoding, authorization, retries and the comms queues.

use super::{BitVMX, Context};
use crate::{
    comms_helper::{deserialize_msg, CommsMessageType, DecodedPeerMessage},
    errors::BitVMXError,
    leader_broadcast::OriginalMessage,
    message_queue::{PushOutcome, QueuedMessage},
    ports::bitcoin_coordinator::BitcoinCoordinatorApi,
    program::program::Program,
    signature_verifier::{OperatorVerificationStore, SignatureVerifier},
    types::{
        FailureDetail, NoOpReason, PeerSetupFault, PeerSetupFaultReason, ResultDisposition,
        RetryReason, SetupFailureReason,
    },
};
use bitvmx_broker::{identification::identifier::PubkHash, ReceivedMessage};
use tracing::{debug, info, warn};
use uuid::Uuid;

/// Part of the broker frame kept free for headers when bounding a peer message.
const FRAME_HEADER_RESERVE_KB: usize = 1;

impl<BC: BitcoinCoordinatorApi> BitVMX<BC> {
    /// Reports a setup failure for a message the node knows it has lost. Unlike the errors
    /// `Program` catches itself, nothing here raised an error: the message simply never
    /// arrived or never left, so setup would otherwise wait for it forever.
    pub(super) fn fail_program_setup(
        &mut self,
        program_id: &Uuid,
        peer: Option<PubkHash>,
        reason: SetupFailureReason,
    ) -> Result<(), BitVMXError> {
        match self.load_program(program_id)? {
            Some(mut program) => program.fail_setup(peer, reason, &mut self.program_context),
            // No local program means no setup to fail, and nobody waiting on one.
            None => {
                debug!(
                    "BitVMX::fail_program_setup() - Program {} not found, nothing to fail",
                    program_id
                );
                Ok(())
            }
        }
    }

    /// Processes a message for a Program and reports whether it was processed
    /// or should be retried later.
    fn process_program_message(
        &mut self,
        message: DecodedPeerMessage,
        sender_pubkey_hash: &PubkHash,
        program: &mut Program,
    ) -> Result<ResultDisposition, BitVMXError> {
        let DecodedPeerMessage {
            version,
            msg_type,
            program_id,
            data,
            timestamp,
            signature,
        } = message;

        debug!(
            "BitVMX::process_program_message() - Processing {:?} for program {} from {}",
            msg_type, program_id, sender_pubkey_hash
        );

        let my_pubkey_hash = self.program_context.comms.get_pubk_hash();
        let participants: Vec<_> = program
            .participants
            .iter()
            .filter(|p| p.pubkey_hash != my_pubkey_hash)
            .map(|p| p.pubkey_hash.clone())
            .collect();
        if !OperatorVerificationStore::has_all_keys(&self.program_context.globals, &participants)? {
            info!(
                "BitVMX::process_program_message() - Missing verification keys for program: {:?}",
                program_id
            );
            return Ok(ResultDisposition::Retry(
                RetryReason::MissingParticipantVerificationKeys,
            ));
        }

        // If this operator is the leader and the message type should be broadcast, store the original message
        if program.my_idx == program.leader && msg_type.should_store() {
            let original_msg = OriginalMessage {
                sender_pubkey_hash: sender_pubkey_hash.clone(),
                msg_type,
                data: data.clone(),
                original_timestamp: timestamp,
                original_signature: signature,
                version,
            };
            if !self
                .program_context
                .leader_broadcast_helper
                .store_original_message(&program_id, msg_type, original_msg)?
            {
                info!(
                    "There is a message already stored for program {}",
                    program_id
                );
                return Ok(ResultDisposition::Retry(RetryReason::SetupNotReady));
            }
        }

        program.process_comms_message(
            sender_pubkey_hash,
            &msg_type,
            data,
            &mut self.program_context,
        )
    }

    fn request_missing_verification_keys(&self, program_id: &Uuid) -> Result<(), BitVMXError> {
        let Some(program) = self.load_program(program_id)? else {
            return Ok(());
        };
        OperatorVerificationStore::request_missing_verification_keys(
            &self.program_context.globals,
            &self.program_context.comms,
            &self.program_context.key_manager,
            &self.program_context.rsa_public_key,
            program_id,
            &program.participants,
        )
    }

    /// Applies peer-message control flow in one place so handlers only classify outcomes.
    fn apply_message_disposition(
        &mut self,
        msg: QueuedMessage,
        program_id: &Uuid,
        msg_type: CommsMessageType,
        disposition: ResultDisposition,
    ) -> Result<(), BitVMXError> {
        match disposition {
            ResultDisposition::Success => Ok(()),
            ResultDisposition::NoOp(reason) => {
                debug!(
                    "Consuming no-op peer message {:?} for program {} from {}: {:?}",
                    msg_type, program_id, msg.identifier.pubkey_hash, reason
                );
                Ok(())
            }
            ResultDisposition::Retry(reason) => {
                info!(
                    "Pending message to back: {:?} for program {:?} from {:?}: {:?}",
                    msg_type, program_id, msg.identifier.pubkey_hash, reason,
                );
                self.defer_message(msg, program_id, reason)
            }
            ResultDisposition::Fail(FailureDetail::PeerSetup(PeerSetupFault { peer, reason })) => {
                warn!(
                    "Failing setup for program {} after peer fault from {}: {:?}",
                    program_id, peer, reason
                );
                self.fail_program_setup(
                    program_id,
                    Some(peer),
                    SetupFailureReason::StepError(format!("{reason:?}")),
                )
            }
            ResultDisposition::Fail(FailureDetail::DispatcherJob(_)) => {
                unreachable!("invalid peer-message disposition")
            }
        }
    }

    /// Queues the message for a later retry, or fails setup once its retries run out.
    fn defer_message(
        &mut self,
        msg: QueuedMessage,
        program_id: &Uuid,
        reason: RetryReason,
    ) -> Result<(), BitVMXError> {
        let (peer, failure_reason) = reason.setup_failure(&msg.identifier.pubkey_hash);
        match self.message_queue.push_deferred(msg)? {
            PushOutcome::Dropped => {
                self.fail_program_setup(program_id, Some(peer), failure_reason)?;
            }
            PushOutcome::Queued | PushOutcome::AlreadyQueued => {
                if reason.needs_verification_keys() {
                    // Verification-key requests are intentionally idempotent.
                    // Re-requesting is harmless, and key presence in
                    // OperatorVerificationStore naturally stops future requests.
                    self.request_missing_verification_keys(program_id)?;
                }
            }
        }
        Ok(())
    }

    pub fn process_msg(&mut self, msg: QueuedMessage) -> Result<(), BitVMXError> {
        let decoded = deserialize_msg(
            &msg.data,
            self.config
                .broker
                .settings
                .msg_size_config
                .max_frame_size_kb
                - FRAME_HEADER_RESERVE_KB,
        );
        let Some(message) = Self::discard_if_malformed(decoded) else {
            return Ok(());
        };
        let program_id = message.program_id;
        let msg_type = message.msg_type;
        let disposition = self.process_decoded_peer_message(&msg, message)?;
        self.apply_message_disposition(msg, &program_id, msg_type, disposition)
    }

    fn process_decoded_peer_message(
        &mut self,
        msg: &QueuedMessage,
        message: DecodedPeerMessage,
    ) -> Result<ResultDisposition, BitVMXError> {
        let program_id = message.program_id;
        let msg_type = message.msg_type;

        // Apply the lifecycle gate before authentication or message-specific
        // handling. Terminal setup traffic is stale and cannot mutate state.
        let Some(mut program) = self.load_program(&program_id)? else {
            debug!("Program {} not found", program_id);
            return Ok(ResultDisposition::Retry(RetryReason::ProgramNotInstalled));
        };

        if let Some(disposition) = program.peer_message_lifecycle_disposition() {
            return Ok(disposition);
        }

        let sender_pubkey_hash = msg.identifier.pubkey_hash.clone();
        let Some(peer_address) = program.get_address_from_pubkey_hash(&sender_pubkey_hash) else {
            warn!(
                "Consuming peer message {:?} for program {} from non-participant {}",
                msg_type, program_id, sender_pubkey_hash
            );
            return Ok(ResultDisposition::NoOp(NoOpReason::UnauthorizedSender));
        };

        // The broker constructs `Identifier` from the mutually authenticated TLS
        // connection, so authorization must use that immediate sender rather than
        // anything claimed inside the payload. Only the configured leader may
        // forward a Broadcasted envelope for this program.
        if msg_type == CommsMessageType::Broadcasted
            && !program.validate_leader_pubkey_hash(&sender_pubkey_hash)?
        {
            warn!(
                "Rejecting Broadcasted message for program {} from non-leader participant {}",
                program_id, sender_pubkey_hash
            );
            return Ok(ResultDisposition::fail_peer_reason(
                sender_pubkey_hash,
                PeerSetupFaultReason::UnauthorizedMessage,
            ));
        }

        let is_verification_msg = matches!(
            msg_type,
            CommsMessageType::VerificationKey | CommsMessageType::VerificationKeyRequest
        );

        if !is_verification_msg {
            if let Some(reason) = program.classify_setup_message(&sender_pubkey_hash, msg_type) {
                return Ok(ResultDisposition::NoOp(reason));
            }

            match SignatureVerifier::authenticate_message(
                &self.program_context,
                &program_id,
                &message.version,
                msg_type,
                &message.data,
                message.timestamp,
                &message.signature,
                &sender_pubkey_hash,
            )? {
                ResultDisposition::Success => {}
                disposition => return Ok(disposition),
            }
        }

        // Broadcasts use the same outer application-signature pipeline as
        // direct setup messages. Only a verified leader envelope reaches the
        // embedded-original processor.
        if msg_type == CommsMessageType::Broadcasted {
            info!(
                "Processing authenticated Broadcasted message for program {} from leader {}",
                program_id, sender_pubkey_hash
            );
            return self
                .program_context
                .leader_broadcast_helper
                .process_broadcasted_message(
                    &self.program_context,
                    &program,
                    msg.identifier.clone(),
                    program_id,
                    message.data,
                    &self.message_queue,
                );
        }

        if is_verification_msg {
            return match SignatureVerifier::handle_verification_messages(
                &self.program_context,
                &program_id,
                &msg_type,
                &message.data,
                &peer_address,
            )? {
                ResultDisposition::Success => Ok(ResultDisposition::Success),
                failure @ ResultDisposition::Fail(FailureDetail::PeerSetup(_)) => Ok(failure),
                _ => unreachable!("invalid verification-message disposition"),
            };
        }

        self.process_program_message(message, &peer_address.pubkey_hash, &mut program)
    }

    pub fn process_pending_messages(&mut self) -> Result<bool, BitVMXError> {
        if self.message_queue.is_empty()? {
            return Ok(false);
        }

        if let Some(msg) = self.message_queue.pop_front()? {
            self.process_msg(msg)?;
        }
        Ok(true)
    }

    /// Processes up to 20 inputs from each comms queue, committing each independently.
    /// Must be called without an active global transaction.
    pub fn process_comms_messages(&mut self) -> Result<bool, BitVMXError> {
        let incoming = self
            .run_step("comms inbox", |this| {
                this.process_inputs(Self::process_one_comms_message)
            })?
            .unwrap_or(true);
        let deadletters = self
            .run_step("comms dead letters", |this| {
                this.process_inputs(Self::process_one_deadletter)
            })?
            .unwrap_or(true);
        Ok(incoming || deadletters)
    }

    fn process_one_comms_message(&mut self) -> Result<bool, BitVMXError> {
        let messages = self.program_context.comms.check_receive(Some(1))?;
        let had_work = !messages.is_empty();
        for message in messages {
            match message {
                ReceivedMessage::Msg(identifier, msg) => {
                    let msg: QueuedMessage = QueuedMessage::new(identifier, msg)?;
                    self.process_msg(msg)?;
                }
            }
        }

        Ok(had_work)
    }

    fn process_one_deadletter(&mut self) -> Result<bool, BitVMXError> {
        let deadletter_messages = self.program_context.comms.check_deadletter(Some(1))?;
        let had_work = !deadletter_messages.is_empty();
        for deadletter in deadletter_messages {
            match deadletter {
                (ReceivedMessage::Msg(identifier, _msg), ctx) => {
                    let Some(context) = Self::discard_if_malformed(Context::from_string(&ctx))
                    else {
                        continue;
                    };
                    warn!(
                        "Processing deadletter message for context: {:?} and identifier: {:?}",
                        context, identifier
                    );
                    // Setup traffic is sent with Context::ProgramId; other contexts have no
                    // program to fail.
                    if let Context::ProgramId(program_id) = context {
                        self.fail_program_setup(
                            &program_id,
                            Some(identifier.pubkey_hash.clone()),
                            SetupFailureReason::Undeliverable,
                        )?;
                    }
                }
            }
        }

        Ok(had_work)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bitvmx::test_support::{
            create_program, create_single_participant_program, peer_message, self_address,
            test_l2_messages,
        },
        comms_helper::{prepare_message, serialize_msg, VerificationKeyAnnouncement},
        leader_broadcast::BroadcastedMessage,
        program::{participant::CommsAddress, variables::VariableTypes},
        test_utils::TestBitVMXEnv,
        types::{ErrorReport, ErrorReportKind, ErrorScope, OutgoingBitVMXApiMessages},
    };
    use bitvmx_broker::identification::identifier::Identifier;

    #[test]
    fn terminal_programs_discard_peer_messages_before_payload_processing() {
        let mut env = TestBitVMXEnv::new("peer-lifecycle-gate").unwrap();
        let self_hash = env.bitvmx.program_context.comms.get_pubk_hash();

        let ready_id = Uuid::new_v4();
        let store = create_single_participant_program(&mut env, ready_id);
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
        let reports_before = test_l2_messages(&env).unwrap().len();

        // The invalid RSA signature would be rejected if authentication ran.
        env.bitvmx
            .process_msg(peer_message(
                &self_hash,
                CommsMessageType::Keys,
                &ready_id,
                serde_json::json!({"stale": true}),
            ))
            .unwrap();

        assert_eq!(
            Program::load(store.clone(), &ready_id)
                .unwrap()
                .unwrap()
                .peer_message_lifecycle_disposition(),
            Some(ResultDisposition::NoOp(NoOpReason::SetupAlreadyComplete))
        );
        assert!(env.bitvmx.message_queue.is_empty().unwrap());
        assert_eq!(test_l2_messages(&env).unwrap().len(), reports_before);

        let remote_leader = CommsAddress::new("127.0.0.1:1".parse().unwrap(), "22".repeat(32));
        let participants = vec![remote_leader.clone(), self_address(&env)];
        let failed_id = Uuid::new_v4();
        create_program(&mut env, failed_id, participants);
        let mut failed_program = Program::load(store, &failed_id).unwrap().unwrap();
        failed_program
            .fail_setup(
                None,
                SetupFailureReason::StepError("test failure".to_string()),
                &mut env.bitvmx.program_context,
            )
            .unwrap();
        let reports_before = test_l2_messages(&env).unwrap().len();

        // The leader's verification key is missing, so without the lifecycle gate
        // authentication would queue this message for a retry that can never help.
        env.bitvmx
            .process_msg(peer_message(
                &remote_leader.pubkey_hash,
                CommsMessageType::Broadcasted,
                &failed_id,
                serde_json::json!({"malformed": true}),
            ))
            .unwrap();

        assert!(env.bitvmx.message_queue.is_empty().unwrap());
        assert_eq!(test_l2_messages(&env).unwrap().len(), reports_before);
    }

    #[test]
    fn attributable_peer_fault_is_terminal_and_notified_once() {
        let mut env = TestBitVMXEnv::new("peer-fault-terminal").unwrap();
        let self_hash = env.bitvmx.program_context.comms.get_pubk_hash();
        let program_id = Uuid::new_v4();
        let store = create_single_participant_program(&mut env, program_id);

        // The sender is an expected participant and its current contribution is
        // pending, so malformed signature bytes are an attributable peer fault.
        let queued = peer_message(
            &self_hash,
            CommsMessageType::Keys,
            &program_id,
            serde_json::json!({"malformed": true}),
        );
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
        let self_hash = env.bitvmx.program_context.comms.get_pubk_hash();
        let program_id = Uuid::new_v4();
        let store = create_single_participant_program(&mut env, program_id);

        env.bitvmx
            .process_msg(peer_message(
                &self_hash,
                CommsMessageType::VerificationKey,
                &program_id,
                serde_json::json!({"wrong_field": true}),
            ))
            .unwrap();

        let program = Program::load(store, &program_id).unwrap().unwrap();
        assert!(program.is_failed());
    }

    #[test]
    fn verification_key_fingerprint_mismatch_fails_setup_without_storing_key() {
        let mut env = TestBitVMXEnv::new("verification-bootstrap-fingerprint-mismatch").unwrap();
        let peer_hash = "ab".repeat(32);
        let peer = CommsAddress::new("127.0.0.1:1".parse().unwrap(), peer_hash.clone());
        let participants = vec![self_address(&env), peer];
        let program_id = Uuid::new_v4();
        let store = create_program(&mut env, program_id, participants);

        // This is a valid RSA public key, but it belongs to this node rather
        // than to the TLS-authenticated peer fingerprint in `peer_hash`.
        let announcement = VerificationKeyAnnouncement {
            verification_key: env.bitvmx.program_context.rsa_public_key.clone(),
        }
        .to_value()
        .unwrap();
        env.bitvmx
            .process_msg(peer_message(
                &peer_hash,
                CommsMessageType::VerificationKey,
                &program_id,
                announcement,
            ))
            .unwrap();

        assert!(Program::load(store, &program_id)
            .unwrap()
            .unwrap()
            .is_failed());
        assert!(
            !OperatorVerificationStore::has(&env.bitvmx.program_context.globals, &peer_hash,)
                .unwrap()
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
        let non_leader = CommsAddress::new("127.0.0.1:1".parse().unwrap(), "11".repeat(32));
        let participants = vec![self_address(&env), non_leader.clone()];
        let program_id = Uuid::new_v4();
        let store = create_program(&mut env, program_id, participants);

        // Authorization precedes broadcast payload parsing, so even this
        // malformed envelope is an attributable leader-role violation.
        env.bitvmx
            .process_msg(peer_message(
                &non_leader.pubkey_hash,
                CommsMessageType::Broadcasted,
                &program_id,
                serde_json::json!({"malformed": true}),
            ))
            .unwrap();

        let program = Program::load(store, &program_id).unwrap().unwrap();
        assert!(program.is_failed());
    }

    #[test]
    fn broadcast_from_configured_leader_is_authorized() {
        let mut env = TestBitVMXEnv::new("leader-broadcast-authorization").unwrap();
        let leader_hash = env.bitvmx.program_context.comms.get_pubk_hash();
        let program_id = Uuid::new_v4();
        let store = create_single_participant_program(&mut env, program_id);

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
        let leader_hash = env.bitvmx.program_context.comms.get_pubk_hash();
        let program_id = Uuid::new_v4();
        let store = create_single_participant_program(&mut env, program_id);

        env.bitvmx
            .process_msg(peer_message(
                &leader_hash,
                CommsMessageType::Broadcasted,
                &program_id,
                serde_json::json!({"malformed": true}),
            ))
            .unwrap();

        let program = Program::load(store, &program_id).unwrap().unwrap();
        assert!(program.is_failed());
        assert!(env.bitvmx.message_queue.is_empty().unwrap());
    }

    #[test]
    fn broadcast_with_missing_leader_key_is_retried() {
        let mut env = TestBitVMXEnv::new("leader-broadcast-missing-outer-key").unwrap();
        let remote_leader = CommsAddress::new("127.0.0.1:1".parse().unwrap(), "22".repeat(32));
        let participants = vec![remote_leader.clone(), self_address(&env)];
        let program_id = Uuid::new_v4();
        let store = create_program(&mut env, program_id, participants);

        env.bitvmx
            .process_msg(peer_message(
                &remote_leader.pubkey_hash,
                CommsMessageType::Broadcasted,
                &program_id,
                serde_json::json!({"not_processed_without_the_key": true}),
            ))
            .unwrap();

        let program = Program::load(store, &program_id).unwrap().unwrap();
        assert!(!program.is_failed());
        assert!(!env.bitvmx.message_queue.is_empty().unwrap());
    }

    #[test]
    fn non_participant_message_does_not_fail_active_setup() {
        let mut env = TestBitVMXEnv::new("non-participant-message").unwrap();
        let program_id = Uuid::new_v4();
        let store = create_single_participant_program(&mut env, program_id);

        env.bitvmx
            .process_msg(peer_message(
                "non-participant",
                CommsMessageType::Keys,
                &program_id,
                serde_json::json!({"malformed": true}),
            ))
            .unwrap();

        let program = Program::load(store, &program_id).unwrap().unwrap();
        assert_eq!(program.peer_message_lifecycle_disposition(), None);
        assert!(env.bitvmx.message_queue.is_empty().unwrap());
        assert!(test_l2_messages(&env).unwrap().is_empty());
    }
}
