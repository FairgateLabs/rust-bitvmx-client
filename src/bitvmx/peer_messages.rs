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
        RetryReason, SetupFailureReason, SuccessDetail,
    },
};
use bitvmx_broker::{identification::identifier::PubkHash, ReceivedMessage};
use tracing::{debug, info, warn};
use uuid::Uuid;

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
        if !SignatureVerifier::has_all_keys(&self.program_context.globals, &participants)? {
            info!(
                "BitVMX::process_program_message() - Missing verification keys for program: {:?}",
                program_id
            );
            return Ok(ResultDisposition::Retry(
                RetryReason::MissingParticipantVerificationKeys,
            ));
        }

        // If this operator is the leader and the message type should be broadcast, store the original message
        if program.my_idx == program.leader {
            let should_store = msg_type.should_store();
            if should_store {
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
        }

        // Process the message
        /*let data_bytes: Vec<u8> = serde_json::from_value(data.clone()).map_err(|e| {
            BitVMXError::InvalidMessage(format!(
                "Failed to parse message data as byte array: {}. Expected JSON array of integers [0-255], got: {}",
                e,
                serde_json::to_string(&data).unwrap_or_else(|_| "<unparseable>".to_string())
            ))
        })?;*/
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
            ResultDisposition::Success(SuccessDetail::Processed) => Ok(()),
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
                let (peer, failure_reason) = match &reason {
                    RetryReason::MissingVerificationKey { peer } => {
                        (peer.clone(), SetupFailureReason::VerificationKeyMissing)
                    }
                    _ => (
                        msg.identifier.pubkey_hash.clone(),
                        SetupFailureReason::MessageLost,
                    ),
                };
                let retry_needs_keys = matches!(
                    reason,
                    RetryReason::MissingVerificationKey { .. }
                        | RetryReason::MissingParticipantVerificationKeys
                );
                match self.message_queue.push_deferred(msg)? {
                    PushOutcome::Dropped => {
                        self.fail_program_setup(program_id, Some(peer), failure_reason)?;
                    }
                    PushOutcome::Queued | PushOutcome::AlreadyQueued => {
                        if retry_needs_keys {
                            // Verification-key requests are intentionally idempotent.
                            // Re-requesting is harmless, and key presence in
                            // OperatorVerificationStore naturally stops future requests.
                            self.request_missing_verification_keys(program_id)?;
                        }
                    }
                }
                Ok(())
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
            _ => unreachable!("invalid peer-message disposition"),
        }
    }

    pub fn process_msg(&mut self, msg: QueuedMessage) -> Result<(), BitVMXError> {
        let decoded = deserialize_msg(
            &msg.data,
            self.config
                .broker
                .settings
                .msg_size_config
                .max_frame_size_kb
                - 1, // Reserve 1kb for headers
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
            let setup_state = program.classify_setup_message(&sender_pubkey_hash, msg_type);
            if let Some(reason) = setup_state.into_no_op_reason() {
                return Ok(ResultDisposition::NoOp(reason));
            }

            let my_pubkey_hash = self.program_context.comms.get_pubk_hash();
            match SignatureVerifier::authenticate_message(
                &self.program_context.globals,
                &program_id.to_string(),
                &message.version,
                &msg_type,
                &message.data,
                message.timestamp,
                &message.signature,
                &sender_pubkey_hash,
                &self.program_context.rsa_public_key,
                &my_pubkey_hash,
            )? {
                ResultDisposition::Success(SuccessDetail::Processed) => {}
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
                ResultDisposition::Success(SuccessDetail::Processed) => {
                    Ok(ResultDisposition::Success(SuccessDetail::Processed))
                }
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
            .run_step("comms inbox", Self::process_comms_inbox)?
            .unwrap_or(true);
        let deadletters = self
            .run_step("comms dead letters", Self::process_deadletters)?
            .unwrap_or(true);
        Ok(incoming || deadletters)
    }

    fn process_comms_inbox(&mut self) -> Result<bool, BitVMXError> {
        const MAX_MESSAGES: usize = 20;
        let store = self.store.clone();
        let mut had_work = false;
        for _ in 0..MAX_MESSAGES {
            if !Self::run_transaction(&store, || self.process_one_comms_message())? {
                break;
            }
            had_work = true;
        }
        Ok(had_work)
    }

    fn process_deadletters(&mut self) -> Result<bool, BitVMXError> {
        const MAX_MESSAGES: usize = 20;
        let store = self.store.clone();
        let mut had_work = false;
        for _ in 0..MAX_MESSAGES {
            if !Self::run_transaction(&store, || self.process_one_deadletter())? {
                break;
            }
            had_work = true;
        }
        Ok(had_work)
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
