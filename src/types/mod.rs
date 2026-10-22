mod shared;
pub use shared::*;

use std::rc::Rc;

use crate::config::ComponentsConfig;
use bitcoin_coordinator::coordinator::BitcoinCoordinator;
use bitvmx_broker::{
    identification::identifier::{Identifier, PubkHash},
    BrokerNode, RemoteChannel,
};
use key_manager::key_manager::KeyManager;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    expected_job::ExpectedJobs,
    leader_broadcast::LeaderBroadcastHelper,
    message_queue::QueuedMessage,
    operation_timeout::OperationTimeouts,
    ports::bitcoin_coordinator::BitcoinCoordinatorApi,
    program::variables::{Globals, WitnessVars},
};

/// The common result of handling externally supplied input.
///
/// Domain-controlled outcomes are values so transaction owners can decide whether to
/// consume, retry, or reject the input. Infrastructure and local-state failures remain
/// regular `Result::Err` values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResultDisposition {
    Success(SuccessDetail),
    NoOp(NoOpReason),
    Retry(RetryReason),
    Fail(FailureDetail),
}

impl ResultDisposition {
    pub fn fail_peer(fault: PeerSetupFault) -> Self {
        Self::Fail(FailureDetail::PeerSetup(fault))
    }

    pub fn fail_dispatcher(failure: DispatcherJobFailure) -> Self {
        Self::Fail(FailureDetail::DispatcherJob(failure))
    }
}

#[derive(Debug, Clone)]
pub enum SuccessDetail {
    Processed,
    QueuedMessage(QueuedMessage),
}

impl PartialEq for SuccessDetail {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Processed, Self::Processed) => true,
            (Self::QueuedMessage(left), Self::QueuedMessage(right)) => {
                left.identifier == right.identifier && left.data == right.data
            }
            _ => false,
        }
    }
}

impl Eq for SuccessDetail {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailureDetail {
    PeerSetup(PeerSetupFault),
    DispatcherJob(DispatcherJobFailure),
    MessageReconstruction { reason: String },
    MalformedSignature,
    SignatureMismatch,
    MalformedVerificationMessage,
    InvalidVerificationKey,
    VerificationKeyFingerprintMismatch,
    MalformedSetupContribution,
    InvalidSetupContribution,
}

impl FailureDetail {
    pub fn peer_setup_fault_reason(&self) -> PeerSetupFaultReason {
        match self {
            Self::MalformedVerificationMessage | Self::MalformedSetupContribution => {
                PeerSetupFaultReason::MalformedMessage
            }
            Self::InvalidVerificationKey => PeerSetupFaultReason::InvalidVerificationKey,
            Self::VerificationKeyFingerprintMismatch => {
                PeerSetupFaultReason::VerificationKeyFingerprintMismatch
            }
            Self::InvalidSetupContribution => PeerSetupFaultReason::InvalidSetupContribution,
            Self::MessageReconstruction { .. }
            | Self::MalformedSignature
            | Self::SignatureMismatch => PeerSetupFaultReason::AuthenticationRejected,
            Self::PeerSetup(fault) => fault.reason.clone(),
            Self::DispatcherJob(_) => {
                unreachable!("dispatcher failures are not peer setup failures")
            }
        }
    }
}

/// A runtime job rejection reported by the dispatcher.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatcherJobFailure {
    pub program_id: Uuid,
    /// Exact wire id used to retrieve the durable expected-job record.
    pub expected_job_id: String,
    /// Human-readable protocol job name used in reports.
    pub job_id: String,
    pub reason: String,
}

/// Why processing the unchanged message may succeed later.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetryReason {
    /// The sender's application verification key has not arrived yet.
    MissingVerificationKey { peer: PubkHash },
    /// One or more participant verification keys needed by setup are absent.
    MissingParticipantVerificationKeys,
    /// The referenced program has not been installed locally yet.
    ProgramNotInstalled,
    /// Setup has not reached the state that can consume this message.
    SetupNotReady,
    /// The active setup step accepts a different message type.
    UnexpectedSetupMessageType,
    /// The active setup step is still waiting for a prerequisite.
    MissingSetupPrerequisite,
}

/// Why consuming a message without applying it is safe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoOpReason {
    ContributionAlreadyAccepted,
    SetupComplete,
    SetupFailed,
    UnauthorizedSender,
    Duplicate,
    Stale,
    Orphaned,
    MalformedEnvelope,
    Uncorrelatable,
}

/// A protocol violation attributable to an authenticated peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerSetupFault {
    pub peer: PubkHash,
    pub reason: PeerSetupFaultReason,
}

/// Peer-controlled failures that make active setup untrustworthy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerSetupFaultReason {
    AuthenticationRejected,
    MalformedMessage,
    InvalidVerificationKey,
    VerificationKeyFingerprintMismatch,
    UnauthorizedMessage,
    InvalidSetupContribution,
}

impl std::fmt::Display for PeerSetupFaultReason {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let description = match self {
            Self::AuthenticationRejected => "message authentication was rejected",
            Self::MalformedMessage => "message was malformed",
            Self::InvalidVerificationKey => "verification key was invalid",
            Self::VerificationKeyFingerprintMismatch => {
                "verification key fingerprint did not match the authenticated peer"
            }
            Self::UnauthorizedMessage => "message was not authorized",
            Self::InvalidSetupContribution => "setup contribution was invalid",
        };
        formatter.write_str(description)
    }
}

// The coordinator is statically dispatched: production code uses the default
// `BitcoinCoordinator`, unit tests can instantiate with a mock implementing
// `BitcoinCoordinatorApi`.
pub struct ProgramContext<BC: BitcoinCoordinatorApi = BitcoinCoordinator> {
    pub key_manager: Rc<KeyManager>,
    pub rsa_public_key: String, //TODO: this should not be here
    pub comms: BrokerNode,
    pub bitcoin_coordinator: BC,
    pub broker_channel: BrokerNode,
    pub globals: Globals,
    pub witness: WitnessVars,
    pub components_config: ComponentsConfig,
    pub leader_broadcast_helper: LeaderBroadcastHelper,
    pub(crate) operation_timeouts: OperationTimeouts,
    pub(crate) expected_jobs: ExpectedJobs,
}

impl<BC: BitcoinCoordinatorApi> ProgramContext<BC> {
    pub(crate) fn new(
        comms: BrokerNode,
        key_manager: Rc<KeyManager>,
        rsa_public_key: String,
        bitcoin_coordinator: BC,
        broker_channel: BrokerNode,
        globals: Globals,
        witness: WitnessVars,
        components_config: ComponentsConfig,
        leader_broadcast_helper: LeaderBroadcastHelper,
        operation_timeouts: OperationTimeouts,
        expected_jobs: ExpectedJobs,
    ) -> Self {
        Self {
            comms,
            key_manager,
            rsa_public_key,
            bitcoin_coordinator,
            broker_channel,
            globals,
            witness,
            components_config,
            leader_broadcast_helper,
            operation_timeouts,
            expected_jobs,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProgramStatus {
    pub program_id: Uuid,
}

impl ProgramStatus {
    pub fn new(program_id: Uuid) -> Self {
        Self { program_id }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct RequestId(Uuid);

impl RequestId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

/// ZKP-specific API correlation and output. Dispatcher lifecycle and failure
/// state are owned by the corresponding expected-job record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ZKPExecution {
    requester: Identifier,
    output: Option<ZKPOutput>,
}

impl ZKPExecution {
    pub(crate) fn new(requester: Identifier) -> Self {
        Self {
            requester,
            output: None,
        }
    }

    pub(crate) fn with_output(requester: Identifier, proof: Vec<u8>, journal: Vec<u8>) -> Self {
        Self {
            requester,
            output: Some(ZKPOutput::new(proof, journal)),
        }
    }

    pub(crate) fn requester(&self) -> &Identifier {
        &self.requester
    }

    pub(crate) fn into_output(self) -> Option<ZKPOutput> {
        self.output
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ZKPOutput {
    proof: Vec<u8>,
    journal: Vec<u8>,
}

impl ZKPOutput {
    pub(crate) fn new(proof: Vec<u8>, journal: Vec<u8>) -> Self {
        Self { proof, journal }
    }

    pub(crate) fn into_parts(self) -> (Vec<u8>, Vec<u8>) {
        (self.proof, self.journal)
    }
}

#[derive(Clone, Debug)]
pub struct ParticipantChannel {
    pub id: Identifier,
    pub channel: RemoteChannel,
}

pub const PROGRAM_TYPE_AGGREGATED_KEY: &str = "aggregated_key";
pub const FINAL_AGGREGATED_KEY: &str = "final_aggregated_key";
pub const PROGRAM_TYPE_LOCK: &str = "lock";
pub const PROGRAM_TYPE_DRP: &str = "drp";
pub const PROGRAM_TYPE_SLOT: &str = "slot";
pub const PROGRAM_TYPE_TRANSFER: &str = "transfer";
pub const PROGRAM_TYPE_ACCEPT_PEGIN: &str = "accept_pegin";
pub const PROGRAM_TYPE_USER_TAKE: &str = "take";
pub const PROGRAM_TYPE_ADVANCE_FUNDS: &str = "advance_funds";
pub const PROGRAM_TYPE_REJECT_PEGIN: &str = "reject_pegin";
pub const PROGRAM_TYPE_DISPUTE_CORE: &str = "dispute_core";
pub const PROGRAM_TYPE_PAIRWISE_PENALIZATION: &str = "pairwise_penalization";
pub const PROGRAM_TYPE_FULL_PENALIZATION: &str = "full_penalization";
pub const PROGRAM_TYPE_PACKET: &str = "packet";
pub const PROGRAM_TYPE_GC_DRP: &str = "gc_drp";
pub const PROGRAM_TYPE_GC_GENERATION: &str = "gc_generation";
