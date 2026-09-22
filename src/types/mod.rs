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
    leader_broadcast::LeaderBroadcastHelper,
    ports::bitcoin_coordinator::BitcoinCoordinatorApi,
    program::variables::{Globals, WitnessVars},
};

/// Outcome of handling an incoming peer message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageDisposition {
    /// The message was processed and should not be retried.
    Processed,
    /// A temporary prerequisite is absent, so the message should be retried.
    RetryLater(RetryReason),
    /// The message cannot change protocol state and should be consumed.
    DiscardNoOp(NoOpReason),
    /// An attributable peer fault must terminate setup without retrying the input.
    FailSetup(PeerSetupFault),
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
}

/// Why consuming a message without applying it is safe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoOpReason {
    ContributionAlreadyAccepted,
    SetupComplete,
    SetupFailed,
    UnauthorizedSender,
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
}

impl<BC: BitcoinCoordinatorApi> ProgramContext<BC> {
    pub fn new(
        comms: BrokerNode,
        key_manager: Rc<KeyManager>,
        rsa_public_key: String,
        bitcoin_coordinator: BC,
        broker_channel: BrokerNode,
        globals: Globals,
        witness: WitnessVars,
        components_config: ComponentsConfig,
        leader_broadcast_helper: LeaderBroadcastHelper,
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
