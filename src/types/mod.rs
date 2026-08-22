mod shared;
pub use shared::*;

use std::rc::Rc;

use crate::config::ComponentsConfig;
use bitcoin_coordinator::coordinator::BitcoinCoordinator;
use bitvmx_broker::{identification::identifier::Identifier, BrokerNode, RemoteChannel};
use key_manager::key_manager::KeyManager;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    leader_broadcast::LeaderBroadcastHelper,
    ports::bitcoin_coordinator::BitcoinCoordinatorApi,
    program::variables::{Globals, WitnessVars},
};

/// Outcome of handling an incoming message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageDisposition {
    /// The message was processed and should not be retried.
    Processed,
    /// The message could not be processed yet and should be queued for retry.
    RetryLater,
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
