use anyhow::{bail, Result};

use bitvmx_broker::RemoteChannel;
use bitvmx_broker::{BrokerNode, ReceivedMessage};
use bitvmx_client::bitvmx::{BitVMX, Context};
use bitvmx_client::comms_allow_list;
use bitvmx_client::comms_helper::{deserialize_msg, serialize_msg, CommsMessageType};
use bitvmx_client::config::Config;
use bitvmx_client::program::participant::CommsAddress;
use bitvmx_client::types::{
    IncomingBitVMXApiMessages, OutgoingBitVMXApiMessages, SetupFailureReason,
};
use bitvmx_settings::settings;
use serde_json::{json, Value};
use std::rc::Rc;
use std::time::{Duration, Instant};
use storage_backend::storage::Storage;
use tracing::info;
use uuid::Uuid;

mod common;

/// The wire version `comms_helper` speaks; its own constant is private.
const PROTOCOL_VERSION: &str = "1.0";
/// Never inspected: both paths under test fail before the signature is parsed.
const UNCHECKED_SIGNATURE: &[u8] = &[1, 2, 3, 4];

const DEADLINE: Duration = Duration::from_secs(60);

/// A peer holding a real operator identity that speaks the comms protocol directly,
/// so a test can send frames a well-behaved client never would. It must be reachable:
/// an unreachable peer trips the dead letter path instead (see `setup_failed.rs`).
struct RawPeer {
    node: BrokerNode,
    address: CommsAddress,
}

impl RawPeer {
    fn new(role: &str) -> Result<Self> {
        let config = Config::new(Some(format!("config/{}.yaml", role)))?;
        common::clear_db(&config.comms.storage_path);
        common::clear_db(&config.storage.path);

        let store = Rc::new(Storage::new(&config.storage)?);
        let node = BrokerNode::new_peers(
            "comms",
            config.comms.address,
            &settings::decrypt_or_read_file(&config.comms.priv_key)?,
            store.clone(),
            &config.comms.storage_path,
            comms_allow_list::build(&store, &config.comms.allow_list)?,
            config.broker.settings.clone(),
        )?;

        let address = CommsAddress::new(node.get_address(), node.get_pubk_hash()?);
        info!("Raw peer listening as {:?}", address);
        Ok(Self { node, address })
    }

    fn send(
        &self,
        to: &CommsAddress,
        program_id: &Uuid,
        msg_type: CommsMessageType,
        payload: Value,
    ) -> Result<()> {
        let raw = serialize_msg(
            PROTOCOL_VERSION,
            msg_type,
            program_id,
            payload,
            chrono_now_millis(),
            UNCHECKED_SIGNATURE.to_vec(),
        )?;
        self.node.send_peer(
            &Context::ProgramId(*program_id).to_string()?,
            &to.pubkey_hash,
            to.address,
            raw,
        )?;
        self.node.tick()?;
        Ok(())
    }

    /// Drains the inbox, reporting whether anything arrived for `program_id`. The client
    /// asks for our verification key as soon as it creates the program, so this doubles
    /// as "the program now exists on the other side".
    fn heard_about(&mut self, program_id: &Uuid) -> Result<bool> {
        self.node.tick()?;
        let mut heard = false;
        for message in self.node.check_receive(None)? {
            if let ReceivedMessage::Msg(_, raw) = message {
                if let Ok((_, msg_type, id, _, _, _)) = deserialize_msg(raw, 200000) {
                    info!("Raw peer received {:?} for program {}", msg_type, id);
                    heard |= id == *program_id;
                }
            }
        }
        Ok(heard)
    }
}

fn chrono_now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_millis() as i64
}

/// Runs both sides until the client reports something to L2.
fn drive_until_l2_message(
    bitvmx: &mut BitVMX,
    peer: &mut RawPeer,
    channel: &RemoteChannel,
) -> Result<OutgoingBitVMXApiMessages> {
    let deadline = Instant::now() + DEADLINE;
    while Instant::now() < deadline {
        common::tick(bitvmx)?;
        peer.node.tick()?;
        let _ = peer.node.check_receive(None)?;
        if let Some((msg, _)) = channel.recv()? {
            return Ok(OutgoingBitVMXApiMessages::from_string(&msg)?);
        }
    }
    bail!("timed out waiting for a message on the L2 channel")
}

/// Starts a program and waits until the peer sees traffic for it, which means the
/// program exists on the client and any message we send now will find it.
fn start_program(
    bitvmx: &mut BitVMX,
    peer: &mut RawPeer,
    channel: &RemoteChannel,
    leader: u16,
) -> Result<Uuid> {
    let program_id = Uuid::new_v4();
    let me = CommsAddress::new(bitvmx.address(), bitvmx.pubkey_hash()?);

    channel.send(
        &bitvmx.get_components_config().bitvmx,
        IncomingBitVMXApiMessages::SetupKey(
            program_id,
            vec![me, peer.address.clone()],
            None,
            leader,
        )
        .to_string()?,
    )?;

    let deadline = Instant::now() + DEADLINE;
    while Instant::now() < deadline {
        common::tick(bitvmx)?;
        if peer.heard_about(&program_id)? {
            return Ok(program_id);
        }
    }
    bail!("timed out waiting for the client to contact the peer about {program_id}")
}

fn assert_setup_failed(
    message: OutgoingBitVMXApiMessages,
    expected_id: Uuid,
    expected_peer: &str,
    expected_reason: SetupFailureReason,
    phase: &str,
) {
    match message {
        OutgoingBitVMXApiMessages::SetupFailed(id, step, peer, reason) => {
            assert_eq!(id, expected_id, "{phase}: wrong program");
            assert!(
                !step.is_empty(),
                "{phase}: the failing step should be named"
            );
            assert_eq!(
                peer.as_deref(),
                Some(expected_peer),
                "{phase}: the peer that sent the message should be named",
            );
            assert_eq!(reason, expected_reason, "{phase}: wrong failure reported");
        }
        other => panic!("{phase}: expected SetupFailed, got {other:?}"),
    }
}

/// Both drop paths in `bitvmx.rs`: a queued setup message whose retries run out is
/// reported to L2 rather than vanishing. The two differ in why the message is queued.
///
/// Kept in one test because each `prepare_bitcoin()` call creates the same
/// `bitcoin-regtest` container, so two tests in one binary would race for it.
#[test]
#[ignore]
fn dropped_setup_messages_are_reported_to_l2() -> Result<()> {
    common::config_trace();

    let (_bitcoin_client, _bitcoind_guard, _wallet) = common::prepare_bitcoin_guarded()?;

    // Two attempts, so a message that cannot make progress is dropped in well under a second.
    let (mut bitvmx, _address, channel, _emulator) =
        common::init_bitvmx_with_config("op_1", false, true, |config| {
            let node = &mut config.broker.settings.broker_node_config;
            node.max_send_attempts = 2;
            node.retry_min_delay_msecs = 100;
            node.retry_max_delay_msecs = 200;
        })?;

    let mut peer = RawPeer::new("op_2")?;
    let peer_hash = peer.address.pubkey_hash.clone();

    // The missing-key drop in `process_msg`. Setup data is buffered until the
    // sender's key arrives; this peer never answers the request, so it is dropped instead.
    info!("Phase 1: setup data that can never be verified");
    let program_id = start_program(&mut bitvmx, &mut peer, &channel, 0)?;
    peer.send(
        &CommsAddress::new(bitvmx.address(), bitvmx.pubkey_hash()?),
        &program_id,
        CommsMessageType::Keys,
        json!({ "keys": [] }),
    )?;

    let message = drive_until_l2_message(&mut bitvmx, &mut peer, &channel)?;
    assert_setup_failed(
        message,
        program_id,
        &peer_hash,
        SetupFailureReason::VerificationKeyMissing,
        "phase 1",
    );

    // The exhausted-RetryLater drop in `process_msg`. An announcement the client
    // cannot accept goes back on the queue, and retrying cannot help. `MessageLost` names no
    // message type, but RawPeer sends one frame per program, so the drop can only be this one.
    info!("Phase 2: a verification key the client cannot accept");
    let program_id = start_program(&mut bitvmx, &mut peer, &channel, 0)?;
    peer.send(
        &CommsAddress::new(bitvmx.address(), bitvmx.pubkey_hash()?),
        &program_id,
        CommsMessageType::VerificationKey,
        json!({ "verification_key": "-----BEGIN PUBLIC KEY-----\nnot this peer's key\n-----END PUBLIC KEY-----" }),
    )?;

    let message = drive_until_l2_message(&mut bitvmx, &mut peer, &channel)?;
    assert_setup_failed(
        message,
        program_id,
        &peer_hash,
        SetupFailureReason::MessageLost,
        "phase 2",
    );

    bitvmx.shutdown()?;
    Ok(())
}
