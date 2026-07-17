// Regression test for the union-bridge committee-setup stall observed in
// testnet (operator-03 stuck at 3/4 on the take-aggregated-key step). The
// bug is in `LeaderBroadcastHelper::process_broadcasted_message`
// (src/leader_broadcast.rs): when an embedded `OriginalMessage` is signed by
// a peer whose verification key has not arrived yet, `verify_and_get_key`
// returns `MissingVerificationKey`, the helper treats that as `Ok(false)`,
// the loop `continue`s, and the embedded original is silently dropped, with
// no buffering or retry path (the regular `push_back` path used for non-
// `Broadcasted` messages is bypassed by the early return at bitvmx.rs:388).
//
// This test exercises the actual production code path: it boots a real
// `BitVMX` instance and feeds it a hand-crafted `Broadcasted`-typed
// `QueuedMessage` via the public `BitVMX::process_msg` API. State is then
// inspected through `BitVMX::get_store` using a `MessageQueue` view backed
// by the same storage.
//
// The bug-reproducer test encodes the *desired* behavior (the embedded
// original must be buffered for retry when its verification key is missing),
// not the current buggy behavior. As long as the silent-drop bug exists,
// the test will FAIL. That is the signal that the fix has not landed yet.
// Once `process_broadcasted_message` is fixed to buffer the missing-key
// original (or the whole envelope) onto the message queue or an equivalent
// retry slot, the test will start passing.
//
// Tests are marked `#[ignore]` and require bitcoind (matching the convention
// in tests/aggregated_key.rs). Run with:
//   cargo test --test leader_broadcast_test -- --ignored --test-threads 1

#![cfg(test)]

use anyhow::Result;
use bitvmx_broker::channel::retry_helper::RetryPolicy;
use bitvmx_broker::identification::identifier::{Identifier, PubkHash};
use bitvmx_broker::rpc::config::QueueChannelConfig;
use bitvmx_client::comms_helper::{prepare_message, serialize_msg, CommsMessageType};
use bitvmx_client::config::Config;
use bitvmx_client::helper::compute_pubkey_hash;
use bitvmx_client::leader_broadcast::{BroadcastedMessage, OriginalMessage};
use bitvmx_client::message_queue::{MessageQueue, QueuedMessage};
use bitvmx_client::program::variables::Globals;
use bitvmx_client::signature_verifier::OperatorVerificationStore;
use bitvmx_settings::settings;
use chrono::Utc;
use common::{config_trace, init_bitvmx, prepare_bitcoin_guarded};
use key_manager::create_key_manager_from_config;
use key_manager::key_manager::KeyManager;
use serde_json::json;
use std::rc::Rc;
use uuid::Uuid;

mod common;

// =============================================================================
// Tests
// =============================================================================

/// Failure-path test. Models the bug-triggering branch of the timing race
/// observed in the operator-03 logs by feeding the BitVMX events in the
/// problematic order, deterministically (rather than racing two real
/// network messages).
///
/// # Production timeline (operator-03 logs, 2026-05-06)
///
/// | Time              | Event                                                                                      |
/// |-------------------|--------------------------------------------------------------------------------------------|
/// | 21:11:06.922      | op-03 receives `SetupKey`, requests verification keys from all 3 peers                     |
/// | 21:11:07.125      | Verification key from peer A (`768485a4…`) validated                                       |
/// | 21:11:07.289      | Verification key from peer B (`4c6e3b0e…`) validated                                       |
/// | **21:11:07.948**  | **Leader's BroadcastedMessage arrives** with 3 embedded originals                          |
/// | 21:11:07.948514   | peer A's embedded original verified → queued                                               |
/// | 21:11:07.948803   | peer B's embedded original verified → queued                                               |
/// | 21:11:07.948853   | `No verification key found for sender: f46f2413…` (leader)                                 |
/// | 21:11:07.948856   | `Original message from f46f2413… failed signature verification, skipping` (silent drop)    |
/// | **21:11:08.052**  | Leader's verification key finally validated, **104 ms too late**                           |
/// | 21:11:08.166–.178 | Previously-queued peer-A and peer-B originals processed → 2/4 → 3/4                        |
/// | (12 h later)      | Still at 3/4; setup never recovers                                                         |
///
/// The test maps these events to three checkpoints:
///
///   T0: BroadcastedMessage from leader is processed. The leader's
///       verification key is NOT yet registered in the local Globals.
///   T1: Leader's verification key is stored, simulating the late-arriving
///       VerificationKey response that op-03 received ~100 ms after the
///       broadcast.
///   T2: The embedded OriginalMessage must still be recoverable so a retry
///       can complete the keys step at 4/4.
///
/// In production, ordering between T0 and T1 is non-deterministic. The test
/// does not reproduce that race; it just pins the events to the ordering
/// that exposes the bug, then asserts the post-T1 invariant the system
/// needs in order to recover.
///
/// # Code references
///
/// - **Bug location.** `src/leader_broadcast.rs:404-410`. In
///   `LeaderBroadcastHelper::process_broadcasted_message`, an embedded
///   original whose signer is unknown returns `Ok(false)` from
///   `verify_original_message_signature`, the loop `continue`s, and the
///   message is dropped without being buffered.
/// - **Early-return that skips normal buffering for `Broadcasted`.**
///   `src/bitvmx.rs:388-400`. `BitVMX::process_msg` dispatches
///   `Broadcasted` straight into the helper, bypassing the path that
///   would otherwise re-queue on missing keys.
/// - **The retry pattern the fix should mirror.** `src/bitvmx.rs:407-423`.
///   For regular non-`Broadcasted` messages, a missing verification key
///   triggers `MessageQueue::push_back(msg)`, deferring the message until
///   the key arrives.
///
/// EXPECTED-FAILURE-UNTIL-FIX. While the silent-drop bug is present, the
/// embedded original is discarded at T0, so at T2 there is nothing left
/// to re-process and the assertion fails. That is the intended signal
/// that the fix has not landed. Once the helper buffers missing-key
/// originals the same way the regular path at `src/bitvmx.rs:407-423`
/// does, the queue will retain the contribution and this test will pass.
#[ignore]
#[test]
fn process_broadcasted_buffers_originals_when_verification_key_unknown() -> Result<()> {
    config_trace();
    let (_bitcoin_client, _bitcoind_guard, _wallet) = prepare_bitcoin_guarded()?;

    // Boot one BitVMX as the recipient. This corresponds to op-03 in the
    // production logs: it has just begun setup and has not yet received
    // the leader's VerificationKey response when the BroadcastedMessage
    // arrives.
    let (mut recipient, _recipient_addr, _bridge, _) = init_bitvmx("op_1", false)?;

    // Independent signing identity standing in for the leader (op-01 in
    // the production logs). The recipient does NOT have this peer's
    // verification key registered in its Globals at T0; that's the race.
    let leader = build_leader_env()?;

    let program_id = Uuid::new_v4();
    let leader_original = build_signed_leader_original(
        &leader,
        &program_id,
        json!({"step": "keys", "data": [1, 2, 3]}),
        CommsMessageType::Keys,
    )?;
    let broadcast_envelope = build_broadcasted_envelope(
        &program_id,
        &leader.pubkey_hash,
        vec![leader_original],
        CommsMessageType::Keys,
    )?;

    // Attach a view onto the recipient's internal MessageQueue. Both queues
    // share storage, so changes inside `process_msg` are visible here.
    let view_queue = MessageQueue::new(
        recipient.get_store(),
        RetryPolicy::new(&QueueChannelConfig::default())?,
    );
    let view_globals = Globals::new(recipient.get_store());
    assert!(
        view_queue.is_empty()?,
        "recipient's queue must start empty before injection"
    );

    // T0: the BroadcastedMessage arrives. Drives the actual production
    // code path: process_msg dispatches the Broadcasted-typed envelope
    // into LeaderBroadcastHelper::process_broadcasted_message in
    // leader_broadcast.rs.
    recipient.process_msg(broadcast_envelope)?;

    // T1: the leader's VerificationKey response arrives. Production goes
    // through SignatureVerifier::handle_verification_messages, which
    // ultimately stores the key via OperatorVerificationStore. We invoke
    // the public storage API directly with a Globals view on the recipient's
    // own backing store. Equivalent end state, no broker-roundtrip
    // required for the test.
    OperatorVerificationStore::store(&view_globals, &leader.pubkey_hash, &leader.rsa_public_key)?;

    // T2: the embedded original must still be recoverable so the keys step
    // can advance to 4/4. With the bug present the queue is empty here
    // (the data was discarded at T0), so this assertion fails, which is
    // the expected signal that the silent-drop bug has not been fixed.
    //
    // The assertion uses `is_empty` rather than `pop_front` so it remains
    // valid regardless of whether the eventual fix re-queues via
    // `push_new` (immediately poppable) or `push_back` (subject to retry-
    // policy backoff before pop_front returns Some).
    assert!(
        !view_queue.is_empty()?,
        "leader's embedded original must survive the verification-key race \
         so it can be retried once the key arrives. Currently it is silently \
         dropped at T0 by leader_broadcast.rs:404-410 (`continue` after \
         MissingVerificationKey), so by T2 there is nothing left to retry. \
         Fix should mirror bitvmx.rs:407-423 which re-queues regular \
         messages via `push_back` on missing keys."
    );

    Ok(())
}

/// Happy-path control test. Same setup as the failure-path test, but the
/// leader's verification key is already registered in the recipient's Globals
/// when the BroadcastedMessage arrives, i.e. the alternate timing where
/// there is no race. Asserts the embedded original ends up queued for
/// downstream processing as expected.
///
/// Acts as a baseline so a generic verification-path regression can be
/// told apart from the specific silent-drop bug exercised in the other
/// test: if both tests start failing the same way, the issue is in
/// signature verification overall, not in the silent-drop branch.
#[ignore]
#[test]
fn process_broadcasted_queues_originals_when_keys_known() -> Result<()> {
    config_trace();
    let (_bitcoin_client, _bitcoind_guard, _wallet) = prepare_bitcoin_guarded()?;

    let (mut recipient, _recipient_addr, _bridge, _) = init_bitvmx("op_1", false)?;
    let leader = build_leader_env()?;

    // Pre-register the leader's verification key, i.e. simulate the
    // alternate timing where the leader's VerificationKey response arrived
    // BEFORE the BroadcastedMessage. We do this by storing into Globals via
    // the same storage the recipient uses internally.
    let view_globals = Globals::new(recipient.get_store());
    OperatorVerificationStore::store(&view_globals, &leader.pubkey_hash, &leader.rsa_public_key)?;

    let program_id = Uuid::new_v4();
    let leader_original = build_signed_leader_original(
        &leader,
        &program_id,
        json!({"step": "keys"}),
        CommsMessageType::Keys,
    )?;
    let queued = build_broadcasted_envelope(
        &program_id,
        &leader.pubkey_hash,
        vec![leader_original],
        CommsMessageType::Keys,
    )?;

    let view_queue = MessageQueue::new(
        recipient.get_store(),
        RetryPolicy::new(&QueueChannelConfig::default())?,
    );

    recipient.process_msg(queued)?;

    let popped = view_queue
        .pop_front()?
        .expect("leader's original must reach the queue when its key is known");
    assert_eq!(popped.identifier.pubkey_hash, leader.pubkey_hash);
    assert!(
        view_queue.is_empty()?,
        "exactly one message should be queued for this single-original broadcast"
    );

    Ok(())
}

// =============================================================================
// Test support
// =============================================================================

const TEST_VERSION: &str = "1.0";

/// A self-contained signing identity that stands in for "the leader" in the
/// test. Holds a `KeyManager` populated from one of the operator key files
/// in `config/keys/` so it can produce real RSA signatures over
/// `OriginalMessage` payloads. The `pubkey_hash` is derived from the imported
/// RSA public key the same way production does it.
struct LeaderEnv {
    key_manager: Rc<KeyManager>,
    rsa_public_key: String,
    pubkey_hash: PubkHash,
}

/// Build a fresh signer environment using `op_2.key` as the simulated
/// leader's RSA private key. Storage paths are scoped to a unique tempdir
/// so this never collides with the recipient BitVMX (which runs as op_1).
fn build_leader_env() -> Result<LeaderEnv> {
    let mut config = Config::new(Some("config/op_1.yaml".to_string()))?;

    let unique_dir = std::env::temp_dir()
        .join("bitvmx-leader-broadcast-test")
        .join(Uuid::new_v4().to_string());
    std::fs::create_dir_all(&unique_dir)?;
    config.storage.path = unique_dir.join("storage.db").to_string_lossy().to_string();
    config.key_storage.path = unique_dir.join("keys.db").to_string_lossy().to_string();
    // op_2.key is a different identity than op_1.key (which the recipient uses),
    // so the resulting pubkey_hash is distinct from the recipient's.
    config.comms.priv_key = "config/keys/op_2.key".to_string();

    let key_manager = create_key_manager_from_config(&config.key_manager, &config.key_storage)?;
    let key_manager = Rc::new(key_manager);
    let rsa_public_key =
        key_manager.import_rsa_private_key(&settings::decrypt_or_read_file(config.comms_key())?)?;
    let pubkey_hash = compute_pubkey_hash(&rsa_public_key)?;

    Ok(LeaderEnv {
        key_manager,
        rsa_public_key,
        pubkey_hash,
    })
}

/// Produce a real signed `OriginalMessage` representing a contribution from
/// `leader` for `program_id`. Mirrors what the production leader stores in
/// its `LeaderBroadcastHelper` before broadcasting (see
/// setup_engine.rs:498-512).
fn build_signed_leader_original(
    leader: &LeaderEnv,
    program_id: &Uuid,
    payload: serde_json::Value,
    msg_type: CommsMessageType,
) -> Result<OriginalMessage> {
    let (version, data, timestamp, signature) = prepare_message(
        &leader.key_manager,
        &leader.rsa_public_key,
        program_id,
        msg_type,
        payload,
    )?;
    Ok(OriginalMessage {
        sender_pubkey_hash: leader.pubkey_hash.clone(),
        msg_type,
        data,
        original_timestamp: timestamp,
        original_signature: signature,
        version,
    })
}

/// Wrap a list of originals in a `Broadcasted`-typed envelope ready to be
/// fed into `BitVMX::process_msg`. The outer signature is intentionally a
/// placeholder: bitvmx.rs:388 takes an early return for `Broadcasted` and
/// never validates the outer envelope, so any non-empty bytes round-trip
/// correctly through `deserialize_msg`.
fn build_broadcasted_envelope(
    program_id: &Uuid,
    sender: &PubkHash,
    originals: Vec<OriginalMessage>,
    msg_type: CommsMessageType,
) -> Result<QueuedMessage> {
    let broadcasted_msg = BroadcastedMessage {
        original_msg_type: msg_type,
        original_messages: originals,
    };
    let bytes = serialize_msg(
        TEST_VERSION,
        CommsMessageType::Broadcasted,
        program_id,
        &broadcasted_msg,
        Utc::now().timestamp_millis(),
        vec![0xab, 0xcd],
    )?;
    Ok(QueuedMessage::new(
        Identifier::new(sender.clone(), 0),
        bytes,
    )?)
}
