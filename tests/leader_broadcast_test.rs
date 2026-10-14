// Regression coverage for the union-bridge committee-setup stall observed in
// testnet (operator-03 stuck at 3/4 on the take-aggregated-key step). The
// relevant path is `LeaderBroadcastHelper::process_broadcasted_message`: when
// an embedded `OriginalMessage` is signed by a peer whose verification key has
// not arrived yet, authentication returns `AuthenticationOutcome::MissingKey`.
// The fixed behavior retains the authenticated outer envelope as the bounded
// retry unit; it does not silently drop the original or give a reconstructed
// message a fresh retry budget.
//
// These integration smoke tests exercise the public `BitVMX::process_msg` API
// and inspect the persistent queue through `BitVMX::get_store`. They use a
// program ID that is not installed yet, so they specifically guard unchanged
// outer-envelope retention at the lifecycle gate. The exact active-program
// missing-key branch is covered by the non-Docker unit tests in
// `src/bitvmx.rs`, `src/leader_broadcast.rs`, and `src/message_queue.rs`.
//
// Tests are marked `#[ignore]` and require bitcoind. Run with:
//   cargo test --test leader_broadcast_test -- --ignored --test-threads 1

#![cfg(test)]

use anyhow::Result;
use bitvmx_broker::identification::identifier::{Identifier, PubkHash};
use bitvmx_broker::retry::RetryPolicy;
use bitvmx_broker::rpc::config::BrokerNodeConfig;
use bitvmx_client::comms_helper::{prepare_message, serialize_msg, CommsMessageType};
use bitvmx_client::config::Config;
use bitvmx_client::helper::compute_pubkey_hash;
use bitvmx_client::leader_broadcast::{BroadcastedMessage, OriginalMessage};
use bitvmx_client::message_queue::{MessageQueue, QueuedMessage};
use bitvmx_client::program::variables::Globals;
use bitvmx_client::signature_verifier::OperatorVerificationStore;
use bitvmx_settings::settings;
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

/// Models the ordering involved in the original verification-key race without
/// relying on nondeterministic network timing.
///
/// # Production timeline (operator-03 logs, 2026-05-06)
///
/// | Time              | Event                                                                                   |
/// |-------------------|-----------------------------------------------------------------------------------------|
/// | 21:11:06.922      | op-03 receives `SetupKey`, requests verification keys from all 3 peers                  |
/// | 21:11:07.125      | Verification key from peer A (`768485a4…`) validated                                    |
/// | 21:11:07.289      | Verification key from peer B (`4c6e3b0e…`) validated                                    |
/// | **21:11:07.948**  | **Leader's `BroadcastedMessage` arrives with 3 embedded originals**                     |
/// | 21:11:07.948514   | peer A's embedded original verified and queued                                          |
/// | 21:11:07.948803   | peer B's embedded original verified and queued                                          |
/// | 21:11:07.948853   | leader's embedded original encounters a missing verification key                       |
/// | **21:11:08.052**  | Leader's verification key is validated, 104 ms too late for the old silent-drop path    |
/// | 21:11:08.166–.178 | Previously queued originals process, but setup remains at 3/4 under the old behavior    |
///
/// The required invariant is that the contribution remains recoverable after
/// the key arrives. Current production code does this by retrying the unchanged
/// authenticated outer envelope with its existing bounded retry state. This
/// integration test guards the same outer-envelope retention invariant at the
/// earlier missing-program lifecycle gate; active-program missing-key coverage
/// lives in the unit tests named above.
#[ignore]
#[test]
fn process_broadcasted_defers_envelope_when_program_is_not_installed() -> Result<()> {
    config_trace();
    let (_bitcoin_client, _bitcoind_guard, _wallet) = prepare_bitcoin_guarded()?;

    // Boot one BitVMX as the recipient. No program is installed for the fresh
    // ID below, so this smoke test reaches the lifecycle deferral before
    // application-signature verification.
    let (mut recipient, _recipient_addr, _bridge, _) = init_bitvmx("op_1", false)?;

    // Independent signing identity standing in for the leader from the
    // production incident.
    let leader = build_leader_env()?;

    let program_id = Uuid::new_v4();
    let leader_original = build_signed_leader_original(
        &leader,
        &program_id,
        json!({"step": "keys", "data": [1, 2, 3]}),
        CommsMessageType::Keys,
    )?;
    let broadcast_envelope = build_broadcasted_envelope(
        &leader,
        &program_id,
        vec![leader_original],
        CommsMessageType::Keys,
    )?;

    // Attach a view onto the recipient's internal MessageQueue. Both queues
    // share storage, so changes inside `process_msg` are visible here.
    let view_queue = MessageQueue::new(
        recipient.get_store(),
        RetryPolicy::new(&BrokerNodeConfig::default())?,
    );
    assert!(
        view_queue.is_empty()?,
        "recipient's queue must start empty before injection"
    );

    // T0: process the envelope before either the program or the leader key is
    // locally available. The unchanged envelope must enter bounded retry.
    recipient.process_msg(broadcast_envelope)?;

    // T1: store the late-arriving key through the same persistent verification
    // store used by production bootstrap handling.
    let view_globals = Globals::new(recipient.get_store());
    OperatorVerificationStore::store(&view_globals, &leader.pubkey_hash, &leader.rsa_public_key)?;

    // T2: the outer envelope must still be recoverable. `is_empty` keeps the
    // assertion independent of retry-policy backoff.
    assert!(
        !view_queue.is_empty()?,
        "the unchanged outer envelope must remain available until the program is installed"
    );

    Ok(())
}

/// Happy-path timing control: the leader verification key is already known
/// when the envelope arrives. Because this smoke test deliberately leaves the
/// program uninstalled, the lifecycle gate still retains the outer envelope.
/// Active-program processing of known-key originals is covered by
/// `process_broadcasted_message_queues_verified_original`.
#[ignore]
#[test]
fn process_broadcasted_with_known_key_still_defers_for_missing_program() -> Result<()> {
    config_trace();
    let (_bitcoin_client, _bitcoind_guard, _wallet) = prepare_bitcoin_guarded()?;

    let (mut recipient, _recipient_addr, _bridge, _) = init_bitvmx("op_1", false)?;
    let leader = build_leader_env()?;

    // Simulate the alternate timing where the leader's VerificationKey response
    // arrives before the broadcast.
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
        &leader,
        &program_id,
        vec![leader_original],
        CommsMessageType::Keys,
    )?;

    let view_queue = MessageQueue::new(
        recipient.get_store(),
        RetryPolicy::new(&BrokerNodeConfig::default())?,
    );

    recipient.process_msg(queued)?;

    let popped = view_queue
        .pop_front()?
        .expect("outer envelope must be deferred while the program is absent");
    assert_eq!(popped.identifier.pubkey_hash, leader.pubkey_hash);
    assert!(
        view_queue.is_empty()?,
        "exactly one outer envelope should be queued"
    );

    Ok(())
}

// =============================================================================
// Test support
// =============================================================================

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

/// Wrap a list of originals in a signed `Broadcasted` envelope ready to be
/// fed into `BitVMX::process_msg`. Production authenticates this outer leader
/// envelope before inspecting any embedded original.
fn build_broadcasted_envelope(
    leader: &LeaderEnv,
    program_id: &Uuid,
    originals: Vec<OriginalMessage>,
    msg_type: CommsMessageType,
) -> Result<QueuedMessage> {
    let broadcasted_msg = BroadcastedMessage {
        original_msg_type: msg_type,
        original_messages: originals,
    };
    let (version, data, timestamp, signature) = prepare_message(
        &leader.key_manager,
        &leader.rsa_public_key,
        program_id,
        CommsMessageType::Broadcasted,
        serde_json::to_value(broadcasted_msg)?,
    )?;
    let bytes = serialize_msg(
        &version,
        CommsMessageType::Broadcasted,
        program_id,
        data,
        timestamp,
        signature,
    )?;
    Ok(QueuedMessage::new(
        Identifier::new(leader.pubkey_hash.clone(), 0),
        bytes,
    )?)
}
