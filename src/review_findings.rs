//! Tests for review findings 2, 3 and 4. Each finding test asserts what `docs/BITVMX_API_ERROR_HANDLING.md`
//! asks for (a validation failure is answered or rejected, not returned as `Err`).
//! The test before it is a control: same sequence, valid input, passes.

use crate::{
    bitvmx::Context,
    comms_helper::{serialize_msg, CommsMessageType, VerificationKeyAnnouncement},
    helper::compute_pubkey_hash,
    program::{participant::CommsAddress, program::Program, variables::VariableTypes},
    signature_verifier::OperatorVerificationStore,
    test_utils::{TestBitVMXEnv, TestStorageDir},
    types::{
        ErrorReport, ErrorReportKind, ErrorScope, IncomingBitVMXApiMessages,
        OutgoingBitVMXApiMessages, PROGRAM_TYPE_AGGREGATED_KEY,
    },
};
use bitvmx_broker::{BrokerNode, LocalChannel};
use bitvmx_settings::settings;
use key_manager::rsa::RSAKeyPair;
use rsa::pkcs1::{EncodeRsaPublicKey, LineEnding};
use std::{
    sync::atomic::{AtomicU16, Ordering},
    thread::sleep,
    time::Duration,
};
use uuid::Uuid;

type Replies = Vec<OutgoingBitVMXApiMessages>;

/// What the node sent to L2.
fn l2_replies(env: &TestBitVMXEnv, l2: &LocalChannel) -> Replies {
    env.bitvmx.program_context.broker_channel.tick().unwrap();
    l2.get_all()
        .unwrap()
        .into_iter()
        .filter_map(|message| OutgoingBitVMXApiMessages::from_string(&message.msg).ok())
        .collect()
}

// --- Findings 2 and 4: a request rejected by validation must get an `ApiError` -------------------------------

/// Queues `requests` and a `Ping` behind them, runs the API step five times like the main loop (which
/// swallows non-fatal errors) and returns what L2 received. The `Pong` shows whether the inbox kept moving.
fn run_api_ticks(requests: Vec<IncomingBitVMXApiMessages>, ping_id: Uuid) -> Replies {
    let mut env = TestBitVMXEnv::new("review-api-ticks").unwrap();
    let destination = env.bitvmx.config.components.bitvmx.clone();
    let l2 = env
        .bitvmx
        .program_context
        .broker_channel
        .create_local_channel(env.bitvmx.config.components.l2.clone())
        .unwrap();
    for request in requests {
        l2.send(&destination, request.to_string().unwrap()).unwrap();
    }
    let ping = IncomingBitVMXApiMessages::Ping(ping_id);
    l2.send(&destination, ping.to_string().unwrap()).unwrap();
    env.bitvmx.program_context.broker_channel.tick().unwrap();

    for _ in 0..5 {
        let _ = env
            .bitvmx
            .run_step("API messages", |bitvmx| bitvmx.process_api_messages());
    }
    l2_replies(&env, &l2)
}

fn answered(replies: &Replies, ping_id: Uuid) -> bool {
    replies
        .iter()
        .any(|reply| matches!(reply, OutgoingBitVMXApiMessages::Pong(id) if *id == ping_id))
}

fn api_error_for(replies: &Replies, request_id: Uuid) -> bool {
    replies.iter().any(
        |reply| matches!(reply, OutgoingBitVMXApiMessages::ApiError(id, _) if *id == request_id),
    )
}

/// The request was rejected with an `ApiError` and the inbox kept moving.
fn assert_rejected(replies: &Replies, request_id: Uuid, ping_id: Uuid) {
    assert!(
        answered(replies, ping_id),
        "the Ping behind the request was never answered in 5 ticks; replies: {replies:?}"
    );
    assert!(
        api_error_for(replies, request_id),
        "L2 never received an ApiError for the request; replies: {replies:?}"
    );
}

/// The request was accepted (no `ApiError`) and the inbox kept moving.
fn assert_accepted(replies: &Replies, request_id: Uuid, ping_id: Uuid) {
    assert!(
        answered(replies, ping_id),
        "control failed, replies: {replies:?}"
    );
    assert!(
        !api_error_for(replies, request_id),
        "control was rejected, replies: {replies:?}"
    );
}

fn set_var(key: &str) -> (Replies, Uuid, Uuid) {
    let (program_id, ping_id) = (Uuid::new_v4(), Uuid::new_v4());
    let request =
        IncomingBitVMXApiMessages::SetVar(program_id, key.to_string(), VariableTypes::Number(1));
    (run_api_ticks(vec![request], ping_id), program_id, ping_id)
}

#[test]
fn set_var_with_valid_key_does_not_block_the_inbox() {
    let (replies, program_id, ping_id) = set_var("ok");
    assert_accepted(&replies, program_id, ping_id);
}

/// Finding 2. `/` is the storage key separator, so `var_key` fails with `InvalidKey`. `handle_api_message`
/// returns that as `Err`, the inbox transaction rolls back and the same request is taken again on every tick.
#[test]
fn set_var_with_invalid_key_is_an_api_error() {
    let (replies, program_id, ping_id) = set_var("a/b");
    assert_rejected(&replies, program_id, ping_id);
}

fn generate_zkp_twice(second_timeout: Option<u64>) -> (Replies, Uuid, Uuid) {
    let (job, ping_id) = (Uuid::new_v4(), Uuid::new_v4());
    let request =
        |timeout| IncomingBitVMXApiMessages::GenerateZKP(job, vec![1], "elf".to_string(), timeout);
    let replies = run_api_ticks(vec![request(None), request(second_timeout)], ping_id);
    (replies, job, ping_id)
}

#[test]
fn generate_zkp_repeated_with_same_timeout_does_not_block_the_inbox() {
    let (replies, job, ping_id) = generate_zkp_twice(None);
    assert_accepted(&replies, job, ping_id);
}

/// Finding 4. The same job id with a different timeout fails the metadata check with `InvalidState`,
/// which comes out as `Err` and blocks the inbox like finding 2.
#[test]
fn generate_zkp_with_conflicting_timeout_is_an_api_error() {
    let (replies, job, ping_id) = generate_zkp_twice(Some(5));
    assert_rejected(&replies, job, ping_id);
}

// --- Finding 3: a peer verification key the verifier cannot use must not wedge the comms inbox -------------
//
// A real second comms node (the development `op_2` identity, own port) joins a program, announces its
// verification key and sends a `Keys` message with a bad signature. The node's comms inbox is then run the
// way the main loop runs it, so the rollback and the retry really happen.

const PEER_KEY_PATH: &str = "config/keys/op_2.key";

struct RealPeer {
    node: BrokerNode,
    _dirs: (TestStorageDir, TestStorageDir), // keep the peer's databases until the test ends
}

impl RealPeer {
    fn new(env: &TestBitVMXEnv) -> Self {
        static NEXT_PORT: AtomicU16 = AtomicU16::new(26100);
        let dirs = (
            TestStorageDir::new("review-peer-storage"),
            TestStorageDir::new("review-peer-comms"),
        );
        let mut address = env.bitvmx.config.comms.address;
        address.set_port(NEXT_PORT.fetch_add(1, Ordering::Relaxed));
        let node = BrokerNode::new_peers_with_paths(
            "review-peer",
            address,
            PEER_KEY_PATH,
            dirs.0.storage(),
            dirs.1.path(),
            &env.bitvmx.config.comms.allow_list,
            env.bitvmx.config.broker.settings.clone(),
        )
        .unwrap();
        Self { node, _dirs: dirs }
    }

    fn address(&self) -> CommsAddress {
        CommsAddress::new(self.node.get_address(), self.node.get_pubk_hash())
    }

    fn send(
        &mut self,
        to: &CommsAddress,
        program_id: &Uuid,
        msg_type: CommsMessageType,
        payload: serde_json::Value,
        signature: Vec<u8>,
    ) {
        let raw = serialize_msg("1.0", msg_type, program_id, payload, 0, signature).unwrap();
        let context = Context::ProgramId(*program_id).to_string().unwrap();
        self.node
            .send_peer(&context, &to.pubkey_hash, to.address, raw)
            .unwrap();
        self.node.tick().unwrap();
    }
}

/// One round of the comms side of the main loop.
fn comms_round(env: &mut TestBitVMXEnv, peer: &mut RealPeer) {
    peer.node.tick().unwrap();
    let _ = peer.node.check_receive(None).unwrap();
    let _ = env.bitvmx.process_broker_queues();
    let _ = env.bitvmx.process_comms_messages();
    sleep(Duration::from_millis(50));
}

/// The peer announces its key as SPKI or as PKCS#1 (same key, same fingerprint) and then sends a `Keys`
/// message with a bad signature. Returns what L2 received after 30 rounds.
fn replies_after_bad_signature_from_real_peer(announce_pkcs1: bool) -> (Replies, Uuid, String) {
    let mut env = TestBitVMXEnv::new("review-real-peer-node").unwrap();
    let l2 = env
        .bitvmx
        .program_context
        .broker_channel
        .create_local_channel(env.bitvmx.config.components.l2.clone())
        .unwrap();
    let mut peer = RealPeer::new(&env);
    let peer_address = peer.address();

    let keypair =
        RSAKeyPair::from_private_pem(&settings::decrypt_or_read_file(PEER_KEY_PATH).unwrap())
            .unwrap();
    let spki = keypair.export_public_pem().unwrap();
    let pkcs1 = keypair.public_key().to_pkcs1_pem(LineEnding::LF).unwrap();
    assert!(pkcs1.contains("BEGIN RSA PUBLIC KEY"));
    assert_eq!(
        compute_pubkey_hash(&spki).unwrap(),
        peer_address.pubkey_hash,
        "the peer's TLS identity must be the fingerprint of the key it announces"
    );

    let node_address = CommsAddress::new(
        env.bitvmx.program_context.comms.get_address(),
        env.bitvmx.program_context.comms.get_pubk_hash(),
    );
    let program_id = Uuid::new_v4();
    let store = env.bitvmx.get_store();
    Program::new(
        program_id,
        PROGRAM_TYPE_AGGREGATED_KEY,
        vec![node_address.clone(), peer_address.clone()],
        0,
        None,
        &mut env.bitvmx.program_context,
        store,
    )
    .unwrap();

    let verification_key = if announce_pkcs1 { pkcs1 } else { spki };
    let announcement = VerificationKeyAnnouncement { verification_key }
        .to_value()
        .unwrap();
    peer.send(
        &node_address,
        &program_id,
        CommsMessageType::VerificationKey,
        announcement,
        vec![1],
    );
    let stored = |env: &TestBitVMXEnv| {
        let globals = &env.bitvmx.program_context.globals;
        OperatorVerificationStore::has(globals, &peer_address.pubkey_hash).unwrap()
    };
    for _ in 0..100 {
        if stored(&env) {
            break;
        }
        comms_round(&mut env, &mut peer);
    }
    assert!(stored(&env), "the node never stored the announced key");

    let keys = serde_json::json!({});
    peer.send(
        &node_address,
        &program_id,
        CommsMessageType::Keys,
        keys,
        vec![7u8; 64],
    );
    for _ in 0..30 {
        comms_round(&mut env, &mut peer);
    }
    (l2_replies(&env, &l2), program_id, peer_address.pubkey_hash)
}

fn non_fatal_reports(replies: &Replies) -> usize {
    let non_fatal = |reply: &&OutgoingBitVMXApiMessages| {
        matches!(
            reply,
            OutgoingBitVMXApiMessages::Error(ErrorReport {
                kind: ErrorReportKind::NonFatal,
                ..
            })
        )
    };
    replies.iter().filter(non_fatal).count()
}

fn setup_failed_because_of(replies: &Replies, program_id: Uuid, peer_hash: &str) -> bool {
    replies.iter().any(|reply| {
        matches!(
            reply,
            OutgoingBitVMXApiMessages::Error(ErrorReport {
                scope: ErrorScope::Program(id),
                kind: ErrorReportKind::SetupFailed { peer: Some(peer), .. },
                ..
            }) if *id == program_id && peer == peer_hash
        )
    })
}

#[test]
fn bad_signature_from_real_peer_with_spki_key_fails_the_setup() {
    let (replies, program_id, peer_hash) = replies_after_bad_signature_from_real_peer(false);
    assert!(
        setup_failed_because_of(&replies, program_id, &peer_hash),
        "control failed, replies: {replies:?}"
    );
    assert_eq!(non_fatal_reports(&replies), 0, "replies: {replies:?}");
}

/// Finding 3. The same key announced as PKCS#1 has the same fingerprint, so it is accepted and stored, but
/// `RSAKeyPair::verify` only parses SPKI. `authenticate_message` returns that parse failure as `Err` instead
/// of a rejection, so the comms inbox rolls back and takes the same message on every round.
#[test]
fn bad_signature_from_real_peer_with_pkcs1_key_fails_the_setup() {
    let (replies, program_id, peer_hash) = replies_after_bad_signature_from_real_peer(true);
    assert!(
        setup_failed_because_of(&replies, program_id, &peer_hash),
        "the bad signature was never rejected; {} non-fatal errors in 30 rounds instead; replies: {replies:?}",
        non_fatal_reports(&replies)
    );
}
