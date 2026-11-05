//! A message that can never succeed must be answered or rejected, not returned as `Err`: that rolls the inbox
//! transaction back and takes the same message again on every tick, blocking everything queued behind it (see
//! `docs/BITVMX_API_ERROR_HANDLING.md` and `docs/ERROR_RECOVER_REVIEW_FINDINGS.md`).
//! Each poison message test sits after a control: same sequence, valid input.
//!
//! The node runs on the mocked coordinator, so no bitcoind is needed.

use anyhow::Result;
use bitvmx_broker::{BrokerNode, LocalChannel};
use bitvmx_client::bitvmx::Context;
use bitvmx_client::comms_helper::{serialize_msg, CommsMessageType, VerificationKeyAnnouncement};
use bitvmx_client::config::Config;
use bitvmx_client::error_handling::is_fatal;
use bitvmx_client::errors::BitVMXError;
use bitvmx_client::helper::compute_pubkey_hash;
use bitvmx_client::program::participant::CommsAddress;
use bitvmx_client::program::variables::{Globals, VariableTypes};
use bitvmx_client::signature_verifier::OperatorVerificationStore;
use bitvmx_client::test_utils::{TestBitVMXEnv, TestStorageDir};
use bitvmx_client::types::{
    ErrorReport, ErrorReportKind, ErrorScope, IncomingBitVMXApiMessages, OutgoingBitVMXApiMessages,
};
use bitvmx_settings::settings;
use key_manager::rsa::RSAKeyPair;
use rsa::pkcs1::{EncodeRsaPublicKey, LineEnding};
use std::sync::atomic::{AtomicU16, Ordering};
use std::thread::sleep;
use std::time::Duration;
use uuid::Uuid;

type Replies = Vec<OutgoingBitVMXApiMessages>;

/// What the node sent to L2.
fn l2_replies(env: &mut TestBitVMXEnv, l2: &LocalChannel) -> Result<Replies> {
    env.bitvmx.process_broker_queues()?;
    l2.get_all()?
        .into_iter()
        .map(|message| Ok(OutgoingBitVMXApiMessages::from_string(&message.msg)?))
        .collect()
}

/// The main loop keeps ticking after a non-fatal step error, so only a fatal one ends the test.
fn tolerate_non_fatal<T>(step: Result<T, BitVMXError>) {
    if let Err(error) = step {
        assert!(!is_fatal(&error), "fatal error: {error}");
    }
}

// --- A request rejected by validation must get an `ApiError` ------------------------------------------------

/// Queues `requests` and a `Ping` behind them, runs the API step five times and returns what L2 received.
/// The `Pong` shows whether the inbox kept moving.
fn replies_to(requests: Vec<IncomingBitVMXApiMessages>, ping_id: Uuid) -> Result<Replies> {
    let mut env = TestBitVMXEnv::new("poison-api")?;
    let l2 = env.bitvmx.l2_channel()?;
    let destination = env.bitvmx.get_components_config().bitvmx.clone();
    for request in requests {
        l2.send(&destination, request.to_string()?)?;
    }
    l2.send(
        &destination,
        IncomingBitVMXApiMessages::Ping(ping_id).to_string()?,
    )?;
    env.bitvmx.process_broker_queues()?;

    for _ in 0..5 {
        tolerate_non_fatal(env.bitvmx.process_api_messages());
    }
    l2_replies(&mut env, &l2)
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

fn set_var(key: &str) -> Result<(Replies, Uuid, Uuid)> {
    let (program_id, ping_id) = (Uuid::new_v4(), Uuid::new_v4());
    let request =
        IncomingBitVMXApiMessages::SetVar(program_id, key.to_string(), VariableTypes::Number(1));
    Ok((replies_to(vec![request], ping_id)?, program_id, ping_id))
}

#[test]
fn set_var_with_valid_key_does_not_block_the_inbox() -> Result<()> {
    let (replies, program_id, ping_id) = set_var("ok")?;
    assert_accepted(&replies, program_id, ping_id);
    Ok(())
}

/// `/` is the storage key separator, so `var_key` fails with `InvalidKey`.
#[test]
fn set_var_with_invalid_key_is_an_api_error() -> Result<()> {
    let (replies, program_id, ping_id) = set_var("a/b")?;
    assert_rejected(&replies, program_id, ping_id);
    Ok(())
}

fn generate_zkp_twice(second_timeout: Option<u64>) -> Result<(Replies, Uuid, Uuid)> {
    let (job, ping_id) = (Uuid::new_v4(), Uuid::new_v4());
    let request =
        |timeout| IncomingBitVMXApiMessages::GenerateZKP(job, vec![1], "elf".to_string(), timeout);
    let replies = replies_to(vec![request(None), request(second_timeout)], ping_id)?;
    Ok((replies, job, ping_id))
}

#[test]
fn generate_zkp_repeated_with_same_timeout_does_not_block_the_inbox() -> Result<()> {
    let (replies, job, ping_id) = generate_zkp_twice(None)?;
    assert_accepted(&replies, job, ping_id);
    Ok(())
}

/// The same job id with a different timeout fails the metadata check with `InvalidState`.
#[test]
fn generate_zkp_with_conflicting_timeout_is_an_api_error() -> Result<()> {
    let (replies, job, ping_id) = generate_zkp_twice(Some(5))?;
    assert_rejected(&replies, job, ping_id);
    Ok(())
}

// --- A peer verification key the verifier cannot use must not block the comms inbox --------------------------

const PEER_KEY_PATH: &str = "config/keys/op_2.key";

/// A real second comms node (the development `op_2` identity, own port), speaking the comms protocol directly so
/// it can announce a key encoding and send signatures a well-behaved client never would.
struct RawPeer {
    node: BrokerNode,
    _dirs: (TestStorageDir, TestStorageDir), // keep the peer's databases until the test ends
}

impl RawPeer {
    fn new(env: &TestBitVMXEnv) -> Result<Self> {
        static NEXT_PORT: AtomicU16 = AtomicU16::new(26100);
        let config = Config::new(Some("config/development.yaml".to_string()))?;
        let dirs = (
            TestStorageDir::new("poison-peer-storage"),
            TestStorageDir::new("poison-peer-comms"),
        );
        let mut address = env.bitvmx.address();
        address.set_port(NEXT_PORT.fetch_add(1, Ordering::Relaxed));
        let node = BrokerNode::new_peers_with_paths(
            "poison-peer",
            address,
            PEER_KEY_PATH,
            dirs.0.storage(),
            dirs.1.path(),
            &config.comms.allow_list,
            config.broker.settings.clone(),
        )?;
        Ok(Self { node, _dirs: dirs })
    }

    fn address(&self) -> CommsAddress {
        CommsAddress::new(self.node.get_address(), self.node.get_pubk_hash())
    }

    fn send(
        &self,
        to: &CommsAddress,
        program_id: &Uuid,
        msg_type: CommsMessageType,
        payload: serde_json::Value,
        signature: Vec<u8>,
    ) -> Result<()> {
        let raw = serialize_msg("1.0", msg_type, program_id, payload, 0, signature)?;
        self.node.send_peer(
            &Context::ProgramId(*program_id).to_string()?,
            &to.pubkey_hash,
            to.address,
            raw,
        )?;
        self.node.tick()?;
        Ok(())
    }
}

/// One round of the comms side of the main loop.
fn comms_round(env: &mut TestBitVMXEnv, peer: &mut RawPeer) -> Result<()> {
    peer.node.tick()?;
    let _ = peer.node.check_receive(None)?;
    env.bitvmx.process_broker_queues()?;
    tolerate_non_fatal(env.bitvmx.process_comms_messages());
    sleep(Duration::from_millis(50));
    Ok(())
}

/// The peer announces its key as SPKI or as PKCS#1 (same key, same fingerprint) and then sends a `Keys`
/// message with a bad signature. Returns what L2 received after 30 rounds.
fn replies_after_bad_signature_from_peer(announce_pkcs1: bool) -> Result<(Replies, Uuid, String)> {
    let mut env = TestBitVMXEnv::new("poison-peer-node")?;
    let l2 = env.bitvmx.l2_channel()?;
    let mut peer = RawPeer::new(&env)?;
    let peer_address = peer.address();
    let peer_hash = peer_address.pubkey_hash.clone();

    let keypair = RSAKeyPair::from_private_pem(&settings::decrypt_or_read_file(PEER_KEY_PATH)?)?;
    let spki = keypair.export_public_pem()?;
    let pkcs1 = keypair.public_key().to_pkcs1_pem(LineEnding::LF)?;
    assert!(pkcs1.contains("BEGIN RSA PUBLIC KEY"));
    assert_eq!(
        compute_pubkey_hash(&spki)?,
        peer_hash,
        "the peer's TLS identity must be the fingerprint of the key it announces"
    );

    let node_address = CommsAddress::new(env.bitvmx.address(), env.bitvmx.pubkey_hash()?);
    let program_id = Uuid::new_v4();
    l2.send(
        &env.bitvmx.get_components_config().bitvmx,
        IncomingBitVMXApiMessages::SetupKey(
            program_id,
            vec![node_address.clone(), peer_address],
            None,
            0,
            None,
        )
        .to_string()?,
    )?;
    env.bitvmx.process_broker_queues()?;
    tolerate_non_fatal(env.bitvmx.process_api_messages());
    assert!(
        env.bitvmx.load_program(&program_id)?.is_some(),
        "the node never created the program"
    );

    let verification_key = if announce_pkcs1 {
        pkcs1.to_string()
    } else {
        spki
    };
    peer.send(
        &node_address,
        &program_id,
        CommsMessageType::VerificationKey,
        VerificationKeyAnnouncement { verification_key }.to_value()?,
        vec![1],
    )?;
    let globals = Globals::new(env.bitvmx.get_store());
    for _ in 0..100 {
        if OperatorVerificationStore::has(&globals, &peer_hash)? {
            break;
        }
        comms_round(&mut env, &mut peer)?;
    }
    assert!(
        OperatorVerificationStore::has(&globals, &peer_hash)?,
        "the node never stored the announced key"
    );

    peer.send(
        &node_address,
        &program_id,
        CommsMessageType::Keys,
        serde_json::json!({}),
        vec![7u8; 64],
    )?;
    for _ in 0..30 {
        comms_round(&mut env, &mut peer)?;
    }
    Ok((l2_replies(&mut env, &l2)?, program_id, peer_hash))
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
fn bad_signature_from_peer_with_spki_key_fails_the_setup() -> Result<()> {
    let (replies, program_id, peer_hash) = replies_after_bad_signature_from_peer(false)?;
    assert!(
        setup_failed_because_of(&replies, program_id, &peer_hash),
        "control failed, replies: {replies:?}"
    );
    assert_eq!(non_fatal_reports(&replies), 0, "replies: {replies:?}");
    Ok(())
}

/// The announcement accepts PKCS#1, but `RSAKeyPair::verify` only parses SPKI, and `authenticate_message` returns
/// that parse failure as `Err` instead of a rejection.
#[test]
fn bad_signature_from_peer_with_pkcs1_key_fails_the_setup() -> Result<()> {
    let (replies, program_id, peer_hash) = replies_after_bad_signature_from_peer(true)?;
    assert!(
        setup_failed_because_of(&replies, program_id, &peer_hash),
        "the bad signature was never rejected; {} non-fatal errors in 30 rounds instead; replies: {replies:?}",
        non_fatal_reports(&replies)
    );
    Ok(())
}
