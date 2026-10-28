use anyhow::Result;

use bitvmx_client::helper::{compute_pubkey_hash, rsa_public_key_pem};
use bitvmx_client::program::participant::CommsAddress;
use bitvmx_client::types::{
    ErrorReportKind, ErrorScope, IncomingBitVMXApiMessages, OutgoingBitVMXApiMessages,
    SetupFailureReason,
};
use bitvmx_settings::settings;
use uuid::Uuid;

mod common;

/// A peer identity that is never brought up, on a port nobody listens on.
const ABSENT_PEER_KEY: &str = "config/keys/op_10.key";
const ABSENT_ADDRESS: &str = "127.0.0.1:61999";

/// A setup whose counterpart never answers must be reported to L2, not left hanging.
///
/// The client is the non-leader, so it sends its first step to the leader straight away
/// (`setup_engine.rs`: non-leaders send only to the leader). Nobody is listening, comms
/// exhausts its send attempts, and the message lands in the dead letter queue, which is
/// where `bitvmx.rs` turns it into `SetupFailed`.
#[test]
#[ignore]
fn undeliverable_setup_message_is_reported_to_l2() -> Result<()> {
    common::config_trace();

    let (_bitcoin_client, _bitcoind_guard, _wallet) = common::prepare_bitcoin_guarded()?;

    // The shipped settings take 30 attempts backing off to 20s, far past any test's patience.
    let (mut bitvmx, address, channel, _emulator) =
        common::init_bitvmx_with_config("op_1", false, true, |config| {
            let node = &mut config.broker.settings.broker_node_config;
            node.max_send_attempts = 2;
            node.retry_min_delay_msecs = 100;
            node.retry_max_delay_msecs = 200;
        })?;

    let absent_pem = rsa_public_key_pem(&settings::decrypt_or_read_file(ABSENT_PEER_KEY)?)?;
    let absent = CommsAddress::new(
        ABSENT_ADDRESS.parse()?,
        compute_pubkey_hash(&absent_pem)?,
        absent_pem,
    );
    let absent_peer = absent.pubkey_hash.clone();
    let program_id = Uuid::new_v4();

    // Participant 1 (the absent peer) leads, so this client has to send to it.
    channel.send(
        &bitvmx.get_components_config().bitvmx,
        IncomingBitVMXApiMessages::SetupKey(
            program_id,
            vec![address, absent],
            None,
            1, // leader index
        )
        .to_string()?,
    )?;

    let (msg, _identifier) =
        common::wait_message_from_channel(&channel, &mut vec![&mut bitvmx], true)?;

    match OutgoingBitVMXApiMessages::from_string(&msg)? {
        OutgoingBitVMXApiMessages::Error(report) => {
            assert_eq!(report.scope, ErrorScope::Program(program_id));
            match report.kind {
                ErrorReportKind::SetupFailed { step, peer, reason } => {
                    assert!(!step.is_empty(), "the failing step should be named");
                    assert_eq!(
                        peer.as_deref(),
                        Some(absent_peer.as_str()),
                        "the peer that could not be reached should be named",
                    );
                    assert_eq!(
                        reason,
                        SetupFailureReason::Undeliverable,
                        "an unreachable peer should be reported as undeliverable",
                    );
                }
                other => panic!("expected SetupFailed, got {other:?}"),
            }
        }
        other => panic!("expected Error, got {other:?}"),
    }

    bitvmx.shutdown()?;
    Ok(())
}
