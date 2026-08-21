use anyhow::Result;

use bitvmx_client::types::{ErrorReportKind, OutgoingBitVMXApiMessages};
use std::time::Duration;

mod common;

fn count_kind(messages: &[OutgoingBitVMXApiMessages], kind: &ErrorReportKind) -> usize {
    messages
        .iter()
        .filter(|message| {
            matches!(message, OutgoingBitVMXApiMessages::Error(report) if &report.kind == kind)
        })
        .count()
}

/// An unreachable bitcoin node is reported once and the client keeps running.
#[test]
#[ignore]
fn bitcoin_outage_is_reported_once_and_the_node_keeps_ticking() -> Result<()> {
    common::config_trace();
    // Not the RAII guard: the handle is needed to bring the node back up. A leaked
    // container is force-removed by the next run's start().
    let (_bitcoin_client, bitcoind, _wallet) = common::prepare_bitcoin()?;
    let bitcoind = bitcoind.expect("regtest bitcoind");

    let (mut bitvmx, _address, l2, _emulator) = common::init_bitvmx("op_1", false)?;

    for _ in 0..20 {
        assert!(bitvmx.tick()?, "the client should be healthy to start with");
    }

    bitcoind.stop()?;

    for _ in 0..200 {
        assert!(
            bitvmx.tick()?,
            "an unreachable node must not stop the client"
        );
        std::thread::sleep(Duration::from_millis(10));
    }

    let mut messages = vec![];
    while let Some((message, _)) = l2.recv()? {
        messages.push(OutgoingBitVMXApiMessages::from_string(&message)?);
    }

    assert_eq!(
        count_kind(&messages, &ErrorReportKind::BitcoinRpcUnavailable),
        1,
        "the outage is reported on change only: {messages:?}"
    );

    bitcoind.start()?;

    for _ in 0..200 {
        let _ = bitvmx.tick();
        std::thread::sleep(Duration::from_millis(10));
    }

    let mut messages = vec![];
    while let Some((message, _)) = l2.recv()? {
        messages.push(OutgoingBitVMXApiMessages::from_string(&message)?);
    }

    bitcoind.stop()?;

    assert_eq!(
        count_kind(&messages, &ErrorReportKind::BitcoinRpcRecovered),
        1,
        "recovery is reported on change only: {messages:?}"
    );

    Ok(())
}
