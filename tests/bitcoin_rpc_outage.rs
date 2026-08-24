use anyhow::Result;

use bitvmx_broker::RemoteChannel;
use bitvmx_client::types::{ErrorReportKind, OutgoingBitVMXApiMessages};
use std::time::Duration;

mod common;

fn drain(l2: &RemoteChannel) -> Result<Vec<OutgoingBitVMXApiMessages>> {
    let mut messages = vec![];
    while let Some((message, _)) = l2.recv()? {
        messages.push(OutgoingBitVMXApiMessages::from_string(&message)?);
    }
    Ok(messages)
}

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
    // Not the RAII guard: the handle is needed to bring the node back up.
    let (_bitcoin_client, bitcoind, _wallet) = common::prepare_bitcoin()?;
    let bitcoind = bitcoind.expect("regtest bitcoind");

    let (mut bitvmx, _address, l2, _emulator) = common::init_bitvmx("op_1", false)?;

    let mut healthy = true;
    for _ in 0..20 {
        healthy &= bitvmx.tick()?;
    }

    bitcoind.stop()?;

    let mut alive_during_outage = true;
    for _ in 0..200 {
        alive_during_outage &= bitvmx.tick()?;
        std::thread::sleep(Duration::from_millis(10));
    }
    let unavailable = count_kind(&drain(&l2)?, &ErrorReportKind::BitcoinRpcUnavailable);

    bitcoind.start()?;

    for _ in 0..200 {
        let _ = bitvmx.tick();
        std::thread::sleep(Duration::from_millis(10));
    }
    let recovered = count_kind(&drain(&l2)?, &ErrorReportKind::BitcoinRpcRecovered);

    // Torn down before asserting, so a failure leaves the same state a pass would.
    bitcoind.stop()?;
    bitvmx.shutdown()?;

    assert!(healthy, "the client should be healthy to start with");
    assert!(
        alive_during_outage,
        "an unreachable node must not stop the client"
    );
    assert_eq!(unavailable, 1, "the outage is reported on change only");
    assert_eq!(recovered, 1, "recovery is reported on change only");

    Ok(())
}
