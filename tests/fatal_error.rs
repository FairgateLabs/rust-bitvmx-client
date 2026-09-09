#![cfg(feature = "testpanic")]

use anyhow::Result;

use bitvmx_client::error_handling::{classify, Severity};
use bitvmx_client::types::{
    ErrorReportKind, ErrorScope, IncomingBitVMXApiMessages, OutgoingBitVMXApiMessages,
};
use std::time::Duration;

mod common;

/// Uses the `testpanic` seam in `handle_api_message`, which raises a real
/// `StorageError::WriteError` from inside the API path.
#[test]
#[ignore]
fn storage_failure_is_reported_to_l2_and_propagates() -> Result<()> {
    common::config_trace();
    let (_bitcoin_client, _bitcoind_guard, _wallet) = common::prepare_bitcoin_guarded()?;

    let (mut bitvmx, _address, l2, _emulator) = common::init_bitvmx("op_1", false)?;

    l2.send(
        &bitvmx.get_components_config().bitvmx,
        IncomingBitVMXApiMessages::Test("fatal".to_string()).to_string()?,
    )?;

    let mut failure = None;
    for _ in 0..200 {
        match bitvmx.tick() {
            Ok(_) => std::thread::sleep(Duration::from_millis(10)),
            Err(e) => {
                failure = Some(e);
                break;
            }
        }
    }

    let failure = failure.expect("the injected storage error should come back out of tick");
    assert_eq!(
        classify(&failure),
        Severity::Fatal,
        "a storage write failure is fatal: {failure:?}"
    );

    let mut messages = vec![];
    while let Some((message, _)) = l2.recv()? {
        messages.push(OutgoingBitVMXApiMessages::from_string(&message)?);
    }

    let reports: Vec<_> = messages
        .iter()
        .filter(|message| {
            matches!(
                message,
                OutgoingBitVMXApiMessages::Error(report)
                    if report.kind == ErrorReportKind::Fatal
            )
        })
        .collect();

    assert_eq!(
        reports.len(),
        1,
        "exactly one fatal report should reach L2: {messages:?}"
    );

    match reports[0] {
        OutgoingBitVMXApiMessages::Error(report) => {
            assert_eq!(report.scope, ErrorScope::Node);
            assert!(
                report.detail.is_some(),
                "the cause belongs in detail, since Fatal carries no payload"
            );
        }
        other => panic!("expected Error, got {other:?}"),
    }

    Ok(())
}
