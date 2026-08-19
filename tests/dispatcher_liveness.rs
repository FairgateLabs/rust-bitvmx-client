use anyhow::Result;

use bitvmx_broker::RemoteChannel;
use bitvmx_client::bitvmx::BitVMX;
use bitvmx_client::config::PingConfig;
use bitvmx_client::types::{ErrorReportKind, JobDispatcherType, OutgoingBitVMXApiMessages};
use bitvmx_job_dispatcher::DispatcherHandler;
use bitvmx_job_dispatcher_types::emulator_messages::EmulatorJobType;
use std::time::{Duration, Instant};

mod common;

// Whole seconds is all PingConfig can express, so these are the shortest legal timings.
const INTERVAL_SECS: u64 = 2;
const TIMEOUT_SECS: u64 = 1;

fn ping_config() -> PingConfig {
    PingConfig {
        enabled: true,
        interval_secs: INTERVAL_SECS,
        timeout_secs: TIMEOUT_SECS,
        services: vec![JobDispatcherType::Emulator],
    }
}

/// Ticks the client and, when present, its dispatcher, draining L2 for `duration`.
/// Both sides advance together, which the shared test loops do not guarantee.
fn pump(
    bitvmx: &mut BitVMX,
    mut dispatcher: Option<&mut DispatcherHandler<EmulatorJobType>>,
    l2: &RemoteChannel,
    duration: Duration,
) -> Result<Vec<OutgoingBitVMXApiMessages>> {
    let mut messages = vec![];
    let deadline = Instant::now() + duration;

    while Instant::now() < deadline {
        if let Some(dispatcher) = dispatcher.as_mut() {
            dispatcher.tick()?;
        }
        bitvmx.tick()?;

        while let Some((message, _)) = l2.recv()? {
            messages.push(OutgoingBitVMXApiMessages::from_string(&message)?);
        }

        std::thread::sleep(Duration::from_millis(10));
    }

    Ok(messages)
}

fn unresponsive_reports(messages: &[OutgoingBitVMXApiMessages]) -> usize {
    messages
        .iter()
        .filter(|message| {
            matches!(
                message,
                OutgoingBitVMXApiMessages::Error(report)
                    if report.kind
                        == ErrorReportKind::JobDispatcherUnresponsive(JobDispatcherType::Emulator)
            )
        })
        .count()
}

/// A dispatcher that is running and being ticked answers every ping, so nothing is
/// reported. Pings go out at 2s, 4s and 6s.
#[test]
#[ignore]
fn answered_pings_are_not_reported() -> Result<()> {
    common::config_trace();
    let (_bitcoin_client, _bitcoind_guard, _wallet) = common::prepare_bitcoin_guarded()?;

    let (mut bitvmx, _address, l2, emulator) =
        common::init_bitvmx_with_config("op_1", true, true, |config| {
            config.job_dispatcher_ping = Some(ping_config());
        })?;

    let storage_path = "/tmp/dispatcher_liveness_emulator.db";
    common::clear_db(storage_path);
    let mut dispatcher = DispatcherHandler::<EmulatorJobType>::new_with_path(
        emulator.expect("an emulator channel was requested"),
        storage_path,
        None,
        true,
    )?;

    let messages = pump(
        &mut bitvmx,
        Some(&mut dispatcher),
        &l2,
        Duration::from_secs(3 * INTERVAL_SECS + TIMEOUT_SECS),
    )?;

    assert_eq!(
        unresponsive_reports(&messages),
        0,
        "a dispatcher answering pings must not be reported: {messages:?}"
    );

    bitvmx.shutdown()?;
    Ok(())
}

/// The counterpart: with no dispatcher running, the same setup reports once. Without this
/// the test above would also pass if pings never went out at all.
///
/// Pings go out at 2s, 4s and 6s and each times out a second later. Only the first is
/// reported; the rest are held back by the latch.
#[test]
#[ignore]
fn unanswered_pings_are_reported_once() -> Result<()> {
    common::config_trace();
    let (_bitcoin_client, _bitcoind_guard, _wallet) = common::prepare_bitcoin_guarded()?;

    let (mut bitvmx, _address, l2, _emulator) =
        common::init_bitvmx_with_config("op_1", false, true, |config| {
            config.job_dispatcher_ping = Some(ping_config());
        })?;

    let messages = pump(
        &mut bitvmx,
        None,
        &l2,
        Duration::from_secs(3 * INTERVAL_SECS + TIMEOUT_SECS),
    )?;

    assert_eq!(
        unresponsive_reports(&messages),
        1,
        "a silent dispatcher is reported on the first miss only: {messages:?}"
    );

    bitvmx.shutdown()?;
    Ok(())
}
