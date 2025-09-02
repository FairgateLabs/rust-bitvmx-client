use anyhow::Result;
use uuid::Uuid;

use bitvmx_client::types::{IncomingBitVMXApiMessages, OutgoingBitVMXApiMessages, BITVMX_ID};
use bitvmx_client::config::Config;
use bitvmx_client::program::variables::VariableTypes;

mod common;

#[test]
fn nonfatal_error_keeps_looping() -> Result<()> {
    common::config_trace();

    let (mut bitvmx, _addr, channel, _emulator) = common::init_bitvmx("op_1", false)?;
 
    // 1) Simple Ping -> Pong
    channel.send(BITVMX_ID, IncomingBitVMXApiMessages::Ping().to_string()?)?;
    let msg = common::wait_message_from_channel(&channel, &mut vec![&mut bitvmx], true)?;
    let out = OutgoingBitVMXApiMessages::from_string(&msg.0)?;
    match out { OutgoingBitVMXApiMessages::Pong() => {}, _ => panic!("expected Pong"), }

    // 2) Send an invalid message (non-fatal: serde error) and ensure loop continues
    channel.send(BITVMX_ID, "this is not json".to_string())?;
    let err = bitvmx
        .process_api_messages()
        .expect_err("expected non-fatal error from invalid json");
    assert!(!err.is_fatal(), "serde/non-fatal error should not be fatal");

    // 3) Verify we can still Ping -> Pong
    channel.send(BITVMX_ID, IncomingBitVMXApiMessages::Ping().to_string()?)?;
    let msg = common::wait_message_from_channel(&channel, &mut vec![&mut bitvmx], true)?;
    let out = OutgoingBitVMXApiMessages::from_string(&msg.0)?;
    match out { OutgoingBitVMXApiMessages::Pong() => {}, _ => panic!("expected Pong after non-fatal"), }

    Ok(())
}

#[test]
fn fatal_error_triggers_shutdown() -> Result<()> {
    common::config_trace();

    let (mut bitvmx, _addr, channel, _emulator) = common::init_bitvmx("op_1", false)?;

    // Trigger a deterministic fatal error via test-only path
    channel.send(BITVMX_ID, IncomingBitVMXApiMessages::Test("fatal".into()).to_string()?)?;
    let err = bitvmx
        .process_api_messages()
        .expect_err("expected fatal error via test path");
    assert!(err.is_fatal(), "Test-induced fatal should be fatal");

    // Coordinated shutdown
    bitvmx.shutdown(std::time::Duration::from_millis(200))?;

    Ok(())
}

#[test]
fn panic_triggers_shutdown() -> Result<()> {
    common::config_trace();

    let (mut bitvmx, _addr, channel, _emulator) = common::init_bitvmx("op_1", false)?;

    // Trigger a test-only panic via API message
    channel.send(BITVMX_ID, IncomingBitVMXApiMessages::Test("panic".into()).to_string()?)?;

    // The call should panic inside processing; catch it here
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = bitvmx.process_api_messages();
    }))
    .is_err();
    assert!(panicked, "expected panic from TestPanic message");

    // After panic we can still call shutdown without panicking
    bitvmx.shutdown(std::time::Duration::from_millis(100))?;

    Ok(())
}
