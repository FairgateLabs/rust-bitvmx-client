use anyhow::Result;

use bitvmx_client::types::{IncomingBitVMXApiMessages, OutgoingBitVMXApiMessages};
use uuid::Uuid;

mod common;

#[test]
#[ignore]
fn shutdown_without_errors() -> Result<()> {
    common::config_trace();

    let (mut bitvmx, _addr, channel, _emulator) = common::init_bitvmx("op_1", false)?;

    // Simple Ping -> Pong
    channel.send(
        &bitvmx.get_components_config().bitvmx,
        IncomingBitVMXApiMessages::Ping(Uuid::new_v4()).to_string()?,
    )?;
    let msg = common::wait_message_from_channel(&channel, &mut vec![&mut bitvmx], true)?;
    let out = OutgoingBitVMXApiMessages::from_string(&msg.0)?;
    match out {
        OutgoingBitVMXApiMessages::Pong(_) => {}
        _ => panic!("expected Pong"),
    }

    let result = bitvmx.tick()?;
    assert!(result, "expected continue from tick");

    // Now shutdown cleanly
    bitvmx.shutdown()?;
    let result = bitvmx.tick()?; // should indicate stop
    assert!(!result, "expected stop from tick after shutdown");

    Ok(())
}
