#[macro_export]
macro_rules! expect_msg {
    ($bitvmx:expr, $pattern:pat => $expr:expr) => {{
        let msg = $bitvmx.wait_message(Some(std::time::Duration::from_secs(60)), None)?;

        if let $pattern = msg {
            Ok($expr)
        } else {
            Err(anyhow::anyhow!(
                "Expected `{}` but got `{:?}`",
                stringify!($pattern),
                msg
            ))
        }
    }};
}

use bitvmx_client::{client::BitVMXClient, types::OutgoingBitVMXApiMessages};
use std::{thread, time::Duration};
use tracing::info;

pub fn wait_for_message_blocking<F>(
    bitvmx: &BitVMXClient,
    matches_fn: F,
) -> Result<OutgoingBitVMXApiMessages, anyhow::Error>
where
    F: Fn(&OutgoingBitVMXApiMessages) -> bool,
{
    let mut msg = bitvmx.wait_message(Some(Duration::from_secs(60)), None)?;
    while !matches_fn(&msg) {
        info!(
            "Waiting for another message that match condition. Message received was: {:?}",
            msg
        );
        thread::sleep(Duration::from_millis(10));
        msg = bitvmx.wait_message(Some(Duration::from_secs(60)), None)?;
    }
    Ok(msg)
}

#[macro_export]
macro_rules! wait_until_msg {
    ($bitvmx:expr, $pat:pat => $extract:expr) => {{
        let msg = wait_for_message_blocking($bitvmx, |msg| matches!(msg, $pat))?;
        if let $pat = msg {
            $extract
        } else {
            return Err(anyhow::anyhow!(
                "Expected `{}` but got `{:?}`",
                stringify!($pattern),
                msg
            ));
        }
    }};
}
