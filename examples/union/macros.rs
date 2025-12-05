const TIMEOUT_SECS: std::time::Duration = std::time::Duration::from_secs(120);

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
    let mut msg = bitvmx.wait_message(Some(TIMEOUT_SECS), None)?;
    while !matches_fn(&msg) {
        info!(
            "Waiting for another message that match condition. Received: {:?}",
            msg.name()
        );
        thread::sleep(Duration::from_millis(200));
        msg = bitvmx.wait_message(Some(TIMEOUT_SECS), None)?;
    }
    Ok(msg)
}

#[macro_export]
macro_rules! wait_until_msg {
    ($bitvmx:expr, $pat:pat => $extract:expr) => {{
        let msg = $crate::macros::wait_for_message_blocking($bitvmx, |msg| matches!(msg, $pat))?;
        if let $pat = msg {
            $extract
        } else {
            return Err(anyhow::anyhow!("Expected `{}`", stringify!($pattern)));
        }
    }};
}
