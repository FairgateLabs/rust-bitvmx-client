//! Delivery of push-style error reports.

use bitvmx_broker::{identification::identifier::Identifier, BrokerNode};
use tracing::error;

use crate::types::{ErrorReport, OutgoingBitVMXApiMessages};

/// Sends a push-style [`ErrorReport`] to `dest`. Logs and drops on failure: a report that
/// cannot be delivered must not take down the path that was only reporting a condition.
pub fn send_error_report(channel: &BrokerNode, dest: &Identifier, report: ErrorReport) {
    let message = match OutgoingBitVMXApiMessages::Error(report).to_string() {
        Ok(message) => message,
        Err(e) => {
            error!("Could not serialize error report: {:?}", e);
            return;
        }
    };

    if let Err(e) = channel.send_service(dest, message) {
        error!("Could not send error report to {:?}: {:?}", dest, e);
    }
}
