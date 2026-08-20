//! Severity of an error, and delivery of push-style error reports.

use std::error::Error;

use bitcoincore_rpc::{jsonrpc, Error as BitcoinRpcError};
use bitvmx_broker::{identification::identifier::Identifier, BrokerNode};
use storage_backend::error::StorageError;
use tracing::error;

use crate::{
    errors::BitVMXError,
    types::{ErrorReport, OutgoingBitVMXApiMessages},
};

#[derive(Debug, PartialEq)]
pub enum Severity {
    BitcoinNodeUnreachable,
    Fatal,
    Other,
}

pub fn classify(error: &BitVMXError) -> Severity {
    let mut next: Option<&(dyn Error + 'static)> = Some(error);

    while let Some(error) = next {
        if let Some(error) = error.downcast_ref::<StorageError>() {
            return match error {
                StorageError::WriteError | StorageError::ReadError | StorageError::CommitError => {
                    Severity::Fatal
                }
                _ => Severity::Other,
            };
        }

        if let Some(error) = error.downcast_ref::<BitcoinRpcError>() {
            // Anything else means the node answered and refused, which is not an outage.
            return match error {
                BitcoinRpcError::JsonRpc(jsonrpc::Error::Transport(_)) => {
                    Severity::BitcoinNodeUnreachable
                }
                _ => Severity::Other,
            };
        }

        next = error.source();
    }

    Severity::Other
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin_coordinator::errors::BitcoinCoordinatorError;
    use bitvmx_bitcoin_rpc::errors::BitcoinClientError;
    use bitvmx_wallet::wallet::errors::WalletError;

    fn unreachable_node() -> BitcoinRpcError {
        BitcoinRpcError::JsonRpc(jsonrpc::Error::Transport(Box::new(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "connection refused",
        ))))
    }

    #[test]
    fn storage_write_failure_is_fatal() {
        let error = BitVMXError::StorageError(StorageError::WriteError);
        assert_eq!(classify(&error), Severity::Fatal);
    }

    #[test]
    fn storage_conversion_failure_is_not_fatal() {
        let error = BitVMXError::StorageError(StorageError::ConversionError);
        assert_eq!(classify(&error), Severity::Other);
    }

    #[test]
    fn wallet_storage_failure_is_fatal() {
        let error = BitVMXError::WalletError(WalletError::StoreError(StorageError::ReadError));
        assert_eq!(classify(&error), Severity::Fatal);
    }

    #[test]
    fn nested_conversion_failure_is_not_fatal() {
        let error = BitVMXError::BitcoinCoordinatorError(
            BitcoinCoordinatorError::StorageBackendError(StorageError::ConversionError),
        );
        assert_eq!(classify(&error), Severity::Other);
    }

    #[test]
    fn rpc_transport_failure_is_an_outage() {
        let error =
            BitVMXError::BitcoinCoordinatorError(BitcoinCoordinatorError::BitcoinClientError(
                BitcoinClientError::RpcError(unreachable_node()),
            ));
        assert_eq!(classify(&error), Severity::BitcoinNodeUnreachable);
    }

    #[test]
    fn rpc_rejection_is_not_an_outage() {
        let error = BitVMXError::BitcoinCoordinatorError(
            BitcoinCoordinatorError::BitcoinClientError(BitcoinClientError::RpcError(
                BitcoinRpcError::JsonRpc(jsonrpc::Error::Rpc(jsonrpc::error::RpcError {
                    code: -8,
                    message: "rejected".to_string(),
                    data: None,
                })),
            )),
        );
        assert_eq!(classify(&error), Severity::Other);
    }
}
