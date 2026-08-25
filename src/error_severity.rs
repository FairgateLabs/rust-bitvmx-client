//! Severity of an error, and delivery of push-style error reports.

use std::error::Error;

use bitcoin_coordinator::config::settings::{CPFP_TRANSACTION_CONTEXT, RBF_TRANSACTION_CONTEXT};
use bitcoincore_rpc::{jsonrpc, Error as BitcoinRpcError};
use bitvmx_broker::{identification::identifier::Identifier, BrokerNode};
use storage_backend::error::StorageError;
use tracing::{error, warn};

use crate::{
    bitvmx::Context,
    types::{ErrorReport, ErrorScope, OutgoingBitVMXApiMessages},
};

#[derive(Debug, PartialEq)]
pub enum Severity {
    BitcoinNodeUnreachable,
    Fatal,
    Other,
}

/// Walks the error's source chain. Takes `dyn Error`so an error
/// borrowed from a dependency can be classified without a conversion that would consume it.
pub fn classify(error: &(dyn Error + 'static)) -> Severity {
    let mut next = Some(error);

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

/// Resolves the `context` a coordinator news item carries into who the report concerns
/// and, for API requests, who to answer. `None` destination means send to L2.
pub(crate) fn resolve_scope(context: &str) -> (ErrorScope, Option<Identifier>) {
    if let Ok(context) = Context::from_string(context) {
        return match context {
            // Carries the `Identifier` so the failure reaches whoever asked, not L2.
            Context::RequestId(id, from) => (ErrorScope::Request(id), Some(from)),
            Context::ProgramId(id)
            | Context::Protocol(id, _)
            | Context::SetupStep(id, _, _, _)
            | Context::ProgramStep(id, _) => (ErrorScope::Program(id), None),
        };
    }

    // The speedup layer writes a fixed marker instead of a context, since it does not know
    // which program it funds. Anything else unreadable is our own bug.
    if !context.contains(CPFP_TRANSACTION_CONTEXT) && !context.contains(RBF_TRANSACTION_CONTEXT) {
        warn!(
            "Coordinator news carried an unreadable context: {}",
            context
        );
    }

    (ErrorScope::Node, None)
}

/// Sends a push-style [`ErrorReport`] to `dest`. Logs and drops on failure: a report that
/// cannot be delivered must not take down the path that was only reporting a condition.
pub(crate) fn send_error_report(channel: &BrokerNode, dest: &Identifier, report: ErrorReport) {
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
    use crate::errors::BitVMXError;
    use bitcoin_coordinator::errors::BitcoinCoordinatorError;
    use bitvmx_bitcoin_rpc::errors::BitcoinClientError;
    use bitvmx_wallet::wallet::errors::WalletError;
    use uuid::Uuid;

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

    #[test]
    fn a_program_context_resolves_to_that_program() {
        let id = Uuid::new_v4();
        let context = Context::ProgramId(id).to_string().unwrap();

        assert_eq!(resolve_scope(&context), (ErrorScope::Program(id), None));
    }

    // Dropping the Identifier would send the failure to L2 and leave the requester hanging.
    #[test]
    fn a_request_context_keeps_the_requester() {
        let id = Uuid::new_v4();
        let requester = Identifier::new("cafe".to_string(), 7);
        let context = Context::RequestId(id, requester.clone())
            .to_string()
            .unwrap();

        assert_eq!(
            resolve_scope(&context),
            (ErrorScope::Request(id), Some(requester))
        );
    }

    // Both fall back to node scope. Only the last warns, which this crate cannot assert on.
    #[test]
    fn an_unreadable_context_falls_back_to_node() {
        let node = (ErrorScope::Node, None);
        assert_eq!(resolve_scope(CPFP_TRANSACTION_CONTEXT), node);
        assert_eq!(resolve_scope(RBF_TRANSACTION_CONTEXT), node);
        assert_eq!(resolve_scope("not a context"), node);
    }
}
