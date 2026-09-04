//! Classification of errors, and delivery of push-style error reports.

use std::error::Error;

use bitcoin_coordinator::config::settings::{CPFP_TRANSACTION_CONTEXT, RBF_TRANSACTION_CONTEXT};
use bitcoincore_rpc::{jsonrpc, Error as BitcoinRpcError};
use bitvmx_broker::{
    identification::{errors::IdentificationError, identifier::Identifier},
    retry::RetryPolicyError,
    BrokerError, BrokerNode,
};
use storage_backend::error::StorageError;
use tracing::{error, info, warn};

use crate::{
    bitvmx::Context,
    errors::BitVMXError,
    types::{ErrorReport, ErrorReportKind, ErrorScope, OutgoingBitVMXApiMessages},
};

#[derive(Debug, PartialEq)]
pub enum Severity {
    BitcoinNodeUnreachable,
    Fatal,
    Other,
}

pub(crate) struct Reporter {
    fatal_reported: bool,
    rpc_unavailable: bool,
    l2_identifier: Identifier,
}

impl Reporter {
    pub(crate) fn new(l2_identifier: Identifier) -> Self {
        Self {
            fatal_reported: false,
            rpc_unavailable: false,
            l2_identifier,
        }
    }

    pub(crate) fn fatal(&mut self, error: &BitVMXError, broker_node: &BrokerNode) {
        if self.fatal_reported {
            return;
        }
        self.fatal_reported = true;

        error!("Fatal error, stopping the node: {:?}", error);
        send_error_report(
            broker_node,
            &self.l2_identifier,
            ErrorReport::new(
                ErrorScope::Node,
                ErrorReportKind::Fatal,
                Some(error.to_string()),
            ),
        );
    }

    pub(crate) fn rpc_unavailable(&mut self, error: &BitVMXError, broker_node: &BrokerNode) {
        if self.rpc_unavailable {
            return;
        }
        self.rpc_unavailable = true;

        error!("Bitcoin node is unreachable: {:?}", error);
        send_error_report(
            broker_node,
            &self.l2_identifier,
            ErrorReport::new(
                ErrorScope::Node,
                ErrorReportKind::BitcoinRpcUnavailable,
                Some(error.to_string()),
            ),
        );
    }

    pub(crate) fn rpc_recovered(&mut self, broker_node: &BrokerNode) {
        if !self.rpc_unavailable {
            return;
        }
        self.rpc_unavailable = false;

        info!("Bitcoin node is reachable again");
        send_error_report(
            broker_node,
            &self.l2_identifier,
            ErrorReport::node(ErrorReportKind::BitcoinRpcRecovered),
        );
    }

    pub(crate) fn coordinator_news(
        &self,
        context: Option<&str>,
        kind: ErrorReportKind,
        broker_node: &BrokerNode,
    ) {
        let (scope, dest) = context.map_or((ErrorScope::Node, None), resolve_scope);

        send_error_report(
            broker_node,
            dest.as_ref().unwrap_or(&self.l2_identifier),
            ErrorReport::new(scope, kind, None),
        );
    }

    /// Reports that the node is stopping on a non-fatal error
    pub(crate) fn stopping(&self, error: &BitVMXError, broker_node: &BrokerNode) {
        send_error_report(
            broker_node,
            &self.l2_identifier,
            ErrorReport::new(
                ErrorScope::Node,
                ErrorReportKind::NodeStopping,
                Some(error.to_string()),
            ),
        );
    }
}

/// Walks the error's source chain. Takes `dyn Error` so an error borrowed from a
/// dependency can be classified without a conversion that would consume it.
pub fn classify(error: &(dyn Error + 'static)) -> Severity {
    let mut next = Some(error);

    while let Some(error) = next {
        if let Some(error) = error.downcast_ref::<StorageError>() {
            if matches!(
                error,
                StorageError::WriteError | StorageError::ReadError | StorageError::CommitError
            ) {
                return Severity::Fatal;
            }
        }

        if let Some(error) = error.downcast_ref::<BitcoinRpcError>() {
            if matches!(
                error,
                BitcoinRpcError::JsonRpc(jsonrpc::Error::Transport(_))
            ) {
                return Severity::BitcoinNodeUnreachable;
            }
        }

        if let Some(error) = error.downcast_ref::<BrokerError>() {
            if error.is_fatal() {
                return Severity::Fatal;
            }
        }

        // Both are broker types that BitVMXError wraps directly, so they reach here without
        // passing through BrokerError and have to be asked for their severity separately.
        if let Some(error) = error.downcast_ref::<IdentificationError>() {
            if error.severity().is_fatal() {
                return Severity::Fatal;
            }
        }

        if let Some(error) = error.downcast_ref::<RetryPolicyError>() {
            if error.severity().is_fatal() {
                return Severity::Fatal;
            }
        }

        if let Some(BitVMXError::PoisonedLockError(_)) = error.downcast_ref::<BitVMXError>() {
            return Severity::Fatal;
        }

        next = error.source();
    }

    Severity::Other
}

/// Most callers only need to know whether an error is survivable at their layer.
pub fn is_fatal(error: &(dyn Error + 'static)) -> bool {
    classify(error) == Severity::Fatal
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
    use bitcoin_coordinator::errors::BitcoinCoordinatorError;
    use bitvmx_bitcoin_rpc::errors::BitcoinClientError;
    use bitvmx_broker::storage::BrokerStorageError;
    use bitvmx_wallet::wallet::errors::WalletError;
    use uuid::Uuid;

    #[test]
    fn a_failed_broker_write_is_fatal() {
        let error =
            BrokerError::BrokerStorageError(BrokerStorageError::Backend(StorageError::WriteError));

        // A tripwire: once the broker discriminates the inner variant, drop the override.
        assert!(
            !error.is_fatal(),
            "the broker is expected to still report this as non-fatal"
        );
        assert_eq!(classify(&error), Severity::Fatal);
    }

    // Conditions the broker calls fatal that our own source-chain walk does not reach.
    #[test]
    fn a_broker_fatal_condition_is_fatal() {
        assert_eq!(
            classify(&BrokerError::MutexError("storage".to_string())),
            Severity::Fatal
        );
        assert_eq!(
            classify(&BrokerError::WrongNodeMode("peers".to_string())),
            Severity::Fatal
        );
    }

    // Wrapped in BrokerError these are already covered; BitVMXError also wraps them directly,
    // and the answer has to be the same either way.
    #[test]
    fn a_broker_type_reached_directly_is_still_fatal() {
        assert_eq!(
            classify(&IdentificationError::InvalidIdentifier("cafe".to_string())),
            Severity::Fatal
        );
        assert_eq!(
            classify(&RetryPolicyError::InvalidMaxAttempts(1)),
            Severity::Fatal
        );
    }

    // The same two errors arriving through the wrapper, to keep the paths in step.
    #[test]
    fn a_broker_type_reached_through_the_wrapper_agrees() {
        assert_eq!(
            classify(&BrokerError::IdentificationError(
                IdentificationError::InvalidIdentifier("cafe".to_string())
            )),
            Severity::Fatal
        );
        assert_eq!(
            classify(&BrokerError::RetryPolicyError(
                RetryPolicyError::InvalidMaxAttempts(1)
            )),
            Severity::Fatal
        );
    }

    // A panic while the allow list was held leaves it half-applied, and the allow list decides
    // who may talk to this node. The second assert keeps the arm a test for one variant rather
    // than a verdict on every BitVMXError.
    #[test]
    fn a_poisoned_lock_is_fatal() {
        assert_eq!(
            classify(&BitVMXError::PoisonedLockError("allow list".to_string())),
            Severity::Fatal
        );
        assert_eq!(
            classify(&BitVMXError::NotImplemented("something else".to_string())),
            Severity::Other
        );
    }

    // One refused message must not take the node down, or a single oversized ping would.
    #[test]
    fn an_ordinary_broker_failure_is_not_fatal() {
        assert_eq!(
            classify(&BrokerError::MessageTooLarge(10, 5)),
            Severity::Other
        );
    }

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
