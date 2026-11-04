//! Step and transaction runners shared by every tick phase.

use super::BitVMX;
use crate::{
    error_handling::{classify, Reporter, Severity},
    errors::BitVMXError,
    expected_job::ExpectedJobTarget,
    ports::bitcoin_coordinator::BitcoinCoordinatorApi,
    types::{DispatcherJobFailure, ResultDisposition, SetupFailureReason},
};
use bitvmx_broker::BrokerNode;
use std::time::{Duration, Instant};
use storage_backend::storage::Storage;
use tracing::{error, warn};

impl<BC: BitcoinCoordinatorApi> BitVMX<BC> {
    /// Accepts pure decoding results before handler state changes. Invalid inputs return
    /// `None`, allowing the receive transaction to commit and consume the malformed event.
    /// Do not pass results from effectful handlers: their errors require rollback.
    pub(super) fn discard_if_malformed<T, E: std::fmt::Display>(
        decoded: Result<T, E>,
    ) -> Option<T> {
        match decoded {
            Ok(value) => Some(value),
            Err(error) => {
                warn!("Rejected malformed input: {}", error);
                None
            }
        }
    }

    /// Reports nonfatal step failures without preventing independent work from running.
    /// The work owns its transactions and must close them before returning.
    pub(super) fn run_step<T>(
        &mut self,
        name: &str,
        work: impl FnOnce(&mut Self) -> Result<T, BitVMXError>,
    ) -> Result<Option<T>, BitVMXError> {
        let result = work(self);
        let result = self.settle_failed_attempt(result);
        Self::finish_step(
            name,
            result,
            &mut self.reporter,
            &self.program_context.broker_channel,
        )
        .map(Option::flatten)
    }

    /// Requires the attempt transaction to be closed. This records failure policy in a
    /// fresh transaction only after all effects staged by the failed attempt were rolled
    /// back. Restored dispatcher inputs are consumed as duplicates on redelivery.
    fn settle_failed_attempt<T>(
        &mut self,
        result: Result<T, BitVMXError>,
    ) -> Result<Option<T>, BitVMXError> {
        match result {
            Err(BitVMXError::SetupAttemptFailed {
                program_id,
                peer,
                source,
            }) => {
                let store = self.store.clone();
                Self::run_transaction(&store, || {
                    self.fail_program_setup(
                        &program_id,
                        peer,
                        SetupFailureReason::StepError(source.to_string()),
                    )
                })?;
                Ok(None)
            }
            Err(BitVMXError::RuntimeJobAttemptFailed {
                program_id,
                expected_job_id,
                job_id,
                reason,
            }) => {
                let store = self.store.clone();
                Self::run_transaction(&store, || {
                    let expected = self
                        .program_context
                        .expected_jobs
                        .get(&expected_job_id)?
                        .ok_or_else(|| {
                            BitVMXError::InvalidState(format!(
                                "dispatcher job '{expected_job_id}' is not registered"
                            ))
                        })?;
                    if expected.target != ExpectedJobTarget::Program(program_id) {
                        return Err(BitVMXError::InvalidState(format!(
                            "dispatcher job '{expected_job_id}' has incompatible runtime ownership"
                        )));
                    }
                    self.apply_dispatcher_result_disposition(
                        expected.dispatcher,
                        ResultDisposition::fail_dispatcher(DispatcherJobFailure {
                            program_id,
                            expected_job_id,
                            job_id,
                            reason,
                        }),
                    )
                })?;
                Ok(None)
            }
            other => other.map(Some),
        }
    }

    pub(super) fn finish_step<T>(
        name: &str,
        result: Result<T, BitVMXError>,
        reporter: &mut Reporter,
        broker_channel: &BrokerNode,
    ) -> Result<Option<T>, BitVMXError> {
        match result {
            Ok(value) => Ok(Some(value)),
            Err(error) => {
                match classify(&error) {
                    // Let tick report fatal errors once and stop processing.
                    Severity::Fatal => return Err(error),
                    Severity::BitcoinNodeUnreachable => {
                        reporter.rpc_unavailable(&error, broker_channel);
                    }
                    Severity::Other => reporter.non_fatal(&error, broker_channel),
                }
                error!("Error in {name}: {error:#?}");
                Ok(None)
            }
        }
    }

    /// Commits the work on success and rolls it back on error.
    /// Requires no active global transaction. Rollback covers database writes only,
    /// not live memory or external effects.
    pub(super) fn run_transaction<T>(
        store: &Storage,
        work: impl FnOnce() -> Result<T, BitVMXError>,
    ) -> Result<T, BitVMXError> {
        store.begin_global_transaction()?;
        match work() {
            Ok(value) => {
                // Storage consumes the transaction even when commit fails.
                store.commit_global_transaction()?;
                Ok(value)
            }
            Err(error) => {
                if let Err(rollback) = store.rollback_global_transaction() {
                    error!(
                        "Could not roll back transaction step after {:?}: {:?}",
                        error, rollback
                    );
                    return Err(rollback.into());
                }
                Err(error)
            }
        }
    }

    pub(super) fn measure_time<T>(operation: &str, work: impl FnOnce() -> T) -> T {
        const WARN_THRESHOLD: Duration = Duration::from_secs(10);

        let instant = Instant::now();
        let result = work();
        let duration = instant.elapsed();
        if duration > WARN_THRESHOLD {
            warn!(
                "Processing {operation} took {:?} which is above the threshold",
                duration
            );
        }
        result
    }
}
