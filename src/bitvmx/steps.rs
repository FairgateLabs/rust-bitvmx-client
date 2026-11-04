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
use uuid::Uuid;

/// How many inputs one tick takes from each queue, so a busy queue can't starve the others.
const MAX_INPUTS_PER_QUEUE: usize = 20;

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

    /// Runs a step in its own transaction, so each step commits independently. The
    /// transaction closes inside `run_step`, which is what failure settlement requires.
    pub(super) fn run_tx_step<T>(
        &mut self,
        name: &str,
        work: impl FnOnce(&mut Self) -> Result<T, BitVMXError>,
    ) -> Result<Option<T>, BitVMXError> {
        let store = self.store.clone();
        self.run_step(name, |this| Self::run_transaction(&store, || work(this)))
    }

    /// Times a step and returns whether it did work. A failed step stays pending, so it
    /// counts as work rather than idle.
    pub(super) fn timed_step(
        &mut self,
        name: &str,
        work: impl FnOnce(&mut Self) -> Result<bool, BitVMXError>,
    ) -> Result<bool, BitVMXError> {
        Ok(Self::measure_time(name, || self.run_step(name, work))?.unwrap_or(true))
    }

    /// `timed_step` with the work in its own transaction.
    pub(super) fn timed_tx_step(
        &mut self,
        name: &str,
        work: impl FnOnce(&mut Self) -> Result<bool, BitVMXError>,
    ) -> Result<bool, BitVMXError> {
        Ok(Self::measure_time(name, || self.run_tx_step(name, work))?.unwrap_or(true))
    }

    /// Calls `process_one` until it reports no more input, up to `MAX_INPUTS_PER_QUEUE` times,
    /// committing each input independently. Returns whether any input was processed.
    /// Must be called without an active global transaction.
    pub(super) fn process_inputs(
        &mut self,
        process_one: fn(&mut Self) -> Result<bool, BitVMXError>,
    ) -> Result<bool, BitVMXError> {
        let store = self.store.clone();
        let mut had_work = false;
        for _ in 0..MAX_INPUTS_PER_QUEUE {
            if !Self::run_transaction(&store, || process_one(self))? {
                break;
            }
            had_work = true;
        }
        Ok(had_work)
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
                    self.fail_runtime_job(program_id, expected_job_id, job_id, reason)
                })?;
                Ok(None)
            }
            other => other.map(Some),
        }
    }

    fn fail_runtime_job(
        &mut self,
        program_id: Uuid,
        expected_job_id: String,
        job_id: String,
        reason: String,
    ) -> Result<(), BitVMXError> {
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
