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
        let key_store = self.key_store.clone();
        self.run_step(name, |this| {
            Self::run_state_transaction(&store, &key_store, || work(this))
        })
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
        let key_store = self.key_store.clone();
        let mut had_work = false;
        for _ in 0..MAX_INPUTS_PER_QUEUE {
            if !Self::run_state_transaction(&store, &key_store, || process_one(self))? {
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
                let key_store = self.key_store.clone();
                Self::run_state_transaction(&store, &key_store, || {
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
                let key_store = self.key_store.clone();
                Self::run_state_transaction(&store, &key_store, || {
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
            .get_registered(&expected_job_id)?;
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

    /// Runs one client event with both main state and key state staged, committing on success and
    /// rolling back on error. Requires no active global transaction on either store. Rollback covers
    /// database writes only, not live memory or external effects.
    ///
    /// Key storage commits first: if the main commit is interrupted, replay-safe key-manager
    /// operations accept the already committed values instead of advancing main state without its
    /// required keys.
    pub(super) fn run_state_transaction<T>(
        store: &Storage,
        key_store: &Storage,
        work: impl FnOnce() -> Result<T, BitVMXError>,
    ) -> Result<T, BitVMXError> {
        Self::run_state_transaction_committing_if(store, key_store, || {
            work().map(|value| (value, true))
        })
    }

    /// Like `run_state_transaction`, but the work also decides whether its writes are kept: they are
    /// committed when it returns `(value, true)` and rolled back when it returns `(value, false)`.
    /// Errors always roll back.
    pub(super) fn run_state_transaction_committing_if<T>(
        store: &Storage,
        key_store: &Storage,
        work: impl FnOnce() -> Result<(T, bool), BitVMXError>,
    ) -> Result<T, BitVMXError> {
        store.begin_global_transaction()?;
        if let Err(error) = key_store.begin_global_transaction() {
            error!("Could not begin key transaction: {:?}", error);
            Self::rollback_store("state", store, &error)?;
            return Err(error.into());
        }

        match work() {
            Ok((value, true)) => {
                // The databases cannot commit atomically together. Commit keys first so a crash
                // leaves replayable key effects, never main state referring to absent key data.
                // Storage consumes the transaction even when commit fails.
                if let Err(error) = key_store.commit_global_transaction() {
                    error!("Could not commit key transaction: {:?}", error);
                    Self::rollback_store("state", store, &error)?;
                    return Err(error.into());
                }
                store.commit_global_transaction()?;
                Ok(value)
            }
            Ok((value, false)) => {
                Self::rollback_both(store, key_store, &"discarded work")?;
                Ok(value)
            }
            Err(error) => {
                Self::rollback_both(store, key_store, &error)?;
                Err(error)
            }
        }
    }

    /// Rolls back both stores, attempting each even if the other fails, so neither is left with
    /// an active global transaction. Returns the first rollback failure.
    fn rollback_both(
        store: &Storage,
        key_store: &Storage,
        cause: &dyn std::fmt::Debug,
    ) -> Result<(), BitVMXError> {
        let key_rollback = Self::rollback_store("key", key_store, cause);
        let state_rollback = Self::rollback_store("state", store, cause);
        key_rollback.and(state_rollback)
    }

    fn rollback_store(
        name: &str,
        store: &Storage,
        cause: &dyn std::fmt::Debug,
    ) -> Result<(), BitVMXError> {
        store.rollback_global_transaction().map_err(|rollback| {
            error!(
                "Could not roll back {name} transaction after {:?}: {:?}",
                cause, rollback
            );
            rollback.into()
        })
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bitvmx::{test_support::create_single_participant_program, Context},
        comms_helper::deserialize_msg,
        expected_job::ExpectedJobStatus,
        program::program::Program,
        test_utils::{TestBitVMXEnv, TestStorageDir},
        types::IncomingBitVMXApiMessages,
    };
    use bitcoin_coordinator::coordinator::BitcoinCoordinator;
    use key_manager::key_type::BitcoinKeyType;
    use std::collections::HashMap;
    use storage_backend::{error::StorageError, key::StorageKey};

    type BitVMX = super::BitVMX<BitcoinCoordinator>;

    macro_rules! test_key {
        ($name:expr) => {
            StorageKey::new(["bitvmx", "test", $name]).unwrap()
        };
    }

    #[test]
    fn runtime_dispatcher_failure_rolls_back_attempt_before_scheduling_retry() {
        let mut env = TestBitVMXEnv::new("runtime-dispatcher-rollback-settlement").unwrap();
        let program_id = Uuid::new_v4();
        let store = create_single_participant_program(&mut env, program_id);
        let key_store = env.bitvmx.key_store.clone();
        let context = Context::ProgramStep(program_id, "execute-round-1".to_string());
        let expected_job_id = context.to_string().unwrap();
        env.bitvmx
            .program_context
            .expected_jobs
            .register(
                expected_job_id.clone(),
                crate::types::JobDispatcherType::Emulator,
            )
            .unwrap();
        let staged_key = test_key!("runtime-dispatcher-staged-effect");

        let outcome = env
            .bitvmx
            .run_step(
                "runtime dispatcher result",
                |_this| -> Result<(), BitVMXError> {
                    BitVMX::run_state_transaction(&store, &key_store, || {
                        store.set(&staged_key, "must roll back".to_string(), None)?;
                        Err(BitVMXError::RuntimeJobAttemptFailed {
                            program_id,
                            expected_job_id: expected_job_id.clone(),
                            job_id: "execute-round-1".to_string(),
                            reason: "invalid emulator output".to_string(),
                        })
                    })
                },
            )
            .unwrap();

        assert!(outcome.is_none());
        assert_eq!(store.get::<String>(&staged_key, None).unwrap(), None);
        assert!(matches!(
            env.bitvmx
                .program_context
                .expected_jobs
                .get(&expected_job_id)
                .unwrap()
                .unwrap()
                .status,
            ExpectedJobStatus::RetryPending(ref reason) if reason == "invalid emulator output"
        ));
        assert!(!Program::load(store, &program_id)
            .unwrap()
            .unwrap()
            .is_failed());
    }

    #[test]
    fn state_transaction_rolls_key_manager_back_with_main_state() {
        let env = TestBitVMXEnv::new("key-and-main-global-transaction").unwrap();
        let store = env.bitvmx.store.clone();
        let key_store = env.bitvmx.key_store.clone();
        let key_manager = env.bitvmx.program_context.key_manager.clone();
        let main_key = test_key!("coordinated-main-state");

        let rolled_back_key = BitVMX::run_state_transaction_committing_if(
            &store,
            &key_store,
            || -> Result<_, BitVMXError> {
                store.set(&main_key, true, None)?;
                let public_key = key_manager.next_keypair(BitcoinKeyType::P2tr)?;
                Ok((public_key, false))
            },
        )
        .unwrap();

        assert_eq!(store.get::<bool>(&main_key, None).unwrap(), None);

        let committed_key =
            BitVMX::run_state_transaction(&store, &key_store, || -> Result<_, BitVMXError> {
                store.set(&main_key, true, None)?;
                Ok(key_manager.next_keypair(BitcoinKeyType::P2tr)?)
            })
            .unwrap();

        assert_eq!(rolled_back_key, committed_key);
        assert_eq!(store.get::<bool>(&main_key, None).unwrap(), Some(true));
    }

    /// Simulates a crash between the two commits: key state is committed, main state is lost.
    fn interrupt_after_key_commit(
        store: &Storage,
        key_store: &Storage,
        work: impl FnOnce() -> Result<(), BitVMXError>,
    ) {
        store.begin_global_transaction().unwrap();
        key_store.begin_global_transaction().unwrap();
        work().unwrap();
        key_store.commit_global_transaction().unwrap();
        store.rollback_global_transaction().unwrap();
    }

    #[test]
    fn setup_exchange_replays_after_key_commit_survives_lost_main_commit() {
        let first = TestBitVMXEnv::new("replay-first").unwrap();
        let second = TestBitVMXEnv::new("replay-second").unwrap();
        let km1 = first.bitvmx.program_context.key_manager.clone();
        let km2 = second.bitvmx.program_context.key_manager.clone();
        let store = first.bitvmx.store.clone();
        let key_store = first.bitvmx.key_store.clone();
        let session_id = "replay-session";
        let message_id = "replay-message";

        let first_key = km1.next_keypair(BitcoinKeyType::P2tr).unwrap();
        // Both environments share a derivation seed; skip an index so the participants differ.
        km2.next_keypair(BitcoinKeyType::P2tr).unwrap();
        let second_key = km2.next_keypair(BitcoinKeyType::P2tr).unwrap();
        let participants = vec![first_key, second_key];
        let aggregate = km1
            .new_musig2_session(participants.clone(), first_key)
            .unwrap();
        km2.new_musig2_session(participants, second_key).unwrap();
        for km in [&km1, &km2] {
            km.generate_nonce(
                message_id,
                message_id.as_bytes().to_vec(),
                &aggregate,
                session_id,
                None,
            )
            .unwrap();
        }

        let second_nonces = HashMap::from([(
            second_key,
            km2.get_my_pub_nonces(&aggregate, session_id).unwrap(),
        )]);
        let nonces_received = test_key!("replay-nonces-received");
        let receive_nonces = || -> Result<(), BitVMXError> {
            store.set(&nonces_received, true, None)?;
            Ok(km1.aggregate_nonces(&aggregate, session_id, second_nonces.clone())?)
        };
        interrupt_after_key_commit(&store, &key_store, receive_nonces);
        assert_eq!(store.get::<bool>(&nonces_received, None).unwrap(), None);
        BitVMX::run_state_transaction(&store, &key_store, receive_nonces).unwrap();
        assert_eq!(
            store.get::<bool>(&nonces_received, None).unwrap(),
            Some(true)
        );

        let first_nonces = HashMap::from([(
            first_key,
            km1.get_my_pub_nonces(&aggregate, session_id).unwrap(),
        )]);
        km2.aggregate_nonces(&aggregate, session_id, first_nonces)
            .unwrap();
        let second_signatures = HashMap::from([(
            second_key,
            km2.get_my_partial_signatures(&aggregate, session_id)
                .unwrap(),
        )]);
        let signatures_received = test_key!("replay-signatures-received");
        let receive_signatures = || -> Result<(), BitVMXError> {
            store.set(&signatures_received, true, None)?;
            Ok(km1.save_partial_signatures_multi(
                &aggregate,
                session_id,
                second_signatures.clone(),
            )?)
        };
        interrupt_after_key_commit(&store, &key_store, receive_signatures);
        assert_eq!(store.get::<bool>(&signatures_received, None).unwrap(), None);
        BitVMX::run_state_transaction(&store, &key_store, receive_signatures).unwrap();
        assert_eq!(
            store.get::<bool>(&signatures_received, None).unwrap(),
            Some(true)
        );

        let signature = km1
            .get_aggregated_signature(&aggregate, session_id, message_id)
            .unwrap();
        assert!(km1
            .verify_final_signature(message_id, signature, aggregate, session_id)
            .unwrap());
    }

    #[test]
    fn discarded_work_rolls_back_main_state_even_if_key_rollback_fails() {
        let dir = TestStorageDir::new("discard-key-rollback-failure");
        let store = dir.storage();
        let key_dir = TestStorageDir::new("key-store");
        let key_store = key_dir.storage();

        let result = BitVMX::run_state_transaction_committing_if(&store, &key_store, || {
            store.set(test_key!("discarded"), true, None)?;
            // Simulate a handler incorrectly consuming the key transaction.
            key_store.rollback_global_transaction()?;
            Ok(((), false))
        });

        assert!(matches!(
            result,
            Err(BitVMXError::StorageError(
                StorageError::TransactionRollbackFailed
            ))
        ));
        assert_eq!(
            store.get::<bool>(test_key!("discarded"), None).unwrap(),
            None
        );
        // Neither store is left with an active global transaction.
        BitVMX::run_state_transaction(&store, &key_store, || Ok(())).unwrap();
    }

    #[test]
    fn only_committed_transactions_survive_reopening_the_store() {
        let dir = TestStorageDir::new("independent-transactions");
        let store = dir.storage();
        let key_dir = TestStorageDir::new("key-store");
        let key_store = key_dir.storage();
        let result: Result<(), BitVMXError> =
            BitVMX::run_state_transaction(&store, &key_store, || {
                store.set(test_key!("failed-a"), true, None)?;
                store.set(test_key!("failed-b"), true, None)?;
                Err(BitVMXError::InvalidMessageFormat)
            });
        assert!(result.is_err());
        BitVMX::run_state_transaction(&store, &key_store, || {
            store.set(test_key!("committed-a"), true, None)?;
            store.set(test_key!("committed-b"), true, None)?;
            Ok(())
        })
        .unwrap();

        drop(store);
        let store = dir.storage();
        assert_eq!(
            store.get::<bool>(test_key!("failed-a"), None).unwrap(),
            None
        );
        assert_eq!(
            store.get::<bool>(test_key!("failed-b"), None).unwrap(),
            None
        );
        assert_eq!(
            store.get::<bool>(test_key!("committed-a"), None).unwrap(),
            Some(true)
        );
        assert_eq!(
            store.get::<bool>(test_key!("committed-b"), None).unwrap(),
            Some(true)
        );
    }

    #[test]
    fn malformed_input_is_consumed_and_the_next_input_can_commit() {
        let dir = TestStorageDir::new("reject-malformed-input");
        let store = dir.storage();
        let key_dir = TestStorageDir::new("key-store");
        let key_store = key_dir.storage();
        let valid =
            serde_json::to_string(&IncomingBitVMXApiMessages::Ping(Uuid::new_v4())).unwrap();
        store.set(test_key!("bad-input"), "not JSON", None).unwrap();
        store.set(test_key!("next-input"), &valid, None).unwrap();

        for key in ["bad-input", "next-input"] {
            BitVMX::run_state_transaction(&store, &key_store, || {
                let payload: String = store.get(test_key!(key), None)?.unwrap();
                store.remove(test_key!(key), None)?;
                if BitVMX::discard_if_malformed(serde_json::from_str::<IncomingBitVMXApiMessages>(
                    &payload,
                ))
                .is_some()
                {
                    store.set(test_key!("handled"), true, None)?;
                }
                Ok(())
            })
            .unwrap();
        }

        assert_eq!(
            store.get::<String>(test_key!("bad-input"), None).unwrap(),
            None
        );
        assert_eq!(
            store.get::<String>(test_key!("next-input"), None).unwrap(),
            None
        );
        assert_eq!(
            store.get::<bool>(test_key!("handled"), None).unwrap(),
            Some(true)
        );
    }

    #[test]
    fn malformed_input_consumption_rolls_back_with_transaction() {
        let dir = TestStorageDir::new("reject-rollback");
        let store = dir.storage();
        let key_dir = TestStorageDir::new("key-store");
        let key_store = key_dir.storage();
        store.set(test_key!("input"), "[]", None).unwrap();
        let result: Result<(), BitVMXError> =
            BitVMX::run_state_transaction(&store, &key_store, || {
                store.remove(test_key!("input"), None)?;
                assert!(BitVMX::discard_if_malformed(deserialize_msg("[]".into(), 1024)).is_none());
                Err(BitVMXError::StorageError(StorageError::WriteError))
            });
        assert!(result.is_err());
        assert_eq!(
            store.get::<String>(test_key!("input"), None).unwrap(),
            Some("[]".into())
        );
    }

    #[test]
    fn nonfatal_step_reports_after_rollback_and_allows_independent_work() {
        let env = crate::test_utils::TestProgramContextEnv::new("nonfatal-step").unwrap();
        let mut reporter = Reporter::new(env.context.components_config.l2.clone());
        let dir = TestStorageDir::new("nonfatal-step-storage");
        let store = dir.storage();
        let key_dir = TestStorageDir::new("key-store");
        let key_store = key_dir.storage();
        store.set(test_key!("input"), true, None).unwrap();

        let failed: Result<(), BitVMXError> =
            BitVMX::run_state_transaction(&store, &key_store, || {
                store.remove(test_key!("input"), None)?;
                store.set(test_key!("partial"), true, None)?;
                Err(BitVMXError::InvalidMessageFormat)
            });
        assert_eq!(
            BitVMX::finish_step("input", failed, &mut reporter, &env.context.broker_channel)
                .unwrap(),
            None
        );
        assert_eq!(
            store.get::<bool>(test_key!("input"), None).unwrap(),
            Some(true)
        );
        assert_eq!(store.get::<bool>(test_key!("partial"), None).unwrap(), None);
        assert_eq!(env.l2_messages().unwrap().len(), 1);

        let next = BitVMX::run_state_transaction(&store, &key_store, || {
            store.set(test_key!("independent"), true, None)?;
            Ok(true)
        });
        assert_eq!(
            BitVMX::finish_step("next", next, &mut reporter, &env.context.broker_channel).unwrap(),
            Some(true)
        );
        assert_eq!(
            store.get::<bool>(test_key!("independent"), None).unwrap(),
            Some(true)
        );
        assert_eq!(env.l2_messages().unwrap().len(), 1);
    }

    #[test]
    fn fatal_step_propagates_without_reporting_twice() {
        let env = crate::test_utils::TestProgramContextEnv::new("fatal-step").unwrap();
        let mut reporter = Reporter::new(env.context.components_config.l2.clone());
        let result = BitVMX::finish_step::<()>(
            "storage",
            Err(BitVMXError::StorageError(StorageError::WriteError)),
            &mut reporter,
            &env.context.broker_channel,
        );
        assert!(matches!(
            result,
            Err(BitVMXError::StorageError(StorageError::WriteError))
        ));
        // Fatal reporting belongs to tick, not the individual step.
        assert!(env.l2_messages().unwrap().is_empty());
    }

    #[test]
    fn failed_item_preserves_previous_commit_and_unvisited_input() {
        let dir = TestStorageDir::new("application-item-transactions");
        let store = dir.storage();
        let key_dir = TestStorageDir::new("key-store");
        let key_store = key_dir.storage();
        for key in ["input-a", "input-b", "input-c"] {
            store.set(test_key!(key), true, None).unwrap();
        }

        let value = BitVMX::run_state_transaction(&store, &key_store, || {
            store.remove(test_key!("input-a"), None)?;
            store.set(test_key!("state-a"), true, None)?;
            Ok(42)
        })
        .unwrap();
        assert_eq!(value, 42);

        let result: Result<(), BitVMXError> =
            BitVMX::run_state_transaction(&store, &key_store, || {
                store.remove(test_key!("input-b"), None)?;
                store.set(test_key!("partial-b"), true, None)?;
                Err(BitVMXError::InvalidMessageFormat)
            });
        assert!(matches!(result, Err(BitVMXError::InvalidMessageFormat)));
        assert_eq!(store.get::<bool>(test_key!("input-a"), None).unwrap(), None);
        assert_eq!(
            store.get::<bool>(test_key!("state-a"), None).unwrap(),
            Some(true)
        );
        assert_eq!(
            store.get::<bool>(test_key!("partial-b"), None).unwrap(),
            None
        );
        assert_eq!(
            store.get::<bool>(test_key!("input-b"), None).unwrap(),
            Some(true)
        );
        assert_eq!(
            store.get::<bool>(test_key!("input-c"), None).unwrap(),
            Some(true)
        );

        // The next step can open its own transaction after the failure.
        BitVMX::run_state_transaction(&store, &key_store, || {
            store.set(test_key!("next-step"), true, None)?;
            Ok(())
        })
        .unwrap();
        assert_eq!(
            store.get::<bool>(test_key!("next-step"), None).unwrap(),
            Some(true)
        );
    }

    #[test]
    fn rollback_failure_is_fatal_even_if_the_original_error_was_not() {
        let dir = TestStorageDir::new("transaction-rollback-failure");
        let store = dir.storage();
        let key_dir = TestStorageDir::new("key-store");
        let key_store = key_dir.storage();
        let result: Result<(), BitVMXError> =
            BitVMX::run_state_transaction(&store, &key_store, || {
                // Simulate a handler incorrectly consuming its owner's transaction.
                store.rollback_global_transaction()?;
                Err(BitVMXError::InvalidMessageFormat)
            });
        let error = result.unwrap_err();
        assert!(matches!(
            error,
            BitVMXError::StorageError(StorageError::TransactionRollbackFailed)
        ));
        assert!(matches!(classify(&error), Severity::Fatal));
    }

    #[test]
    fn fatal_error_also_rolls_back() {
        let dir = TestStorageDir::new("transaction-fatal-error");
        let store = dir.storage();
        let key_dir = TestStorageDir::new("key-store");
        let key_store = key_dir.storage();
        store.set(test_key!("incoming"), true, None).unwrap();
        let result: Result<(), BitVMXError> =
            BitVMX::run_state_transaction(&store, &key_store, || {
                store.remove(test_key!("incoming"), None)?;
                Err(BitVMXError::StorageError(StorageError::WriteError))
            });
        assert!(matches!(
            result,
            Err(BitVMXError::StorageError(StorageError::WriteError))
        ));
        assert_eq!(
            store.get::<bool>(test_key!("incoming"), None).unwrap(),
            Some(true)
        );
        store.begin_global_transaction().unwrap();
        store.rollback_global_transaction().unwrap();
    }
}
