use crate::error_handling::{classify, send_error_report, Severity};
use crate::ports::bitcoin_coordinator::BitcoinCoordinatorApi;
use crate::{
    config::{ComponentsConfig, PingConfig},
    errors::{BitVMXError, ConfigError},
    types::{ErrorReport, ErrorReportKind, JobDispatcherType, ProgramContext},
};
use bitvmx_broker::{identification::identifier::Identifier, BrokerError};
use bitvmx_dispatcher_utils::PingMessage;
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};
use tracing::{debug, error, info, warn};

/// Whether a ping that could not be sent should stop the node. The broker calls a failed
/// storage write non-fatal so a shared bus keeps serving; we take the stricter verdict, since
/// `tick` leaves its global transaction open on failure and continuing would wedge every tick.
fn send_failure_is_fatal(error: &BrokerError) -> bool {
    error.is_fatal() || classify(error) == Severity::Fatal
}

struct DispatcherState {
    pinged_at: Option<Instant>,
    reported_down: bool,
}

pub(crate) struct PingHelper {
    dispatchers: HashMap<JobDispatcherType, DispatcherState>,
    time_to_send_check: Instant,
    ping_timeout: Duration,
    time_between_checks: Duration,
}

impl PingHelper {
    pub fn new(config: Option<PingConfig>) -> Result<Self, ConfigError> {
        let Some(config) = config else {
            return Ok(Self::build(
                Duration::from_secs(30),
                Duration::from_secs(120),
                Vec::new(),
            ));
        };

        let timeout_secs = config.timeout_secs.unwrap_or(30);
        let interval_secs = config.interval_secs.unwrap_or(120);

        let ping_timeout = Duration::from_secs(timeout_secs);
        let time_between_checks = Duration::from_secs(interval_secs);

        // if timeout >= interval no dispatcher is ever reported as down
        if !config.services.is_empty() && ping_timeout >= time_between_checks {
            return Err(ConfigError::InvalidPingConfig(format!(
                "timeout_secs ({}) must be shorter than interval_secs ({})",
                timeout_secs, interval_secs
            )));
        }

        Ok(Self::build(
            ping_timeout,
            time_between_checks,
            config.services,
        ))
    }

    // Sub-second timings setter for testing, cannot be built via config file.
    #[cfg(test)]
    fn set_timings_ms(&mut self, timeout_ms: u64, interval_ms: u64) {
        self.ping_timeout = Duration::from_millis(timeout_ms);
        self.time_between_checks = Duration::from_millis(interval_ms);
    }

    fn build(
        ping_timeout: Duration,
        time_between_checks: Duration,
        services: Vec<JobDispatcherType>,
    ) -> Self {
        Self {
            dispatchers: services
                .into_iter()
                .map(|s| {
                    (
                        s,
                        DispatcherState {
                            pinged_at: None,
                            reported_down: false,
                        },
                    )
                })
                .collect(),
            time_to_send_check: Instant::now(),
            ping_timeout,
            time_between_checks,
        }
    }

    fn identifier(dispatcher: JobDispatcherType, components: &ComponentsConfig) -> &Identifier {
        match dispatcher {
            JobDispatcherType::ZKP => &components.prover,
            JobDispatcherType::Emulator => &components.emulator,
            JobDispatcherType::Garbler => &components.garbler,
        }
    }

    pub fn check_job_dispatchers_liveness<BC: BitcoinCoordinatorApi>(
        &mut self,
        program_context: &ProgramContext<BC>,
        components: &ComponentsConfig,
    ) -> Result<(), BitVMXError> {
        if self.dispatchers.is_empty() {
            return Ok(());
        }
        self.check_if_dispatchers_timed_out(program_context, components);

        if self.time_to_send_check.elapsed() >= self.time_between_checks {
            self.send_liveness_message_to_dispatchers(program_context, components)?;
            self.time_to_send_check = Instant::now();
        }

        Ok(())
    }

    // Reports on the first missed pong. A running job does not block the reply, since jobs
    // are child processes, but the dispatcher reads one message per tick: a miss means it is
    // gone or far enough behind on its inbox to look that way.
    fn check_if_dispatchers_timed_out<BC: BitcoinCoordinatorApi>(
        &mut self,
        program_context: &ProgramContext<BC>,
        components: &ComponentsConfig,
    ) {
        let timeout_dispatcher: Vec<_> = self
            .dispatchers
            .iter()
            .filter(|(_, state)| {
                state
                    .pinged_at
                    .is_some_and(|sent_at| sent_at.elapsed() >= self.ping_timeout)
            })
            .map(|(dispatcher, _)| *dispatcher)
            .collect();

        for dispatcher_name in timeout_dispatcher {
            let Some(dispatcher_state) = self.dispatchers.get_mut(&dispatcher_name) else {
                continue;
            };
            // dropping the pending instant is what re-arms the dispatcher next interval.
            dispatcher_state.pinged_at = None;

            if dispatcher_state.reported_down {
                continue;
            }
            dispatcher_state.reported_down = true;

            error!(
                "No Pong received from {:?} Job Dispatcher within timeout period",
                dispatcher_name
            );
            send_error_report(
                &program_context.broker_channel,
                &components.l2,
                ErrorReport::node(ErrorReportKind::JobDispatcherUnresponsive(dispatcher_name)),
            );
        }
    }

    fn send_liveness_message_to_dispatchers<BC: BitcoinCoordinatorApi>(
        &mut self,
        program_context: &ProgramContext<BC>,
        components: &ComponentsConfig,
    ) -> Result<(), BitVMXError> {
        let message = serde_json::to_string(&PingMessage::Ping)?;

        let services = self
            .dispatchers
            .keys()
            .copied()
            .collect::<Vec<JobDispatcherType>>();

        for dispatcher in services {
            debug!(
                "Sending {:?} dispatcher ping message: {}",
                dispatcher, message
            );

            if let Err(e) = program_context
                .broker_channel
                .send_service(Self::identifier(dispatcher, components), message.clone())
            {
                // Failing to send a health check must not be worse than the dispatcher
                // being down, so only a fatal condition propagates.
                if send_failure_is_fatal(&e) {
                    return Err(e.into());
                }

                error!("Could not ping {:?} Job Dispatcher: {:?}", dispatcher, e);
                // No pending entry, so an unsent ping cannot time out as unresponsive.
                continue;
            }
            let Some(dispatcher_state) = self.dispatchers.get_mut(&dispatcher) else {
                continue;
            };
            dispatcher_state.pinged_at = Some(Instant::now());
        }

        Ok(())
    }

    pub fn received_message<BC: BitcoinCoordinatorApi>(
        &mut self,
        dispatcher_name: JobDispatcherType,
        message: &PingMessage,
        program_context: &ProgramContext<BC>,
        components: &ComponentsConfig,
    ) {
        match message {
            PingMessage::Ping => {
                warn!("Client should not receive Ping");
                return;
            }
            PingMessage::Pong => debug!(
                "Received Pong Message from {:?} Job Dispatcher",
                dispatcher_name
            ),
        }

        let Some(dispatcher_state) = self.dispatchers.get_mut(&dispatcher_name) else {
            return;
        };

        dispatcher_state.pinged_at = None;

        if dispatcher_state.reported_down {
            dispatcher_state.reported_down = false;
            info!(
                "{:?} Job Dispatcher is answering pings again",
                dispatcher_name
            );
            send_error_report(
                &program_context.broker_channel,
                &components.l2,
                ErrorReport::node(ErrorReportKind::JobDispatcherRecovered(dispatcher_name)),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TestProgramContextEnv;
    use crate::types::{ErrorScope, OutgoingBitVMXApiMessages};
    use bitvmx_broker::storage::BrokerStorageError;
    use std::thread::sleep;
    use storage_backend::error::StorageError;

    #[test]
    fn a_failed_broker_write_stops_the_node() {
        let error =
            BrokerError::BrokerStorageError(BrokerStorageError::Backend(StorageError::WriteError));

        // A tripwire: once the broker discriminates the inner variant, drop the override.
        assert!(
            !error.is_fatal(),
            "the broker is expected to still report this as non-fatal"
        );
        assert!(send_failure_is_fatal(&error));
    }

    // Conditions the broker calls fatal that our own source-chain walk does not reach.
    #[test]
    fn a_broker_fatal_condition_stops_the_node() {
        assert!(send_failure_is_fatal(&BrokerError::MutexError(
            "storage".to_string()
        )));
        assert!(send_failure_is_fatal(&BrokerError::WrongNodeMode(
            "peers".to_string()
        )));
    }

    // One refused message must not take the node down, or a single oversized ping would.
    #[test]
    fn an_ordinary_send_failure_is_not_fatal() {
        assert!(!send_failure_is_fatal(&BrokerError::MessageTooLarge(10, 5)));
    }

    const TIMEOUT_MS: u64 = 50;
    const INTERVAL_MS: u64 = 200;
    const TIMEOUT: Duration = Duration::from_millis(TIMEOUT_MS);
    const INTERVAL: Duration = Duration::from_millis(INTERVAL_MS);

    // Goes through the real constructor, then shortens the timings the config cannot.
    fn enabled_helper(services: Vec<JobDispatcherType>) -> PingHelper {
        let mut helper = PingHelper::new(Some(PingConfig {
            interval_secs: Some(120),
            timeout_secs: Some(30),
            services,
        }))
        .unwrap();
        helper.set_timings_ms(TIMEOUT_MS, INTERVAL_MS);
        helper
    }

    #[test]
    fn silent_dispatcher_is_reported_once_and_recovers_once() -> Result<(), BitVMXError> {
        let env = TestProgramContextEnv::new("ping-helper-liveness")?;
        let components = env.context.components_config.clone();
        let mut ping_helper = enabled_helper(vec![JobDispatcherType::Emulator]);

        // Nothing is pending yet, so this only sends the first ping.
        sleep(INTERVAL);
        ping_helper.check_job_dispatchers_liveness(&env.context, &components)?;
        assert!(
            env.l2_messages()?.is_empty(),
            "a ping in flight is not yet a failure"
        );

        // The pong never arrives, so the entry ages out.
        sleep(TIMEOUT);
        ping_helper.check_job_dispatchers_liveness(&env.context, &components)?;

        // A second interval re-arms and times out again; the latch keeps it quiet.
        sleep(INTERVAL);
        ping_helper.check_job_dispatchers_liveness(&env.context, &components)?;
        sleep(TIMEOUT);
        ping_helper.check_job_dispatchers_liveness(&env.context, &components)?;

        let messages = env.l2_messages()?;
        assert_eq!(
            messages.len(),
            1,
            "the condition is reported on change only"
        );
        assert!(
            matches!(
                &messages[0],
                OutgoingBitVMXApiMessages::Error(report)
                    if report.scope == ErrorScope::Node
                    && report.kind
                        == ErrorReportKind::JobDispatcherUnresponsive(JobDispatcherType::Emulator)
            ),
            "expected JobDispatcherUnresponsive, got {:?}",
            messages[0]
        );

        ping_helper.received_message(
            JobDispatcherType::Emulator,
            &PingMessage::Pong,
            &env.context,
            &components,
        );
        // A second pong is not a second recovery.
        ping_helper.received_message(
            JobDispatcherType::Emulator,
            &PingMessage::Pong,
            &env.context,
            &components,
        );

        let messages = env.l2_messages()?;
        assert_eq!(messages.len(), 2, "recovery is reported on change only");
        assert!(
            matches!(
                &messages[1],
                OutgoingBitVMXApiMessages::Error(report)
                    if report.kind
                        == ErrorReportKind::JobDispatcherRecovered(JobDispatcherType::Emulator)
            ),
            "expected JobDispatcherRecovered, got {:?}",
            messages[1]
        );

        Ok(())
    }

    #[test]
    fn answering_dispatcher_is_not_reported() -> Result<(), BitVMXError> {
        let env = TestProgramContextEnv::new("ping-helper-answering")?;
        let components = env.context.components_config.clone();
        let mut ping_helper = enabled_helper(vec![JobDispatcherType::Emulator]);

        sleep(INTERVAL);
        ping_helper.check_job_dispatchers_liveness(&env.context, &components)?;
        ping_helper.received_message(
            JobDispatcherType::Emulator,
            &PingMessage::Pong,
            &env.context,
            &components,
        );

        sleep(TIMEOUT);
        ping_helper.check_job_dispatchers_liveness(&env.context, &components)?;

        assert!(env.l2_messages()?.is_empty(), "a pong clears the check");
        Ok(())
    }

    // A dispatcher is pinged only when a config names it, so no list means no pinging.
    #[test]
    fn an_empty_service_list_pings_nobody() {
        let helper = PingHelper::new(Some(PingConfig {
            interval_secs: Some(120),
            timeout_secs: Some(30),
            services: vec![],
        }))
        .unwrap();

        assert!(helper.dispatchers.is_empty());
    }

    // Omitting the timings is allowed; they fall back to the shipped interval and timeout.
    #[test]
    fn absent_timings_fall_back_to_the_defaults() {
        let helper = PingHelper::new(Some(PingConfig {
            interval_secs: None,
            timeout_secs: None,
            services: vec![JobDispatcherType::Emulator],
        }))
        .unwrap();

        assert_eq!(helper.time_between_checks, Duration::from_secs(120));
        assert_eq!(helper.ping_timeout, Duration::from_secs(30));
    }

    #[test]
    fn timeout_not_shorter_than_interval_is_rejected() {
        assert!(PingHelper::new(Some(PingConfig {
            interval_secs: Some(30),
            timeout_secs: Some(30),
            services: vec![JobDispatcherType::Emulator],
        }))
        .is_err());
    }

    // Timings are not checked when nothing is pinged.
    #[test]
    fn a_config_naming_no_services_is_not_validated() {
        let helper = PingHelper::new(Some(PingConfig {
            interval_secs: Some(30),
            timeout_secs: Some(30),
            services: vec![],
        }))
        .unwrap();

        assert!(helper.dispatchers.is_empty());
    }

    // The block shipped in config/.
    #[test]
    fn shipped_config_is_accepted() {
        let helper = PingHelper::new(Some(PingConfig {
            interval_secs: None,
            timeout_secs: None,
            services: vec![JobDispatcherType::Emulator],
        }))
        .unwrap();

        // No deployment runs a garbler or a ZKP, so only the emulator is pinged.
        assert_eq!(helper.dispatchers.len(), 1);
        assert!(helper
            .dispatchers
            .contains_key(&JobDispatcherType::Emulator));
    }
}
