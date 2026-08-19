use crate::error_severity::send_error_report;
use crate::ports::bitcoin_coordinator::BitcoinCoordinatorApi;
use crate::{
    config::{ComponentsConfig, PingConfig},
    errors::{BitVMXError, ConfigError},
    types::{ErrorReport, ErrorReportKind, JobDispatcherType, ProgramContext},
};
use bitvmx_broker::identification::identifier::Identifier;
use bitvmx_dispatcher_utils::PingMessage;
use std::{
    collections::{HashMap, HashSet},
    time::{Duration, Instant},
};
use tracing::{debug, error, info, warn};

pub(crate) struct PingHelper {
    time_since_sent_check: HashMap<JobDispatcherType, Instant>,
    unresponsive: HashSet<JobDispatcherType>, // reported down; keeps reports to one per change
    time_to_send_check: Instant,
    ping_timeout: Duration,
    time_between_checks: Duration,
    services: Vec<JobDispatcherType>,
    enabled: bool,
}

impl PingHelper {
    pub fn new(config: Option<PingConfig>) -> Result<Self, ConfigError> {
        let Some(config) = config else {
            return Ok(Self::build(
                Duration::from_secs(30),
                Duration::from_secs(120),
                Vec::new(),
                false,
            ));
        };

        let ping_timeout = Duration::from_secs(config.timeout_secs);
        let time_between_checks = Duration::from_secs(config.interval_secs);

        // if timeout >= interval no dispatcher is ever reported as down
        if config.enabled && ping_timeout >= time_between_checks {
            return Err(ConfigError::InvalidPingConfig(format!(
                "timeout_secs ({}) must be shorter than interval_secs ({})",
                config.timeout_secs, config.interval_secs
            )));
        }

        // if enabled without naming dispatchers, we assume all supported dispatchers.
        // No deployment runs a ZKP, so pinging it by default would report it down.
        let services = if config.enabled && config.services.is_empty() {
            vec![JobDispatcherType::Emulator, JobDispatcherType::Garbler]
        } else {
            config.services
        };

        Ok(Self::build(
            ping_timeout,
            time_between_checks,
            services,
            config.enabled,
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
        enabled: bool,
    ) -> Self {
        Self {
            time_since_sent_check: HashMap::new(),
            unresponsive: HashSet::new(),
            time_to_send_check: Instant::now(),
            ping_timeout,
            time_between_checks,
            services,
            enabled,
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
        if !self.enabled {
            return Ok(());
        }
        self.check_if_dispatchers_timed_out(program_context, components);

        if self.time_to_send_check.elapsed() >= self.time_between_checks {
            self.send_liveness_message_to_dispatchers(program_context, components)?;
            self.time_to_send_check = Instant::now();
        }

        Ok(())
    }

    // Reports on the first missed pong: a dispatcher busy with a job still answers pings,
    // so a miss means the process or its channel is gone.
    fn check_if_dispatchers_timed_out<BC: BitcoinCoordinatorApi>(
        &mut self,
        program_context: &ProgramContext<BC>,
        components: &ComponentsConfig,
    ) {
        let timeout_dispatcher: Vec<_> = self
            .time_since_sent_check
            .iter()
            .filter(|(_, time)| time.elapsed() >= self.ping_timeout)
            .map(|(dispatcher, _)| *dispatcher)
            .collect();

        for dispatcher_name in timeout_dispatcher {
            // Dropped so the next interval re-arms this dispatcher.
            self.time_since_sent_check.remove(&dispatcher_name);

            if !self.unresponsive.insert(dispatcher_name) {
                continue;
            }

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
        for dispatcher in self.services.clone() {
            let message = serde_json::to_string(&PingMessage::Ping)?;
            debug!(
                "Sending {:?} dispatcher ping message: {}",
                dispatcher, message
            );

            program_context
                .broker_channel
                .send_service(Self::identifier(dispatcher, components), message)?;

            self.time_since_sent_check
                .insert(dispatcher, Instant::now());
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

        self.time_since_sent_check.remove(&dispatcher_name);

        if self.unresponsive.remove(&dispatcher_name) {
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
    use std::thread::sleep;

    const TIMEOUT_MS: u64 = 50;
    const INTERVAL_MS: u64 = 200;
    const TIMEOUT: Duration = Duration::from_millis(TIMEOUT_MS);
    const INTERVAL: Duration = Duration::from_millis(INTERVAL_MS);

    // Goes through the real constructor, then shortens the timings the config cannot.
    fn enabled_helper(services: Vec<JobDispatcherType>) -> PingHelper {
        let mut helper = PingHelper::new(Some(PingConfig {
            enabled: true,
            interval_secs: 120,
            timeout_secs: 30,
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

    // ZKP is only ever pinged when a config names it.
    #[test]
    fn empty_service_list_pings_the_dispatchers_we_run() {
        let helper = PingHelper::new(Some(PingConfig {
            enabled: true,
            interval_secs: 120,
            timeout_secs: 30,
            services: vec![],
        }))
        .unwrap();

        assert!(helper.enabled);
        assert_eq!(
            helper.services,
            vec![JobDispatcherType::Emulator, JobDispatcherType::Garbler]
        );
    }

    #[test]
    fn timeout_not_shorter_than_interval_is_rejected() {
        assert!(PingHelper::new(Some(PingConfig {
            enabled: true,
            interval_secs: 30,
            timeout_secs: 30,
            services: vec![JobDispatcherType::Emulator],
        }))
        .is_err());
    }

    // Timings are not checked when the feature is off.
    #[test]
    fn disabled_config_is_not_validated() {
        let helper = PingHelper::new(Some(PingConfig {
            enabled: false,
            interval_secs: 30,
            timeout_secs: 30,
            services: vec![],
        }))
        .unwrap();

        assert!(!helper.enabled);
    }

    // The block shipped in config/.
    #[test]
    fn shipped_config_is_accepted() {
        let helper = PingHelper::new(Some(PingConfig {
            enabled: true,
            interval_secs: 120,
            timeout_secs: 30,
            services: vec![JobDispatcherType::Emulator, JobDispatcherType::Garbler],
        }))
        .unwrap();

        assert!(helper.enabled);
        assert_eq!(
            helper.services,
            vec![JobDispatcherType::Emulator, JobDispatcherType::Garbler]
        );
    }
}
