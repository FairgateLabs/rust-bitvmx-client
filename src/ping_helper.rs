use crate::{
    config::{ComponentsConfig, PingConfig},
    errors::BitVMXError,
    types::ProgramContext,
};
use dispatcher_utils::PingMessage;
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};
use tracing::{debug, warn};

#[derive(Eq, Hash, PartialEq, Clone, Copy, Debug)]
pub(crate) enum JobDispatcherType {
    ZKP,
    Emulator,
}

pub(crate) struct PingHelper {
    time_since_sent_check: HashMap<JobDispatcherType, Instant>,
    time_to_send_check: Instant,
    ping_timeout: Duration,
    time_between_checks: Duration,
    enabled: bool,
}

impl PingHelper {
    pub fn new(config: Option<PingConfig>) -> Self {
        let (ping_timeout, time_between_checks, enabled) = match config {
            Some(c) => (
                Duration::from_secs(c.timeout_secs),
                Duration::from_secs(c.interval_secs),
                c.enabled,
            ),
            None => (Duration::from_secs(30), Duration::from_secs(120), false),
        };
        Self {
            time_since_sent_check: HashMap::new(),
            time_to_send_check: Instant::now(),
            ping_timeout,
            time_between_checks,
            enabled,
        }
    }

    pub fn check_job_dispatchers_liveness(
        &mut self,
        program_context: &ProgramContext,
        components: &ComponentsConfig,
    ) -> Result<(), BitVMXError> {
        if !self.enabled {
            return Ok(());
        }
        self.check_if_dispatchers_timed_out();

        if self.time_to_send_check.elapsed() >= self.time_between_checks {
            self.send_liveness_message_to_dispatchers(program_context, components)?;
            self.time_to_send_check = Instant::now();
        }

        Ok(())
    }

    fn check_if_dispatchers_timed_out(&mut self) {
        let timeout_dispatcher: Vec<_> = self
            .time_since_sent_check
            .iter()
            .filter(|(_, time)| time.elapsed() >= self.ping_timeout)
            .map(|(dispatcher, _)| dispatcher.clone())
            .collect();

        if !timeout_dispatcher.is_empty() {
            for dispatcher_name in timeout_dispatcher {
                warn!(
                    "No Pong received from {:?} Job Dispatcher within timeout period",
                    dispatcher_name
                );
                self.time_since_sent_check.remove(&dispatcher_name);
            }
        }
    }

    fn send_liveness_message_to_dispatchers(
        &mut self,
        program_context: &ProgramContext,
        components: &ComponentsConfig,
    ) -> Result<(), BitVMXError> {
        let msg_to_prover = serde_json::to_string(&PingMessage::Ping)?;

        let msg_to_emulator = serde_json::to_string(&PingMessage::Ping)?;

        debug!("Sending ZKP dispatcher ping message: {}", msg_to_prover);
        program_context
            .broker_channel
            .send(&components.prover, msg_to_prover)?;

        self.time_since_sent_check
            .insert(JobDispatcherType::ZKP, Instant::now());

        debug!(
            "Sending Emulator dispatcher ping message: {}",
            msg_to_emulator
        );

        program_context
            .broker_channel
            .send(&components.emulator, msg_to_emulator)?;

        self.time_since_sent_check
            .insert(JobDispatcherType::Emulator, Instant::now());

        Ok(())
    }

    pub fn received_message(&mut self, dispatcher_name: JobDispatcherType, message: &PingMessage) {
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
    }
}
