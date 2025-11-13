use std::{collections::HashMap, time::{Duration, Instant}};
use tracing::{debug, warn};
use bitvmx_job_dispatcher::helper::PingMessage;
use crate::{config::{ComponentsConfig, PingConfig}, errors::BitVMXError, types::ProgramContext};

pub struct PingHelper {
    time_since_sent_check: HashMap<String, Instant>,
    time_to_send_check: Instant,
    ping_timeout: Duration,
    time_between_checks: Duration,
}

impl Default for PingHelper {
    fn default() -> Self {
        Self {
            time_since_sent_check: HashMap::new(),
            time_to_send_check: Instant::now(),
            ping_timeout: Duration::from_secs(30),
            time_between_checks: Duration::from_secs(120),
        }
    }
}

impl PingHelper {
    pub fn new(config: PingConfig) -> Self {
        let ping_timeout = Duration::from_secs(config.timeout_secs);
        let time_between_checks = Duration::from_secs(config.interval_secs);
        Self {
            time_since_sent_check: HashMap::new(),
            time_to_send_check: Instant::now(),
            ping_timeout,
            time_between_checks,
        }
    }

    pub fn check_job_dispatchers_liveness(&mut self, program_context: &ProgramContext, components: &ComponentsConfig) -> Result<(), BitVMXError> {
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
                warn!("No Pong received from {} Job Dispatcher within timeout period", dispatcher_name);
                self.time_since_sent_check.remove(&dispatcher_name);
            }
        }
    }
    
    fn send_liveness_message_to_dispatchers(&mut self, program_context: &ProgramContext, components: &ComponentsConfig) -> Result<(), BitVMXError> {
        let msg_to_prover = serde_json::to_string(&PingMessage::Ping)?;

        let msg_to_emulator = serde_json::to_string(&PingMessage::Ping)?;

        debug!("Sending ZKP dispatcher ping message: {}", msg_to_prover);
        program_context
            .broker_channel
            .send(&components.prover, msg_to_prover)?;

        self.time_since_sent_check.insert("ZKP".to_string(), Instant::now());

        debug!("Sending Emulator dispatcher ping message: {}", msg_to_emulator);

        program_context
            .broker_channel
            .send(&components.emulator, msg_to_emulator)?;

        self.time_since_sent_check.insert("Emulator".to_string(), Instant::now());
        
        Ok(())
    }

    pub fn received_message(&mut self, dispatcher_name: &str, message: &PingMessage){
        match message {
            PingMessage::Ping => {
                warn!("Client should not receive Ping");
                return;
            },
            PingMessage::Pong => debug!("Received Pong Message from {} Job Dispatcher", dispatcher_name),
        }

        self.time_since_sent_check.remove(dispatcher_name);
    }

}