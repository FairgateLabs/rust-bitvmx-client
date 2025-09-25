use operator_comms::operator_comms::OperatorComms;

pub trait GracefulShutdown {
    /// Signal the component to stop accepting new work immediately.
    fn begin_shutdown(&mut self);

    /// Best-effort draining of in-flight work until the deadline.
    fn drain_until_idle(&mut self, deadline: std::time::Instant);

    /// Close resources and finalize shutdown.
    fn shutdown_now(&mut self);
}

// Temporary no-op implementations for subcomponents. Replace with real logic later.

impl GracefulShutdown for OperatorComms {
    fn begin_shutdown(&mut self) {
        // TODO: stop accepting new Comms work and close listeners
    }
    fn drain_until_idle(&mut self, _deadline: std::time::Instant) {
        // TODO: drain internal queues if any
    }
    fn shutdown_now(&mut self) {
        // TODO: close connections cleanly
    }
}

impl GracefulShutdown for bitcoin_coordinator::coordinator::BitcoinCoordinator {
    fn begin_shutdown(&mut self) {
        // TODO: stop monitors and avoid dispatching new txs
    }
    fn drain_until_idle(&mut self, _deadline: std::time::Instant) {
        // TODO: flush pending acks/writes to storage
    }
    fn shutdown_now(&mut self) {
        // TODO: release resources
    }
}

impl GracefulShutdown for bitvmx_broker::rpc::sync_server::BrokerSync {
    fn begin_shutdown(&mut self) {
        // no-op
    }
    fn drain_until_idle(&mut self, _deadline: std::time::Instant) {
        // no-op
    }
    fn shutdown_now(&mut self) {
        // Prefer using this over direct close() calls
        self.close();
    }
}

impl GracefulShutdown for crate::program::program::Program {
    fn begin_shutdown(&mut self) {
        // TODO: stop scheduling new protocol steps
    }
    fn drain_until_idle(&mut self, _deadline: std::time::Instant) {
        // TODO: persist state machine snapshot if needed
    }
    fn shutdown_now(&mut self) {
        // TODO: finalize program resources
    }
}
