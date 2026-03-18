use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Default, Deserialize)]
pub struct ThrotthleConfig {
    /// Optional interval (ms) used until the component is initialized.
    pub init_interval: Option<u64>,
    /// Interval (ms) used when the previous call had work to do.
    pub busy_interval: u64,
    /// Interval (ms) used when the previous call found no work.
    pub idle_interval: u64,
}

impl ThrotthleConfig {
    pub fn new(init_interval: Option<u64>, busy_interval: u64, idle_interval: u64) -> Self {
        Self {
            init_interval,
            busy_interval,
            idle_interval,
        }
    }
}

/// Tracks whether a throttled component should be called on this tick.
///
/// Supports three intervals:
/// - `init_interval` (optional): used until the first call reports work done.
/// - `busy_interval`: used when the previous call had work to do.
/// - `idle_interval`: used when the previous call found no work.
pub struct Throtthle {
    init_interval: Option<Duration>,
    busy_interval: Duration,
    idle_interval: Duration,
    last_call: Instant,
    initialized: bool,
    last_was_busy: bool,
}

impl Throtthle {
    pub fn new(config: ThrotthleConfig) -> Self {
        Self {
            init_interval: config.init_interval.map(Duration::from_millis),
            busy_interval: Duration::from_millis(config.busy_interval),
            idle_interval: Duration::from_millis(config.idle_interval),
            last_call: Instant::now(),
            initialized: config.init_interval.is_none(),
            last_was_busy: true,
        }
    }

    /// Returns `true` if enough time has elapsed and the component should be called.
    pub fn should_call(&self) -> bool {
        let elapsed = self.last_call.elapsed();
        elapsed >= self.current_interval()
    }

    /// Record the outcome of the call and update internal timestamps.
    /// Must be called after each execution so the throttle can adjust its pace.
    pub fn record(&mut self, had_work: bool) {
        self.last_call = Instant::now();
        if had_work {
            self.initialized = true;
        }
        self.last_was_busy = had_work;
    }

    /// Returns the current active interval based on the component's state.
    fn current_interval(&self) -> Duration {
        if !self.initialized {
            // Safe to unwrap: `initialized` is false only when `init_interval` is Some.
            self.init_interval.unwrap()
        } else if self.last_was_busy {
            self.busy_interval
        } else {
            self.idle_interval
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_with_init_interval() {
        let t = Throtthle::new(ThrotthleConfig::new(Some(1000), 2000, 5000));
        assert!(!t.initialized);
        assert_eq!(t.current_interval(), Duration::from_millis(1000));
    }

    #[test]
    fn skips_init_when_none() {
        let t = Throtthle::new(ThrotthleConfig::new(None, 2000, 5000));
        assert!(t.initialized);
        assert_eq!(t.current_interval(), Duration::from_millis(2000));
    }

    #[test]
    fn transitions_to_busy_after_work() {
        let mut t = Throtthle::new(ThrotthleConfig::new(Some(0), 2000, 5000));
        t.record(true);
        assert!(t.initialized);
        assert_eq!(t.current_interval(), Duration::from_millis(2000));
    }

    #[test]
    fn uses_idle_interval_after_idle_outcome() {
        let mut t = Throtthle::new(ThrotthleConfig::new(None, 2000, 5000));
        t.record(true);
        assert_eq!(t.current_interval(), Duration::from_millis(2000));
        t.record(false);
        assert_eq!(t.current_interval(), Duration::from_millis(5000));
    }

    #[test]
    fn should_call_respects_interval() {
        let mut t = Throtthle::new(ThrotthleConfig::new(Some(0), 10000, 20000));
        // init_interval is 0 → should_call immediately true
        assert!(t.should_call());
        t.record(true);
        // busy_interval is 10s → should_call is false right after record
        assert!(!t.should_call());
    }
}
