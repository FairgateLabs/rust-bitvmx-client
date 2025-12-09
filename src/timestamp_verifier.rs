use crate::errors::BitVMXError;
use bitvmx_operator_comms::operator_comms::PubKeyHash;
use chrono::Utc;
use std::collections::HashMap;
use tracing::warn;

pub struct TimestampVerifier {
    message_timestamps: HashMap<PubKeyHash, i64>,
    enable_check: bool,
    max_timestamp_drift_ms: i64,
}

impl TimestampVerifier {
    pub fn new(enable_check: bool, max_timestamp_drift_ms: i64) -> Self {
        Self {
            message_timestamps: HashMap::new(),
            enable_check,
            max_timestamp_drift_ms,
        }
    }

    pub fn ensure_fresh(&self, peer: &PubKeyHash, timestamp: i64) -> Result<(), BitVMXError> {
        if !self.enable_check {
            return Ok(());
        }

        ensure_timestamp_fresh_internal(
            &self.message_timestamps,
            peer,
            timestamp,
            self.max_timestamp_drift_ms,
        )
    }

    pub fn record(&mut self, peer: &PubKeyHash, timestamp: i64) {
        record_timestamp_internal(&mut self.message_timestamps, peer, timestamp);
    }
}

pub(crate) fn ensure_timestamp_fresh_internal(
    message_timestamps: &HashMap<PubKeyHash, i64>,
    peer: &PubKeyHash,
    timestamp: i64,
    max_timestamp_drift_ms: i64,
) -> Result<(), BitVMXError> {
    let now = Utc::now().timestamp_millis();
    if timestamp > now + max_timestamp_drift_ms {
        let drift_ms = timestamp - now;
        warn!(
            "Warning: message from {} has timestamp {} too far in the future (now: {}, drift: {}ms). Accepting message despite drift.",
            peer, timestamp, now, drift_ms
        );
        // Don't reject - clock skew or network delays can cause legitimate drift
    }
    if timestamp < now - max_timestamp_drift_ms {
        let drift_ms = now - timestamp;
        warn!(
            "Warning: message from {} has timestamp {} too old (now: {}, drift: {}ms). Accepting message despite drift.",
            peer, timestamp, now, drift_ms
        );
        // Don't reject - clock skew or network delays can cause legitimate drift
    }
    if let Some(last_timestamp) = message_timestamps.get(peer) {
        if timestamp <= *last_timestamp {
            warn!(
                "Rejecting message from {}: timestamp {} not newer than last seen {}",
                peer, timestamp, last_timestamp
            );
            return Err(BitVMXError::TimestampReplayAttack {
                peer: peer.clone(),
                timestamp,
                last_timestamp: *last_timestamp,
            });
        }
    }
    Ok(())
}

pub(crate) fn record_timestamp_internal(
    message_timestamps: &mut HashMap<PubKeyHash, i64>,
    peer: &PubKeyHash,
    timestamp: i64,
) {
    message_timestamps.insert(peer.clone(), timestamp);
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    const TEST_MAX_TIMESTAMP_DRIFT_MS: i64 = 1_000;

    fn peer() -> PubKeyHash {
        "peer-hash".to_string()
    }

    #[test]
    fn ensure_timestamp_fresh_internal_accepts_recent_message() {
        let map = HashMap::new();
        let now = Utc::now().timestamp_millis();
        ensure_timestamp_fresh_internal(&map, &peer(), now, TEST_MAX_TIMESTAMP_DRIFT_MS).unwrap();
    }

    #[test]
    fn ensure_timestamp_fresh_internal_warns_but_accepts_future_message() {
        let map = HashMap::new();
        // Use a larger margin to account for timing differences between test and function
        let future = Utc::now().timestamp_millis() + TEST_MAX_TIMESTAMP_DRIFT_MS + 1000;
        let result =
            ensure_timestamp_fresh_internal(&map, &peer(), future, TEST_MAX_TIMESTAMP_DRIFT_MS);
        // Should accept despite drift (only warns, doesn't reject)
        assert!(result.is_ok());
    }

    #[test]
    fn ensure_timestamp_fresh_internal_warns_but_accepts_stale_message() {
        let map = HashMap::new();
        // Use a larger margin to account for timing differences between test and function
        let past = Utc::now().timestamp_millis() - TEST_MAX_TIMESTAMP_DRIFT_MS - 1000;
        let result =
            ensure_timestamp_fresh_internal(&map, &peer(), past, TEST_MAX_TIMESTAMP_DRIFT_MS);
        // Should accept despite drift (only warns, doesn't reject)
        assert!(result.is_ok());
    }

    #[test]
    fn ensure_timestamp_fresh_internal_rejects_replay() {
        let mut map = HashMap::new();
        let now = Utc::now().timestamp_millis();
        record_timestamp_internal(&mut map, &peer(), now);
        let replay =
            ensure_timestamp_fresh_internal(&map, &peer(), now, TEST_MAX_TIMESTAMP_DRIFT_MS);
        assert!(matches!(
            replay,
            Err(BitVMXError::TimestampReplayAttack { .. })
        ));
        let older =
            ensure_timestamp_fresh_internal(&map, &peer(), now - 1, TEST_MAX_TIMESTAMP_DRIFT_MS);
        assert!(matches!(
            older,
            Err(BitVMXError::TimestampReplayAttack { .. })
        ));
    }

    #[test]
    fn record_timestamp_internal_updates_state() {
        let mut map = HashMap::new();
        let now = Utc::now().timestamp_millis();
        record_timestamp_internal(&mut map, &peer(), now);
        assert_eq!(map.get(&peer()), Some(&now));

        let newer = now + Duration::milliseconds(1).num_milliseconds();
        record_timestamp_internal(&mut map, &peer(), newer);
        assert_eq!(map.get(&peer()), Some(&newer));
    }
}
