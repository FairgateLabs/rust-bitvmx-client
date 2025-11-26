use crate::errors::BitVMXError;
use bitvmx_operator_comms::operator_comms::PubKeyHash;
use chrono::Utc;
use std::collections::HashMap;
use tracing::warn;

pub const MAX_TIMESTAMP_DRIFT_MS: i64 = 1_000; // 1 second in milliseconds
pub const ENABLE_TIMESTAMP_CHECK: bool = true; // enabled or disabled timestamp check

pub struct TimestampVerifier {
    message_timestamps: HashMap<PubKeyHash, i64>,
    enable_check: bool,
}

impl TimestampVerifier {
    pub fn new(enable_check: bool) -> Self {
        Self {
            message_timestamps: HashMap::new(),
            enable_check,
        }
    }

    pub fn ensure_fresh(&self, peer: &PubKeyHash, timestamp: i64) -> Result<(), BitVMXError> {
        if !self.enable_check {
            return Ok(());
        }

        ensure_timestamp_fresh_internal(&self.message_timestamps, peer, timestamp)
    }

    pub fn record(&mut self, peer: &PubKeyHash, timestamp: i64) {
        record_timestamp_internal(&mut self.message_timestamps, peer, timestamp);
    }
}

impl Default for TimestampVerifier {
    fn default() -> Self {
        Self::new(ENABLE_TIMESTAMP_CHECK)
    }
}

pub(crate) fn ensure_timestamp_fresh_internal(
    message_timestamps: &HashMap<PubKeyHash, i64>,
    peer: &PubKeyHash,
    timestamp: i64,
) -> Result<(), BitVMXError> {
    let now = Utc::now().timestamp_millis();
    if timestamp > now + MAX_TIMESTAMP_DRIFT_MS {
        let drift_ms = timestamp - now;
        warn!(
            "Rejecting message from {}: timestamp {} is too far in the future (now: {}, drift: {}ms)",
            peer, timestamp, now, drift_ms
        );
        return Err(BitVMXError::TimestampTooFarInFuture {
            peer: peer.clone(),
            timestamp,
            now,
            drift_ms,
            max_drift_ms: MAX_TIMESTAMP_DRIFT_MS,
        });
    }
    if timestamp < now - MAX_TIMESTAMP_DRIFT_MS {
        let drift_ms = now - timestamp;
        warn!(
            "Rejecting message from {}: timestamp {} is too old (now: {}, drift: {}ms)",
            peer, timestamp, now, drift_ms
        );
        return Err(BitVMXError::TimestampTooOld {
            peer: peer.clone(),
            timestamp,
            now,
            drift_ms,
            max_drift_ms: MAX_TIMESTAMP_DRIFT_MS,
        });
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

    fn peer() -> PubKeyHash {
        "peer-hash".to_string()
    }

    fn ensure_timestamp_fresh_internal_accepts_recent_message_case() {
        let map = HashMap::new();
        let now = Utc::now().timestamp_millis();
        ensure_timestamp_fresh_internal(&map, &peer(), now).unwrap();
    }

    fn ensure_timestamp_fresh_internal_rejects_future_message_case() {
        let map = HashMap::new();
        // Use a larger margin to account for timing differences between test and function
        let future = Utc::now().timestamp_millis() + MAX_TIMESTAMP_DRIFT_MS + 1000;
        let result = ensure_timestamp_fresh_internal(&map, &peer(), future);
        assert!(matches!(
            result,
            Err(BitVMXError::TimestampTooFarInFuture { .. })
        ));
    }

    fn ensure_timestamp_fresh_internal_rejects_stale_message_case() {
        let map = HashMap::new();
        // Use a larger margin to account for timing differences between test and function
        let past = Utc::now().timestamp_millis() - MAX_TIMESTAMP_DRIFT_MS - 1000;
        let result = ensure_timestamp_fresh_internal(&map, &peer(), past);
        assert!(matches!(result, Err(BitVMXError::TimestampTooOld { .. })));
    }

    fn ensure_timestamp_fresh_internal_rejects_replay_case() {
        let mut map = HashMap::new();
        let now = Utc::now().timestamp_millis();
        record_timestamp_internal(&mut map, &peer(), now);
        let replay = ensure_timestamp_fresh_internal(&map, &peer(), now);
        assert!(matches!(
            replay,
            Err(BitVMXError::TimestampReplayAttack { .. })
        ));
        let older = ensure_timestamp_fresh_internal(&map, &peer(), now - 1);
        assert!(matches!(
            older,
            Err(BitVMXError::TimestampReplayAttack { .. })
        ));
    }

    fn record_timestamp_internal_updates_state_case() {
        let mut map = HashMap::new();
        let now = Utc::now().timestamp_millis();
        record_timestamp_internal(&mut map, &peer(), now);
        assert_eq!(map.get(&peer()), Some(&now));

        let newer = now + Duration::milliseconds(1).num_milliseconds();
        record_timestamp_internal(&mut map, &peer(), newer);
        assert_eq!(map.get(&peer()), Some(&newer));
    }

    #[test]
    fn ensure_timestamp_fresh_internal_accepts_recent_message() {
        ensure_timestamp_fresh_internal_accepts_recent_message_case();
    }

    #[test]
    fn ensure_timestamp_fresh_internal_rejects_future_message() {
        ensure_timestamp_fresh_internal_rejects_future_message_case();
    }

    #[test]
    fn ensure_timestamp_fresh_internal_rejects_stale_message() {
        ensure_timestamp_fresh_internal_rejects_stale_message_case();
    }

    #[test]
    fn ensure_timestamp_fresh_internal_rejects_replay() {
        ensure_timestamp_fresh_internal_rejects_replay_case();
    }

    #[test]
    fn record_timestamp_internal_updates_state() {
        record_timestamp_internal_updates_state_case();
    }
}
