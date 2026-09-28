use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

pub const PUNCH_MAX_ATTEMPTS: usize = 7;
pub const PUNCH_START_DELAY: Duration = Duration::from_millis(100);
pub const PUNCH_AUTH_TTL: Duration = Duration::from_secs(5);

const RETRY_DELAYS_AFTER_SEND_MS: [u64; PUNCH_MAX_ATTEMPTS - 1] =
    [100, 150, 250, 400, 650, 1_000];

#[derive(Debug, Clone)]
pub struct PunchSchedule {
    expected_node_id: String,
    candidate_endpoint: SocketAddr,
    expires_at: Instant,
    next_probe_at: Option<Instant>,
    attempts_sent: usize,
}

impl PunchSchedule {
    pub fn new(expected_node_id: String, candidate_endpoint: SocketAddr, now: Instant) -> Self {
        Self {
            expected_node_id,
            candidate_endpoint,
            expires_at: now + PUNCH_AUTH_TTL,
            next_probe_at: Some(now + PUNCH_START_DELAY),
            attempts_sent: 0,
        }
    }

    pub fn candidate_allowed(endpoint: SocketAddr) -> bool {
        if endpoint.port() == 0 {
            return false;
        }

        match endpoint.ip() {
            IpAddr::V4(ip) => {
                !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast() && !ip.is_broadcast()
            }
            IpAddr::V6(ip) => !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast(),
        }
    }

    pub fn expected_node_id(&self) -> &str {
        &self.expected_node_id
    }

    pub fn candidate_endpoint(&self) -> SocketAddr {
        self.candidate_endpoint
    }

    pub fn attempts_sent(&self) -> usize {
        self.attempts_sent
    }

    pub fn probe_due(&self, now: Instant) -> bool {
        now < self.expires_at
            && self.attempts_sent < PUNCH_MAX_ATTEMPTS
            && self.next_probe_at.is_some_and(|next| next <= now)
    }

    pub fn mark_probe_sent(&mut self, now: Instant) -> usize {
        if self.attempts_sent >= PUNCH_MAX_ATTEMPTS {
            return self.attempts_sent;
        }

        self.attempts_sent += 1;

        if self.attempts_sent < PUNCH_MAX_ATTEMPTS {
            let retry_delay =
                Duration::from_millis(RETRY_DELAYS_AFTER_SEND_MS[self.attempts_sent - 1]);
            self.next_probe_at = Some(now + retry_delay);
        } else {
            self.next_probe_at = None;
        }

        self.attempts_sent
    }

    pub fn is_authorized(&self, sender_node_id: &str, now: Instant) -> bool {
        self.expected_node_id == sender_node_id && now < self.expires_at
    }

    pub fn is_expired(&self, now: Instant) -> bool {
        now >= self.expires_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn punch_schedule_uses_bounded_backoff_burst() {
        let start = Instant::now();
        let endpoint: SocketAddr = "203.0.113.20:47000".parse().unwrap();
        let mut schedule = PunchSchedule::new("knp1peer".into(), endpoint, start);

        assert!(!schedule.probe_due(start));

        let offsets_ms = [100_u64, 200, 350, 600, 1_000, 1_650, 2_650];
        for (index, offset) in offsets_ms.into_iter().enumerate() {
            let now = start + Duration::from_millis(offset);
            assert!(schedule.probe_due(now));
            assert_eq!(schedule.mark_probe_sent(now), index + 1);
        }

        assert_eq!(schedule.attempts_sent(), PUNCH_MAX_ATTEMPTS);
        assert!(!schedule.probe_due(start + Duration::from_secs(3)));
        assert!(schedule.is_authorized("knp1peer", start + Duration::from_secs(4)));
        assert!(schedule.is_expired(start + PUNCH_AUTH_TTL));
    }

    #[test]
    fn punch_authorization_is_bound_to_expected_identity() {
        let start = Instant::now();
        let endpoint: SocketAddr = "198.51.100.20:47000".parse().unwrap();
        let schedule = PunchSchedule::new("knp1expected".into(), endpoint, start);

        assert!(schedule.is_authorized("knp1expected", start));
        assert!(!schedule.is_authorized("knp1attacker", start));
    }

    #[test]
    fn unsafe_rendezvous_targets_are_rejected() {
        assert!(!PunchSchedule::candidate_allowed(
            "127.0.0.1:47000".parse().unwrap()
        ));
        assert!(!PunchSchedule::candidate_allowed(
            "0.0.0.0:47000".parse().unwrap()
        ));
        assert!(!PunchSchedule::candidate_allowed(
            "224.0.0.1:47000".parse().unwrap()
        ));
        assert!(PunchSchedule::candidate_allowed(
            "192.168.1.20:47000".parse().unwrap()
        ));
        assert!(PunchSchedule::candidate_allowed(
            "203.0.113.20:47000".parse().unwrap()
        ));
    }
}
