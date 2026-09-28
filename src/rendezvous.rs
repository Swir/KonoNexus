use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

pub const MAX_AUTO_COORDINATORS_PER_ROUND: usize = 3;
pub const AUTO_RENDEZVOUS_RETRY_DELAY: Duration = Duration::from_secs(2);
pub const AUTO_RENDEZVOUS_ROUND_COOLDOWN: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy)]
pub struct CoordinatorCandidate {
    pub endpoint: SocketAddr,
    pub first_seen: Instant,
}

#[derive(Debug)]
pub struct AutoRendezvousState {
    target_node_id: String,
    tried: HashSet<SocketAddr>,
    next_attempt_at: Instant,
    round_started_at: Instant,
}

impl AutoRendezvousState {
    pub fn new(target_node_id: String, now: Instant) -> Self {
        Self {
            target_node_id,
            tried: HashSet::new(),
            next_attempt_at: now,
            round_started_at: now,
        }
    }

    pub fn target_node_id(&self) -> &str {
        &self.target_node_id
    }

    pub fn next_candidate(
        &mut self,
        candidates: &[CoordinatorCandidate],
        now: Instant,
    ) -> Option<SocketAddr> {
        if now < self.next_attempt_at {
            return None;
        }

        if self.tried.len() >= MAX_AUTO_COORDINATORS_PER_ROUND {
            let reset_at = self.round_started_at + AUTO_RENDEZVOUS_ROUND_COOLDOWN;
            if now < reset_at {
                self.next_attempt_at = reset_at;
                return None;
            }

            self.tried.clear();
            self.round_started_at = now;
        }

        let mut available: Vec<CoordinatorCandidate> = candidates
            .iter()
            .copied()
            .filter(|candidate| !self.tried.contains(&candidate.endpoint))
            .collect();

        available.sort_by_key(|candidate| {
            (
                if candidate.endpoint.is_ipv6() { 0_u8 } else { 1_u8 },
                candidate.first_seen,
                candidate.endpoint,
            )
        });

        let selected = available.first()?.endpoint;
        self.tried.insert(selected);
        self.next_attempt_at = now + AUTO_RENDEZVOUS_RETRY_DELAY;
        Some(selected)
    }

    pub fn hurry(&mut self, now: Instant) {
        self.next_attempt_at = now;
    }

    pub fn defer(&mut self, now: Instant, delay: Duration) {
        self.next_attempt_at = now + delay;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selector_prefers_ipv6_then_long_lived_peers() {
        let now = Instant::now();
        let candidates = vec![
            CoordinatorCandidate {
                endpoint: "203.0.113.2:47000".parse().unwrap(),
                first_seen: now - Duration::from_secs(30),
            },
            CoordinatorCandidate {
                endpoint: "[2001:db8::2]:47000".parse().unwrap(),
                first_seen: now - Duration::from_secs(5),
            },
            CoordinatorCandidate {
                endpoint: "[2001:db8::1]:47000".parse().unwrap(),
                first_seen: now - Duration::from_secs(30),
            },
        ];

        let mut state = AutoRendezvousState::new("knp1target".into(), now);
        assert_eq!(
            state.next_candidate(&candidates, now),
            Some("[2001:db8::1]:47000".parse().unwrap())
        );
    }

    #[test]
    fn selector_does_not_repeat_coordinator_in_same_round() {
        let now = Instant::now();
        let endpoint: SocketAddr = "203.0.113.2:47000".parse().unwrap();
        let candidates = vec![CoordinatorCandidate {
            endpoint,
            first_seen: now,
        }];
        let mut state = AutoRendezvousState::new("knp1target".into(), now);

        assert_eq!(state.next_candidate(&candidates, now), Some(endpoint));
        state.hurry(now + Duration::from_millis(1));
        assert_eq!(
            state.next_candidate(&candidates, now + Duration::from_millis(1)),
            None
        );
    }
}
