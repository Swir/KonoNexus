use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

pub const MAX_AUTO_COORDINATORS_PER_ROUND: usize = 3;
pub const AUTO_RENDEZVOUS_RETRY_DELAY: Duration = Duration::from_secs(2);
pub const AUTO_RENDEZVOUS_ROUND_COOLDOWN: Duration = Duration::from_secs(30);
pub const AUTO_RENDEZVOUS_LIFETIME: Duration = Duration::from_secs(120);
pub const MAX_AUTO_RENDEZVOUS_TARGETS: usize = 256;

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
    expires_at: Instant,
}

impl AutoRendezvousState {
    pub fn new(target_node_id: String, now: Instant) -> Self {
        Self {
            target_node_id,
            tried: HashSet::new(),
            next_attempt_at: now,
            round_started_at: now,
            expires_at: now + AUTO_RENDEZVOUS_LIFETIME,
        }
    }

    pub fn target_node_id(&self) -> &str {
        &self.target_node_id
    }

    pub fn expired(&self, now: Instant) -> bool {
        now >= self.expires_at
    }

    pub fn round_exhausted(&self, candidates: &[CoordinatorCandidate]) -> bool {
        !self.tried.is_empty()
            && (self.tried.len() >= MAX_AUTO_COORDINATORS_PER_ROUND
                || candidates
                    .iter()
                    .all(|candidate| self.tried.contains(&candidate.endpoint)))
    }

    pub fn next_candidate(
        &mut self,
        candidates: &[CoordinatorCandidate],
        now: Instant,
    ) -> Option<SocketAddr> {
        if self.expired(now) || now < self.next_attempt_at {
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
                if candidate.endpoint.is_ipv6() {
                    0_u8
                } else {
                    1_u8
                },
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

pub fn admit_auto_rendezvous_target(
    active: &mut HashMap<String, AutoRendezvousState>,
    target_node_id: String,
    now: Instant,
) -> bool {
    active.retain(|_, state| !state.expired(now));

    if active.contains_key(&target_node_id) {
        return true;
    }
    if active.len() >= MAX_AUTO_RENDEZVOUS_TARGETS {
        return false;
    }

    active.insert(
        target_node_id.clone(),
        AutoRendezvousState::new(target_node_id, now),
    );
    true
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
    fn state_lifetime_and_target_admission_are_bounded() {
        let now = Instant::now();
        let mut state = AutoRendezvousState::new("knp1target".into(), now);
        let candidate = CoordinatorCandidate {
            endpoint: "203.0.113.10:47000".parse().unwrap(),
            first_seen: now,
        };

        assert!(!state.expired(now + Duration::from_secs(119)));
        assert!(state.expired(now + AUTO_RENDEZVOUS_LIFETIME));
        assert_eq!(
            state.next_candidate(&[candidate], now + AUTO_RENDEZVOUS_LIFETIME),
            None
        );

        let mut active = HashMap::new();
        for index in 0..MAX_AUTO_RENDEZVOUS_TARGETS {
            assert!(admit_auto_rendezvous_target(
                &mut active,
                format!("knp1target{index:03}"),
                now
            ));
        }
        assert_eq!(active.len(), MAX_AUTO_RENDEZVOUS_TARGETS);
        assert!(!admit_auto_rendezvous_target(
            &mut active,
            "knp1overflow".into(),
            now
        ));

        let later = now + AUTO_RENDEZVOUS_LIFETIME;
        assert!(admit_auto_rendezvous_target(
            &mut active,
            "knp1after-expiry".into(),
            later
        ));
        assert_eq!(active.len(), 1);
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

    #[test]
    fn round_exhaustion_requires_every_available_coordinator_or_the_hard_cap() {
        let now = Instant::now();
        let candidates: Vec<CoordinatorCandidate> = (1..=4)
            .map(|last_octet| CoordinatorCandidate {
                endpoint: format!("203.0.113.{last_octet}:47000").parse().unwrap(),
                first_seen: now,
            })
            .collect();
        let mut state = AutoRendezvousState::new("knp1target".into(), now);

        assert!(!state.round_exhausted(&candidates));
        for index in 0..MAX_AUTO_COORDINATORS_PER_ROUND {
            let attempt_at =
                now + AUTO_RENDEZVOUS_RETRY_DELAY.saturating_mul(u32::try_from(index).unwrap());
            assert!(state.next_candidate(&candidates, attempt_at).is_some());
        }
        assert!(state.round_exhausted(&candidates));
    }
}
