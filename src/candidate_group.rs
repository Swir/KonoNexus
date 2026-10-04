use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

pub const MAX_CANDIDATES_PER_GROUP: usize = 3;
pub const MAX_ACTIVE_CANDIDATE_GROUPS: usize = 256;
pub const CANDIDATE_GROUP_TTL: Duration = Duration::from_secs(30);
pub const CANDIDATE_STAGGER: Duration = Duration::from_secs(4);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateAction {
    Try(SocketAddr),
    Exhausted,
}

#[derive(Debug, Clone)]
pub struct CandidateGroup {
    candidates: Vec<SocketAddr>,
    next_index: usize,
    next_at: Instant,
    expires_at: Instant,
    completed: bool,
    fallback_emitted: bool,
}

impl CandidateGroup {
    pub fn new(candidates: impl IntoIterator<Item = SocketAddr>, now: Instant) -> Self {
        let mut seen = HashSet::new();
        let candidates = candidates
            .into_iter()
            .filter(|endpoint| seen.insert(*endpoint))
            .take(MAX_CANDIDATES_PER_GROUP)
            .collect();
        Self {
            candidates,
            next_index: 0,
            next_at: now,
            expires_at: now + CANDIDATE_GROUP_TTL,
            completed: false,
            fallback_emitted: false,
        }
    }

    pub fn candidates(&self) -> &[SocketAddr] {
        &self.candidates
    }

    pub fn extend(&mut self, candidates: impl IntoIterator<Item = SocketAddr>) {
        let mut seen: HashSet<SocketAddr> = self.candidates.iter().copied().collect();
        for endpoint in candidates {
            if self.candidates.len() >= MAX_CANDIDATES_PER_GROUP {
                break;
            }
            if seen.insert(endpoint) {
                self.candidates.push(endpoint);
            }
        }
    }

    pub fn next_action(&mut self, now: Instant) -> Option<CandidateAction> {
        if self.completed || self.fallback_emitted || now < self.next_at {
            return None;
        }
        if now >= self.expires_at || self.next_index >= self.candidates.len() {
            self.fallback_emitted = true;
            return Some(CandidateAction::Exhausted);
        }

        let endpoint = self.candidates[self.next_index];
        self.next_index += 1;
        self.next_at = now + CANDIDATE_STAGGER;
        Some(CandidateAction::Try(endpoint))
    }

    pub fn complete(&mut self) {
        self.completed = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(port: u16) -> SocketAddr {
        format!("192.0.2.10:{port}").parse().unwrap()
    }

    #[test]
    fn caps_dedupes_and_preserves_candidate_order() {
        let now = Instant::now();
        let group = CandidateGroup::new(
            [
                endpoint(47001),
                endpoint(47001),
                endpoint(47002),
                endpoint(47003),
                endpoint(47004),
            ],
            now,
        );
        assert_eq!(
            group.candidates(),
            &[endpoint(47001), endpoint(47002), endpoint(47003)]
        );
    }

    #[test]
    fn candidates_are_exact_and_never_synthesized_from_ports() {
        let now = Instant::now();
        let supplied = [endpoint(47001), endpoint(48000)];
        let mut group = CandidateGroup::new(supplied, now);
        assert_eq!(
            group.next_action(now),
            Some(CandidateAction::Try(endpoint(47001)))
        );
        assert_eq!(
            group.next_action(now + CANDIDATE_STAGGER),
            Some(CandidateAction::Try(endpoint(48000)))
        );
    }

    #[test]
    fn authenticated_success_cancels_remaining_candidates_and_fallback() {
        let now = Instant::now();
        let mut group = CandidateGroup::new([endpoint(47001), endpoint(47002)], now);
        assert_eq!(
            group.next_action(now),
            Some(CandidateAction::Try(endpoint(47001)))
        );
        group.complete();
        assert_eq!(group.next_action(now + CANDIDATE_GROUP_TTL), None);
    }

    #[test]
    fn escalation_waits_for_candidate_group_exhaustion_and_fires_once() {
        let now = Instant::now();
        let mut group = CandidateGroup::new([endpoint(47001), endpoint(47002)], now);
        assert_eq!(
            group.next_action(now),
            Some(CandidateAction::Try(endpoint(47001)))
        );
        assert_eq!(
            group.next_action(now + CANDIDATE_STAGGER),
            Some(CandidateAction::Try(endpoint(47002)))
        );
        assert_eq!(
            group.next_action(now + CANDIDATE_STAGGER * 2),
            Some(CandidateAction::Exhausted)
        );
        assert_eq!(group.next_action(now + CANDIDATE_STAGGER * 3), None);
    }

    #[test]
    fn candidate_group_expires_with_a_bounded_lifetime() {
        let now = Instant::now();
        let mut group = CandidateGroup::new([endpoint(47001)], now);
        assert_eq!(
            group.next_action(now),
            Some(CandidateAction::Try(endpoint(47001)))
        );
        assert_eq!(
            group.next_action(now + CANDIDATE_GROUP_TTL),
            Some(CandidateAction::Exhausted)
        );
    }
}
