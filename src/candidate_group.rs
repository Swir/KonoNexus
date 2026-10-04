use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
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
        let candidates = select_bounded_candidates(candidates, MAX_CANDIDATES_PER_GROUP);
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
        let attempted = self.candidates[..self.next_index].to_vec();
        let attempted_set: HashSet<SocketAddr> = attempted.iter().copied().collect();
        let remaining_capacity = MAX_CANDIDATES_PER_GROUP.saturating_sub(attempted.len());
        let pending: Vec<SocketAddr> = self.candidates[self.next_index..]
            .iter()
            .copied()
            .chain(candidates)
            .filter(|endpoint| !attempted_set.contains(endpoint))
            .collect();
        let mut remaining = select_bounded_candidates(pending.iter().copied(), remaining_capacity);
        let attempted_native_ipv6 = attempted.iter().copied().any(is_native_ipv6);
        let attempted_ipv4_fallback = attempted
            .iter()
            .copied()
            .any(|endpoint| !is_native_ipv6(endpoint));
        if remaining_capacity == 1 && attempted_native_ipv6 && !attempted_ipv4_fallback {
            if let Some(fallback) = pending
                .iter()
                .copied()
                .find(|endpoint| !is_native_ipv6(*endpoint))
            {
                remaining = vec![fallback];
            }
        }
        self.candidates = attempted.into_iter().chain(remaining).collect();
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

fn prioritize_ipv6(candidates: impl IntoIterator<Item = SocketAddr>) -> Vec<SocketAddr> {
    let mut candidates: Vec<SocketAddr> = candidates.into_iter().collect();
    candidates.sort_by_key(|endpoint| match endpoint.ip() {
        IpAddr::V6(ip) if ip.to_ipv4_mapped().is_none() => 0_u8,
        _ => 1_u8,
    });
    candidates
}

fn select_bounded_candidates(
    candidates: impl IntoIterator<Item = SocketAddr>,
    limit: usize,
) -> Vec<SocketAddr> {
    if limit == 0 {
        return Vec::new();
    }

    let mut seen = HashSet::new();
    let candidates: Vec<SocketAddr> = prioritize_ipv6(candidates)
        .into_iter()
        .filter(|endpoint| seen.insert(*endpoint))
        .collect();
    if candidates.len() <= limit {
        return candidates;
    }

    let ipv6_count = candidates
        .iter()
        .filter(|endpoint| is_native_ipv6(**endpoint))
        .count();
    let Some(first_ipv4) = candidates
        .iter()
        .position(|endpoint| !is_native_ipv6(*endpoint))
    else {
        return candidates.into_iter().take(limit).collect();
    };
    if limit < 2 || ipv6_count == 0 {
        return candidates.into_iter().take(limit).collect();
    }

    let mut selected: Vec<SocketAddr> = candidates
        .iter()
        .copied()
        .filter(|endpoint| is_native_ipv6(*endpoint))
        .take(limit - 1)
        .collect();
    selected.push(candidates[first_ipv4]);
    for endpoint in candidates {
        if selected.len() == limit {
            break;
        }
        if !selected.contains(&endpoint) {
            selected.push(endpoint);
        }
    }
    selected
}

fn is_native_ipv6(endpoint: SocketAddr) -> bool {
    matches!(endpoint.ip(), IpAddr::V6(ip) if ip.to_ipv4_mapped().is_none())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(port: u16) -> SocketAddr {
        format!("192.0.2.10:{port}").parse().unwrap()
    }

    #[test]
    fn ipv6_candidates_are_prioritized_before_deduplication_and_cap() {
        let now = Instant::now();
        let ipv6_first: SocketAddr = "[2001:db8::1]:47006".parse().unwrap();
        let ipv6_second: SocketAddr = "[2001:db8::2]:47007".parse().unwrap();
        let group = CandidateGroup::new(
            [
                endpoint(47001),
                endpoint(47001),
                endpoint(47002),
                ipv6_first,
                endpoint(47003),
                ipv6_second,
            ],
            now,
        );
        assert_eq!(
            group.candidates(),
            &[ipv6_first, ipv6_second, endpoint(47001)]
        );
    }

    #[test]
    fn mapped_ipv4_candidate_is_fallback_and_keeps_its_exact_address() {
        let now = Instant::now();
        let mapped_ipv4: SocketAddr = "[::ffff:192.0.2.10]:47001".parse().unwrap();
        let ipv6: SocketAddr = "[2001:db8::1]:47002".parse().unwrap();
        let group = CandidateGroup::new([mapped_ipv4, ipv6], now);

        assert_eq!(group.candidates(), &[ipv6, mapped_ipv4]);
        assert_eq!(group.candidates()[1].port(), 47001);
        assert!(group.candidates()[1].is_ipv6());
    }

    #[test]
    fn ipv4_candidates_remain_as_bounded_fallback_without_synthesizing_ports() {
        let now = Instant::now();
        let ipv6: SocketAddr = "[2001:db8::1]:48123".parse().unwrap();
        let group = CandidateGroup::new(
            [endpoint(47001), endpoint(47002), ipv6, endpoint(47003)],
            now,
        );

        assert_eq!(
            group.candidates(),
            &[ipv6, endpoint(47001), endpoint(47002)]
        );
    }

    #[test]
    fn one_ipv4_fallback_is_reserved_when_ipv6_candidates_exceed_the_cap() {
        let now = Instant::now();
        let ipv6_first: SocketAddr = "[2001:db8::1]:47001".parse().unwrap();
        let ipv6_second: SocketAddr = "[2001:db8::2]:47002".parse().unwrap();
        let ipv4_fallback = endpoint(47003);
        let group = CandidateGroup::new(
            [
                ipv6_first,
                ipv6_second,
                "[2001:db8::3]:47004".parse().unwrap(),
                ipv4_fallback,
            ],
            now,
        );

        assert_eq!(
            group.candidates(),
            &[ipv6_first, ipv6_second, ipv4_fallback]
        );
    }

    #[test]
    fn extending_prioritizes_new_ipv6_without_reordering_attempted_candidates() {
        let now = Instant::now();
        let attempted_ipv4 = endpoint(47001);
        let pending_ipv4 = endpoint(47002);
        let pending_ipv6: SocketAddr = "[2001:db8::1]:47003".parse().unwrap();
        let mut group = CandidateGroup::new([attempted_ipv4, pending_ipv4], now);
        assert_eq!(
            group.next_action(now),
            Some(CandidateAction::Try(attempted_ipv4))
        );

        group.extend([pending_ipv6, attempted_ipv4, pending_ipv4]);

        assert_eq!(
            group.candidates(),
            &[attempted_ipv4, pending_ipv6, pending_ipv4]
        );
    }

    #[test]
    fn extending_after_two_ipv6_attempts_preserves_ipv4_fallback() {
        let now = Instant::now();
        let ipv6_first: SocketAddr = "[2001:db8::1]:47001".parse().unwrap();
        let ipv6_second: SocketAddr = "[2001:db8::2]:47002".parse().unwrap();
        let ipv6_new: SocketAddr = "[2001:db8::3]:47003".parse().unwrap();
        let ipv4_fallback = endpoint(47004);
        let mut group = CandidateGroup::new([ipv6_first, ipv6_second, ipv4_fallback], now);

        assert_eq!(
            group.next_action(now),
            Some(CandidateAction::Try(ipv6_first))
        );
        assert_eq!(
            group.next_action(now + CANDIDATE_STAGGER),
            Some(CandidateAction::Try(ipv6_second))
        );

        group.extend([ipv6_new]);

        assert_eq!(
            group.candidates(),
            &[ipv6_first, ipv6_second, ipv4_fallback]
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
