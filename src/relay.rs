use crate::security::SequenceWindow;
use anyhow::{bail, Result};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

pub const MAX_RELAY_CIRCUITS: usize = 256;
pub const MAX_RELAY_CIRCUITS_PER_NODE: usize = 16;
pub const MAX_RELAY_CELL_BYTES: usize = 3 * 1024;
pub const MAX_RELAY_CELLS_PER_SECOND: usize = 128;
pub const MAX_RELAY_BYTES_PER_SECOND: usize = 256 * 1024;
pub const RELAY_CIRCUIT_TTL: Duration = Duration::from_secs(120);
pub const RELAY_RATE_WINDOW: Duration = Duration::from_secs(1);
pub const RELAY_ABUSE_WINDOW: Duration = Duration::from_secs(60);
pub const RELAY_ABUSE_DECAY: Duration = Duration::from_secs(120);
pub const MAX_RELAY_ABUSE_TRACKED_NODES: usize = 2_048;
pub const MAX_RELAY_ABUSE_PENALTY_LEVEL: u8 = 3;
pub const RELAY_ABUSE_VIOLATIONS_PER_LEVEL: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayCircuitState {
    PendingTargetConsent,
    Active,
}

#[derive(Debug, Clone)]
struct RelayRateWindow {
    started_at: Instant,
    cells: usize,
    bytes: usize,
}

impl RelayRateWindow {
    fn new(now: Instant) -> Self {
        Self {
            started_at: now,
            cells: 0,
            bytes: 0,
        }
    }

    fn consume(
        &mut self,
        bytes: usize,
        now: Instant,
        max_cells: usize,
        max_bytes: usize,
    ) -> Result<()> {
        if now.duration_since(self.started_at) >= RELAY_RATE_WINDOW {
            self.started_at = now;
            self.cells = 0;
            self.bytes = 0;
        }

        if self.cells >= max_cells || self.bytes.saturating_add(bytes) > max_bytes {
            bail!("relay circuit rate quota exceeded");
        }

        self.cells += 1;
        self.bytes += bytes;
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct RelayAbuseState {
    window_started_at: Instant,
    last_violation_at: Instant,
    violations: usize,
    penalty_level: u8,
}

impl RelayAbuseState {
    fn new(now: Instant) -> Self {
        Self {
            window_started_at: now,
            last_violation_at: now,
            violations: 0,
            penalty_level: 0,
        }
    }

    fn refresh(&mut self, now: Instant) {
        if now.duration_since(self.window_started_at) >= RELAY_ABUSE_WINDOW {
            self.window_started_at = now;
            self.violations = 0;
        }

        if self.penalty_level == 0 {
            return;
        }

        let quiet_for = now.duration_since(self.last_violation_at);
        let decay_steps = quiet_for.as_secs() / RELAY_ABUSE_DECAY.as_secs();
        if decay_steps == 0 {
            return;
        }

        self.penalty_level = self
            .penalty_level
            .saturating_sub(decay_steps.min(u64::from(u8::MAX)) as u8);
        self.last_violation_at += RELAY_ABUSE_DECAY * decay_steps.min(u32::MAX as u64) as u32;
        if self.penalty_level == 0 {
            self.violations = 0;
            self.window_started_at = now;
        }
    }

    fn record_violation(&mut self, now: Instant) {
        self.refresh(now);
        if now.duration_since(self.window_started_at) >= RELAY_ABUSE_WINDOW {
            self.window_started_at = now;
            self.violations = 0;
        }
        self.last_violation_at = now;
        self.violations = self.violations.saturating_add(1);

        let desired_level = (self.violations / RELAY_ABUSE_VIOLATIONS_PER_LEVEL)
            .min(usize::from(MAX_RELAY_ABUSE_PENALTY_LEVEL)) as u8;
        self.penalty_level = self.penalty_level.max(desired_level);
    }
}

#[derive(Debug, Clone)]
pub struct RelayCircuit {
    pub circuit_id: u64,
    pub origin_endpoint: SocketAddr,
    pub origin_node_id: String,
    pub target_endpoint: SocketAddr,
    pub target_node_id: String,
    pub state: RelayCircuitState,
    pub expires_at: Instant,
    origin_window: SequenceWindow,
    target_window: SequenceWindow,
    origin_rate: RelayRateWindow,
    target_rate: RelayRateWindow,
}

#[derive(Debug, Clone)]
pub struct RelayForward {
    pub destination: SocketAddr,
    pub peer_node_id: String,
    pub circuit_id: u64,
    pub sequence: u64,
    pub opaque_payload_hex: String,
}

#[derive(Debug, Default)]
pub struct RelayManager {
    circuits: HashMap<u64, RelayCircuit>,
    abuse: HashMap<String, RelayAbuseState>,
}

impl RelayManager {
    fn prune_abuse_state(&mut self, now: Instant) {
        self.abuse.retain(|_, state| {
            state.refresh(now);
            state.penalty_level > 0
                || now.duration_since(state.last_violation_at) < RELAY_ABUSE_DECAY
        });

        while self.abuse.len() > MAX_RELAY_ABUSE_TRACKED_NODES {
            let Some(oldest) = self
                .abuse
                .iter()
                .min_by_key(|(_, state)| state.last_violation_at)
                .map(|(node_id, _)| node_id.clone())
            else {
                break;
            };
            self.abuse.remove(&oldest);
        }
    }

    fn adaptive_limits(&mut self, node_id: &str, now: Instant) -> (usize, usize) {
        self.prune_abuse_state(now);
        let penalty = self
            .abuse
            .get_mut(node_id)
            .map(|state| {
                state.refresh(now);
                state.penalty_level
            })
            .unwrap_or(0);
        let divisor = 1_usize << usize::from(penalty);
        (
            (MAX_RELAY_CELLS_PER_SECOND / divisor).max(1),
            (MAX_RELAY_BYTES_PER_SECOND / divisor).max(MAX_RELAY_CELL_BYTES),
        )
    }

    fn record_abuse_violation(&mut self, node_id: &str, now: Instant) {
        self.prune_abuse_state(now);

        if !self.abuse.contains_key(node_id)
            && self.abuse.len() >= MAX_RELAY_ABUSE_TRACKED_NODES
        {
            if let Some(oldest) = self
                .abuse
                .iter()
                .min_by_key(|(_, state)| state.last_violation_at)
                .map(|(node_id, _)| node_id.clone())
            {
                self.abuse.remove(&oldest);
            }
        }

        self.abuse
            .entry(node_id.to_owned())
            .or_insert_with(|| RelayAbuseState::new(now))
            .record_violation(now);
    }

    pub fn open(
        &mut self,
        circuit_id: u64,
        origin_endpoint: SocketAddr,
        origin_node_id: String,
        target_endpoint: SocketAddr,
        target_node_id: String,
        now: Instant,
    ) -> Result<()> {
        if self.circuits.contains_key(&circuit_id) {
            bail!("relay circuit id already exists");
        }
        if self.circuits.len() >= MAX_RELAY_CIRCUITS {
            bail!("relay circuit limit reached");
        }

        let origin_circuits = self
            .circuits
            .values()
            .filter(|circuit| {
                circuit.origin_node_id == origin_node_id || circuit.target_node_id == origin_node_id
            })
            .count();
        let target_circuits = self
            .circuits
            .values()
            .filter(|circuit| {
                circuit.origin_node_id == target_node_id || circuit.target_node_id == target_node_id
            })
            .count();

        if origin_circuits >= MAX_RELAY_CIRCUITS_PER_NODE
            || target_circuits >= MAX_RELAY_CIRCUITS_PER_NODE
        {
            bail!("per-node relay circuit limit reached");
        }

        if origin_endpoint == target_endpoint || origin_node_id == target_node_id {
            bail!("relay circuit endpoints must be distinct");
        }

        self.circuits.insert(
            circuit_id,
            RelayCircuit {
                circuit_id,
                origin_endpoint,
                origin_node_id,
                target_endpoint,
                target_node_id,
                state: RelayCircuitState::PendingTargetConsent,
                expires_at: now + RELAY_CIRCUIT_TTL,
                origin_window: SequenceWindow::default(),
                target_window: SequenceWindow::default(),
                origin_rate: RelayRateWindow::new(now),
                target_rate: RelayRateWindow::new(now),
            },
        );
        Ok(())
    }

    pub fn accept(
        &mut self,
        circuit_id: u64,
        target_endpoint: SocketAddr,
        target_node_id: &str,
        now: Instant,
    ) -> Result<(SocketAddr, String)> {
        let circuit = self
            .circuits
            .get_mut(&circuit_id)
            .ok_or_else(|| anyhow::anyhow!("relay circuit not found"))?;

        if circuit.expires_at <= now {
            bail!("relay circuit expired");
        }
        if circuit.state != RelayCircuitState::PendingTargetConsent
            || circuit.target_endpoint != target_endpoint
            || circuit.target_node_id != target_node_id
        {
            bail!("relay accept does not match pending target");
        }

        circuit.state = RelayCircuitState::Active;
        circuit.expires_at = now + RELAY_CIRCUIT_TTL;
        Ok((circuit.origin_endpoint, circuit.origin_node_id.clone()))
    }

    pub fn forward(
        &mut self,
        circuit_id: u64,
        source_endpoint: SocketAddr,
        source_node_id: &str,
        sequence: u64,
        opaque_payload_hex: String,
        now: Instant,
    ) -> Result<RelayForward> {
        let raw = hex::decode(&opaque_payload_hex)
            .map_err(|_| anyhow::anyhow!("relay payload is not valid hex"))?;
        if raw.is_empty() || raw.len() > MAX_RELAY_CELL_BYTES {
            bail!("relay payload size is invalid");
        }

        let (max_cells, max_bytes) = self.adaptive_limits(source_node_id, now);
        let forward_result = {
            let circuit = self
                .circuits
                .get_mut(&circuit_id)
                .ok_or_else(|| anyhow::anyhow!("relay circuit not found"))?;

            if circuit.expires_at <= now || circuit.state != RelayCircuitState::Active {
                bail!("relay circuit is not active");
            }

            let (destination, peer_node_id, receive_window, rate_window) = if source_endpoint
                == circuit.origin_endpoint
                && source_node_id == circuit.origin_node_id
            {
                (
                    circuit.target_endpoint,
                    circuit.target_node_id.clone(),
                    &mut circuit.origin_window,
                    &mut circuit.origin_rate,
                )
            } else if source_endpoint == circuit.target_endpoint
                && source_node_id == circuit.target_node_id
            {
                (
                    circuit.origin_endpoint,
                    circuit.origin_node_id.clone(),
                    &mut circuit.target_window,
                    &mut circuit.target_rate,
                )
            } else {
                bail!("relay cell source does not match circuit");
            };

            rate_window.consume(raw.len(), now, max_cells, max_bytes)?;
            receive_window.check_and_record(sequence)?;
            circuit.expires_at = now + RELAY_CIRCUIT_TTL;

            Ok(RelayForward {
                destination,
                peer_node_id,
                circuit_id,
                sequence,
                opaque_payload_hex,
            })
        };

        if forward_result.is_err() {
            let quota_exceeded = self.circuits.get(&circuit_id).is_some_and(|circuit| {
                let rate_window = if source_node_id == circuit.origin_node_id {
                    Some(&circuit.origin_rate)
                } else if source_node_id == circuit.target_node_id {
                    Some(&circuit.target_rate)
                } else {
                    None
                };
                rate_window.is_some_and(|rate| {
                    rate.cells >= max_cells || rate.bytes >= max_bytes
                })
            });
            if quota_exceeded {
                self.record_abuse_violation(source_node_id, now);
            }
        }

        forward_result
    }

    pub fn close(
        &mut self,
        circuit_id: u64,
        source_endpoint: SocketAddr,
        source_node_id: &str,
    ) -> Option<(SocketAddr, String)> {
        let circuit = self.circuits.get(&circuit_id)?;
        let other = if source_endpoint == circuit.origin_endpoint
            && source_node_id == circuit.origin_node_id
        {
            Some((circuit.target_endpoint, circuit.target_node_id.clone()))
        } else if source_endpoint == circuit.target_endpoint
            && source_node_id == circuit.target_node_id
        {
            Some((circuit.origin_endpoint, circuit.origin_node_id.clone()))
        } else {
            None
        }?;

        self.circuits.remove(&circuit_id);
        Some(other)
    }

    pub fn expire(&mut self, now: Instant) -> usize {
        let before = self.circuits.len();
        self.circuits.retain(|_, circuit| circuit.expires_at > now);
        self.prune_abuse_state(now);
        before.saturating_sub(self.circuits.len())
    }

    pub fn len(&self) -> usize {
        self.circuits.len()
    }

    pub fn is_empty(&self) -> bool {
        self.circuits.is_empty()
    }

    pub fn get(&self, circuit_id: u64) -> Option<&RelayCircuit> {
        self.circuits.get(&circuit_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (RelayManager, u64, SocketAddr, SocketAddr) {
        let mut relay = RelayManager::default();
        let circuit_id = 7;
        let origin: SocketAddr = "203.0.113.10:47000".parse().unwrap();
        let target: SocketAddr = "198.51.100.20:47000".parse().unwrap();
        relay
            .open(
                circuit_id,
                origin,
                "knp1origin".into(),
                target,
                "knp1target".into(),
                Instant::now(),
            )
            .unwrap();
        (relay, circuit_id, origin, target)
    }

    #[test]
    fn target_must_accept_before_cells_flow() {
        let (mut relay, id, origin, target) = setup();

        assert!(relay
            .forward(id, origin, "knp1origin", 0, "aa".into(), Instant::now())
            .is_err());

        relay
            .accept(id, target, "knp1target", Instant::now())
            .unwrap();
        let forwarded = relay
            .forward(id, origin, "knp1origin", 0, "aabb".into(), Instant::now())
            .unwrap();

        assert_eq!(forwarded.destination, target);
        assert_eq!(forwarded.peer_node_id, "knp1target");
        assert_eq!(forwarded.opaque_payload_hex, "aabb");
    }

    #[test]
    fn relay_accepts_bounded_reordered_cells() {
        let (mut relay, id, origin, target) = setup();
        relay
            .accept(id, target, "knp1target", Instant::now())
            .unwrap();

        relay
            .forward(id, origin, "knp1origin", 2, "aa".into(), Instant::now())
            .unwrap();
        relay
            .forward(id, origin, "knp1origin", 0, "bb".into(), Instant::now())
            .unwrap();
        relay
            .forward(id, origin, "knp1origin", 1, "cc".into(), Instant::now())
            .unwrap();

        assert!(relay
            .forward(id, origin, "knp1origin", 1, "dd".into(), Instant::now())
            .is_err());
    }

    #[test]
    fn relay_rejects_replay_and_oversized_cells() {
        let (mut relay, id, origin, target) = setup();
        relay
            .accept(id, target, "knp1target", Instant::now())
            .unwrap();

        relay
            .forward(id, origin, "knp1origin", 1, "aa".into(), Instant::now())
            .unwrap();
        assert!(relay
            .forward(id, origin, "knp1origin", 1, "bb".into(), Instant::now())
            .is_err());

        let oversized = hex::encode(vec![0_u8; MAX_RELAY_CELL_BYTES + 1]);
        assert!(relay
            .forward(id, target, "knp1target", 0, oversized, Instant::now())
            .is_err());
    }

    #[test]
    fn relay_enforces_per_circuit_rate_quota() {
        let (mut relay, id, origin, target) = setup();
        let now = Instant::now();
        relay.accept(id, target, "knp1target", now).unwrap();

        for sequence in 0..MAX_RELAY_CELLS_PER_SECOND as u64 {
            relay
                .forward(id, origin, "knp1origin", sequence, "aa".into(), now)
                .unwrap();
        }

        assert!(relay
            .forward(
                id,
                origin,
                "knp1origin",
                MAX_RELAY_CELLS_PER_SECOND as u64,
                "aa".into(),
                now,
            )
            .is_err());

        relay
            .forward(
                id,
                origin,
                "knp1origin",
                MAX_RELAY_CELLS_PER_SECOND as u64,
                "aa".into(),
                now + RELAY_RATE_WINDOW,
            )
            .unwrap();
    }

    #[test]
    fn repeated_quota_violations_reduce_next_window_budget() {
        let (mut relay, id, origin, target) = setup();
        let now = Instant::now();
        relay.accept(id, target, "knp1target", now).unwrap();

        for sequence in 0..MAX_RELAY_CELLS_PER_SECOND as u64 {
            relay
                .forward(id, origin, "knp1origin", sequence, "aa".into(), now)
                .unwrap();
        }

        for offset in 0..RELAY_ABUSE_VIOLATIONS_PER_LEVEL {
            assert!(relay
                .forward(
                    id,
                    origin,
                    "knp1origin",
                    MAX_RELAY_CELLS_PER_SECOND as u64 + offset as u64,
                    "aa".into(),
                    now,
                )
                .is_err());
        }

        let penalized_now = now + RELAY_RATE_WINDOW;
        let reduced_cells = MAX_RELAY_CELLS_PER_SECOND / 2;
        for offset in 0..reduced_cells as u64 {
            relay
                .forward(
                    id,
                    origin,
                    "knp1origin",
                    1_000 + offset,
                    "aa".into(),
                    penalized_now,
                )
                .unwrap();
        }
        assert!(relay
            .forward(
                id,
                origin,
                "knp1origin",
                2_000,
                "aa".into(),
                penalized_now,
            )
            .is_err());
    }

    #[test]
    fn adaptive_penalty_decays_after_quiet_period() {
        let mut relay = RelayManager::default();
        let now = Instant::now();

        for _ in 0..RELAY_ABUSE_VIOLATIONS_PER_LEVEL {
            relay.record_abuse_violation("knp1noisy", now);
        }
        assert_eq!(relay.adaptive_limits("knp1noisy", now).0, MAX_RELAY_CELLS_PER_SECOND / 2);

        let recovered = now + RELAY_ABUSE_DECAY;
        assert_eq!(
            relay.adaptive_limits("knp1noisy", recovered).0,
            MAX_RELAY_CELLS_PER_SECOND
        );
    }

    #[test]
    fn abuse_accounting_state_stays_bounded() {
        let mut relay = RelayManager::default();
        let now = Instant::now();

        for index in 0..(MAX_RELAY_ABUSE_TRACKED_NODES + 64) {
            relay.record_abuse_violation(&format!("knp1node{index}"), now);
        }

        assert_eq!(relay.abuse.len(), MAX_RELAY_ABUSE_TRACKED_NODES);
    }

    #[test]
    fn relay_enforces_per_node_circuit_limit() {
        let mut relay = RelayManager::default();
        let now = Instant::now();

        for index in 0..MAX_RELAY_CIRCUITS_PER_NODE {
            relay
                .open(
                    index as u64,
                    "203.0.113.10:47000".parse().unwrap(),
                    "knp1origin".into(),
                    format!("198.51.100.{}:47000", index + 1).parse().unwrap(),
                    format!("knp1target{index}"),
                    now,
                )
                .unwrap();
        }

        assert!(relay
            .open(
                999,
                "203.0.113.10:47000".parse().unwrap(),
                "knp1origin".into(),
                "198.51.100.250:47000".parse().unwrap(),
                "knp1overflow".into(),
                now,
            )
            .is_err());
    }

    #[test]
    fn relay_expires_idle_circuits() {
        let (mut relay, _, _, _) = setup();
        assert_eq!(
            relay.expire(Instant::now() + RELAY_CIRCUIT_TTL + Duration::from_secs(1)),
            1
        );
        assert!(relay.is_empty());
    }
}
