use crate::konomind::{KonoMindAdvisor, PathKind, PathMetrics, RouteCandidate};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

pub const MAX_RELAY_ROUTE_CANDIDATES: usize = 3;
const MAX_ROUTE_HEALTH_ENTRIES: usize = 2048;
const ROUTE_FAILURE_COOLDOWN: Duration = Duration::from_secs(5);
const ROUTE_SWITCH_HYSTERESIS: f32 = 0.08;
const DEFAULT_RELAY_RTT_MS: f32 = 100.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ControlRoute {
    Direct(SocketAddr),
    Relay {
        relay_endpoint: SocketAddr,
        circuit_id: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayRouteCandidate {
    pub relay_endpoint: SocketAddr,
    pub circuit_id: u64,
}

impl RelayRouteCandidate {
    pub fn new(relay_endpoint: SocketAddr, circuit_id: u64) -> Self {
        Self {
            relay_endpoint,
            circuit_id,
        }
    }

    fn route(self) -> ControlRoute {
        ControlRoute::Relay {
            relay_endpoint: self.relay_endpoint,
            circuit_id: self.circuit_id,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteDecision {
    pub route: ControlRoute,
    pub generation: u64,
    pub changed: bool,
}

#[derive(Debug, Clone, Copy)]
struct ActiveRoute {
    route: Option<ControlRoute>,
    generation: u64,
}

#[derive(Debug, Clone, Copy, Default)]
struct RouteHealth {
    last_failure: Option<Instant>,
    successes: u32,
    failures: u32,
    rtt_ewma_ms: Option<f32>,
    touch: u64,
}

#[derive(Debug, Default)]
pub struct RouteController {
    active: HashMap<String, ActiveRoute>,
    health: HashMap<(String, ControlRoute), RouteHealth>,
    health_touch: u64,
}

impl RouteController {
    pub fn select<I>(
        &mut self,
        peer_node_id: &str,
        direct: Option<SocketAddr>,
        relay_candidates: I,
    ) -> Option<RouteDecision>
    where
        I: IntoIterator<Item = RelayRouteCandidate>,
    {
        self.select_at(peer_node_id, direct, relay_candidates, Instant::now())
    }

    pub fn select_at<I>(
        &mut self,
        peer_node_id: &str,
        direct: Option<SocketAddr>,
        relay_candidates: I,
        now: Instant,
    ) -> Option<RouteDecision>
    where
        I: IntoIterator<Item = RelayRouteCandidate>,
    {
        let mut relays: Vec<RelayRouteCandidate> = relay_candidates.into_iter().collect();
        relays.sort_by_key(|candidate| {
            (
                if candidate.relay_endpoint.is_ipv6() {
                    0_u8
                } else {
                    1_u8
                },
                candidate.relay_endpoint,
                candidate.circuit_id,
            )
        });
        relays.dedup_by_key(|candidate| (candidate.relay_endpoint, candidate.circuit_id));
        relays.truncate(MAX_RELAY_ROUTE_CANDIDATES);

        let current = self
            .active
            .get(peer_node_id)
            .and_then(|active| active.route);
        let confirmed_direct = direct
            .map(ControlRoute::Direct)
            .filter(|route| !self.route_on_cooldown(peer_node_id, *route, now));
        let desired = if let Some(route) = confirmed_direct {
            Some(route)
        } else {
            let mut scored: Vec<(ControlRoute, f32)> = relays
                .into_iter()
                .map(|candidate| {
                    let route = candidate.route();
                    (route, self.route_score(peer_node_id, route))
                })
                .filter(|(route, _)| !self.route_on_cooldown(peer_node_id, *route, now))
                .collect();
            scored.sort_by(|(left_route, left_score), (right_route, right_score)| {
                right_score
                    .total_cmp(left_score)
                    .then_with(|| route_order_key(*left_route).cmp(&route_order_key(*right_route)))
            });
            let best = scored.first().copied();
            current
                .and_then(|route| {
                    scored
                        .iter()
                        .find(|(candidate, _)| *candidate == route)
                        .copied()
                })
                .filter(|(_, current_score)| {
                    best.is_some_and(|(_, best_score)| {
                        best_score - *current_score <= ROUTE_SWITCH_HYSTERESIS
                    })
                })
                .or(best)
                .map(|(route, _)| route)
        };

        let Some(route) = desired else {
            if let Some(active) = self.active.get_mut(peer_node_id) {
                if active.route.take().is_some() {
                    active.generation = active.generation.saturating_add(1);
                }
            }
            return None;
        };

        match self.active.get(peer_node_id).copied() {
            Some(active) if active.route == Some(route) => Some(RouteDecision {
                route,
                generation: active.generation,
                changed: false,
            }),
            Some(active) => {
                let generation = active.generation.saturating_add(1);
                self.active.insert(
                    peer_node_id.to_owned(),
                    ActiveRoute {
                        route: Some(route),
                        generation,
                    },
                );
                Some(RouteDecision {
                    route,
                    generation,
                    changed: true,
                })
            }
            None => {
                self.active.insert(
                    peer_node_id.to_owned(),
                    ActiveRoute {
                        route: Some(route),
                        generation: 1,
                    },
                );
                Some(RouteDecision {
                    route,
                    generation: 1,
                    changed: true,
                })
            }
        }
    }

    pub fn invalidate_relay(
        &mut self,
        peer_node_id: &str,
        relay_endpoint: SocketAddr,
        circuit_id: u64,
    ) -> bool {
        let matches = self.active.get(peer_node_id).is_some_and(|active| {
            active.route
                == Some(ControlRoute::Relay {
                    relay_endpoint,
                    circuit_id,
                })
        });
        if matches {
            if let Some(active) = self.active.get_mut(peer_node_id) {
                active.route = None;
                active.generation = active.generation.saturating_add(1);
            }
        }
        matches
    }

    pub fn report_success(&mut self, peer_node_id: &str, route: ControlRoute) {
        self.health_touch = self.health_touch.saturating_add(1);
        let health = self
            .health
            .entry((peer_node_id.to_owned(), route))
            .or_default();
        health.successes = health.successes.saturating_add(1);
        health.last_failure = None;
        health.touch = self.health_touch;
        self.evict_health_if_needed();
    }

    pub fn report_ack_success(
        &mut self,
        peer_node_id: &str,
        route: ControlRoute,
        rtt: Duration,
        sent_at: Instant,
    ) {
        self.health_touch = self.health_touch.saturating_add(1);
        let health = self
            .health
            .entry((peer_node_id.to_owned(), route))
            .or_default();
        health.successes = health.successes.saturating_add(1);
        if health
            .last_failure
            .is_none_or(|failed_at| failed_at <= sent_at)
        {
            health.last_failure = None;
        }
        let rtt_ms = rtt.as_secs_f64() * 1000.0;
        if rtt_ms.is_finite() {
            let sample = rtt_ms.min(60_000.0) as f32;
            health.rtt_ewma_ms = Some(match health.rtt_ewma_ms {
                Some(previous) => previous * 0.8 + sample * 0.2,
                None => sample,
            });
        }
        health.touch = self.health_touch;
        self.evict_health_if_needed();
    }

    pub fn report_failure(&mut self, peer_node_id: &str, route: ControlRoute, now: Instant) {
        self.health_touch = self.health_touch.saturating_add(1);
        let health = self
            .health
            .entry((peer_node_id.to_owned(), route))
            .or_default();
        health.failures = health.failures.saturating_add(1);
        health.last_failure = Some(now);
        health.touch = self.health_touch;
        self.evict_health_if_needed();
    }

    pub fn route_on_cooldown(&self, peer_node_id: &str, route: ControlRoute, now: Instant) -> bool {
        self.health
            .get(&(peer_node_id.to_owned(), route))
            .and_then(|health| health.last_failure)
            .is_some_and(|failed_at| {
                now.saturating_duration_since(failed_at) < ROUTE_FAILURE_COOLDOWN
            })
    }

    fn route_score(&self, peer_node_id: &str, route: ControlRoute) -> f32 {
        let health = self.health.get(&(peer_node_id.to_owned(), route));
        let successes = health.map_or(0, |health| health.successes) as f32;
        let failures = health.map_or(0, |health| health.failures) as f32;
        let reliability = (successes + 1.0) / (successes + failures + 2.0);
        let metrics = PathMetrics {
            rtt_ms: health
                .and_then(|health| health.rtt_ewma_ms)
                .unwrap_or(DEFAULT_RELAY_RTT_MS),
            packet_loss: 1.0 - reliability,
            stability: reliability,
            // Relay load is not yet measured in production, so keep its input neutral.
            relay_load: 0.5,
        };
        KonoMindAdvisor::default()
            .recommend(&[RouteCandidate {
                path: match route {
                    ControlRoute::Direct(_) => PathKind::Direct,
                    ControlRoute::Relay { .. } => PathKind::Relay,
                },
                metrics,
            }])
            .map_or(0.0, |recommendation| recommendation.score)
    }

    #[cfg(test)]
    pub(crate) fn health_counts(
        &self,
        peer_node_id: &str,
        route: ControlRoute,
    ) -> (u32, u32, Option<f32>) {
        self.health
            .get(&(peer_node_id.to_owned(), route))
            .map_or((0, 0, None), |health| {
                (health.successes, health.failures, health.rtt_ewma_ms)
            })
    }

    fn evict_health_if_needed(&mut self) {
        while self.health.len() > MAX_ROUTE_HEALTH_ENTRIES {
            let victim = self
                .health
                .iter()
                .min_by(|(left_key, left), (right_key, right)| {
                    left.touch
                        .cmp(&right.touch)
                        .then_with(|| left_key.0.cmp(&right_key.0))
                        .then_with(|| {
                            route_order_key(left_key.1).cmp(&route_order_key(right_key.1))
                        })
                })
                .map(|(key, _)| key.clone());
            let Some(victim) = victim else {
                break;
            };
            self.health.remove(&victim);
        }
    }

    pub fn forget_peer(&mut self, peer_node_id: &str) {
        self.active.remove(peer_node_id);
        self.health
            .retain(|(stored_peer, _), _| stored_peer != peer_node_id);
    }

    pub fn active_route(&self, peer_node_id: &str) -> Option<ControlRoute> {
        self.active
            .get(peer_node_id)
            .and_then(|active| active.route)
    }
}

fn route_order_key(route: ControlRoute) -> (u8, u8, SocketAddr, u64) {
    match route {
        ControlRoute::Direct(endpoint) => (0, if endpoint.is_ipv6() { 0 } else { 1 }, endpoint, 0),
        ControlRoute::Relay {
            relay_endpoint,
            circuit_id,
        } => (
            1,
            if relay_endpoint.is_ipv6() { 0 } else { 1 },
            relay_endpoint,
            circuit_id,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn relay(endpoint: &str, circuit_id: u64) -> RelayRouteCandidate {
        RelayRouteCandidate::new(endpoint.parse().unwrap(), circuit_id)
    }

    #[test]
    fn direct_path_preempts_relay_and_increments_generation_once() {
        let mut controller = RouteController::default();
        let peer = "knp1peer";
        let relay_route = relay("127.0.0.20:47000", 7);

        let first = controller
            .select(peer, None, [relay_route])
            .expect("relay route should be selected");
        assert_eq!(first.generation, 1);
        assert!(first.changed);

        let direct: SocketAddr = "127.0.0.50:47000".parse().unwrap();
        let migrated = controller
            .select(peer, Some(direct), [relay_route])
            .expect("direct route should be selected");
        assert_eq!(migrated.route, ControlRoute::Direct(direct));
        assert_eq!(migrated.generation, 2);
        assert!(migrated.changed);

        let stable = controller
            .select(peer, Some(direct), [relay_route])
            .expect("direct route should stay selected");
        assert_eq!(stable.generation, 2);
        assert!(!stable.changed);
    }

    #[test]
    fn relay_selection_is_deterministic_and_sticky_within_bounded_set() {
        let mut controller = RouteController::default();
        let peer = "knp1peer";
        let v4_a = relay("127.0.0.10:47000", 20);
        let v4_b = relay("127.0.0.11:47000", 10);
        let v6 = relay("[::1]:47000", 30);

        let first = controller
            .select(peer, None, [v4_b, v4_a, v6])
            .expect("relay route should be selected");
        assert_eq!(first.route, v6.route());

        let reordered = controller
            .select(peer, None, [v4_a, v6, v4_b])
            .expect("relay route should remain selected");
        assert_eq!(reordered.route, first.route);
        assert_eq!(reordered.generation, 1);
        assert!(!reordered.changed);
    }

    #[test]
    fn relay_failure_migrates_to_next_existing_circuit() {
        let mut controller = RouteController::default();
        let peer = "knp1peer";
        let primary = relay("127.0.0.10:47000", 1);
        let secondary = relay("127.0.0.11:47000", 2);

        let first = controller
            .select(peer, None, [secondary, primary])
            .expect("primary relay should be selected");
        assert_eq!(first.route, primary.route());

        assert!(controller.invalidate_relay(peer, primary.relay_endpoint, primary.circuit_id));

        let failover = controller
            .select(peer, None, [secondary])
            .expect("secondary relay should be selected");
        assert_eq!(failover.route, secondary.route());
        assert_eq!(failover.generation, 3);
        assert!(failover.changed);
    }

    #[test]
    fn relay_failover_walks_three_existing_circuits_in_order() {
        let mut controller = RouteController::default();
        let peer = "knp1peer";
        let primary = relay("127.0.0.10:47000", 1);
        let secondary = relay("127.0.0.11:47000", 2);
        let tertiary = relay("127.0.0.12:47000", 3);

        let first = controller
            .select(peer, None, [tertiary, secondary, primary])
            .expect("primary relay should be selected");
        assert_eq!(first.route, primary.route());

        assert!(controller.invalidate_relay(peer, primary.relay_endpoint, primary.circuit_id));
        let second = controller
            .select(peer, None, [tertiary, secondary])
            .expect("secondary relay should be selected");
        assert_eq!(second.route, secondary.route());

        assert!(controller.invalidate_relay(peer, secondary.relay_endpoint, secondary.circuit_id));
        let third = controller
            .select(peer, None, [tertiary])
            .expect("tertiary relay should be selected");
        assert_eq!(third.route, tertiary.route());

        assert!(controller.invalidate_relay(peer, tertiary.relay_endpoint, tertiary.circuit_id));
        assert!(controller
            .select(peer, None, std::iter::empty::<RelayRouteCandidate>())
            .is_none());
        assert!(controller.active_route(peer).is_none());
    }

    #[test]
    fn selection_considers_at_most_three_established_relay_candidates() {
        let mut controller = RouteController::default();
        let peer = "knp1peer";
        let candidates = [
            relay("127.0.0.40:47000", 4),
            relay("127.0.0.30:47000", 3),
            relay("127.0.0.20:47000", 2),
            relay("127.0.0.10:47000", 1),
        ];

        let selected = controller
            .select(peer, None, candidates)
            .expect("one bounded relay candidate should be selected");

        assert_eq!(
            selected.route,
            ControlRoute::Relay {
                relay_endpoint: "127.0.0.10:47000".parse().unwrap(),
                circuit_id: 1,
            }
        );
    }

    #[test]
    fn route_failure_cooldown_and_success_recovery_are_deterministic() {
        let mut controller = RouteController::default();
        let peer = "knp1peer";
        let route = ControlRoute::Direct("127.0.0.50:47000".parse().unwrap());
        let now = Instant::now();

        controller.report_failure(peer, route, now);
        assert!(controller.route_on_cooldown(peer, route, now + Duration::from_secs(4)));
        assert!(!controller.route_on_cooldown(peer, route, now + Duration::from_secs(5)));

        controller.report_success(peer, route);
        assert!(!controller.route_on_cooldown(peer, route, now + Duration::from_secs(1)));
    }

    #[test]
    fn cooldown_changes_selection_and_direct_recovers_after_expiry() {
        let mut controller = RouteController::default();
        let peer = "knp1peer";
        let direct: SocketAddr = "127.0.0.50:47000".parse().unwrap();
        let relay = relay("127.0.0.10:47000", 1);
        let now = Instant::now();

        assert_eq!(
            controller
                .select_at(peer, Some(direct), [relay], now)
                .unwrap()
                .route,
            ControlRoute::Direct(direct)
        );
        controller.report_failure(peer, ControlRoute::Direct(direct), now);

        assert_eq!(
            controller
                .select_at(peer, Some(direct), [relay], now + Duration::from_secs(1))
                .unwrap()
                .route,
            relay.route()
        );
        assert_eq!(
            controller
                .select_at(peer, Some(direct), [relay], now + Duration::from_secs(5))
                .unwrap()
                .route,
            ControlRoute::Direct(direct)
        );
    }

    #[test]
    fn relay_health_scores_candidates_and_hysteresis_keeps_a_close_active_route() {
        let mut controller = RouteController::default();
        let peer = "knp1peer";
        let slower = relay("127.0.0.10:47000", 1);
        let faster = relay("127.0.0.11:47000", 2);
        let now = Instant::now();
        controller.report_ack_success(peer, faster.route(), Duration::from_millis(20), now);
        assert_eq!(
            controller
                .select_at(peer, None, [slower, faster], now)
                .unwrap()
                .route,
            faster.route()
        );

        controller.select_at(peer, None, [slower], now).unwrap();
        controller.report_ack_success(peer, slower.route(), Duration::from_millis(80), now);
        controller.report_ack_success(peer, faster.route(), Duration::from_millis(300), now);
        let stable = controller
            .select_at(peer, None, [slower, faster], now)
            .unwrap();
        assert_eq!(stable.route, slower.route());
        assert!(!stable.changed);
    }

    #[test]
    fn failed_relay_falls_back_and_returns_after_cooldown() {
        let mut controller = RouteController::default();
        let peer = "knp1peer";
        let primary = relay("127.0.0.10:47000", 1);
        let fallback = relay("127.0.0.11:47000", 2);
        let now = Instant::now();
        assert_eq!(
            controller
                .select_at(peer, None, [primary, fallback], now)
                .unwrap()
                .route,
            primary.route()
        );
        controller.report_failure(peer, primary.route(), now);
        assert_eq!(
            controller
                .select_at(
                    peer,
                    None,
                    [primary, fallback],
                    now + Duration::from_secs(1)
                )
                .unwrap()
                .route,
            fallback.route()
        );
        assert_eq!(
            controller
                .select_at(peer, None, [primary], now + Duration::from_secs(5))
                .unwrap()
                .route,
            primary.route()
        );
    }

    #[test]
    fn route_metrics_are_bounded_by_route_and_peer() {
        let mut controller = RouteController::default();
        let route = ControlRoute::Direct("127.0.0.2:47000".parse().unwrap());
        controller.report_ack_success(
            "peer-a",
            route,
            Duration::from_secs(u64::MAX),
            Instant::now(),
        );
        let (successes, failures, rtt) = controller.health_counts("peer-a", route);
        assert_eq!((successes, failures), (1, 0));
        assert!(rtt.is_some_and(|value| value.is_finite() && value <= 60_000.0));
        assert_eq!(controller.health_counts("peer-b", route), (0, 0, None));
    }

    #[test]
    fn stale_ack_does_not_clear_a_newer_route_failure() {
        let mut controller = RouteController::default();
        let peer = "knp1peer";
        let route = ControlRoute::Direct("127.0.0.2:47000".parse().unwrap());
        let start = Instant::now();
        let failed_at = start + Duration::from_secs(2);

        controller.report_failure(peer, route, failed_at);
        controller.report_ack_success(peer, route, Duration::from_secs(3), start);
        assert!(controller.route_on_cooldown(peer, route, failed_at + Duration::from_secs(1)));

        let recovered_at = failed_at + Duration::from_secs(1);
        controller.report_ack_success(peer, route, Duration::from_millis(20), recovered_at);
        assert!(!controller.route_on_cooldown(peer, route, recovered_at));
    }

    #[test]
    fn route_health_is_bounded_and_forget_peer_clears_it() {
        let mut controller = RouteController::default();
        let now = Instant::now();

        for index in 0..=MAX_ROUTE_HEALTH_ENTRIES {
            let peer = format!("knp1peer{index:04}");
            let endpoint: SocketAddr = format!("127.0.0.1:{}", 10000 + index).parse().unwrap();
            controller.report_failure(&peer, ControlRoute::Direct(endpoint), now);
        }

        assert_eq!(controller.health.len(), MAX_ROUTE_HEALTH_ENTRIES);

        let peer = "knp1forget";
        let route = ControlRoute::Direct("127.0.0.2:47000".parse().unwrap());
        controller.report_failure(peer, route, now);
        assert!(controller
            .health
            .keys()
            .any(|(stored_peer, _)| stored_peer == peer));
        controller.forget_peer(peer);
        assert!(!controller
            .health
            .keys()
            .any(|(stored_peer, _)| stored_peer == peer));
    }

    #[test]
    fn losing_all_routes_clears_control_plane_state() {
        let mut controller = RouteController::default();
        let peer = "knp1peer";
        let candidate = relay("127.0.0.10:47000", 1);

        controller
            .select(peer, None, [candidate])
            .expect("relay route should be selected");
        assert!(controller
            .select(peer, None, std::iter::empty::<RelayRouteCandidate>())
            .is_none());
        assert!(controller.active_route(peer).is_none());
    }
}
