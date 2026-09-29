use std::collections::HashMap;
use std::net::SocketAddr;

pub const MAX_RELAY_ROUTE_CANDIDATES: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

#[derive(Debug, Default)]
pub struct RouteController {
    active: HashMap<String, ActiveRoute>,
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

        let desired = if let Some(endpoint) = direct {
            Some(ControlRoute::Direct(endpoint))
        } else {
            let current = self
                .active
                .get(peer_node_id)
                .and_then(|active| active.route);
            current
                .and_then(|route| match route {
                    ControlRoute::Relay {
                        relay_endpoint,
                        circuit_id,
                    } if relays.iter().any(|candidate| {
                        candidate.relay_endpoint == relay_endpoint
                            && candidate.circuit_id == circuit_id
                    }) =>
                    {
                        Some(route)
                    }
                    _ => None,
                })
                .or_else(|| relays.first().copied().map(RelayRouteCandidate::route))
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

    pub fn forget_peer(&mut self, peer_node_id: &str) {
        self.active.remove(peer_node_id);
    }

    pub fn active_route(&self, peer_node_id: &str) -> Option<ControlRoute> {
        self.active
            .get(peer_node_id)
            .and_then(|active| active.route)
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
