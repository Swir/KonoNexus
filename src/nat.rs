use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;

pub const DEFAULT_MAX_NAT_OBSERVERS: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatMappingBehavior {
    Unknown,
    SingleObservation,
    StableEndpoint,
    PortVariant,
    AddressVariant,
}

#[derive(Debug)]
pub struct NatProfile {
    observations: HashMap<String, SocketAddr>,
    order: VecDeque<String>,
    max_observers: usize,
}

impl Default for NatProfile {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_NAT_OBSERVERS)
    }
}

impl NatProfile {
    pub fn new(max_observers: usize) -> Self {
        Self {
            observations: HashMap::new(),
            order: VecDeque::new(),
            max_observers: max_observers.max(1),
        }
    }

    pub fn observe(&mut self, observer_node_id: String, endpoint: SocketAddr) {
        if !self.observations.contains_key(&observer_node_id) {
            while self.observations.len() >= self.max_observers {
                if let Some(oldest) = self.order.pop_front() {
                    self.observations.remove(&oldest);
                } else {
                    break;
                }
            }
            self.order.push_back(observer_node_id.clone());
        }

        self.observations.insert(observer_node_id, endpoint);
    }

    pub fn behavior(&self) -> NatMappingBehavior {
        let endpoints: Vec<SocketAddr> = self.observations.values().copied().collect();
        match endpoints.len() {
            0 => NatMappingBehavior::Unknown,
            1 => NatMappingBehavior::SingleObservation,
            _ => {
                let first = endpoints[0];
                if endpoints.iter().all(|endpoint| *endpoint == first) {
                    NatMappingBehavior::StableEndpoint
                } else if endpoints.iter().all(|endpoint| endpoint.ip() == first.ip()) {
                    NatMappingBehavior::PortVariant
                } else {
                    NatMappingBehavior::AddressVariant
                }
            }
        }
    }

    pub fn observation_count(&self) -> usize {
        self.observations.len()
    }

    pub fn endpoint_seen_by(&self, observer_node_id: &str) -> Option<SocketAddr> {
        self.observations.get(observer_node_id).copied()
    }

    pub fn preferred_endpoint(&self) -> Option<SocketAddr> {
        let mut counts: HashMap<SocketAddr, usize> = HashMap::new();
        for endpoint in self.observations.values() {
            *counts.entry(*endpoint).or_default() += 1;
        }

        counts
            .into_iter()
            .max_by_key(|(endpoint, count)| (*count, *endpoint))
            .map(|(endpoint, _)| endpoint)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_single_observer_is_not_enough_to_classify_mapping() {
        let mut profile = NatProfile::default();
        profile.observe("peer-a".into(), "203.0.113.1:40000".parse().unwrap());

        assert_eq!(profile.behavior(), NatMappingBehavior::SingleObservation);
    }

    #[test]
    fn identical_observations_indicate_stable_mapping() {
        let mut profile = NatProfile::default();
        let endpoint = "203.0.113.1:40000".parse().unwrap();
        profile.observe("peer-a".into(), endpoint);
        profile.observe("peer-b".into(), endpoint);

        assert_eq!(profile.behavior(), NatMappingBehavior::StableEndpoint);
        assert_eq!(profile.preferred_endpoint(), Some(endpoint));
    }

    #[test]
    fn same_address_with_different_ports_is_detected() {
        let mut profile = NatProfile::default();
        profile.observe("peer-a".into(), "203.0.113.1:40000".parse().unwrap());
        profile.observe("peer-b".into(), "203.0.113.1:41000".parse().unwrap());

        assert_eq!(profile.behavior(), NatMappingBehavior::PortVariant);
    }

    #[test]
    fn different_addresses_are_marked_as_address_variant() {
        let mut profile = NatProfile::default();
        profile.observe("peer-a".into(), "203.0.113.1:40000".parse().unwrap());
        profile.observe("peer-b".into(), "198.51.100.7:40000".parse().unwrap());

        assert_eq!(profile.behavior(), NatMappingBehavior::AddressVariant);
    }

    #[test]
    fn observer_table_is_bounded() {
        let mut profile = NatProfile::new(2);
        profile.observe("peer-a".into(), "203.0.113.1:40000".parse().unwrap());
        profile.observe("peer-b".into(), "203.0.113.1:40000".parse().unwrap());
        profile.observe("peer-c".into(), "203.0.113.1:40000".parse().unwrap());

        assert_eq!(profile.observation_count(), 2);
        assert!(profile.endpoint_seen_by("peer-a").is_none());
    }
}
