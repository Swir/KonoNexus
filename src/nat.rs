use crate::identity::{node_id_from_public_key, NodeIdentity, PUBLIC_KEY_LEN, SIGNATURE_LEN};
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

pub const DEFAULT_MAX_NAT_OBSERVERS: usize = 32;
pub const FILTER_PROBE_AUTH_TTL_MS: u64 = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatMappingBehavior {
    Unknown,
    SingleObservation,
    StableEndpoint,
    PortVariant,
    AddressVariant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatFilteringEvidence {
    Unknown,
    EndpointIndependentObserved,
    EndpointIndependentRepeated,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FilterProbeAuthorization {
    pub target_node_id: String,
    pub target_public_key: String,
    pub target_endpoint: String,
    pub helper_node_id: String,
    pub probe_token: u64,
    pub expires_unix_ms: u64,
    pub signature: String,
}

#[derive(Serialize)]
struct UnsignedFilterProbeAuthorization<'a> {
    target_node_id: &'a str,
    target_public_key: &'a str,
    target_endpoint: &'a str,
    helper_node_id: &'a str,
    probe_token: u64,
    expires_unix_ms: u64,
}

impl FilterProbeAuthorization {
    pub fn signed(
        identity: &NodeIdentity,
        target_endpoint: SocketAddr,
        helper_node_id: String,
        probe_token: u64,
    ) -> Result<Self> {
        let mut authorization = Self {
            target_node_id: identity.node_id(),
            target_public_key: identity.public_key_hex(),
            target_endpoint: target_endpoint.to_string(),
            helper_node_id,
            probe_token,
            expires_unix_ms: unix_time_ms()?.saturating_add(FILTER_PROBE_AUTH_TTL_MS),
            signature: String::new(),
        };
        authorization.signature = hex::encode(identity.sign(&authorization.signing_bytes()?));
        Ok(authorization)
    }

    pub fn verify(&self) -> Result<()> {
        if unix_time_ms()? > self.expires_unix_ms {
            bail!("filter probe authorization expired");
        }

        self.target_endpoint
            .parse::<SocketAddr>()
            .context("filter probe target endpoint is invalid")?;

        let raw =
            hex::decode(&self.target_public_key).context("filter target public key is invalid")?;
        let public_key: [u8; PUBLIC_KEY_LEN] = raw
            .try_into()
            .map_err(|_| anyhow!("filter target public key must be 32 bytes"))?;

        if node_id_from_public_key(&public_key) != self.target_node_id {
            bail!("filter authorization NodeID/public-key mismatch");
        }

        let raw =
            hex::decode(&self.signature).context("filter authorization signature is invalid")?;
        let signature: [u8; SIGNATURE_LEN] = raw
            .try_into()
            .map_err(|_| anyhow!("filter authorization signature must be 64 bytes"))?;

        NodeIdentity::verify_with_public_key(&public_key, &self.signing_bytes()?, &signature)
    }

    fn signing_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(&UnsignedFilterProbeAuthorization {
            target_node_id: &self.target_node_id,
            target_public_key: &self.target_public_key,
            target_endpoint: &self.target_endpoint,
            helper_node_id: &self.helper_node_id,
            probe_token: self.probe_token,
            expires_unix_ms: self.expires_unix_ms,
        })
        .context("failed to serialize filter probe authorization")
    }
}

#[derive(Debug)]
pub struct NatProfile {
    observations: HashMap<String, SocketAddr>,
    order: VecDeque<String>,
    filter_helpers: HashSet<String>,
    filter_order: VecDeque<String>,
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
            filter_helpers: HashSet::new(),
            filter_order: VecDeque::new(),
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

    pub fn record_endpoint_independent_probe(&mut self, helper_node_id: String) {
        if self.filter_helpers.insert(helper_node_id.clone()) {
            self.filter_order.push_back(helper_node_id);
        }
        while self.filter_helpers.len() > self.max_observers {
            if let Some(oldest) = self.filter_order.pop_front() {
                self.filter_helpers.remove(&oldest);
            } else {
                break;
            }
        }
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

    pub fn filtering_evidence(&self) -> NatFilteringEvidence {
        match self.filter_helpers.len() {
            0 => NatFilteringEvidence::Unknown,
            1 => NatFilteringEvidence::EndpointIndependentObserved,
            _ => NatFilteringEvidence::EndpointIndependentRepeated,
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

fn unix_time_ms() -> Result<u64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?;
    Ok(duration.as_millis().try_into().unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapping_and_filtering_evidence_remain_distinct() {
        let mut profile = NatProfile::default();
        profile.observe("peer-a".into(), "203.0.113.1:40000".parse().unwrap());
        assert_eq!(profile.behavior(), NatMappingBehavior::SingleObservation);
        assert_eq!(profile.filtering_evidence(), NatFilteringEvidence::Unknown);

        profile.record_endpoint_independent_probe("helper-a".into());
        assert_eq!(
            profile.filtering_evidence(),
            NatFilteringEvidence::EndpointIndependentObserved
        );
    }

    #[test]
    fn repeated_independent_helpers_strengthen_positive_evidence() {
        let mut profile = NatProfile::default();
        profile.record_endpoint_independent_probe("helper-a".into());
        profile.record_endpoint_independent_probe("helper-b".into());
        assert_eq!(
            profile.filtering_evidence(),
            NatFilteringEvidence::EndpointIndependentRepeated
        );
    }

    #[test]
    fn signed_filter_authorization_detects_tampering() {
        let identity = NodeIdentity::generate();
        let mut authorization = FilterProbeAuthorization::signed(
            &identity,
            "203.0.113.55:47000".parse().unwrap(),
            "knp1helper".into(),
            42,
        )
        .unwrap();

        authorization.verify().unwrap();
        authorization.helper_node_id.push('x');
        assert!(authorization.verify().is_err());
    }
}
