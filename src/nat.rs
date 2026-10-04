use crate::identity::{node_id_from_public_key, NodeIdentity, PUBLIC_KEY_LEN, SIGNATURE_LEN};
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const DEFAULT_MAX_NAT_OBSERVERS: usize = 32;
pub const FILTER_PROBE_AUTH_TTL_MS: u64 = 10_000;
pub const FILTERING_MATRIX_AUTH_DOMAIN: &str = "kononexus/filtering-matrix-authorization";
pub const FILTERING_MATRIX_AUTH_VERSION: u8 = 1;
pub const FILTERING_MATRIX_AUTH_TTL_MS: u64 = 10_000;
pub const FILTERING_MATRIX_EVIDENCE_TTL: Duration = Duration::from_secs(30 * 60);

pub(crate) const FILTERING_MATRIX_CLOCK_SKEW_MS: u64 = 2_000;

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
    Inconclusive,
    ContactedEndpointObserved,
    SameAddressDifferentPortObserved,
    EndpointIndependentObserved,
    EndpointIndependentRepeated,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum FilterProbeClass {
    ContactedEndpoint,
    SameAddressDifferentPort,
    DifferentAddress,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum FilterProbeOutcome {
    Observed,
    TimedOut,
    Unavailable,
    SendFailed,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum FilterCellStatus {
    Unknown,
    Observed,
    InconclusiveTimedOut,
    InconclusiveControlCorrelatedTimeout,
    InconclusiveUnavailable,
    InconclusiveSendFailed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FilterMatrixSnapshot {
    pub target_endpoint: Option<SocketAddr>,
    pub contacted_endpoint: FilterCellStatus,
    pub same_address_different_port: FilterCellStatus,
    pub different_address: FilterCellStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FilteringMatrixAuthorization {
    pub domain: String,
    pub version: u8,
    pub target_node_id: String,
    pub target_public_key: String,
    pub target_endpoint: String,
    pub coordinator_node_id: String,
    pub coordinator_baseline_endpoint: String,
    pub helper_node_id: String,
    pub class: FilterProbeClass,
    pub trial_id: u64,
    pub probe_token: u64,
    pub issued_unix_ms: u64,
    pub expires_unix_ms: u64,
    pub signature: String,
}

#[derive(Serialize)]
struct UnsignedFilteringMatrixAuthorization<'a> {
    domain: &'a str,
    version: u8,
    target_node_id: &'a str,
    target_public_key: &'a str,
    target_endpoint: &'a str,
    coordinator_node_id: &'a str,
    coordinator_baseline_endpoint: &'a str,
    helper_node_id: &'a str,
    class: FilterProbeClass,
    trial_id: u64,
    probe_token: u64,
    issued_unix_ms: u64,
    expires_unix_ms: u64,
}

impl FilteringMatrixAuthorization {
    #[allow(clippy::too_many_arguments)]
    pub fn signed(
        identity: &NodeIdentity,
        target_endpoint: SocketAddr,
        coordinator_node_id: String,
        coordinator_baseline_endpoint: SocketAddr,
        helper_node_id: String,
        class: FilterProbeClass,
        trial_id: u64,
        probe_token: u64,
    ) -> Result<Self> {
        Self::signed_at(
            identity,
            target_endpoint,
            coordinator_node_id,
            coordinator_baseline_endpoint,
            helper_node_id,
            class,
            trial_id,
            probe_token,
            unix_time_ms()?,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn signed_at(
        identity: &NodeIdentity,
        target_endpoint: SocketAddr,
        coordinator_node_id: String,
        coordinator_baseline_endpoint: SocketAddr,
        helper_node_id: String,
        class: FilterProbeClass,
        trial_id: u64,
        probe_token: u64,
        issued_unix_ms: u64,
    ) -> Result<Self> {
        if coordinator_node_id.is_empty() {
            bail!("filtering matrix coordinator NodeID is empty");
        }
        if helper_node_id.is_empty() {
            bail!("filtering matrix helper NodeID is empty");
        }

        let mut authorization = Self {
            domain: FILTERING_MATRIX_AUTH_DOMAIN.to_owned(),
            version: FILTERING_MATRIX_AUTH_VERSION,
            target_node_id: identity.node_id(),
            target_public_key: identity.public_key_hex(),
            target_endpoint: target_endpoint.to_string(),
            coordinator_node_id,
            coordinator_baseline_endpoint: coordinator_baseline_endpoint.to_string(),
            helper_node_id,
            class,
            trial_id,
            probe_token,
            issued_unix_ms,
            expires_unix_ms: issued_unix_ms
                .checked_add(FILTERING_MATRIX_AUTH_TTL_MS)
                .context("filtering matrix authorization expiry overflow")?,
            signature: String::new(),
        };
        authorization.signature = hex::encode(identity.sign(&authorization.signing_bytes()?));
        Ok(authorization)
    }

    pub fn verify(&self) -> Result<()> {
        self.verify_at(unix_time_ms()?)
    }

    pub fn verify_at(&self, now_unix_ms: u64) -> Result<()> {
        if self.domain != FILTERING_MATRIX_AUTH_DOMAIN {
            bail!("filtering matrix authorization domain is invalid");
        }
        if self.version != FILTERING_MATRIX_AUTH_VERSION {
            bail!("filtering matrix authorization version is unsupported");
        }
        if self.coordinator_node_id.is_empty() {
            bail!("filtering matrix coordinator NodeID is empty");
        }
        if self.helper_node_id.is_empty() {
            bail!("filtering matrix helper NodeID is empty");
        }
        if self.issued_unix_ms > now_unix_ms.saturating_add(FILTERING_MATRIX_CLOCK_SKEW_MS) {
            bail!("filtering matrix authorization issued too far in the future");
        }
        if self.expires_unix_ms <= now_unix_ms {
            bail!("filtering matrix authorization expired");
        }
        if self.expires_unix_ms <= self.issued_unix_ms
            || self.expires_unix_ms - self.issued_unix_ms > FILTERING_MATRIX_AUTH_TTL_MS
        {
            bail!("filtering matrix authorization TTL is invalid");
        }

        parse_canonical_endpoint(&self.target_endpoint, "filtering matrix target endpoint")?;
        parse_canonical_endpoint(
            &self.coordinator_baseline_endpoint,
            "filtering matrix coordinator baseline endpoint",
        )?;

        let raw = hex::decode(&self.target_public_key)
            .context("filtering matrix target public key is invalid")?;
        let public_key: [u8; PUBLIC_KEY_LEN] = raw
            .try_into()
            .map_err(|_| anyhow!("filtering matrix target public key must be 32 bytes"))?;
        if node_id_from_public_key(&public_key) != self.target_node_id {
            bail!("filtering matrix authorization NodeID/public-key mismatch");
        }

        let raw = hex::decode(&self.signature)
            .context("filtering matrix authorization signature is invalid")?;
        let signature: [u8; SIGNATURE_LEN] = raw
            .try_into()
            .map_err(|_| anyhow!("filtering matrix authorization signature must be 64 bytes"))?;
        NodeIdentity::verify_with_public_key(&public_key, &self.signing_bytes()?, &signature)
    }

    fn signing_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(&UnsignedFilteringMatrixAuthorization {
            domain: &self.domain,
            version: self.version,
            target_node_id: &self.target_node_id,
            target_public_key: &self.target_public_key,
            target_endpoint: &self.target_endpoint,
            coordinator_node_id: &self.coordinator_node_id,
            coordinator_baseline_endpoint: &self.coordinator_baseline_endpoint,
            helper_node_id: &self.helper_node_id,
            class: self.class,
            trial_id: self.trial_id,
            probe_token: self.probe_token,
            issued_unix_ms: self.issued_unix_ms,
            expires_unix_ms: self.expires_unix_ms,
        })
        .context("failed to serialize filtering matrix authorization")
    }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum FilterSourceGroup {
    Ipv4([u8; 3]),
    Ipv6([u16; 3]),
}

#[derive(Debug)]
struct FilterMatrixObservation {
    target_node_id: String,
    target_endpoint: SocketAddr,
    coordinator_node_id: String,
    coordinator_baseline_endpoint: SocketAddr,
    helper_node_id: String,
    class: FilterProbeClass,
    trial_id: u64,
    probe_token: u64,
    source_endpoint: Option<SocketAddr>,
    source_group: Option<FilterSourceGroup>,
    outcome: FilterProbeOutcome,
    observed_at: Instant,
}

#[derive(Debug)]
pub struct NatProfile {
    observations: HashMap<String, SocketAddr>,
    order: VecDeque<String>,
    filter_helpers: HashSet<String>,
    filter_order: VecDeque<String>,
    // Each record represents one matrix cell. Keeping this queue at or below
    // max_observers bounds all matrix evidence independently of trial IDs.
    filter_matrix: VecDeque<FilterMatrixObservation>,
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
            filter_matrix: VecDeque::new(),
            max_observers: max_observers.clamp(1, DEFAULT_MAX_NAT_OBSERVERS),
        }
    }

    pub fn observe(&mut self, observer_node_id: String, endpoint: SocketAddr) {
        let previous_preferred = self.preferred_endpoint();
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

        if self.preferred_endpoint() != previous_preferred {
            self.filter_matrix.clear();
        }
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
        self.filtering_evidence_at(Instant::now())
    }

    pub fn filtering_evidence_at(&self, now: Instant) -> NatFilteringEvidence {
        let target_endpoint = self.preferred_endpoint();
        let fresh: Vec<&FilterMatrixObservation> = self
            .filter_matrix
            .iter()
            .filter(|observation| {
                target_endpoint == Some(observation.target_endpoint)
                    && observation_is_fresh(observation, now)
            })
            .collect();

        let different_address_groups: HashSet<FilterSourceGroup> = fresh
            .iter()
            .filter(|observation| {
                observation.class == FilterProbeClass::DifferentAddress
                    && observation.outcome == FilterProbeOutcome::Observed
            })
            .filter_map(|observation| observation.source_group)
            .collect();
        if different_address_groups.len() >= 2 {
            return NatFilteringEvidence::EndpointIndependentRepeated;
        }
        if !different_address_groups.is_empty() {
            return NatFilteringEvidence::EndpointIndependentObserved;
        }
        if fresh.iter().any(|observation| {
            observation.class == FilterProbeClass::SameAddressDifferentPort
                && observation.outcome == FilterProbeOutcome::Observed
        }) {
            return NatFilteringEvidence::SameAddressDifferentPortObserved;
        }
        if fresh.iter().any(|observation| {
            observation.class == FilterProbeClass::ContactedEndpoint
                && observation.outcome == FilterProbeOutcome::Observed
        }) {
            return NatFilteringEvidence::ContactedEndpointObserved;
        }
        if !fresh.is_empty() {
            return NatFilteringEvidence::Inconclusive;
        }

        // Keep accepting the legacy single-probe wire format during the
        // transition, but a helper NodeID without a bound source tuple,
        // target mapping, trial control, or freshness cannot establish EIM.
        match self.filter_helpers.len() {
            0 => NatFilteringEvidence::Unknown,
            _ => NatFilteringEvidence::Inconclusive,
        }
    }

    pub fn record_filter_probe(
        &mut self,
        authorization: &FilteringMatrixAuthorization,
        source_endpoint: Option<SocketAddr>,
        outcome: FilterProbeOutcome,
    ) -> Result<()> {
        let now_unix_ms = unix_time_ms()?;
        self.record_filter_probe_at(
            authorization,
            source_endpoint,
            outcome,
            Instant::now(),
            now_unix_ms,
        )
    }

    pub fn record_filter_probe_at(
        &mut self,
        authorization: &FilteringMatrixAuthorization,
        source_endpoint: Option<SocketAddr>,
        outcome: FilterProbeOutcome,
        now: Instant,
        now_unix_ms: u64,
    ) -> Result<()> {
        authorization.verify_at(now_unix_ms)?;

        let target_endpoint = parse_canonical_endpoint(
            &authorization.target_endpoint,
            "filtering matrix target endpoint",
        )?;
        let baseline_endpoint = parse_canonical_endpoint(
            &authorization.coordinator_baseline_endpoint,
            "filtering matrix coordinator baseline endpoint",
        )?;
        if self.preferred_endpoint() != Some(target_endpoint) {
            bail!("filtering matrix target is not the current preferred mapping");
        }
        match (outcome, source_endpoint) {
            (FilterProbeOutcome::Observed, Some(source_endpoint)) => validate_probe_source(
                authorization.class,
                baseline_endpoint,
                target_endpoint,
                source_endpoint,
            )?,
            (FilterProbeOutcome::Observed, None) => {
                bail!("observed filtering matrix probe is missing its source tuple")
            }
            (_, Some(_)) => {
                bail!("negative filtering matrix outcome must not claim a source tuple")
            }
            (_, None) => {}
        }

        self.expire_filter_matrix_at(now);

        let same_cell = |observation: &FilterMatrixObservation| {
            observation.target_node_id == authorization.target_node_id
                && observation.target_endpoint == target_endpoint
                && observation.coordinator_node_id == authorization.coordinator_node_id
                && observation.trial_id == authorization.trial_id
                && observation.class == authorization.class
        };
        if let Some(existing) = self
            .filter_matrix
            .iter()
            .find(|observation| same_cell(observation))
        {
            let is_exact_replay = existing.coordinator_baseline_endpoint == baseline_endpoint
                && existing.helper_node_id == authorization.helper_node_id
                && existing.probe_token == authorization.probe_token
                && existing.source_endpoint == source_endpoint
                && existing.outcome == outcome;
            if is_exact_replay {
                return Ok(());
            }
            bail!("filtering matrix trial cell conflicts with existing evidence");
        }

        while self.filter_matrix.len() >= self.max_observers {
            self.filter_matrix.pop_front();
        }
        self.filter_matrix.push_back(FilterMatrixObservation {
            target_node_id: authorization.target_node_id.clone(),
            target_endpoint,
            coordinator_node_id: authorization.coordinator_node_id.clone(),
            coordinator_baseline_endpoint: baseline_endpoint,
            helper_node_id: authorization.helper_node_id.clone(),
            class: authorization.class,
            trial_id: authorization.trial_id,
            probe_token: authorization.probe_token,
            source_endpoint,
            source_group: source_endpoint.map(|source| filter_source_group(source.ip())),
            outcome,
            observed_at: now,
        });
        Ok(())
    }

    pub fn filter_matrix_snapshot(&self) -> FilterMatrixSnapshot {
        self.filter_matrix_snapshot_at(Instant::now())
    }

    pub fn filter_matrix_snapshot_at(&self, now: Instant) -> FilterMatrixSnapshot {
        let target_endpoint = self.preferred_endpoint();
        let fresh: Vec<&FilterMatrixObservation> = self
            .filter_matrix
            .iter()
            .filter(|observation| {
                target_endpoint == Some(observation.target_endpoint)
                    && observation_is_fresh(observation, now)
            })
            .collect();

        FilterMatrixSnapshot {
            target_endpoint,
            contacted_endpoint: matrix_cell_status(FilterProbeClass::ContactedEndpoint, &fresh),
            same_address_different_port: matrix_cell_status(
                FilterProbeClass::SameAddressDifferentPort,
                &fresh,
            ),
            different_address: matrix_cell_status(FilterProbeClass::DifferentAddress, &fresh),
        }
    }

    pub fn expire_filter_matrix_at(&mut self, now: Instant) -> usize {
        let before = self.filter_matrix.len();
        let target_endpoint = self.preferred_endpoint();
        self.filter_matrix.retain(|observation| {
            target_endpoint == Some(observation.target_endpoint)
                && observation_is_fresh(observation, now)
        });
        before - self.filter_matrix.len()
    }

    pub fn filter_matrix_evidence_count(&self) -> usize {
        self.filter_matrix.len()
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

fn parse_canonical_endpoint(encoded: &str, label: &str) -> Result<SocketAddr> {
    let endpoint = encoded
        .parse::<SocketAddr>()
        .with_context(|| format!("{label} is invalid"))?;
    if endpoint.to_string() != encoded {
        bail!("{label} is not canonically encoded");
    }
    Ok(endpoint)
}

fn normalized_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
        ip => ip,
    }
}

fn filter_source_group(ip: IpAddr) -> FilterSourceGroup {
    match normalized_ip(ip) {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            FilterSourceGroup::Ipv4([octets[0], octets[1], octets[2]])
        }
        IpAddr::V6(ip) => {
            let segments = ip.segments();
            FilterSourceGroup::Ipv6([segments[0], segments[1], segments[2]])
        }
    }
}

fn validate_probe_source(
    class: FilterProbeClass,
    baseline: SocketAddr,
    target: SocketAddr,
    source: SocketAddr,
) -> Result<()> {
    let baseline_ip = normalized_ip(baseline.ip());
    let target_ip = normalized_ip(target.ip());
    let source_ip = normalized_ip(source.ip());
    match class {
        FilterProbeClass::ContactedEndpoint if source != baseline => {
            bail!("contacted-endpoint probe source does not match the signed baseline")
        }
        FilterProbeClass::SameAddressDifferentPort
            if source_ip != baseline_ip || source.port() == baseline.port() =>
        {
            bail!("same-address probe source is not a different port on the baseline address")
        }
        FilterProbeClass::DifferentAddress
            if !same_address_family(source_ip, baseline_ip)
                || !same_address_family(source_ip, target_ip)
                || source_ip == baseline_ip
                || source_ip == target_ip =>
        {
            bail!(
                "different-address probe source must share the address family and differ from both baseline and target"
            )
        }
        _ => Ok(()),
    }
}

fn same_address_family(left: IpAddr, right: IpAddr) -> bool {
    matches!(
        (left, right),
        (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_))
    )
}

fn observation_is_fresh(observation: &FilterMatrixObservation, now: Instant) -> bool {
    now.checked_duration_since(observation.observed_at)
        .is_some_and(|age| age < FILTERING_MATRIX_EVIDENCE_TTL)
}

fn matrix_cell_status(
    class: FilterProbeClass,
    observations: &[&FilterMatrixObservation],
) -> FilterCellStatus {
    let cell: Vec<&FilterMatrixObservation> = observations
        .iter()
        .copied()
        .filter(|observation| observation.class == class)
        .collect();
    if cell.is_empty() {
        return FilterCellStatus::Unknown;
    }
    if cell
        .iter()
        .any(|observation| observation.outcome == FilterProbeOutcome::Observed)
    {
        return FilterCellStatus::Observed;
    }
    if class != FilterProbeClass::ContactedEndpoint
        && cell.iter().any(|observation| {
            observation.outcome == FilterProbeOutcome::TimedOut
                && observations.iter().any(|control| {
                    control.class == FilterProbeClass::ContactedEndpoint
                        && control.outcome == FilterProbeOutcome::Observed
                        && control.target_node_id == observation.target_node_id
                        && control.target_endpoint == observation.target_endpoint
                        && control.coordinator_node_id == observation.coordinator_node_id
                        && control.coordinator_baseline_endpoint
                            == observation.coordinator_baseline_endpoint
                        && control.trial_id == observation.trial_id
                })
        })
    {
        return FilterCellStatus::InconclusiveControlCorrelatedTimeout;
    }
    if cell
        .iter()
        .any(|observation| observation.outcome == FilterProbeOutcome::TimedOut)
    {
        return FilterCellStatus::InconclusiveTimedOut;
    }
    if cell
        .iter()
        .any(|observation| observation.outcome == FilterProbeOutcome::Unavailable)
    {
        return FilterCellStatus::InconclusiveUnavailable;
    }
    FilterCellStatus::InconclusiveSendFailed
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

    const MATRIX_WALL_NOW: u64 = 1_700_000_000_000;

    fn target_endpoint() -> SocketAddr {
        "203.0.113.55:47000".parse().unwrap()
    }

    fn baseline_endpoint() -> SocketAddr {
        "198.51.100.10:39000".parse().unwrap()
    }

    fn matrix_authorization(
        identity: &NodeIdentity,
        class: FilterProbeClass,
        trial_id: u64,
        probe_token: u64,
    ) -> FilteringMatrixAuthorization {
        FilteringMatrixAuthorization::signed_at(
            identity,
            target_endpoint(),
            "knp1coordinator".into(),
            baseline_endpoint(),
            "knp1helper".into(),
            class,
            trial_id,
            probe_token,
            MATRIX_WALL_NOW,
        )
        .unwrap()
    }

    fn profile_with_target() -> NatProfile {
        let mut profile = NatProfile::default();
        profile.observe("observer-a".into(), target_endpoint());
        profile
    }

    #[test]
    fn mapping_and_filtering_evidence_remain_distinct() {
        let mut profile = NatProfile::default();
        profile.observe("peer-a".into(), "203.0.113.1:40000".parse().unwrap());
        assert_eq!(profile.behavior(), NatMappingBehavior::SingleObservation);
        assert_eq!(profile.filtering_evidence(), NatFilteringEvidence::Unknown);

        profile.record_endpoint_independent_probe("helper-a".into());
        assert_eq!(
            profile.filtering_evidence(),
            NatFilteringEvidence::Inconclusive
        );
    }

    #[test]
    fn legacy_helpers_are_accepted_without_overclaiming_filtering_behavior() {
        let mut profile = NatProfile::default();
        profile.record_endpoint_independent_probe("helper-a".into());
        profile.record_endpoint_independent_probe("helper-b".into());
        assert_eq!(
            profile.filtering_evidence(),
            NatFilteringEvidence::Inconclusive
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

    #[test]
    fn filtering_matrix_authorization_is_versioned_bounded_and_deterministic() {
        let identity = NodeIdentity::generate();
        let authorization =
            matrix_authorization(&identity, FilterProbeClass::DifferentAddress, 7, 42);
        let repeated = matrix_authorization(&identity, FilterProbeClass::DifferentAddress, 7, 42);

        assert_eq!(authorization, repeated);
        assert_eq!(authorization.domain, FILTERING_MATRIX_AUTH_DOMAIN);
        assert_eq!(authorization.version, FILTERING_MATRIX_AUTH_VERSION);
        assert_eq!(authorization.issued_unix_ms, MATRIX_WALL_NOW);
        assert_eq!(
            authorization.expires_unix_ms,
            MATRIX_WALL_NOW + FILTERING_MATRIX_AUTH_TTL_MS
        );
        authorization.verify_at(MATRIX_WALL_NOW).unwrap();
        authorization
            .verify_at(MATRIX_WALL_NOW + FILTERING_MATRIX_AUTH_TTL_MS - 1)
            .unwrap();
        assert!(authorization
            .verify_at(MATRIX_WALL_NOW + FILTERING_MATRIX_AUTH_TTL_MS)
            .is_err());

        let future = FilteringMatrixAuthorization::signed_at(
            &identity,
            target_endpoint(),
            "knp1coordinator".into(),
            baseline_endpoint(),
            "knp1helper".into(),
            FilterProbeClass::ContactedEndpoint,
            8,
            43,
            MATRIX_WALL_NOW + FILTERING_MATRIX_CLOCK_SKEW_MS + 1,
        )
        .unwrap();
        assert!(future.verify_at(MATRIX_WALL_NOW).is_err());
    }

    #[test]
    fn filtering_matrix_authorization_detects_signed_field_tampering() {
        let identity = NodeIdentity::generate();
        let authorization =
            matrix_authorization(&identity, FilterProbeClass::DifferentAddress, 7, 42);

        let mut tampered = authorization.clone();
        tampered.domain.push('x');
        assert!(tampered.verify_at(MATRIX_WALL_NOW).is_err());

        let mut tampered = authorization.clone();
        tampered.version += 1;
        assert!(tampered.verify_at(MATRIX_WALL_NOW).is_err());

        let mut tampered = authorization.clone();
        tampered.target_endpoint = "203.0.113.56:47000".into();
        assert!(tampered.verify_at(MATRIX_WALL_NOW).is_err());

        let mut tampered = authorization.clone();
        tampered.target_node_id.push('x');
        assert!(tampered.verify_at(MATRIX_WALL_NOW).is_err());

        let mut tampered = authorization.clone();
        let replacement = if tampered.target_public_key.starts_with("00") {
            "01"
        } else {
            "00"
        };
        tampered.target_public_key.replace_range(..2, replacement);
        assert!(tampered.verify_at(MATRIX_WALL_NOW).is_err());

        let mut tampered = authorization.clone();
        tampered.coordinator_node_id.push('x');
        assert!(tampered.verify_at(MATRIX_WALL_NOW).is_err());

        let mut tampered = authorization.clone();
        tampered.coordinator_baseline_endpoint = "198.51.100.10:39001".into();
        assert!(tampered.verify_at(MATRIX_WALL_NOW).is_err());

        let mut tampered = authorization.clone();
        tampered.helper_node_id.push('x');
        assert!(tampered.verify_at(MATRIX_WALL_NOW).is_err());

        let mut tampered = authorization.clone();
        tampered.class = FilterProbeClass::SameAddressDifferentPort;
        assert!(tampered.verify_at(MATRIX_WALL_NOW).is_err());

        let mut tampered = authorization.clone();
        tampered.trial_id += 1;
        assert!(tampered.verify_at(MATRIX_WALL_NOW).is_err());

        let mut tampered = authorization.clone();
        tampered.probe_token += 1;
        assert!(tampered.verify_at(MATRIX_WALL_NOW).is_err());

        let mut tampered = authorization.clone();
        tampered.issued_unix_ms -= 1;
        assert!(tampered.verify_at(MATRIX_WALL_NOW).is_err());

        let mut tampered = authorization;
        tampered.expires_unix_ms += 1;
        assert!(tampered.verify_at(MATRIX_WALL_NOW).is_err());
    }

    #[test]
    fn filtering_matrix_rejects_noncanonical_endpoint_encoding() {
        let identity = NodeIdentity::generate();
        let mut authorization =
            matrix_authorization(&identity, FilterProbeClass::DifferentAddress, 7, 42);
        authorization.target_endpoint = "[2001:0db8::1]:47000".into();
        authorization.signature =
            hex::encode(identity.sign(&authorization.signing_bytes().unwrap()));
        assert!(authorization.verify_at(MATRIX_WALL_NOW).is_err());
    }

    #[test]
    fn matrix_positive_evidence_progresses_without_interpreting_negatives() {
        let identity = NodeIdentity::generate();
        let now = Instant::now();
        let mut profile = profile_with_target();

        let control = matrix_authorization(&identity, FilterProbeClass::ContactedEndpoint, 1, 101);
        profile
            .record_filter_probe_at(
                &control,
                Some(baseline_endpoint()),
                FilterProbeOutcome::Observed,
                now,
                MATRIX_WALL_NOW,
            )
            .unwrap();
        assert_eq!(
            profile.filtering_evidence_at(now),
            NatFilteringEvidence::ContactedEndpointObserved
        );

        let same_address = matrix_authorization(
            &identity,
            FilterProbeClass::SameAddressDifferentPort,
            1,
            102,
        );
        profile
            .record_filter_probe_at(
                &same_address,
                Some("198.51.100.10:39001".parse().unwrap()),
                FilterProbeOutcome::Observed,
                now,
                MATRIX_WALL_NOW,
            )
            .unwrap();
        assert_eq!(
            profile.filtering_evidence_at(now),
            NatFilteringEvidence::SameAddressDifferentPortObserved
        );

        let different_address =
            matrix_authorization(&identity, FilterProbeClass::DifferentAddress, 1, 103);
        profile
            .record_filter_probe_at(
                &different_address,
                Some("192.0.2.10:39000".parse().unwrap()),
                FilterProbeOutcome::Observed,
                now,
                MATRIX_WALL_NOW,
            )
            .unwrap();
        assert_eq!(
            profile.filtering_evidence_at(now),
            NatFilteringEvidence::EndpointIndependentObserved
        );
    }

    #[test]
    fn repeated_different_address_requires_distinct_network_groups() {
        let identity = NodeIdentity::generate();
        let now = Instant::now();
        let mut profile = profile_with_target();

        for (trial_id, source) in [(1, "192.0.2.10:39000"), (2, "192.0.2.20:39000")] {
            let authorization = matrix_authorization(
                &identity,
                FilterProbeClass::DifferentAddress,
                trial_id,
                100 + trial_id,
            );
            profile
                .record_filter_probe_at(
                    &authorization,
                    Some(source.parse().unwrap()),
                    FilterProbeOutcome::Observed,
                    now,
                    MATRIX_WALL_NOW,
                )
                .unwrap();
        }
        assert_eq!(
            profile.filtering_evidence_at(now),
            NatFilteringEvidence::EndpointIndependentObserved
        );

        let other_group =
            matrix_authorization(&identity, FilterProbeClass::DifferentAddress, 3, 103);
        profile
            .record_filter_probe_at(
                &other_group,
                Some("192.0.3.10:39000".parse().unwrap()),
                FilterProbeOutcome::Observed,
                now,
                MATRIX_WALL_NOW,
            )
            .unwrap();
        assert_eq!(
            profile.filtering_evidence_at(now),
            NatFilteringEvidence::EndpointIndependentRepeated
        );
    }

    #[test]
    fn ipv4_24_and_ipv6_48_source_groups_are_stable() {
        assert_eq!(
            filter_source_group("192.0.2.1".parse().unwrap()),
            filter_source_group("192.0.2.254".parse().unwrap())
        );
        assert_ne!(
            filter_source_group("192.0.2.1".parse().unwrap()),
            filter_source_group("192.0.3.1".parse().unwrap())
        );
        assert_eq!(
            filter_source_group("2001:db8:1::1".parse().unwrap()),
            filter_source_group("2001:db8:1:ffff::1".parse().unwrap())
        );
        assert_ne!(
            filter_source_group("2001:db8:1::1".parse().unwrap()),
            filter_source_group("2001:db8:2::1".parse().unwrap())
        );
    }

    #[test]
    fn snapshot_distinguishes_control_correlated_timeout_as_inconclusive() {
        let identity = NodeIdentity::generate();
        let now = Instant::now();
        let mut profile = profile_with_target();
        let control = matrix_authorization(&identity, FilterProbeClass::ContactedEndpoint, 8, 201);
        let experiment =
            matrix_authorization(&identity, FilterProbeClass::DifferentAddress, 8, 202);

        profile
            .record_filter_probe_at(
                &control,
                Some(baseline_endpoint()),
                FilterProbeOutcome::Observed,
                now,
                MATRIX_WALL_NOW,
            )
            .unwrap();
        profile
            .record_filter_probe_at(
                &experiment,
                None,
                FilterProbeOutcome::TimedOut,
                now,
                MATRIX_WALL_NOW,
            )
            .unwrap();

        let snapshot = profile.filter_matrix_snapshot_at(now);
        assert_eq!(snapshot.contacted_endpoint, FilterCellStatus::Observed);
        assert_eq!(
            snapshot.different_address,
            FilterCellStatus::InconclusiveControlCorrelatedTimeout
        );
        assert_eq!(
            profile.filtering_evidence_at(now),
            NatFilteringEvidence::ContactedEndpointObserved
        );
    }

    #[test]
    fn uncorrelated_negatives_remain_explicitly_inconclusive() {
        let identity = NodeIdentity::generate();
        let now = Instant::now();
        let mut profile = profile_with_target();
        let timeout = matrix_authorization(&identity, FilterProbeClass::DifferentAddress, 9, 301);
        profile
            .record_filter_probe_at(
                &timeout,
                None,
                FilterProbeOutcome::TimedOut,
                now,
                MATRIX_WALL_NOW,
            )
            .unwrap();

        assert_eq!(
            profile.filter_matrix_snapshot_at(now).different_address,
            FilterCellStatus::InconclusiveTimedOut
        );
        assert_eq!(
            profile.filtering_evidence_at(now),
            NatFilteringEvidence::Inconclusive
        );
    }

    #[test]
    fn unavailable_and_send_failure_have_explicit_inconclusive_cells() {
        let identity = NodeIdentity::generate();
        let now = Instant::now();
        let mut profile = profile_with_target();
        let send_failed =
            matrix_authorization(&identity, FilterProbeClass::ContactedEndpoint, 20, 801);
        let unavailable = matrix_authorization(
            &identity,
            FilterProbeClass::SameAddressDifferentPort,
            21,
            802,
        );
        profile
            .record_filter_probe_at(
                &send_failed,
                None,
                FilterProbeOutcome::SendFailed,
                now,
                MATRIX_WALL_NOW,
            )
            .unwrap();
        profile
            .record_filter_probe_at(
                &unavailable,
                None,
                FilterProbeOutcome::Unavailable,
                now,
                MATRIX_WALL_NOW,
            )
            .unwrap();

        let snapshot = profile.filter_matrix_snapshot_at(now);
        assert_eq!(
            snapshot.contacted_endpoint,
            FilterCellStatus::InconclusiveSendFailed
        );
        assert_eq!(
            snapshot.same_address_different_port,
            FilterCellStatus::InconclusiveUnavailable
        );
        assert_eq!(
            profile.filtering_evidence_at(now),
            NatFilteringEvidence::Inconclusive
        );
    }

    #[test]
    fn only_observed_outcomes_accept_and_validate_source_tuples() {
        let identity = NodeIdentity::generate();
        let now = Instant::now();
        let mut profile = profile_with_target();
        let different =
            matrix_authorization(&identity, FilterProbeClass::DifferentAddress, 10, 401);

        assert!(profile
            .record_filter_probe_at(
                &different,
                None,
                FilterProbeOutcome::Observed,
                now,
                MATRIX_WALL_NOW,
            )
            .is_err());
        assert!(profile
            .record_filter_probe_at(
                &different,
                Some("192.0.2.10:39000".parse().unwrap()),
                FilterProbeOutcome::TimedOut,
                now,
                MATRIX_WALL_NOW,
            )
            .is_err());
        assert!(profile
            .record_filter_probe_at(
                &different,
                Some(baseline_endpoint()),
                FilterProbeOutcome::Observed,
                now,
                MATRIX_WALL_NOW,
            )
            .is_err());
        assert!(profile
            .record_filter_probe_at(
                &different,
                Some(target_endpoint()),
                FilterProbeOutcome::Observed,
                now,
                MATRIX_WALL_NOW,
            )
            .is_err());
        assert!(profile
            .record_filter_probe_at(
                &different,
                Some("[2001:db8::1]:39000".parse().unwrap()),
                FilterProbeOutcome::Observed,
                now,
                MATRIX_WALL_NOW,
            )
            .is_err());

        let control = matrix_authorization(&identity, FilterProbeClass::ContactedEndpoint, 11, 402);
        for wrong_source in [
            "198.51.100.10:39001".parse().unwrap(),
            "192.0.2.10:39000".parse().unwrap(),
        ] {
            assert!(profile
                .record_filter_probe_at(
                    &control,
                    Some(wrong_source),
                    FilterProbeOutcome::Observed,
                    now,
                    MATRIX_WALL_NOW,
                )
                .is_err());
        }

        let same_address = matrix_authorization(
            &identity,
            FilterProbeClass::SameAddressDifferentPort,
            12,
            403,
        );
        for wrong_source in [baseline_endpoint(), "192.0.2.10:39001".parse().unwrap()] {
            assert!(profile
                .record_filter_probe_at(
                    &same_address,
                    Some(wrong_source),
                    FilterProbeOutcome::Observed,
                    now,
                    MATRIX_WALL_NOW,
                )
                .is_err());
        }
    }

    #[test]
    fn valid_authorization_for_an_old_target_mapping_is_rejected() {
        let identity = NodeIdentity::generate();
        let now = Instant::now();
        let mut profile = profile_with_target();
        let authorization = FilteringMatrixAuthorization::signed_at(
            &identity,
            "203.0.113.55:47001".parse().unwrap(),
            "knp1coordinator".into(),
            baseline_endpoint(),
            "knp1helper".into(),
            FilterProbeClass::DifferentAddress,
            22,
            901,
            MATRIX_WALL_NOW,
        )
        .unwrap();

        assert!(profile
            .record_filter_probe_at(
                &authorization,
                Some("192.0.2.10:39000".parse().unwrap()),
                FilterProbeOutcome::Observed,
                now,
                MATRIX_WALL_NOW,
            )
            .is_err());
        assert_eq!(profile.filter_matrix_evidence_count(), 0);
    }

    #[test]
    fn matrix_evidence_expires_and_mapping_changes_invalidate_it() {
        let identity = NodeIdentity::generate();
        let now = Instant::now();
        let mut profile = profile_with_target();
        let authorization =
            matrix_authorization(&identity, FilterProbeClass::DifferentAddress, 11, 501);
        profile
            .record_filter_probe_at(
                &authorization,
                Some("192.0.2.10:39000".parse().unwrap()),
                FilterProbeOutcome::Observed,
                now,
                MATRIX_WALL_NOW,
            )
            .unwrap();

        assert_eq!(
            profile.filtering_evidence_at(now + FILTERING_MATRIX_EVIDENCE_TTL),
            NatFilteringEvidence::Unknown
        );
        assert_eq!(
            profile.expire_filter_matrix_at(now + FILTERING_MATRIX_EVIDENCE_TTL),
            1
        );

        profile
            .record_filter_probe_at(
                &authorization,
                Some("192.0.2.10:39000".parse().unwrap()),
                FilterProbeOutcome::Observed,
                now,
                MATRIX_WALL_NOW,
            )
            .unwrap();
        profile.observe("observer-a".into(), "203.0.113.55:47001".parse().unwrap());
        assert_eq!(profile.filter_matrix_evidence_count(), 0);
        assert_eq!(
            profile.filtering_evidence_at(now),
            NatFilteringEvidence::Unknown
        );
        assert_eq!(
            profile.filter_matrix_snapshot_at(now).target_endpoint,
            Some("203.0.113.55:47001".parse().unwrap())
        );
    }

    #[test]
    fn matrix_storage_is_bounded_by_profile_capacity() {
        let identity = NodeIdentity::generate();
        let now = Instant::now();
        let mut profile = NatProfile::new(3);
        profile.observe("observer-a".into(), target_endpoint());

        for trial_id in 1..=4 {
            let authorization = matrix_authorization(
                &identity,
                FilterProbeClass::DifferentAddress,
                trial_id,
                600 + trial_id,
            );
            profile
                .record_filter_probe_at(
                    &authorization,
                    Some(format!("192.0.{}.10:39000", trial_id).parse().unwrap()),
                    FilterProbeOutcome::Observed,
                    now,
                    MATRIX_WALL_NOW,
                )
                .unwrap();
        }

        assert_eq!(profile.filter_matrix_evidence_count(), 3);
        assert_eq!(profile.filter_matrix.front().unwrap().trial_id, 2);
    }

    #[test]
    fn conflicting_trial_cell_is_rejected_but_exact_replay_is_idempotent() {
        let identity = NodeIdentity::generate();
        let now = Instant::now();
        let mut profile = profile_with_target();
        let authorization =
            matrix_authorization(&identity, FilterProbeClass::DifferentAddress, 12, 701);
        let source = Some("192.0.2.10:39000".parse().unwrap());
        profile
            .record_filter_probe_at(
                &authorization,
                source,
                FilterProbeOutcome::Observed,
                now,
                MATRIX_WALL_NOW,
            )
            .unwrap();
        profile
            .record_filter_probe_at(
                &authorization,
                source,
                FilterProbeOutcome::Observed,
                now + Duration::from_secs(1),
                MATRIX_WALL_NOW,
            )
            .unwrap();
        assert_eq!(profile.filter_matrix_evidence_count(), 1);
        assert!(profile
            .record_filter_probe_at(
                &authorization,
                Some("192.0.3.10:39000".parse().unwrap()),
                FilterProbeOutcome::Observed,
                now + Duration::from_secs(1),
                MATRIX_WALL_NOW,
            )
            .is_err());
    }
}
