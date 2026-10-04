use crate::identity::{node_id_from_public_key, NodeIdentity, PUBLIC_KEY_LEN, SIGNATURE_LEN};
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const DEFAULT_DHT_MAX_RECORDS: usize = 4_096;
pub const DHT_RESPONSE_LIMIT: usize = 8;
pub const MAX_RECORD_ENDPOINTS: usize = 4;
pub const DEFAULT_RECORD_TTL_MS: u64 = 10 * 60 * 1_000;
pub const MAX_RECORD_TTL_MS: u64 = 30 * 60 * 1_000;
pub const DHT_BUCKET_COUNT: usize = 256;
pub const DHT_BUCKET_SIZE: usize = 8;
pub const DHT_QUERY_FANOUT: usize = 2;
pub const DHT_MAX_HOPS: u8 = 3;
pub const DHT_QUERY_TIMEOUT: Duration = Duration::from_secs(8);
pub const DHT_QUERY_RETRY_DELAY: Duration = Duration::from_secs(5);
pub const DEFAULT_ENDPOINT_ATTESTATION_TTL_MS: u64 = 5 * 60 * 1_000;
pub const MAX_ENDPOINT_ATTESTATION_TTL_MS: u64 = 10 * 60 * 1_000;
pub const DEFAULT_DHT_MAX_ATTESTATIONS: usize = DEFAULT_DHT_MAX_RECORDS * MAX_RECORD_ENDPOINTS;
const RECORD_CLOCK_SKEW_MS: u64 = 120_000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EndpointAttestation {
    pub subject_node_id: String,
    pub endpoint: String,
    pub observer_node_id: String,
    pub observer_public_key: String,
    pub observed_unix_ms: u64,
    pub expires_unix_ms: u64,
    pub signature: String,
}

#[derive(Serialize)]
struct UnsignedEndpointAttestation<'a> {
    subject_node_id: &'a str,
    endpoint: &'a str,
    observer_node_id: &'a str,
    observer_public_key: &'a str,
    observed_unix_ms: u64,
    expires_unix_ms: u64,
}

impl EndpointAttestation {
    pub fn signed(
        observer: &NodeIdentity,
        subject_node_id: String,
        endpoint: SocketAddr,
    ) -> Result<Self> {
        let now = unix_time_ms()?;
        Self::signed_at(
            observer,
            subject_node_id,
            endpoint,
            now,
            DEFAULT_ENDPOINT_ATTESTATION_TTL_MS,
        )
    }

    fn signed_at(
        observer: &NodeIdentity,
        subject_node_id: String,
        endpoint: SocketAddr,
        now: u64,
        ttl_ms: u64,
    ) -> Result<Self> {
        if observer.node_id() == subject_node_id {
            bail!("endpoint attestation requires an independent observer");
        }
        if !endpoint_publishable(endpoint) {
            bail!("attested endpoint is not publishable");
        }

        let mut attestation = Self {
            subject_node_id,
            endpoint: endpoint.to_string(),
            observer_node_id: observer.node_id(),
            observer_public_key: observer.public_key_hex(),
            observed_unix_ms: now,
            expires_unix_ms: now.saturating_add(ttl_ms.min(MAX_ENDPOINT_ATTESTATION_TTL_MS)),
            signature: String::new(),
        };
        attestation.signature = hex::encode(observer.sign(&attestation.signing_bytes()?));
        Ok(attestation)
    }

    pub fn verify(&self) -> Result<()> {
        self.verify_at(unix_time_ms()?)
    }

    fn verify_at(&self, now: u64) -> Result<()> {
        if !plausible_node_id(&self.subject_node_id) {
            bail!("endpoint attestation subject NodeID is invalid");
        }
        if self.subject_node_id == self.observer_node_id {
            bail!("endpoint attestation is self-issued");
        }
        if self.observed_unix_ms > now.saturating_add(RECORD_CLOCK_SKEW_MS) {
            bail!("endpoint attestation issued too far in the future");
        }
        if self.expires_unix_ms <= now {
            bail!("endpoint attestation expired");
        }
        if self.expires_unix_ms < self.observed_unix_ms
            || self.expires_unix_ms - self.observed_unix_ms > MAX_ENDPOINT_ATTESTATION_TTL_MS
        {
            bail!("endpoint attestation TTL is invalid");
        }

        let endpoint = self
            .endpoint
            .parse::<SocketAddr>()
            .context("attested endpoint is not a socket address")?;
        if !endpoint_publishable(endpoint) {
            bail!("attested endpoint is not publishable");
        }

        let public_key_raw = hex::decode(&self.observer_public_key)
            .context("attestation observer public key is not valid hex")?;
        let public_key: [u8; PUBLIC_KEY_LEN] = public_key_raw
            .try_into()
            .map_err(|_| anyhow!("attestation observer public key must be 32 bytes"))?;
        if node_id_from_public_key(&public_key) != self.observer_node_id {
            bail!("attestation observer NodeID/public-key mismatch");
        }

        let signature_raw = hex::decode(&self.signature)
            .context("attestation signature is not valid hex")?;
        let signature: [u8; SIGNATURE_LEN] = signature_raw
            .try_into()
            .map_err(|_| anyhow!("attestation signature must be 64 bytes"))?;
        NodeIdentity::verify_with_public_key(&public_key, &self.signing_bytes()?, &signature)
    }

    fn signing_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(&UnsignedEndpointAttestation {
            subject_node_id: &self.subject_node_id,
            endpoint: &self.endpoint,
            observer_node_id: &self.observer_node_id,
            observer_public_key: &self.observer_public_key,
            observed_unix_ms: self.observed_unix_ms,
            expires_unix_ms: self.expires_unix_ms,
        })
        .context("failed to serialize endpoint attestation")
    }
}

#[derive(Debug)]
pub struct EndpointAttestationTable {
    attestations: HashMap<(String, String, String), EndpointAttestation>,
    max_attestations: usize,
}

impl Default for EndpointAttestationTable {
    fn default() -> Self {
        Self::new(DEFAULT_DHT_MAX_ATTESTATIONS)
    }
}

impl EndpointAttestationTable {
    pub fn new(max_attestations: usize) -> Self {
        Self {
            attestations: HashMap::new(),
            max_attestations: max_attestations.max(1),
        }
    }

    pub fn upsert(&mut self, attestation: EndpointAttestation) -> Result<bool> {
        attestation.verify()?;
        let key = (
            attestation.subject_node_id.clone(),
            attestation.endpoint.clone(),
            attestation.observer_node_id.clone(),
        );
        if self
            .attestations
            .get(&key)
            .is_some_and(|existing| existing.observed_unix_ms >= attestation.observed_unix_ms)
        {
            return Ok(false);
        }
        if !self.attestations.contains_key(&key)
            && self.attestations.len() >= self.max_attestations
        {
            self.evict_oldest();
        }
        self.attestations.insert(key, attestation);
        Ok(true)
    }

    pub fn independent_observer_count(&self, subject_node_id: &str, endpoint: SocketAddr) -> usize {
        let endpoint = endpoint.to_string();
        let now = unix_time_ms().unwrap_or(u64::MAX);
        self.attestations
            .values()
            .filter(|attestation| {
                attestation.subject_node_id == subject_node_id
                    && attestation.endpoint == endpoint
                    && attestation.expires_unix_ms > now
            })
            .map(|attestation| &attestation.observer_node_id)
            .collect::<HashSet<_>>()
            .len()
    }

    pub fn attested_endpoints(
        &self,
        record: &PeerRecord,
        minimum_independent_observers: usize,
    ) -> Vec<SocketAddr> {
        record
            .socket_endpoints()
            .into_iter()
            .filter(|endpoint| {
                self.independent_observer_count(&record.node_id, *endpoint)
                    >= minimum_independent_observers.max(1)
            })
            .collect()
    }

    pub fn expire(&mut self) -> usize {
        let now = unix_time_ms().unwrap_or(u64::MAX);
        let before = self.attestations.len();
        self.attestations.retain(|_, attestation| attestation.expires_unix_ms > now);
        before.saturating_sub(self.attestations.len())
    }

    pub fn len(&self) -> usize {
        self.attestations.len()
    }

    pub fn is_empty(&self) -> bool {
        self.attestations.is_empty()
    }

    fn evict_oldest(&mut self) {
        if let Some(key) = self
            .attestations
            .iter()
            .min_by_key(|(_, attestation)| {
                (attestation.expires_unix_ms, attestation.observed_unix_ms)
            })
            .map(|(key, _)| key.clone())
        {
            self.attestations.remove(&key);
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerRecord {
    pub node_id: String,
    pub public_key: String,
    pub endpoints: Vec<String>,
    pub sequence: u64,
    pub issued_unix_ms: u64,
    pub expires_unix_ms: u64,
    pub signature: String,
}

#[derive(Serialize)]
struct UnsignedPeerRecord<'a> {
    node_id: &'a str,
    public_key: &'a str,
    endpoints: &'a [String],
    sequence: u64,
    issued_unix_ms: u64,
    expires_unix_ms: u64,
}

impl PeerRecord {
    pub fn signed(identity: &NodeIdentity, endpoints: Vec<SocketAddr>) -> Result<Self> {
        let now = unix_time_ms()?;
        Self::signed_at(identity, endpoints, now, DEFAULT_RECORD_TTL_MS)
    }

    fn signed_at(
        identity: &NodeIdentity,
        endpoints: Vec<SocketAddr>,
        now: u64,
        ttl_ms: u64,
    ) -> Result<Self> {
        if endpoints.is_empty() {
            bail!("DHT peer record requires at least one endpoint");
        }
        if endpoints.len() > MAX_RECORD_ENDPOINTS {
            bail!("DHT peer record contains too many endpoints");
        }

        let mut endpoints: Vec<String> = endpoints
            .into_iter()
            .filter(|endpoint| endpoint_publishable(*endpoint))
            .map(|endpoint| endpoint.to_string())
            .collect();
        endpoints.sort();
        endpoints.dedup();

        if endpoints.is_empty() {
            bail!("DHT peer record has no publishable endpoint");
        }

        let ttl_ms = ttl_ms.min(MAX_RECORD_TTL_MS);
        let mut record = Self {
            node_id: identity.node_id(),
            public_key: identity.public_key_hex(),
            endpoints,
            sequence: now,
            issued_unix_ms: now,
            expires_unix_ms: now.saturating_add(ttl_ms),
            signature: String::new(),
        };
        record.signature = hex::encode(identity.sign(&record.signing_bytes()?));
        Ok(record)
    }

    pub fn verify(&self) -> Result<()> {
        self.verify_at(unix_time_ms()?)
    }

    fn verify_at(&self, now: u64) -> Result<()> {
        if self.endpoints.is_empty() || self.endpoints.len() > MAX_RECORD_ENDPOINTS {
            bail!("invalid DHT endpoint count");
        }
        if self.sequence != self.issued_unix_ms {
            bail!("DHT record sequence/issued timestamp mismatch");
        }
        if self.issued_unix_ms > now.saturating_add(RECORD_CLOCK_SKEW_MS) {
            bail!("DHT record issued too far in the future");
        }
        if self.expires_unix_ms <= now {
            bail!("DHT record expired");
        }
        if self.expires_unix_ms < self.issued_unix_ms
            || self.expires_unix_ms - self.issued_unix_ms > MAX_RECORD_TTL_MS
        {
            bail!("DHT record TTL is invalid");
        }

        for endpoint in &self.endpoints {
            let endpoint = endpoint
                .parse::<SocketAddr>()
                .context("DHT endpoint is not a socket address")?;
            if !endpoint_publishable(endpoint) {
                bail!("DHT endpoint is not publishable");
            }
        }

        let public_key_raw =
            hex::decode(&self.public_key).context("DHT public key is not valid hex")?;
        let public_key: [u8; PUBLIC_KEY_LEN] = public_key_raw
            .try_into()
            .map_err(|_| anyhow!("DHT public key must be 32 bytes"))?;

        if node_id_from_public_key(&public_key) != self.node_id {
            bail!("DHT NodeID/public-key mismatch");
        }

        let signature_raw =
            hex::decode(&self.signature).context("DHT signature is not valid hex")?;
        let signature: [u8; SIGNATURE_LEN] = signature_raw
            .try_into()
            .map_err(|_| anyhow!("DHT signature must be 64 bytes"))?;

        NodeIdentity::verify_with_public_key(&public_key, &self.signing_bytes()?, &signature)
    }

    pub fn socket_endpoints(&self) -> Vec<SocketAddr> {
        self.endpoints
            .iter()
            .filter_map(|endpoint| endpoint.parse().ok())
            .collect()
    }

    fn signing_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(&UnsignedPeerRecord {
            node_id: &self.node_id,
            public_key: &self.public_key,
            endpoints: &self.endpoints,
            sequence: self.sequence,
            issued_unix_ms: self.issued_unix_ms,
            expires_unix_ms: self.expires_unix_ms,
        })
        .context("failed to serialize DHT peer record")
    }
}

#[derive(Debug)]
pub struct DhtTable {
    records: HashMap<String, PeerRecord>,
    max_records: usize,
}

impl Default for DhtTable {
    fn default() -> Self {
        Self::new(DEFAULT_DHT_MAX_RECORDS)
    }
}

impl DhtTable {
    pub fn new(max_records: usize) -> Self {
        Self {
            records: HashMap::new(),
            max_records: max_records.max(1),
        }
    }

    pub fn upsert(&mut self, record: PeerRecord) -> Result<bool> {
        record.verify()?;

        if let Some(existing) = self.records.get(&record.node_id) {
            if record.sequence <= existing.sequence {
                return Ok(false);
            }
        }

        if !self.records.contains_key(&record.node_id) && self.records.len() >= self.max_records {
            self.evict_oldest();
        }

        self.records.insert(record.node_id.clone(), record);
        Ok(true)
    }

    pub fn get(&self, node_id: &str) -> Option<&PeerRecord> {
        self.records.get(node_id)
    }

    pub fn nearest(&self, target_node_id: &str, limit: usize) -> Vec<PeerRecord> {
        let target = key_hash(target_node_id);
        let mut records: Vec<&PeerRecord> = self.records.values().collect();
        records.sort_by_key(|record| xor_distance(key_hash(&record.node_id), target));
        records
            .into_iter()
            .take(limit.min(DHT_RESPONSE_LIMIT))
            .cloned()
            .collect()
    }

    pub fn expire(&mut self) -> usize {
        let now = unix_time_ms().unwrap_or(u64::MAX);
        let before = self.records.len();
        self.records
            .retain(|_, record| record.expires_unix_ms > now);
        before.saturating_sub(self.records.len())
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    fn evict_oldest(&mut self) {
        if let Some(node_id) = self
            .records
            .iter()
            .min_by_key(|(_, record)| (record.expires_unix_ms, record.sequence))
            .map(|(node_id, _)| node_id.clone())
        {
            self.records.remove(&node_id);
        }
    }
}

#[derive(Debug, Clone)]
pub struct RoutingPeer {
    pub node_id: String,
    pub endpoint: SocketAddr,
    pub last_seen: Instant,
}

#[derive(Debug)]
pub struct RoutingTable {
    local_key: [u8; 32],
    buckets: Vec<Vec<RoutingPeer>>,
}

impl RoutingTable {
    pub fn new(local_node_id: &str) -> Self {
        Self {
            local_key: key_hash(local_node_id),
            buckets: vec![Vec::new(); DHT_BUCKET_COUNT],
        }
    }

    pub fn observe(&mut self, node_id: String, endpoint: SocketAddr, now: Instant) {
        let remote_key = key_hash(&node_id);
        let Some(bucket_index) = bucket_index(self.local_key, remote_key) else {
            return;
        };
        let bucket = &mut self.buckets[bucket_index];

        if let Some(existing) = bucket
            .iter_mut()
            .find(|peer| peer.node_id == node_id || peer.endpoint == endpoint)
        {
            existing.node_id = node_id;
            existing.endpoint = endpoint;
            existing.last_seen = now;
            return;
        }

        if bucket.len() >= DHT_BUCKET_SIZE {
            if let Some(oldest_index) = bucket
                .iter()
                .enumerate()
                .min_by_key(|(_, peer)| peer.last_seen)
                .map(|(index, _)| index)
            {
                bucket.remove(oldest_index);
            }
        }

        bucket.push(RoutingPeer {
            node_id,
            endpoint,
            last_seen: now,
        });
    }

    pub fn nearest(&self, target_node_id: &str, limit: usize) -> Vec<RoutingPeer> {
        let target = key_hash(target_node_id);
        let mut peers: Vec<RoutingPeer> = self.buckets.iter().flatten().cloned().collect();

        peers.sort_by_key(|peer| xor_distance(key_hash(&peer.node_id), target));
        peers.truncate(limit);
        peers
    }

    pub fn remove_endpoint(&mut self, endpoint: SocketAddr) {
        for bucket in &mut self.buckets {
            bucket.retain(|peer| peer.endpoint != endpoint);
        }
    }

    pub fn retain_endpoints(&mut self, endpoints: &HashSet<SocketAddr>) {
        for bucket in &mut self.buckets {
            bucket.retain(|peer| endpoints.contains(&peer.endpoint));
        }
    }

    pub fn len(&self) -> usize {
        self.buckets.iter().map(Vec::len).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn bucket_entries(&self) -> Vec<(usize, RoutingPeer)> {
        self.buckets
            .iter()
            .enumerate()
            .flat_map(|(bucket_index, peers)| {
                peers.iter().cloned().map(move |peer| (bucket_index, peer))
            })
            .collect()
    }
}

pub fn routing_bucket_index(local_node_id: &str, remote_node_id: &str) -> Option<usize> {
    bucket_index(key_hash(local_node_id), key_hash(remote_node_id))
}

fn bucket_index(local: [u8; 32], remote: [u8; 32]) -> Option<usize> {
    let distance = xor_distance(local, remote);
    let leading_zero_bits: usize = distance
        .iter()
        .take_while(|byte| **byte == 0)
        .count()
        .saturating_mul(8);

    let first_nonzero = distance.iter().find(|byte| **byte != 0)?;
    let leading_zero_bits = leading_zero_bits + first_nonzero.leading_zeros() as usize;
    Some(255_usize.saturating_sub(leading_zero_bits))
}

pub fn endpoint_publishable(endpoint: SocketAddr) -> bool {
    if endpoint.port() == 0 {
        return false;
    }

    match endpoint.ip() {
        IpAddr::V4(ip) => {
            !ip.is_unspecified()
                && !ip.is_loopback()
                && !ip.is_multicast()
                && !ip.is_broadcast()
                && !ip.is_private()
                && !ip.is_link_local()
        }
        IpAddr::V6(ip) => {
            !ip.is_unspecified()
                && !ip.is_loopback()
                && !ip.is_multicast()
                && !ip.is_unique_local()
                && !ip.is_unicast_link_local()
        }
    }
}

fn key_hash(node_id: &str) -> [u8; 32] {
    Sha256::digest(node_id.as_bytes()).into()
}

fn plausible_node_id(node_id: &str) -> bool {
    node_id.len() == 44
        && node_id.starts_with("knp1")
        && node_id[4..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn xor_distance(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut distance = [0_u8; 32];
    for index in 0..32 {
        distance[index] = left[index] ^ right[index];
    }
    distance
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
    fn signed_record_verifies_and_tampering_fails() {
        let identity = NodeIdentity::generate();
        let mut record =
            PeerRecord::signed(&identity, vec!["8.8.8.8:47000".parse().unwrap()]).unwrap();

        record.verify().unwrap();
        record.endpoints[0] = "1.1.1.1:47000".to_owned();
        assert!(record.verify().is_err());
    }

    #[test]
    fn endpoint_attestation_requires_independent_valid_observer() {
        let subject = NodeIdentity::generate();
        let observer = NodeIdentity::generate();
        let endpoint: SocketAddr = "8.8.8.8:47000".parse().unwrap();
        let mut attestation =
            EndpointAttestation::signed(&observer, subject.node_id(), endpoint).unwrap();

        attestation.verify().unwrap();
        attestation.endpoint = "1.1.1.1:47000".into();
        assert!(attestation.verify().is_err());
        assert!(EndpointAttestation::signed(&subject, subject.node_id(), endpoint).is_err());
    }

    #[test]
    fn attestation_table_deduplicates_observers_rejects_rollback_and_is_bounded() {
        let now = unix_time_ms().unwrap();
        let subject = NodeIdentity::generate();
        let observer_a = NodeIdentity::generate();
        let observer_b = NodeIdentity::generate();
        let endpoint: SocketAddr = "8.8.8.8:47000".parse().unwrap();
        let mut table = EndpointAttestationTable::new(2);

        let first = EndpointAttestation::signed_at(
            &observer_a,
            subject.node_id(),
            endpoint,
            now,
            DEFAULT_ENDPOINT_ATTESTATION_TTL_MS,
        )
        .unwrap();
        table.upsert(first).unwrap();
        let rollback = EndpointAttestation::signed_at(
            &observer_a,
            subject.node_id(),
            endpoint,
            now.saturating_sub(1),
            DEFAULT_ENDPOINT_ATTESTATION_TTL_MS,
        )
        .unwrap();
        assert!(!table.upsert(rollback).unwrap());
        assert_eq!(
            table.independent_observer_count(&subject.node_id(), endpoint),
            1
        );

        let second = EndpointAttestation::signed_at(
            &observer_b,
            subject.node_id(),
            endpoint,
            now.saturating_add(1),
            DEFAULT_ENDPOINT_ATTESTATION_TTL_MS,
        )
        .unwrap();
        table.upsert(second).unwrap();
        assert_eq!(
            table.independent_observer_count(&subject.node_id(), endpoint),
            2
        );

        let record = PeerRecord::signed_at(
            &subject,
            vec![endpoint, "1.1.1.1:47000".parse().unwrap()],
            now,
            DEFAULT_RECORD_TTL_MS,
        )
        .unwrap();
        assert_eq!(table.attested_endpoints(&record, 2), vec![endpoint]);
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn unsafe_or_local_endpoints_are_not_publishable() {
        assert!(!endpoint_publishable("127.0.0.1:47000".parse().unwrap()));
        assert!(!endpoint_publishable("192.168.1.20:47000".parse().unwrap()));
        assert!(!endpoint_publishable("[::1]:47000".parse().unwrap()));
        assert!(endpoint_publishable("8.8.8.8:47000".parse().unwrap()));
    }

    #[test]
    fn routing_table_keeps_only_bucket_limit_and_refreshes_peers() {
        let local = "knp1-local";
        let desired_bucket = 255;
        let mut matching = Vec::new();

        for index in 0..100_000_u32 {
            let node_id = format!("knp1-candidate-{index}");
            if bucket_index(key_hash(local), key_hash(&node_id)) == Some(desired_bucket) {
                matching.push(node_id);
                if matching.len() == DHT_BUCKET_SIZE + 2 {
                    break;
                }
            }
        }

        assert_eq!(matching.len(), DHT_BUCKET_SIZE + 2);

        let mut routing = RoutingTable::new(local);
        let now = Instant::now();
        for (index, node_id) in matching.into_iter().enumerate() {
            routing.observe(
                node_id,
                format!("8.8.8.{}:47000", (index % 200) + 1)
                    .parse()
                    .unwrap(),
                now + Duration::from_millis(index as u64),
            );
        }

        assert_eq!(routing.len(), DHT_BUCKET_SIZE);
    }

    #[test]
    fn routing_table_snapshot_preserves_bucket_membership() {
        let local = "knp1-local";
        let mut routing = RoutingTable::new(local);
        let now = Instant::now();
        routing.observe("knp1-a".into(), "8.8.8.8:47000".parse().unwrap(), now);
        routing.observe("knp1-b".into(), "1.1.1.1:47000".parse().unwrap(), now);

        let snapshot = routing.bucket_entries();
        assert_eq!(snapshot.len(), 2);
        for (bucket_index, peer) in snapshot {
            assert_eq!(
                routing_bucket_index(local, &peer.node_id),
                Some(bucket_index)
            );
        }
    }

    #[test]
    fn routing_table_nearest_prefers_target_identity() {
        let mut routing = RoutingTable::new("knp1-local");
        let now = Instant::now();
        routing.observe("knp1-a".into(), "8.8.8.8:47000".parse().unwrap(), now);
        routing.observe("knp1-b".into(), "1.1.1.1:47000".parse().unwrap(), now);

        let nearest = routing.nearest("knp1-a", 2);
        assert_eq!(
            nearest.first().map(|peer| peer.node_id.as_str()),
            Some("knp1-a")
        );
    }

    #[test]
    fn table_rejects_rollback_and_is_bounded() {
        let now = unix_time_ms().unwrap();
        let a = NodeIdentity::generate();
        let b = NodeIdentity::generate();
        let mut table = DhtTable::new(1);

        let first = PeerRecord::signed_at(
            &a,
            vec!["8.8.8.8:47000".parse().unwrap()],
            now,
            DEFAULT_RECORD_TTL_MS,
        )
        .unwrap();
        table.upsert(first.clone()).unwrap();

        let rollback = PeerRecord::signed_at(
            &a,
            vec!["8.8.4.4:47000".parse().unwrap()],
            now.saturating_sub(1),
            DEFAULT_RECORD_TTL_MS,
        )
        .unwrap();
        assert!(!table.upsert(rollback).unwrap());
        assert_eq!(table.get(&a.node_id()), Some(&first));

        let second = PeerRecord::signed_at(
            &b,
            vec!["1.1.1.1:47000".parse().unwrap()],
            now.saturating_add(1),
            DEFAULT_RECORD_TTL_MS,
        )
        .unwrap();
        table.upsert(second).unwrap();
        assert_eq!(table.len(), 1);
    }
}
