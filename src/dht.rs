use crate::identity::{
    node_id_from_public_key, NodeIdentity, PUBLIC_KEY_LEN, SIGNATURE_LEN,
};
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};

pub const DEFAULT_DHT_MAX_RECORDS: usize = 4_096;
pub const DHT_RESPONSE_LIMIT: usize = 8;
pub const MAX_RECORD_ENDPOINTS: usize = 4;
pub const DEFAULT_RECORD_TTL_MS: u64 = 10 * 60 * 1_000;
pub const MAX_RECORD_TTL_MS: u64 = 30 * 60 * 1_000;
const RECORD_CLOCK_SKEW_MS: u64 = 120_000;

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
        let mut record = PeerRecord::signed(
            &identity,
            vec!["8.8.8.8:47000".parse().unwrap()],
        )
        .unwrap();

        record.verify().unwrap();
        record.endpoints[0] = "1.1.1.1:47000".to_owned();
        assert!(record.verify().is_err());
    }

    #[test]
    fn unsafe_or_local_endpoints_are_not_publishable() {
        assert!(!endpoint_publishable("127.0.0.1:47000".parse().unwrap()));
        assert!(!endpoint_publishable("192.168.1.20:47000".parse().unwrap()));
        assert!(!endpoint_publishable("[::1]:47000".parse().unwrap()));
        assert!(endpoint_publishable("8.8.8.8:47000".parse().unwrap()));
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
