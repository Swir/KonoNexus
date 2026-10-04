use crate::dht::{
    dht_network_group, routing_bucket_index, DHT_BUCKET_COUNT, DHT_BUCKET_NETWORK_GROUP_LIMIT,
    DHT_BUCKET_SIZE,
};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::cmp::Reverse;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const ROUTING_CACHE_VERSION: u16 = 1;
pub const ROUTING_BUCKET_CACHE_VERSION: u16 = 2;
pub const MAX_ROUTING_CACHE_ENTRIES: usize = 256;
pub const MAX_ROUTING_BUCKET_CACHE_ENTRIES: usize = DHT_BUCKET_COUNT * DHT_BUCKET_SIZE;
pub const MAX_ROUTING_BOOTSTRAP_HINTS: usize = 256;
pub const ROUTING_CACHE_MAX_AGE_MS: u64 = 7 * 24 * 60 * 60 * 1_000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RoutingCacheEntry {
    pub node_id: String,
    pub endpoint: String,
    pub saved_unix_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RoutingBucketCacheEntry {
    pub bucket_index: u16,
    pub node_id: String,
    pub endpoint: String,
    pub last_seen_unix_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RoutingCacheFile {
    version: u16,
    entries: Vec<RoutingCacheEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RoutingBucketCacheFile {
    version: u16,
    local_node_id: String,
    saved_unix_ms: u64,
    entries: Vec<RoutingBucketCacheEntry>,
}

pub fn load_routing_hints(path: &Path) -> Result<Vec<RoutingCacheEntry>> {
    if !path.exists() {
        return Ok(Vec::new());
    }

    let raw = fs::read(path)
        .with_context(|| format!("failed to read routing cache {}", path.display()))?;
    let value: serde_json::Value =
        serde_json::from_slice(&raw).context("failed to decode routing cache")?;
    let version = value
        .get("version")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_default();

    let now = unix_time_ms()?;
    let candidates: Vec<RoutingCacheEntry> = match version as u16 {
        ROUTING_CACHE_VERSION => {
            let cache: RoutingCacheFile =
                serde_json::from_value(value).context("failed to decode routing cache")?;
            cache.entries
        }
        ROUTING_BUCKET_CACHE_VERSION => {
            let cache: RoutingBucketCacheFile =
                serde_json::from_value(value).context("failed to decode routing bucket cache")?;
            cache
                .entries
                .into_iter()
                .map(|entry| RoutingCacheEntry {
                    node_id: entry.node_id,
                    endpoint: entry.endpoint,
                    saved_unix_ms: entry.last_seen_unix_ms,
                })
                .collect()
        }
        _ => return Ok(Vec::new()),
    };

    let mut entries = Vec::new();
    for entry in candidates.into_iter().take(MAX_ROUTING_CACHE_ENTRIES) {
        if entry.saved_unix_ms > now
            || now.saturating_sub(entry.saved_unix_ms) > ROUTING_CACHE_MAX_AGE_MS
        {
            continue;
        }

        let Ok(endpoint) = entry.endpoint.parse::<SocketAddr>() else {
            continue;
        };
        if !cache_endpoint_allowed(endpoint) || !plausible_node_id(&entry.node_id) {
            continue;
        }

        entries.push(entry);
    }

    Ok(entries)
}

pub fn save_routing_hints(path: &Path, entries: &[RoutingCacheEntry]) -> Result<()> {
    let mut entries: Vec<RoutingCacheEntry> = entries
        .iter()
        .filter(|entry| {
            plausible_node_id(&entry.node_id)
                && entry
                    .endpoint
                    .parse::<SocketAddr>()
                    .is_ok_and(cache_endpoint_allowed)
        })
        .take(MAX_ROUTING_CACHE_ENTRIES)
        .cloned()
        .collect();

    entries.sort_by(|left, right| {
        left.node_id
            .cmp(&right.node_id)
            .then(left.endpoint.cmp(&right.endpoint))
    });
    entries
        .dedup_by(|left, right| left.node_id == right.node_id && left.endpoint == right.endpoint);

    let encoded = serde_json::to_vec_pretty(&RoutingCacheFile {
        version: ROUTING_CACHE_VERSION,
        entries,
    })
    .context("failed to encode routing cache")?;

    write_atomic(path, &encoded)
}

pub fn load_routing_bucket_snapshot(
    path: &Path,
    local_node_id: &str,
) -> Result<Vec<RoutingBucketCacheEntry>> {
    if !plausible_node_id(local_node_id) {
        bail!("invalid local NodeID for routing bucket cache");
    }
    if !path.exists() {
        return Ok(Vec::new());
    }

    let raw = fs::read(path)
        .with_context(|| format!("failed to read routing cache {}", path.display()))?;
    let value: serde_json::Value =
        serde_json::from_slice(&raw).context("failed to decode routing cache")?;
    let version = value
        .get("version")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_default();

    let now = unix_time_ms()?;
    match version as u16 {
        ROUTING_CACHE_VERSION => {
            let legacy: RoutingCacheFile =
                serde_json::from_value(value).context("failed to decode legacy routing cache")?;
            let entries = legacy
                .entries
                .into_iter()
                .filter_map(|entry| {
                    let bucket_index = routing_bucket_index(local_node_id, &entry.node_id)?;
                    Some(RoutingBucketCacheEntry {
                        bucket_index: bucket_index.try_into().ok()?,
                        node_id: entry.node_id,
                        endpoint: entry.endpoint,
                        last_seen_unix_ms: entry.saved_unix_ms,
                    })
                })
                .collect();
            Ok(normalize_bucket_entries(local_node_id, entries, now))
        }
        ROUTING_BUCKET_CACHE_VERSION => {
            let cache: RoutingBucketCacheFile =
                serde_json::from_value(value).context("failed to decode routing bucket cache")?;
            if cache.local_node_id != local_node_id
                || cache.saved_unix_ms > now
                || now.saturating_sub(cache.saved_unix_ms) > ROUTING_CACHE_MAX_AGE_MS
            {
                return Ok(Vec::new());
            }
            Ok(normalize_bucket_entries(local_node_id, cache.entries, now))
        }
        _ => Ok(Vec::new()),
    }
}

pub fn save_routing_bucket_snapshot(
    path: &Path,
    local_node_id: &str,
    entries: &[RoutingBucketCacheEntry],
) -> Result<()> {
    if !plausible_node_id(local_node_id) {
        bail!("invalid local NodeID for routing bucket cache");
    }

    let now = unix_time_ms()?;
    let entries = normalize_bucket_entries(local_node_id, entries.to_vec(), now);
    let encoded = serde_json::to_vec_pretty(&RoutingBucketCacheFile {
        version: ROUTING_BUCKET_CACHE_VERSION,
        local_node_id: local_node_id.to_owned(),
        saved_unix_ms: now,
        entries,
    })
    .context("failed to encode routing bucket cache")?;

    write_atomic(path, &encoded)
}

pub fn new_cache_entry(node_id: String, endpoint: SocketAddr) -> Result<RoutingCacheEntry> {
    Ok(RoutingCacheEntry {
        node_id,
        endpoint: endpoint.to_string(),
        saved_unix_ms: unix_time_ms()?,
    })
}

pub fn new_bucket_cache_entry(
    local_node_id: &str,
    node_id: String,
    endpoint: SocketAddr,
    last_seen_age: Duration,
) -> Result<RoutingBucketCacheEntry> {
    let Some(bucket_index) = routing_bucket_index(local_node_id, &node_id) else {
        bail!("routing cache peer cannot be the local NodeID");
    };
    let age_ms: u64 = last_seen_age.as_millis().try_into().unwrap_or(u64::MAX);

    Ok(RoutingBucketCacheEntry {
        bucket_index: bucket_index
            .try_into()
            .context("routing bucket index overflow")?,
        node_id,
        endpoint: endpoint.to_string(),
        last_seen_unix_ms: unix_time_ms()?.saturating_sub(age_ms),
    })
}

fn normalize_bucket_entries(
    local_node_id: &str,
    mut entries: Vec<RoutingBucketCacheEntry>,
    now: u64,
) -> Vec<RoutingBucketCacheEntry> {
    entries.retain(|entry| {
        if entry.last_seen_unix_ms > now
            || now.saturating_sub(entry.last_seen_unix_ms) > ROUTING_CACHE_MAX_AGE_MS
        {
            return false;
        }
        let Ok(endpoint) = entry.endpoint.parse::<SocketAddr>() else {
            return false;
        };
        if !cache_endpoint_allowed(endpoint) || !plausible_node_id(&entry.node_id) {
            return false;
        }
        routing_bucket_index(local_node_id, &entry.node_id) == Some(usize::from(entry.bucket_index))
    });

    entries.sort_by_key(|entry| {
        (
            Reverse(entry.last_seen_unix_ms),
            entry.node_id.clone(),
            entry.endpoint.clone(),
            entry.bucket_index,
        )
    });

    let mut seen_node_ids = HashSet::new();
    let mut seen_endpoints = HashSet::new();
    entries.retain(|entry| {
        if seen_node_ids.contains(&entry.node_id) || seen_endpoints.contains(&entry.endpoint) {
            return false;
        }
        seen_node_ids.insert(entry.node_id.clone());
        seen_endpoints.insert(entry.endpoint.clone());
        true
    });

    entries.sort_by_key(|entry| {
        (
            entry.bucket_index,
            Reverse(entry.last_seen_unix_ms),
            entry.node_id.clone(),
            entry.endpoint.clone(),
        )
    });

    let mut per_bucket = [0_usize; DHT_BUCKET_COUNT];
    let mut per_bucket_group = HashMap::new();
    let mut normalized = Vec::new();

    for entry in entries {
        let bucket = usize::from(entry.bucket_index);
        if bucket >= DHT_BUCKET_COUNT || per_bucket[bucket] >= DHT_BUCKET_SIZE {
            continue;
        }
        let Ok(endpoint) = entry.endpoint.parse::<SocketAddr>() else {
            continue;
        };
        let group_count = per_bucket_group
            .entry((bucket, dht_network_group(endpoint.ip())))
            .or_insert(0_usize);
        if *group_count >= DHT_BUCKET_NETWORK_GROUP_LIMIT {
            continue;
        }

        per_bucket[bucket] += 1;
        *group_count += 1;
        normalized.push(entry);
        if normalized.len() >= MAX_ROUTING_BUCKET_CACHE_ENTRIES {
            break;
        }
    }

    normalized
}

fn write_atomic(path: &Path, encoded: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    let temp_path = path.with_extension("tmp");
    fs::write(&temp_path, encoded)
        .with_context(|| format!("failed to write {}", temp_path.display()))?;
    if path.exists() {
        fs::remove_file(path).with_context(|| format!("failed to replace {}", path.display()))?;
    }
    fs::rename(&temp_path, path)
        .with_context(|| format!("failed to commit routing cache {}", path.display()))?;

    Ok(())
}

fn cache_endpoint_allowed(endpoint: SocketAddr) -> bool {
    if endpoint.port() == 0 {
        return false;
    }

    match endpoint.ip() {
        IpAddr::V4(ip) => !ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast(),
        IpAddr::V6(ip) => !ip.is_unspecified() && !ip.is_multicast(),
    }
}

fn plausible_node_id(node_id: &str) -> bool {
    node_id.len() == 44
        && node_id.starts_with("knp1")
        && node_id[4..].bytes().all(|byte| byte.is_ascii_hexdigit())
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
    use std::env;

    fn node_ids_in_bucket(local_node_id: &str, bucket: usize, count: usize) -> Vec<String> {
        let mut matching = Vec::new();
        for index in 1..1_000_000_u64 {
            let node_id = format!("knp1{index:040x}");
            if routing_bucket_index(local_node_id, &node_id) == Some(bucket) {
                matching.push(node_id);
                if matching.len() == count {
                    break;
                }
            }
        }
        assert_eq!(matching.len(), count);
        matching
    }

    fn bucket_entry(
        local_node_id: &str,
        node_id: String,
        endpoint: &str,
        last_seen_unix_ms: u64,
    ) -> RoutingBucketCacheEntry {
        RoutingBucketCacheEntry {
            bucket_index: routing_bucket_index(local_node_id, &node_id)
                .unwrap()
                .try_into()
                .unwrap(),
            node_id,
            endpoint: endpoint.to_owned(),
            last_seen_unix_ms,
        }
    }

    #[test]
    fn cache_round_trip_filters_stale_and_invalid_entries() {
        let path = env::temp_dir().join(format!(
            "kononexus-routing-cache-{}-{}.json",
            std::process::id(),
            rand::random::<u64>()
        ));
        let node_id = format!("knp1{}", "a".repeat(40));
        let valid = new_cache_entry(node_id.clone(), "192.168.1.2:47000".parse().unwrap()).unwrap();
        let invalid = RoutingCacheEntry {
            node_id: "bad".into(),
            endpoint: "0.0.0.0:0".into(),
            saved_unix_ms: valid.saved_unix_ms,
        };

        save_routing_hints(&path, &[valid.clone(), invalid]).unwrap();
        let loaded = load_routing_hints(&path).unwrap();

        assert_eq!(loaded, vec![valid]);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn bucket_snapshot_round_trip_preserves_membership() {
        let path = env::temp_dir().join(format!(
            "kononexus-routing-buckets-{}-{}.json",
            std::process::id(),
            rand::random::<u64>()
        ));
        let local = format!("knp1{}", "0".repeat(40));
        let remote = format!("knp1{}", "1".repeat(40));
        let entry = new_bucket_cache_entry(
            &local,
            remote,
            "192.168.1.20:47000".parse().unwrap(),
            Duration::from_secs(5),
        )
        .unwrap();

        save_routing_bucket_snapshot(&path, &local, std::slice::from_ref(&entry)).unwrap();
        let loaded = load_routing_bucket_snapshot(&path, &local).unwrap();
        let legacy_view = load_routing_hints(&path).unwrap();

        assert_eq!(loaded, vec![entry.clone()]);
        assert_eq!(legacy_view.len(), 1);
        assert_eq!(legacy_view[0].node_id, entry.node_id);
        assert_eq!(legacy_view[0].endpoint, entry.endpoint);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn bucket_snapshot_loads_legacy_v1_hints() {
        let path = env::temp_dir().join(format!(
            "kononexus-routing-legacy-{}-{}.json",
            std::process::id(),
            rand::random::<u64>()
        ));
        let local = format!("knp1{}", "0".repeat(40));
        let remote = format!("knp1{}", "2".repeat(40));
        let legacy = new_cache_entry(remote.clone(), "10.20.30.40:47000".parse().unwrap()).unwrap();
        save_routing_hints(&path, std::slice::from_ref(&legacy)).unwrap();

        let loaded = load_routing_bucket_snapshot(&path, &local).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].node_id, remote);
        assert_eq!(loaded[0].endpoint, legacy.endpoint);
        assert_eq!(
            routing_bucket_index(&local, &remote),
            Some(usize::from(loaded[0].bucket_index))
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn legacy_v1_hints_receive_the_same_network_group_cap() {
        let path = env::temp_dir().join(format!(
            "kononexus-routing-legacy-diverse-{}-{}.json",
            std::process::id(),
            rand::random::<u64>()
        ));
        let local = format!("knp1{}", "0".repeat(40));
        let node_ids = node_ids_in_bucket(&local, 255, DHT_BUCKET_NETWORK_GROUP_LIMIT + 2);
        let now = unix_time_ms().unwrap();
        let entries: Vec<RoutingCacheEntry> = node_ids
            .into_iter()
            .enumerate()
            .map(|(index, node_id)| RoutingCacheEntry {
                node_id,
                endpoint: format!("10.20.30.{}:47000", index + 1),
                saved_unix_ms: now - index as u64,
            })
            .collect();

        save_routing_hints(&path, &entries).unwrap();
        let loaded = load_routing_bucket_snapshot(&path, &local).unwrap();

        assert_eq!(loaded.len(), DHT_BUCKET_NETWORK_GROUP_LIMIT);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn bucket_snapshot_caps_each_network_group() {
        let local = format!("knp1{}", "0".repeat(40));
        let bucket = 255;
        let node_ids = node_ids_in_bucket(&local, bucket, DHT_BUCKET_NETWORK_GROUP_LIMIT + 2);
        let now = 1_000_000_u64;
        let entries: Vec<RoutingBucketCacheEntry> = node_ids
            .iter()
            .enumerate()
            .map(|(index, node_id)| {
                bucket_entry(
                    &local,
                    node_id.clone(),
                    &format!("8.8.8.{}:47000", index + 1),
                    now - index as u64,
                )
            })
            .collect();

        let normalized = normalize_bucket_entries(&local, entries, now);

        assert_eq!(normalized.len(), DHT_BUCKET_NETWORK_GROUP_LIMIT);
        assert_eq!(
            normalized
                .iter()
                .map(|entry| entry.node_id.as_str())
                .collect::<Vec<_>>(),
            node_ids[..DHT_BUCKET_NETWORK_GROUP_LIMIT]
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn diverse_network_groups_can_fill_a_bucket_snapshot() {
        let local = format!("knp1{}", "0".repeat(40));
        let bucket = 255;
        let node_ids = node_ids_in_bucket(&local, bucket, DHT_BUCKET_SIZE);
        let now = 1_000_000_u64;
        let entries: Vec<RoutingBucketCacheEntry> = node_ids
            .into_iter()
            .enumerate()
            .map(|(index, node_id)| {
                bucket_entry(
                    &local,
                    node_id,
                    &format!("8.{}.1.1:47000", index + 1),
                    now - index as u64,
                )
            })
            .collect();

        let normalized = normalize_bucket_entries(&local, entries, now);

        assert_eq!(normalized.len(), DHT_BUCKET_SIZE);
        assert_eq!(
            normalized
                .iter()
                .map(|entry| {
                    let endpoint: SocketAddr = entry.endpoint.parse().unwrap();
                    dht_network_group(endpoint.ip())
                })
                .collect::<HashSet<_>>()
                .len(),
            DHT_BUCKET_SIZE
        );
    }

    #[test]
    fn bucket_snapshot_keeps_newest_unique_node_ids_and_endpoints() {
        let local = format!("knp1{}", "0".repeat(40));
        let node_ids: Vec<String> = (1..)
            .map(|index| format!("knp1{index:040x}"))
            .filter(|node_id| routing_bucket_index(&local, node_id).is_some())
            .take(3)
            .collect();
        let now = 1_000_000_u64;
        let entries = vec![
            bucket_entry(&local, node_ids[0].clone(), "8.8.8.1:47000", now - 30),
            bucket_entry(&local, node_ids[0].clone(), "1.1.1.1:47000", now - 10),
            bucket_entry(&local, node_ids[1].clone(), "9.9.9.9:47000", now - 20),
            bucket_entry(&local, node_ids[2].clone(), "9.9.9.9:47000", now - 5),
        ];

        let normalized = normalize_bucket_entries(&local, entries, now);

        assert_eq!(normalized.len(), 2);
        assert!(normalized.iter().any(|entry| {
            entry.node_id == node_ids[0]
                && entry.endpoint == "1.1.1.1:47000"
                && entry.last_seen_unix_ms == now - 10
        }));
        assert!(normalized.iter().any(|entry| {
            entry.node_id == node_ids[2]
                && entry.endpoint == "9.9.9.9:47000"
                && entry.last_seen_unix_ms == now - 5
        }));
        assert!(!normalized.iter().any(|entry| entry.node_id == node_ids[1]));
    }
}
