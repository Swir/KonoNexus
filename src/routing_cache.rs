use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub const ROUTING_CACHE_VERSION: u16 = 1;
pub const MAX_ROUTING_CACHE_ENTRIES: usize = 256;
pub const ROUTING_CACHE_MAX_AGE_MS: u64 = 7 * 24 * 60 * 60 * 1_000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RoutingCacheEntry {
    pub node_id: String,
    pub endpoint: String,
    pub saved_unix_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RoutingCacheFile {
    version: u16,
    entries: Vec<RoutingCacheEntry>,
}

pub fn load_routing_hints(path: &Path) -> Result<Vec<RoutingCacheEntry>> {
    if !path.exists() {
        return Ok(Vec::new());
    }

    let raw = fs::read(path)
        .with_context(|| format!("failed to read routing cache {}", path.display()))?;
    let cache: RoutingCacheFile =
        serde_json::from_slice(&raw).context("failed to decode routing cache")?;

    if cache.version != ROUTING_CACHE_VERSION {
        return Ok(Vec::new());
    }

    let now = unix_time_ms()?;
    let mut entries = Vec::new();

    for entry in cache.entries.into_iter().take(MAX_ROUTING_CACHE_ENTRIES) {
        if now.saturating_sub(entry.saved_unix_ms) > ROUTING_CACHE_MAX_AGE_MS {
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
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

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
    entries.dedup_by(|left, right| {
        left.node_id == right.node_id && left.endpoint == right.endpoint
    });

    let encoded = serde_json::to_vec_pretty(&RoutingCacheFile {
        version: ROUTING_CACHE_VERSION,
        entries,
    })
    .context("failed to encode routing cache")?;

    let temp_path = path.with_extension("tmp");
    fs::write(&temp_path, encoded)
        .with_context(|| format!("failed to write {}", temp_path.display()))?;
    if path.exists() {
        fs::remove_file(path)
            .with_context(|| format!("failed to replace {}", path.display()))?;
    }
    fs::rename(&temp_path, path)
        .with_context(|| format!("failed to commit routing cache {}", path.display()))?;

    Ok(())
}

pub fn new_cache_entry(node_id: String, endpoint: SocketAddr) -> Result<RoutingCacheEntry> {
    Ok(RoutingCacheEntry {
        node_id,
        endpoint: endpoint.to_string(),
        saved_unix_ms: unix_time_ms()?,
    })
}

fn cache_endpoint_allowed(endpoint: SocketAddr) -> bool {
    if endpoint.port() == 0 {
        return false;
    }

    match endpoint.ip() {
        IpAddr::V4(ip) => {
            !ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast()
        }
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

    #[test]
    fn cache_round_trip_filters_stale_and_invalid_entries() {
        let path = env::temp_dir().join(format!(
            "kononexus-routing-cache-{}.json",
            std::process::id()
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
}
