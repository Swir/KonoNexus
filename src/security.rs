use crate::protocol::WireEnvelope;
use anyhow::{anyhow, bail, Context, Result};
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

pub const DEFAULT_MAX_CLOCK_SKEW_MS: u64 = 120_000;
pub const DEFAULT_MAX_REPLAY_PEERS: usize = 2_048;
pub const DEFAULT_NONCES_PER_PEER: usize = 128;
pub const DEFAULT_COOKIE_BUCKET_MS: u64 = 60_000;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug)]
struct PeerWindow {
    nonces: HashSet<u64>,
    order: VecDeque<u64>,
    last_seen_ms: u64,
}

impl PeerWindow {
    fn new(now_ms: u64) -> Self {
        Self {
            nonces: HashSet::new(),
            order: VecDeque::new(),
            last_seen_ms: now_ms,
        }
    }

    fn record(&mut self, nonce: u64, now_ms: u64, max_nonces: usize) -> Result<()> {
        if self.nonces.contains(&nonce) {
            bail!("duplicate KNP packet");
        }

        self.nonces.insert(nonce);
        self.order.push_back(nonce);
        self.last_seen_ms = now_ms;

        while self.order.len() > max_nonces {
            if let Some(oldest) = self.order.pop_front() {
                self.nonces.remove(&oldest);
            }
        }

        Ok(())
    }
}

#[derive(Debug)]
pub struct ReplayGuard {
    peers: HashMap<String, PeerWindow>,
    max_clock_skew_ms: u64,
    max_peers: usize,
    max_nonces_per_peer: usize,
}

impl Default for ReplayGuard {
    fn default() -> Self {
        Self::new(
            DEFAULT_MAX_CLOCK_SKEW_MS,
            DEFAULT_MAX_REPLAY_PEERS,
            DEFAULT_NONCES_PER_PEER,
        )
    }
}

impl ReplayGuard {
    pub fn new(max_clock_skew_ms: u64, max_peers: usize, max_nonces_per_peer: usize) -> Self {
        Self {
            peers: HashMap::new(),
            max_clock_skew_ms,
            max_peers: max_peers.max(1),
            max_nonces_per_peer: max_nonces_per_peer.max(1),
        }
    }

    pub fn check_and_record(&mut self, envelope: &WireEnvelope) -> Result<()> {
        self.check_and_record_at(envelope, unix_time_ms()?)
    }

    pub fn tracked_peers(&self) -> usize {
        self.peers.len()
    }

    fn check_and_record_at(&mut self, envelope: &WireEnvelope, now_ms: u64) -> Result<()> {
        if now_ms.abs_diff(envelope.timestamp_unix_ms) > self.max_clock_skew_ms {
            bail!("KNP packet timestamp outside accepted window");
        }

        if !self.peers.contains_key(&envelope.sender_node_id) && self.peers.len() >= self.max_peers
        {
            self.evict_oldest();
        }

        self.peers
            .entry(envelope.sender_node_id.clone())
            .or_insert_with(|| PeerWindow::new(now_ms))
            .record(envelope.nonce, now_ms, self.max_nonces_per_peer)
    }

    fn evict_oldest(&mut self) {
        if let Some(node_id) = self
            .peers
            .iter()
            .min_by_key(|(_, state)| state.last_seen_ms)
            .map(|(node_id, _)| node_id.clone())
        {
            self.peers.remove(&node_id);
        }
    }
}

pub struct CookieGuard {
    secret: [u8; 32],
    bucket_ms: u64,
}

impl Default for CookieGuard {
    fn default() -> Self {
        let mut secret = [0_u8; 32];
        let mut rng = OsRng;
        rng.fill_bytes(&mut secret);
        Self {
            secret,
            bucket_ms: DEFAULT_COOKIE_BUCKET_MS,
        }
    }
}

impl CookieGuard {
    pub fn issue(&self, source: &SocketAddr) -> Result<String> {
        self.issue_at(source, unix_time_ms()?)
    }

    pub fn validate(&self, source: &SocketAddr, cookie: &str) -> Result<bool> {
        self.validate_at(source, cookie, unix_time_ms()?)
    }

    fn issue_at(&self, source: &SocketAddr, now_ms: u64) -> Result<String> {
        let bucket = now_ms / self.bucket_ms.max(1);
        Ok(hex::encode(self.cookie_bytes(source, bucket)?))
    }

    fn validate_at(&self, source: &SocketAddr, cookie: &str, now_ms: u64) -> Result<bool> {
        let raw = match hex::decode(cookie) {
            Ok(raw) if raw.len() == 32 => raw,
            _ => return Ok(false),
        };
        let bucket = now_ms / self.bucket_ms.max(1);

        if self.verify_bucket(source, bucket, &raw)? {
            return Ok(true);
        }

        if let Some(previous) = bucket.checked_sub(1) {
            return self.verify_bucket(source, previous, &raw);
        }

        Ok(false)
    }

    fn cookie_bytes(&self, source: &SocketAddr, bucket: u64) -> Result<[u8; 32]> {
        let mut mac = HmacSha256::new_from_slice(&self.secret)
            .map_err(|_| anyhow!("failed to initialize cookie HMAC"))?;
        mac.update(b"knp-cookie-v1");
        mac.update(source.to_string().as_bytes());
        mac.update(&bucket.to_be_bytes());

        let bytes = mac.finalize().into_bytes();
        let mut cookie = [0_u8; 32];
        cookie.copy_from_slice(&bytes);
        Ok(cookie)
    }

    fn verify_bucket(&self, source: &SocketAddr, bucket: u64, cookie: &[u8]) -> Result<bool> {
        let mut mac = HmacSha256::new_from_slice(&self.secret)
            .map_err(|_| anyhow!("failed to initialize cookie HMAC"))?;
        mac.update(b"knp-cookie-v1");
        mac.update(source.to_string().as_bytes());
        mac.update(&bucket.to_be_bytes());
        Ok(mac.verify_slice(cookie).is_ok())
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
    use crate::{MessageBody, NodeIdentity, WireEnvelope};

    fn packet(identity: &NodeIdentity, nonce: u64) -> WireEnvelope {
        WireEnvelope::signed(identity, nonce, MessageBody::Ping { token: nonce }).unwrap()
    }

    #[test]
    fn duplicate_nonce_is_rejected() {
        let id = NodeIdentity::generate();
        let env = packet(&id, 7);
        let mut guard = ReplayGuard::default();
        guard
            .check_and_record_at(&env, env.timestamp_unix_ms)
            .unwrap();
        assert!(guard
            .check_and_record_at(&env, env.timestamp_unix_ms)
            .is_err());
    }

    #[test]
    fn stale_timestamp_is_rejected() {
        let id = NodeIdentity::generate();
        let env = packet(&id, 1);
        let mut guard = ReplayGuard::new(1_000, 16, 8);
        assert!(guard
            .check_and_record_at(&env, env.timestamp_unix_ms + 1_001)
            .is_err());
    }

    #[test]
    fn peer_tracking_is_bounded() {
        let a = NodeIdentity::generate();
        let b = NodeIdentity::generate();
        let c = NodeIdentity::generate();
        let pa = packet(&a, 1);
        let pb = packet(&b, 2);
        let pc = packet(&c, 3);
        let now = pa
            .timestamp_unix_ms
            .max(pb.timestamp_unix_ms)
            .max(pc.timestamp_unix_ms);
        let mut guard = ReplayGuard::new(60_000, 2, 8);

        guard.check_and_record_at(&pa, now).unwrap();
        guard.check_and_record_at(&pb, now + 1).unwrap();
        guard.check_and_record_at(&pc, now + 2).unwrap();

        assert_eq!(guard.tracked_peers(), 2);
    }

    #[test]
    fn cookie_is_bound_to_endpoint() {
        let guard = CookieGuard {
            secret: [7_u8; 32],
            bucket_ms: 60_000,
        };
        let a: SocketAddr = "203.0.113.10:41000".parse().unwrap();
        let b: SocketAddr = "203.0.113.11:41000".parse().unwrap();
        let now = 180_000;

        let cookie = guard.issue_at(&a, now).unwrap();
        assert!(guard.validate_at(&a, &cookie, now).unwrap());
        assert!(!guard.validate_at(&b, &cookie, now).unwrap());
    }

    #[test]
    fn cookie_accepts_only_current_or_previous_bucket() {
        let guard = CookieGuard {
            secret: [9_u8; 32],
            bucket_ms: 60_000,
        };
        let endpoint: SocketAddr = "198.51.100.20:47000".parse().unwrap();

        let cookie = guard.issue_at(&endpoint, 120_000).unwrap();
        assert!(guard.validate_at(&endpoint, &cookie, 179_999).unwrap());
        assert!(guard.validate_at(&endpoint, &cookie, 180_000).unwrap());
        assert!(!guard.validate_at(&endpoint, &cookie, 240_000).unwrap());
    }

    #[test]
    fn malformed_cookie_is_rejected_without_error() {
        let guard = CookieGuard::default();
        let endpoint: SocketAddr = "192.0.2.5:47000".parse().unwrap();

        assert!(!guard.validate_at(&endpoint, "not-hex", 60_000).unwrap());
        assert!(!guard.validate_at(&endpoint, "aa", 60_000).unwrap());
    }
}
