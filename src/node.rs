use crate::identity::NodeIdentity;
use crate::protocol::{MessageBody, WireEnvelope, MAX_PACKET_SIZE};
use crate::security::{CookieGuard, ReplayGuard};
use anyhow::{Context, Result};
use rand::random;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time;
use tracing::{debug, info, warn};

const MAX_ACTIVE_PEERS: usize = 2_048;

#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub node_id: String,
    pub public_key: String,
    pub endpoint: SocketAddr,
    pub first_seen: Instant,
    pub last_seen: Instant,
    pub observed_external_endpoint: Option<String>,
}

pub struct KonoNode {
    identity: NodeIdentity,
    socket: Arc<UdpSocket>,
    bootstrap_peers: Vec<SocketAddr>,
    peers: HashMap<SocketAddr, PeerInfo>,
    cookie_cache: HashMap<SocketAddr, String>,
    replay_guard: ReplayGuard,
    cookie_guard: CookieGuard,
    hello_interval: Duration,
}

impl KonoNode {
    pub async fn bind(
        identity: NodeIdentity,
        bind_addr: SocketAddr,
        bootstrap_peers: Vec<SocketAddr>,
        hello_interval: Duration,
    ) -> Result<Self> {
        let socket = UdpSocket::bind(bind_addr)
            .await
            .with_context(|| format!("failed to bind UDP socket at {bind_addr}"))?;

        Ok(Self {
            identity,
            socket: Arc::new(socket),
            bootstrap_peers,
            peers: HashMap::new(),
            cookie_cache: HashMap::new(),
            replay_guard: ReplayGuard::default(),
            cookie_guard: CookieGuard::default(),
            hello_interval,
        })
    }

    pub fn node_id(&self) -> String {
        self.identity.node_id()
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.socket
            .local_addr()
            .context("failed to read local UDP address")
    }

    pub async fn run(mut self) -> Result<()> {
        let local_addr = self.local_addr()?;
        info!(node_id = %self.node_id(), bind = %local_addr, "KonoNexus node started");

        self.refresh_discovery().await;

        let recv_socket = self.socket.clone();
        let mut recv_buf = vec![0_u8; MAX_PACKET_SIZE + 1];
        let mut ticker = time::interval(self.hello_interval);
        ticker.set_missed_tick_behavior(time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                recv = recv_socket.recv_from(&mut recv_buf) => {
                    match recv {
                        Ok((len, source)) => {
                            if len > MAX_PACKET_SIZE {
                                warn!(%source, len, "dropping oversized KNP datagram");
                                continue;
                            }
                            if let Err(error) = self.handle_datagram(&recv_buf[..len], source).await {
                                debug!(%source, %error, "dropping invalid KNP datagram");
                            }
                        }
                        Err(error) => {
                            warn!(%error, "UDP receive failed");
                        }
                    }
                }
                _ = ticker.tick() => {
                    self.refresh_discovery().await;
                    self.ping_known_peers().await;
                    self.expire_stale_peers();
                }
                _ = tokio::signal::ctrl_c() => {
                    info!("shutdown requested");
                    break;
                }
            }
        }

        Ok(())
    }

    async fn handle_datagram(&mut self, bytes: &[u8], source: SocketAddr) -> Result<()> {
        let envelope = WireEnvelope::decode(bytes)?;
        envelope.verify()?;

        if envelope.sender_node_id == self.node_id() {
            return Ok(());
        }

        self.replay_guard.check_and_record(&envelope)?;
        let sender_node_id = envelope.sender_node_id.clone();

        match envelope.body {
            MessageBody::Hello { cookie, .. } => {
                let cookie_valid = match cookie {
                    Some(cookie) => self.cookie_guard.validate(&source, &cookie)?,
                    None => false,
                };

                if !cookie_valid {
                    let cookie = self.cookie_guard.issue(&source)?;
                    self.send(source, MessageBody::CookieChallenge { cookie })
                        .await?;
                    return Ok(());
                }

                self.record_peer(&envelope, source);
                info!(
                    peer = %sender_node_id,
                    endpoint = %source,
                    "peer admitted after cookie validation"
                );

                self.send(
                    source,
                    MessageBody::HelloAck {
                        observed_endpoint: source.to_string(),
                        features: local_features(),
                    },
                )
                .await?;
            }
            MessageBody::CookieChallenge { cookie } => {
                if self.is_expected_endpoint(source) {
                    self.cookie_cache.insert(source, cookie.clone());
                    self.send(
                        source,
                        MessageBody::Hello {
                            features: local_features(),
                            cookie: Some(cookie),
                        },
                    )
                    .await?;
                } else {
                    debug!(%source, "ignoring unsolicited cookie challenge");
                }
            }
            MessageBody::HelloAck {
                observed_endpoint, ..
            } => {
                if !self.is_expected_endpoint(source) {
                    debug!(%source, "ignoring unsolicited HELLO_ACK");
                    return Ok(());
                }

                self.record_peer(&envelope, source);
                if let Some(peer) = self.peers.get_mut(&source) {
                    peer.observed_external_endpoint = Some(observed_endpoint.clone());
                }
                info!(
                    peer = %sender_node_id,
                    endpoint = %source,
                    observed = %observed_endpoint,
                    "peer handshake acknowledged"
                );
            }
            MessageBody::Ping { token } => {
                if self.peers.contains_key(&source) {
                    self.record_peer(&envelope, source);
                    self.send(source, MessageBody::Pong { token }).await?;
                }
            }
            MessageBody::Pong { token } => {
                if self.peers.contains_key(&source) {
                    self.record_peer(&envelope, source);
                    debug!(peer = %sender_node_id, %source, token, "pong received");
                }
            }
        }

        Ok(())
    }

    fn is_expected_endpoint(&self, source: SocketAddr) -> bool {
        self.bootstrap_peers.contains(&source)
            || self.peers.contains_key(&source)
            || self.cookie_cache.contains_key(&source)
    }

    fn record_peer(&mut self, envelope: &WireEnvelope, source: SocketAddr) {
        if !self.peers.contains_key(&source) && self.peers.len() >= MAX_ACTIVE_PEERS {
            self.evict_oldest_peer();
        }

        let now = Instant::now();
        self.peers
            .entry(source)
            .and_modify(|peer| {
                peer.last_seen = now;
                peer.node_id.clone_from(&envelope.sender_node_id);
                peer.public_key.clone_from(&envelope.sender_public_key);
            })
            .or_insert_with(|| PeerInfo {
                node_id: envelope.sender_node_id.clone(),
                public_key: envelope.sender_public_key.clone(),
                endpoint: source,
                first_seen: now,
                last_seen: now,
                observed_external_endpoint: None,
            });
    }

    fn evict_oldest_peer(&mut self) {
        if let Some(endpoint) = self
            .peers
            .iter()
            .min_by_key(|(_, peer)| peer.last_seen)
            .map(|(endpoint, _)| *endpoint)
        {
            self.peers.remove(&endpoint);
            self.cookie_cache.remove(&endpoint);
        }
    }

    async fn refresh_discovery(&self) {
        let mut endpoints = self.bootstrap_peers.clone();
        endpoints.extend(self.peers.keys().copied());
        endpoints.sort_unstable();
        endpoints.dedup();

        for endpoint in endpoints {
            let cookie = self.cookie_cache.get(&endpoint).cloned();
            if let Err(error) = self
                .send(
                    endpoint,
                    MessageBody::Hello {
                        features: local_features(),
                        cookie,
                    },
                )
                .await
            {
                debug!(%endpoint, %error, "HELLO send failed");
            }
        }
    }

    async fn ping_known_peers(&self) {
        let endpoints: Vec<SocketAddr> = self.peers.keys().copied().collect();
        for endpoint in endpoints {
            if let Err(error) = self
                .send(endpoint, MessageBody::Ping { token: random() })
                .await
            {
                debug!(%endpoint, %error, "PING send failed");
            }
        }
    }

    fn expire_stale_peers(&mut self) {
        let max_age = self.hello_interval.saturating_mul(4);
        let before = self.peers.len();
        self.peers
            .retain(|_, peer| peer.last_seen.elapsed() <= max_age);
        self.cookie_cache.retain(|endpoint, _| {
            self.bootstrap_peers.contains(endpoint) || self.peers.contains_key(endpoint)
        });

        let removed = before.saturating_sub(self.peers.len());
        if removed > 0 {
            debug!(removed, "expired stale peers");
        }
    }

    async fn send(&self, target: SocketAddr, body: MessageBody) -> Result<()> {
        let envelope = WireEnvelope::signed(&self.identity, random(), body)?;
        let bytes = envelope.encode()?;
        self.socket
            .send_to(&bytes, target)
            .await
            .with_context(|| format!("failed to send KNP packet to {target}"))?;
        Ok(())
    }
}

fn local_features() -> Vec<String> {
    vec![
        "knp/1".to_owned(),
        "signed-discovery".to_owned(),
        "replay-guard".to_owned(),
        "cookie-challenge".to_owned(),
        "ping-pong".to_owned(),
    ]
}
