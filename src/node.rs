use crate::identity::NodeIdentity;
use crate::protocol::{MessageBody, WireEnvelope, MAX_PACKET_SIZE};
use crate::security::{CookieGuard, ReplayGuard};
use crate::session::{respond_handshake, PendingHandshake, SecurePayload, SecureSession};
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
    pending_sessions: HashMap<SocketAddr, PendingHandshake>,
    sessions: HashMap<SocketAddr, SecureSession>,
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
            pending_sessions: HashMap::new(),
            sessions: HashMap::new(),
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
        let body = envelope.body.clone();

        match body {
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

                self.maybe_start_session(source, &sender_node_id).await?;
            }
            MessageBody::SessionInit {
                handshake_id,
                ephemeral_public_key,
            } => {
                if !self.peers.contains_key(&source) {
                    debug!(%source, "ignoring session init from unadmitted peer");
                    return Ok(());
                }

                let local_node_id = self.node_id();
                if self.pending_sessions.contains_key(&source) && local_node_id < sender_node_id {
                    debug!(
                        peer = %sender_node_id,
                        %source,
                        "simultaneous handshake: keeping local initiator role"
                    );
                    return Ok(());
                }

                self.pending_sessions.remove(&source);
                let (session, responder_public_key) = respond_handshake(
                    &local_node_id,
                    &sender_node_id,
                    handshake_id,
                    &ephemeral_public_key,
                )?;
                let session_id = session.session_id().to_owned();

                self.send(
                    source,
                    MessageBody::SessionAck {
                        handshake_id,
                        ephemeral_public_key: responder_public_key,
                    },
                )
                .await?;
                self.sessions.insert(source, session);

                info!(
                    peer = %sender_node_id,
                    %source,
                    %session_id,
                    "encrypted KNP session established as responder"
                );
            }
            MessageBody::SessionAck {
                handshake_id,
                ephemeral_public_key,
            } => {
                let valid_pending = self
                    .pending_sessions
                    .get(&source)
                    .is_some_and(|pending| {
                        pending.handshake_id() == handshake_id
                            && pending.peer_node_id() == sender_node_id
                    });
                if !valid_pending {
                    debug!(%source, handshake_id, "ignoring unexpected session ack");
                    return Ok(());
                }

                let pending = self
                    .pending_sessions
                    .remove(&source)
                    .expect("pending session checked above");
                let mut session = pending.complete(&self.node_id(), &ephemeral_public_key)?;
                let session_id = session.session_id().to_owned();
                let frame = session.encrypt(&SecurePayload::Ping { token: random() })?;
                self.sessions.insert(source, session);

                self.send(
                    source,
                    MessageBody::Encrypted {
                        session_id: frame.session_id,
                        sequence: frame.sequence,
                        ciphertext: frame.ciphertext,
                    },
                )
                .await?;

                info!(
                    peer = %sender_node_id,
                    %source,
                    %session_id,
                    "encrypted KNP session established as initiator"
                );
            }
            MessageBody::Encrypted {
                session_id,
                sequence,
                ciphertext,
            } => {
                if !self.peers.contains_key(&source) {
                    debug!(%source, "ignoring secure frame from unadmitted peer");
                    return Ok(());
                }

                let payload = match self.sessions.get_mut(&source) {
                    Some(session) => session.decrypt(&session_id, sequence, &ciphertext)?,
                    None => {
                        debug!(%source, "ignoring secure frame without established session");
                        return Ok(());
                    }
                };

                match payload {
                    SecurePayload::Ping { token } => {
                        if let Some(response) =
                            self.secure_message(source, SecurePayload::Pong { token })?
                        {
                            self.send(source, response).await?;
                        }
                    }
                    SecurePayload::Pong { token } => {
                        debug!(peer = %sender_node_id, %source, token, "secure pong received");
                    }
                }
            }
            MessageBody::Ping { token } => {
                if self.peers.contains_key(&source) && !self.sessions.contains_key(&source) {
                    self.record_peer(&envelope, source);
                    self.send(source, MessageBody::Pong { token }).await?;
                }
            }
            MessageBody::Pong { token } => {
                if self.peers.contains_key(&source) && !self.sessions.contains_key(&source) {
                    self.record_peer(&envelope, source);
                    debug!(peer = %sender_node_id, %source, token, "pong received");
                }
            }
        }

        Ok(())
    }

    async fn maybe_start_session(&mut self, target: SocketAddr, peer_node_id: &str) -> Result<()> {
        if self.sessions.contains_key(&target) || self.pending_sessions.contains_key(&target) {
            return Ok(());
        }

        let pending = PendingHandshake::new(peer_node_id.to_owned());
        let handshake_id = pending.handshake_id();
        let ephemeral_public_key = pending.public_key_hex();
        self.pending_sessions.insert(target, pending);

        if let Err(error) = self
            .send(
                target,
                MessageBody::SessionInit {
                    handshake_id,
                    ephemeral_public_key,
                },
            )
            .await
        {
            self.pending_sessions.remove(&target);
            return Err(error);
        }

        Ok(())
    }

    fn secure_message(
        &mut self,
        target: SocketAddr,
        payload: SecurePayload,
    ) -> Result<Option<MessageBody>> {
        let Some(session) = self.sessions.get_mut(&target) else {
            return Ok(None);
        };
        let frame = session.encrypt(&payload)?;
        Ok(Some(MessageBody::Encrypted {
            session_id: frame.session_id,
            sequence: frame.sequence,
            ciphertext: frame.ciphertext,
        }))
    }

    fn is_expected_endpoint(&self, source: SocketAddr) -> bool {
        self.bootstrap_peers.contains(&source)
            || self.peers.contains_key(&source)
            || self.cookie_cache.contains_key(&source)
    }

    fn record_peer(&mut self, envelope: &WireEnvelope, source: SocketAddr) {
        if let Some(existing) = self.peers.get(&source) {
            if existing.node_id != envelope.sender_node_id {
                self.sessions.remove(&source);
                self.pending_sessions.remove(&source);
            }
        }

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
            self.pending_sessions.remove(&endpoint);
            self.sessions.remove(&endpoint);
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

    async fn ping_known_peers(&mut self) {
        let endpoints: Vec<SocketAddr> = self.peers.keys().copied().collect();
        for endpoint in endpoints {
            let token = random();
            let body = if let Some(body) =
                self.secure_message(endpoint, SecurePayload::Ping { token }).ok().flatten()
            {
                body
            } else {
                MessageBody::Ping { token }
            };

            if let Err(error) = self.send(endpoint, body).await {
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
        self.pending_sessions
            .retain(|endpoint, _| self.peers.contains_key(endpoint));
        self.sessions
            .retain(|endpoint, _| self.peers.contains_key(endpoint));

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
        "x25519-hkdf-session".to_owned(),
        "chacha20poly1305-aead".to_owned(),
        "secure-ping-pong".to_owned(),
    ]
}
