use crate::dht::{endpoint_publishable, DhtTable, PeerRecord, DHT_RESPONSE_LIMIT};
use crate::identity::NodeIdentity;
use crate::nat::{FilterProbeAuthorization, NatFilteringEvidence, NatMappingBehavior, NatProfile};
use crate::protocol::{MessageBody, WireEnvelope, MAX_PACKET_SIZE};
use crate::punch::{PunchSchedule, PUNCH_AUTH_TTL};
use crate::rendezvous::{AutoRendezvousState, CoordinatorCandidate};
use crate::security::{CookieGuard, ReplayGuard};
use crate::session::{respond_handshake, PendingHandshake, SecurePayload, SecureSession};
use anyhow::{Context, Result};
use rand::random;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time;
use tracing::{debug, info, warn};

const MAX_ACTIVE_PEERS: usize = 2_048;
const MAX_PENDING_PUNCHES: usize = 128;
const MAX_PENDING_FILTER_PROBES: usize = 64;
const RENDEZVOUS_REQUEST_COOLDOWN: Duration = Duration::from_secs(1);
const FILTER_TEST_REQUEST_COOLDOWN: Duration = Duration::from_secs(10);
const FILTER_PROBE_STATE_TTL: Duration = Duration::from_secs(10);
const DHT_DISCOVERY_CANDIDATE_TTL: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub node_id: String,
    pub public_key: String,
    pub endpoint: SocketAddr,
    pub first_seen: Instant,
    pub last_seen: Instant,
    pub observed_external_endpoint: Option<String>,
}

#[derive(Debug, Clone)]
struct PendingFilterProbe {
    expected_helper_node_id: String,
    expires_at: Instant,
}

#[derive(Debug, Clone)]
struct PendingFilterConsent {
    requester_endpoint: SocketAddr,
    requester_node_id: String,
    helper_endpoint: SocketAddr,
    helper_node_id: String,
    expires_at: Instant,
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
    nat_profile: NatProfile,
    pending_punches: HashMap<u64, PunchSchedule>,
    queued_rendezvous: HashMap<SocketAddr, Vec<String>>,
    auto_rendezvous: HashMap<String, AutoRendezvousState>,
    queued_filter_tests: HashSet<SocketAddr>,
    pending_filter_probes: HashMap<u64, PendingFilterProbe>,
    pending_filter_consents: HashMap<u64, PendingFilterConsent>,
    last_rendezvous_request: HashMap<SocketAddr, Instant>,
    last_filter_test_request: HashMap<SocketAddr, Instant>,
    dht: DhtTable,
    pending_dht_queries: HashSet<String>,
    discovery_candidates: HashMap<SocketAddr, Instant>,
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
            nat_profile: NatProfile::default(),
            pending_punches: HashMap::new(),
            queued_rendezvous: HashMap::new(),
            auto_rendezvous: HashMap::new(),
            queued_filter_tests: HashSet::new(),
            pending_filter_probes: HashMap::new(),
            pending_filter_consents: HashMap::new(),
            last_rendezvous_request: HashMap::new(),
            last_filter_test_request: HashMap::new(),
            dht: DhtTable::default(),
            pending_dht_queries: HashSet::new(),
            discovery_candidates: HashMap::new(),
            hello_interval,
        })
    }

    pub fn queue_rendezvous(&mut self, coordinator: SocketAddr, target_node_id: String) {
        self.queued_rendezvous
            .entry(coordinator)
            .or_default()
            .push(target_node_id);
    }

    pub fn queue_auto_rendezvous(&mut self, target_node_id: String) {
        self.pending_dht_queries.insert(target_node_id.clone());
        self.auto_rendezvous
            .entry(target_node_id.clone())
            .or_insert_with(|| AutoRendezvousState::new(target_node_id, Instant::now()));
    }

    pub fn queue_filter_test(&mut self, coordinator: SocketAddr) {
        self.queued_filter_tests.insert(coordinator);
    }

    pub fn node_id(&self) -> String {
        self.identity.node_id()
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.socket
            .local_addr()
            .context("failed to read local UDP address")
    }

    pub fn nat_behavior(&self) -> NatMappingBehavior {
        self.nat_profile.behavior()
    }

    pub fn observed_external_endpoint(&self) -> Option<SocketAddr> {
        self.nat_profile.preferred_endpoint()
    }

    pub fn nat_filtering_evidence(&self) -> NatFilteringEvidence {
        self.nat_profile.filtering_evidence()
    }

    pub fn dht_record_count(&self) -> usize {
        self.dht.len()
    }

    pub async fn run(mut self) -> Result<()> {
        let local_addr = self.local_addr()?;
        info!(node_id = %self.node_id(), bind = %local_addr, "KonoNexus node started");

        self.refresh_discovery().await;

        let recv_socket = self.socket.clone();
        let mut recv_buf = vec![0_u8; MAX_PACKET_SIZE + 1];
        let mut ticker = time::interval(self.hello_interval);
        ticker.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
        let mut punch_ticker = time::interval(Duration::from_millis(50));
        punch_ticker.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
        let mut rendezvous_ticker = time::interval(Duration::from_millis(500));
        rendezvous_ticker.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

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
                    self.expire_stale_state();
                }
                _ = punch_ticker.tick() => {
                    self.drive_punch_attempts().await;
                }
                _ = rendezvous_ticker.tick() => {
                    self.drive_auto_rendezvous().await;
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

                if let Ok(observed) = observed_endpoint.parse::<SocketAddr>() {
                    self.nat_profile.observe(sender_node_id.clone(), observed);
                    info!(
                        observer = %sender_node_id,
                        observed = %observed,
                        observations = self.nat_profile.observation_count(),
                        nat_mapping = ?self.nat_profile.behavior(),
                        "updated NAT mapping observations"
                    );
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

                self.flush_rendezvous_requests(source).await?;
                self.flush_filter_test_request(source).await?;
                self.sync_dht_peer(source).await?;
            }
            MessageBody::SessionAck {
                handshake_id,
                ephemeral_public_key,
            } => {
                let valid_pending = self.pending_sessions.get(&source).is_some_and(|pending| {
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

                self.flush_rendezvous_requests(source).await?;
                self.flush_filter_test_request(source).await?;
                self.sync_dht_peer(source).await?;
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

                self.handle_secure_payload(source, &sender_node_id, payload)
                    .await?;
            }
            MessageBody::PunchProbe { punch_token } => {
                if !self.authorize_punch(punch_token, &sender_node_id) {
                    debug!(
                        peer = %sender_node_id,
                        %source,
                        punch_token,
                        "ignoring unauthorized punch probe"
                    );
                    return Ok(());
                }

                if let Some(pending) = self.pending_punches.get(&punch_token) {
                    if pending.candidate_endpoint() != source {
                        debug!(
                            offered = %pending.candidate_endpoint(),
                            actual = %source,
                            peer = %sender_node_id,
                            "punch peer arrived from an alternate mapped endpoint"
                        );
                    }
                }

                let attempts = self
                    .pending_punches
                    .get(&punch_token)
                    .map_or(0, PunchSchedule::attempts_sent);
                self.record_peer(&envelope, source);
                self.pending_punches.remove(&punch_token);
                self.auto_rendezvous.remove(&sender_node_id);

                self.send(
                    source,
                    MessageBody::PunchAck {
                        punch_token,
                        observed_endpoint: source.to_string(),
                    },
                )
                .await?;

                info!(
                    peer = %sender_node_id,
                    %source,
                    punch_token,
                    attempts,
                    "direct UDP punch probe accepted"
                );

                self.maybe_start_session(source, &sender_node_id).await?;
            }
            MessageBody::PunchAck {
                punch_token,
                observed_endpoint,
            } => {
                if !self.authorize_punch(punch_token, &sender_node_id) {
                    debug!(
                        peer = %sender_node_id,
                        %source,
                        punch_token,
                        "ignoring unauthorized punch ack"
                    );
                    return Ok(());
                }

                if let Some(pending) = self.pending_punches.get(&punch_token) {
                    if pending.candidate_endpoint() != source {
                        debug!(
                            offered = %pending.candidate_endpoint(),
                            actual = %source,
                            peer = %sender_node_id,
                            "punch ack arrived from an alternate mapped endpoint"
                        );
                    }
                }

                let attempts = self
                    .pending_punches
                    .get(&punch_token)
                    .map_or(0, PunchSchedule::attempts_sent);
                self.record_peer(&envelope, source);
                self.pending_punches.remove(&punch_token);

                info!(
                    peer = %sender_node_id,
                    %source,
                    %observed_endpoint,
                    punch_token,
                    attempts,
                    "direct UDP punch acknowledged"
                );

                self.maybe_start_session(source, &sender_node_id).await?;
            }
            MessageBody::FilterProbe { probe_token } => {
                let authorized =
                    self.pending_filter_probes
                        .get(&probe_token)
                        .is_some_and(|pending| {
                            pending.expected_helper_node_id == sender_node_id
                                && pending.expires_at > Instant::now()
                        });
                if !authorized {
                    debug!(
                        peer = %sender_node_id,
                        %source,
                        probe_token,
                        "ignoring unauthorized filter probe"
                    );
                    return Ok(());
                }

                self.pending_filter_probes.remove(&probe_token);
                self.nat_profile
                    .record_endpoint_independent_probe(sender_node_id.clone());

                self.send(source, MessageBody::FilterProbeAck { probe_token })
                    .await?;

                info!(
                    helper = %sender_node_id,
                    %source,
                    probe_token,
                    filtering = ?self.nat_profile.filtering_evidence(),
                    "received authorized independent-endpoint filter probe"
                );
            }
            MessageBody::FilterProbeAck { probe_token } => {
                debug!(
                    peer = %sender_node_id,
                    %source,
                    probe_token,
                    "filter probe acknowledged"
                );
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

    async fn handle_secure_payload(
        &mut self,
        source: SocketAddr,
        sender_node_id: &str,
        payload: SecurePayload,
    ) -> Result<()> {
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
            SecurePayload::RendezvousRequest { target_node_id } => {
                self.handle_rendezvous_request(source, sender_node_id, &target_node_id)
                    .await?;
            }
            SecurePayload::RendezvousMiss { target_node_id } => {
                if let Some(state) = self.auto_rendezvous.get_mut(&target_node_id) {
                    state.hurry(Instant::now());
                }
            }
            SecurePayload::FilteringTestRequest => {
                self.handle_filtering_test_request(source, sender_node_id)
                    .await?;
            }
            SecurePayload::FilteringTestProposal {
                helper_node_id,
                target_endpoint,
                probe_token,
            } => {
                self.handle_filtering_test_proposal(
                    source,
                    sender_node_id,
                    &helper_node_id,
                    &target_endpoint,
                    probe_token,
                )
                .await?;
            }
            SecurePayload::FilteringTestConsent { authorization } => {
                self.handle_filtering_test_consent(source, sender_node_id, authorization)
                    .await?;
            }
            SecurePayload::FilteringTestSend { authorization } => {
                self.handle_filtering_test_send(source, sender_node_id, authorization)
                    .await?;
            }
            SecurePayload::FilteringTestUnavailable => {
                debug!(
                    coordinator = %sender_node_id,
                    "filtering test unavailable from this coordinator"
                );
            }
            SecurePayload::DhtStore { record } => {
                let record_node_id = record.node_id.clone();
                match self.dht.upsert(record.clone()) {
                    Ok(true) => {
                        debug!(
                            peer = %record_node_id,
                            records = self.dht.len(),
                            "stored signed DHT peer record"
                        );
                    }
                    Ok(false) => {}
                    Err(error) => {
                        debug!(%error, peer = %record_node_id, "rejected DHT peer record");
                        return Ok(());
                    }
                }

                if self.pending_dht_queries.contains(&record_node_id) {
                    if let Some(current) = self.dht.get(&record_node_id).cloned() {
                        self.activate_dht_record(&current).await?;
                    }
                }
            }
            SecurePayload::DhtFind { target_node_id } => {
                let mut records = Vec::new();

                if target_node_id == self.node_id() {
                    if let Some(record) = self.build_own_dht_record()? {
                        records.push(record);
                    }
                } else if let Some(record) = self.dht.get(&target_node_id) {
                    records.push(record.clone());
                }

                for record in self.dht.nearest(&target_node_id, DHT_RESPONSE_LIMIT) {
                    if records.iter().any(|known| known.node_id == record.node_id) {
                        continue;
                    }
                    records.push(record);
                    if records.len() >= DHT_RESPONSE_LIMIT {
                        break;
                    }
                }

                self.send_secure_payload(
                    source,
                    SecurePayload::DhtNodes {
                        target_node_id,
                        records,
                    },
                )
                .await?;
            }
            SecurePayload::DhtNodes {
                target_node_id,
                records,
            } => {
                if records.len() > DHT_RESPONSE_LIMIT {
                    debug!(
                        peer = %sender_node_id,
                        count = records.len(),
                        "rejected oversized DHT response"
                    );
                    return Ok(());
                }

                for record in records {
                    let exact = record.node_id == target_node_id;
                    if self.dht.upsert(record.clone()).is_err() {
                        continue;
                    }

                    if exact && self.pending_dht_queries.contains(&target_node_id) {
                        if let Some(current) = self.dht.get(&target_node_id).cloned() {
                            self.activate_dht_record(&current).await?;
                        }
                    }
                }
            }
            SecurePayload::RendezvousOffer {
                peer_node_id,
                candidate_endpoint,
                punch_token,
            } => {
                if let Some(state) = self.auto_rendezvous.get_mut(&peer_node_id) {
                    state.defer(Instant::now(), PUNCH_AUTH_TTL);
                }
                let candidate = match candidate_endpoint.parse::<SocketAddr>() {
                    Ok(candidate) => candidate,
                    Err(error) => {
                        debug!(%error, %candidate_endpoint, "invalid rendezvous candidate");
                        return Ok(());
                    }
                };

                if !PunchSchedule::candidate_allowed(candidate) {
                    warn!(
                        %candidate,
                        coordinator = %sender_node_id,
                        "rejected unsafe rendezvous candidate"
                    );
                    return Ok(());
                }

                if !self.pending_punches.contains_key(&punch_token)
                    && self.pending_punches.len() >= MAX_PENDING_PUNCHES
                {
                    warn!(
                        coordinator = %sender_node_id,
                        "pending punch limit reached; ignoring rendezvous offer"
                    );
                    return Ok(());
                }

                self.pending_punches.insert(
                    punch_token,
                    PunchSchedule::new(peer_node_id.clone(), candidate, Instant::now()),
                );

                info!(
                    peer = %peer_node_id,
                    %candidate,
                    punch_token,
                    coordinator = %sender_node_id,
                    "scheduled bounded UDP punch burst"
                );
            }
        }

        Ok(())
    }

    async fn handle_rendezvous_request(
        &mut self,
        requester_endpoint: SocketAddr,
        requester_node_id: &str,
        target_node_id: &str,
    ) -> Result<()> {
        let now = Instant::now();
        if self
            .last_rendezvous_request
            .get(&requester_endpoint)
            .is_some_and(|last| now.duration_since(*last) < RENDEZVOUS_REQUEST_COOLDOWN)
        {
            return Ok(());
        }
        self.last_rendezvous_request.insert(requester_endpoint, now);

        let Some(target_endpoint) = self.peer_endpoint_by_node_id(target_node_id) else {
            debug!(
                requester = %requester_node_id,
                target = %target_node_id,
                "rendezvous target is not known to coordinator"
            );
            self.send_secure_payload(
                requester_endpoint,
                SecurePayload::RendezvousMiss {
                    target_node_id: target_node_id.to_owned(),
                },
            )
            .await?;
            return Ok(());
        };

        if !self.sessions.contains_key(&target_endpoint) {
            debug!(
                requester = %requester_node_id,
                target = %target_node_id,
                "rendezvous target has no encrypted coordinator session"
            );
            self.send_secure_payload(
                requester_endpoint,
                SecurePayload::RendezvousMiss {
                    target_node_id: target_node_id.to_owned(),
                },
            )
            .await?;
            return Ok(());
        }

        let punch_token = random();
        let requester_offer = SecurePayload::RendezvousOffer {
            peer_node_id: target_node_id.to_owned(),
            candidate_endpoint: target_endpoint.to_string(),
            punch_token,
        };
        let target_offer = SecurePayload::RendezvousOffer {
            peer_node_id: requester_node_id.to_owned(),
            candidate_endpoint: requester_endpoint.to_string(),
            punch_token,
        };

        if let Some(message) = self.secure_message(requester_endpoint, requester_offer)? {
            self.send(requester_endpoint, message).await?;
        }
        if let Some(message) = self.secure_message(target_endpoint, target_offer)? {
            self.send(target_endpoint, message).await?;
        }

        info!(
            requester = %requester_node_id,
            target = %target_node_id,
            punch_token,
            "coordinated decentralized UDP rendezvous"
        );

        Ok(())
    }

    async fn flush_rendezvous_requests(&mut self, coordinator: SocketAddr) -> Result<()> {
        let Some(targets) = self.queued_rendezvous.remove(&coordinator) else {
            return Ok(());
        };

        for target_node_id in targets {
            let payload = SecurePayload::RendezvousRequest {
                target_node_id: target_node_id.clone(),
            };
            if let Some(message) = self.secure_message(coordinator, payload)? {
                self.send(coordinator, message).await?;
                info!(
                    %coordinator,
                    target = %target_node_id,
                    "requested decentralized rendezvous"
                );
            }
        }

        Ok(())
    }

    async fn drive_auto_rendezvous(&mut self) {
        let now = Instant::now();
        let targets: Vec<String> = self.auto_rendezvous.keys().cloned().collect();

        for target_node_id in targets {
            if self.peer_endpoint_by_node_id(&target_node_id).is_some() {
                self.auto_rendezvous.remove(&target_node_id);
                continue;
            }

            let candidates: Vec<CoordinatorCandidate> = self
                .sessions
                .keys()
                .filter_map(|endpoint| {
                    let peer = self.peers.get(endpoint)?;
                    if peer.node_id == target_node_id {
                        return None;
                    }
                    Some(CoordinatorCandidate {
                        endpoint: *endpoint,
                        first_seen: peer.first_seen,
                    })
                })
                .collect();

            if candidates.is_empty() {
                if let Some(state) = self.auto_rendezvous.get_mut(&target_node_id) {
                    state.defer(now, Duration::from_secs(2));
                }
                continue;
            }

            let selected = self
                .auto_rendezvous
                .get_mut(&target_node_id)
                .and_then(|state| state.next_candidate(&candidates, now));
            let Some(coordinator) = selected else {
                continue;
            };

            if let Err(error) = self
                .send_secure_payload(
                    coordinator,
                    SecurePayload::RendezvousRequest {
                        target_node_id: target_node_id.clone(),
                    },
                )
                .await
            {
                debug!(%coordinator, target = %target_node_id, %error, "automatic rendezvous send failed");
                if let Some(state) = self.auto_rendezvous.get_mut(&target_node_id) {
                    state.hurry(Instant::now());
                }
            }
        }
    }

    async fn flush_filter_test_request(&mut self, coordinator: SocketAddr) -> Result<()> {
        if self.queued_filter_tests.remove(&coordinator) {
            self.send_secure_payload(coordinator, SecurePayload::FilteringTestRequest)
                .await?;
        }
        Ok(())
    }

    async fn handle_filtering_test_request(
        &mut self,
        requester_endpoint: SocketAddr,
        requester_node_id: &str,
    ) -> Result<()> {
        let now = Instant::now();
        if self
            .last_filter_test_request
            .get(&requester_endpoint)
            .is_some_and(|last| now.duration_since(*last) < FILTER_TEST_REQUEST_COOLDOWN)
        {
            return Ok(());
        }
        self.last_filter_test_request
            .insert(requester_endpoint, now);

        if self.pending_filter_consents.len() >= MAX_PENDING_FILTER_PROBES {
            self.send_secure_payload(requester_endpoint, SecurePayload::FilteringTestUnavailable)
                .await?;
            return Ok(());
        }

        let helper = self
            .sessions
            .keys()
            .filter(|endpoint| **endpoint != requester_endpoint)
            .filter_map(|endpoint| {
                let peer = self.peers.get(endpoint)?;
                if peer.node_id == requester_node_id || endpoint.ip() == requester_endpoint.ip() {
                    return None;
                }
                Some((*endpoint, peer.node_id.clone()))
            })
            .min_by_key(|(endpoint, _)| *endpoint);

        let Some((helper_endpoint, helper_node_id)) = helper else {
            self.send_secure_payload(requester_endpoint, SecurePayload::FilteringTestUnavailable)
                .await?;
            return Ok(());
        };

        let probe_token = random();
        self.pending_filter_consents.insert(
            probe_token,
            PendingFilterConsent {
                requester_endpoint,
                requester_node_id: requester_node_id.to_owned(),
                helper_endpoint,
                helper_node_id: helper_node_id.clone(),
                expires_at: Instant::now() + FILTER_PROBE_STATE_TTL,
            },
        );

        self.send_secure_payload(
            requester_endpoint,
            SecurePayload::FilteringTestProposal {
                helper_node_id,
                target_endpoint: requester_endpoint.to_string(),
                probe_token,
            },
        )
        .await
    }

    async fn handle_filtering_test_proposal(
        &mut self,
        coordinator: SocketAddr,
        coordinator_node_id: &str,
        helper_node_id: &str,
        target_endpoint: &str,
        probe_token: u64,
    ) -> Result<()> {
        if self.pending_filter_probes.len() >= MAX_PENDING_FILTER_PROBES {
            return Ok(());
        }

        let Ok(target_endpoint) = target_endpoint.parse::<SocketAddr>() else {
            return Ok(());
        };

        if self.nat_profile.endpoint_seen_by(coordinator_node_id) != Some(target_endpoint)
            || self.peer_endpoint_by_node_id(helper_node_id).is_some()
        {
            return Ok(());
        }

        let authorization = FilterProbeAuthorization::signed(
            &self.identity,
            target_endpoint,
            helper_node_id.to_owned(),
            probe_token,
        )?;
        self.pending_filter_probes.insert(
            probe_token,
            PendingFilterProbe {
                expected_helper_node_id: helper_node_id.to_owned(),
                expires_at: Instant::now() + FILTER_PROBE_STATE_TTL,
            },
        );

        self.send_secure_payload(
            coordinator,
            SecurePayload::FilteringTestConsent { authorization },
        )
        .await
    }

    async fn handle_filtering_test_consent(
        &mut self,
        requester_endpoint: SocketAddr,
        sender_node_id: &str,
        authorization: FilterProbeAuthorization,
    ) -> Result<()> {
        authorization.verify()?;
        let Some(pending) = self
            .pending_filter_consents
            .get(&authorization.probe_token)
            .cloned()
        else {
            return Ok(());
        };

        if pending.expires_at <= Instant::now()
            || pending.requester_endpoint != requester_endpoint
            || pending.requester_node_id != sender_node_id
            || pending.helper_node_id != authorization.helper_node_id
            || authorization.target_node_id != sender_node_id
            || authorization.target_endpoint != pending.requester_endpoint.to_string()
        {
            return Ok(());
        }

        self.pending_filter_consents
            .remove(&authorization.probe_token);
        self.send_secure_payload(
            pending.helper_endpoint,
            SecurePayload::FilteringTestSend { authorization },
        )
        .await
    }

    async fn handle_filtering_test_send(
        &mut self,
        coordinator: SocketAddr,
        coordinator_node_id: &str,
        authorization: FilterProbeAuthorization,
    ) -> Result<()> {
        authorization.verify()?;
        if authorization.helper_node_id != self.node_id()
            || self
                .peer_endpoint_by_node_id(&authorization.target_node_id)
                .is_some()
        {
            return Ok(());
        }

        let target = authorization.target_endpoint.parse::<SocketAddr>()?;
        if !PunchSchedule::candidate_allowed(target) {
            return Ok(());
        }

        self.send(
            target,
            MessageBody::FilterProbe {
                probe_token: authorization.probe_token,
            },
        )
        .await?;

        info!(
            coordinator = %coordinator_node_id,
            %coordinator,
            target = %authorization.target_node_id,
            %target,
            probe_token = authorization.probe_token,
            "sent consent-authorized independent filter probe"
        );
        Ok(())
    }

    fn build_own_dht_record(&self) -> Result<Option<PeerRecord>> {
        let Some(endpoint) = self.nat_profile.preferred_endpoint() else {
            return Ok(None);
        };
        if !endpoint_publishable(endpoint) {
            return Ok(None);
        }

        Ok(Some(PeerRecord::signed(&self.identity, vec![endpoint])?))
    }

    async fn sync_dht_peer(&mut self, peer: SocketAddr) -> Result<()> {
        if let Some(record) = self.build_own_dht_record()? {
            self.send_secure_payload(peer, SecurePayload::DhtStore { record })
                .await?;
        }

        let targets: Vec<String> = self.pending_dht_queries.iter().cloned().collect();
        for target_node_id in targets {
            self.send_secure_payload(
                peer,
                SecurePayload::DhtFind {
                    target_node_id: target_node_id.clone(),
                },
            )
            .await?;
        }

        Ok(())
    }

    async fn activate_dht_record(&mut self, record: &PeerRecord) -> Result<()> {
        if !self.pending_dht_queries.contains(&record.node_id) {
            return Ok(());
        }

        for endpoint in record.socket_endpoints().into_iter().take(2) {
            self.discovery_candidates
                .insert(endpoint, Instant::now() + DHT_DISCOVERY_CANDIDATE_TTL);

            let cookie = self.cookie_cache.get(&endpoint).cloned();
            self.send(
                endpoint,
                MessageBody::Hello {
                    features: local_features(),
                    cookie,
                },
            )
            .await?;

            info!(
                target = %record.node_id,
                %endpoint,
                "started exact-match DHT discovery attempt"
            );
        }

        Ok(())
    }

    async fn send_secure_payload(
        &mut self,
        target: SocketAddr,
        payload: SecurePayload,
    ) -> Result<()> {
        if let Some(message) = self.secure_message(target, payload)? {
            self.send(target, message).await?;
        }
        Ok(())
    }

    fn authorize_punch(&self, token: u64, sender_node_id: &str) -> bool {
        self.pending_punches
            .get(&token)
            .is_some_and(|pending| pending.is_authorized(sender_node_id, Instant::now()))
    }

    async fn drive_punch_attempts(&mut self) {
        let now = Instant::now();
        let mut due = Vec::new();

        for (token, schedule) in &mut self.pending_punches {
            if schedule.probe_due(now) {
                let attempt = schedule.mark_probe_sent(now);
                due.push((
                    *token,
                    schedule.candidate_endpoint(),
                    schedule.expected_node_id().to_owned(),
                    attempt,
                ));
            }
        }

        for (token, candidate, peer_node_id, attempt) in due {
            if let Err(error) = self
                .send(candidate, MessageBody::PunchProbe { punch_token: token })
                .await
            {
                debug!(
                    %candidate,
                    peer = %peer_node_id,
                    punch_token = token,
                    attempt,
                    %error,
                    "UDP punch probe send failed"
                );
            } else {
                debug!(
                    %candidate,
                    peer = %peer_node_id,
                    punch_token = token,
                    attempt,
                    "sent UDP punch probe"
                );
            }
        }

        let expired: Vec<u64> = self
            .pending_punches
            .iter()
            .filter(|(_, schedule)| schedule.is_expired(Instant::now()))
            .map(|(token, _)| *token)
            .collect();

        for token in expired {
            if let Some(schedule) = self.pending_punches.remove(&token) {
                if let Some(state) = self.auto_rendezvous.get_mut(schedule.expected_node_id()) {
                    state.hurry(Instant::now());
                }
                info!(
                    peer = %schedule.expected_node_id(),
                    candidate = %schedule.candidate_endpoint(),
                    punch_token = token,
                    attempts = schedule.attempts_sent(),
                    "UDP punch burst expired without direct-path confirmation"
                );
            }
        }
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

    fn peer_endpoint_by_node_id(&self, node_id: &str) -> Option<SocketAddr> {
        self.peers
            .iter()
            .find(|(_, peer)| peer.node_id == node_id)
            .map(|(endpoint, _)| *endpoint)
    }

    fn is_expected_endpoint(&self, source: SocketAddr) -> bool {
        self.bootstrap_peers.contains(&source)
            || self.peers.contains_key(&source)
            || self.cookie_cache.contains_key(&source)
            || self.discovery_candidates.contains_key(&source)
    }

    fn record_peer(&mut self, envelope: &WireEnvelope, source: SocketAddr) {
        let previous_endpoint = self
            .peers
            .iter()
            .find(|(endpoint, peer)| {
                **endpoint != source && peer.node_id == envelope.sender_node_id
            })
            .map(|(endpoint, _)| *endpoint);

        if let Some(previous_endpoint) = previous_endpoint {
            self.peers.remove(&previous_endpoint);
            self.cookie_cache.remove(&previous_endpoint);
            self.pending_sessions.remove(&previous_endpoint);
            self.sessions.remove(&previous_endpoint);
        }

        if let Some(existing) = self.peers.get(&source) {
            if existing.node_id != envelope.sender_node_id {
                self.sessions.remove(&source);
                self.pending_sessions.remove(&source);
            }
        }

        if !self.peers.contains_key(&source) && self.peers.len() >= MAX_ACTIVE_PEERS {
            self.evict_oldest_peer();
        }

        self.discovery_candidates.remove(&source);
        self.pending_dht_queries.remove(&envelope.sender_node_id);
        self.auto_rendezvous.remove(&envelope.sender_node_id);

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
        endpoints.extend(self.discovery_candidates.keys().copied());
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
            let body = if let Some(body) = self
                .secure_message(endpoint, SecurePayload::Ping { token })
                .ok()
                .flatten()
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

    fn expire_stale_state(&mut self) {
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
        self.pending_filter_probes
            .retain(|_, pending| pending.expires_at > Instant::now());
        self.pending_filter_consents
            .retain(|_, pending| pending.expires_at > Instant::now());
        self.last_rendezvous_request
            .retain(|_, last| last.elapsed() < Duration::from_secs(60));
        self.last_filter_test_request
            .retain(|_, last| last.elapsed() < Duration::from_secs(60));
        self.discovery_candidates
            .retain(|_, expires_at| *expires_at > Instant::now());
        let expired_dht = self.dht.expire();
        if expired_dht > 0 {
            debug!(expired_dht, "expired stale DHT peer records");
        }
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
        "nat-observation".to_owned(),
        "decentralized-rendezvous".to_owned(),
        "auto-rendezvous-selection".to_owned(),
        "signed-dht-records".to_owned(),
        "encrypted-dht-lookup".to_owned(),
        "consent-filter-probe".to_owned(),
        "udp-punch-probe".to_owned(),
        "udp-punch-burst-v1".to_owned(),
        "secure-ping-pong".to_owned(),
    ]
}
