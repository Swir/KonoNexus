use crate::dht::{
    endpoint_publishable, DhtTable, PeerRecord, RoutingTable, DHT_MAX_HOPS, DHT_QUERY_FANOUT,
    DHT_QUERY_RETRY_DELAY, DHT_QUERY_TIMEOUT, DHT_RESPONSE_LIMIT,
};
use crate::identity::NodeIdentity;
use crate::nat::{FilterProbeAuthorization, NatFilteringEvidence, NatMappingBehavior, NatProfile};
use crate::protocol::{MessageBody, WireEnvelope, MAX_PACKET_SIZE};
use crate::punch::{PunchSchedule, PUNCH_AUTH_TTL};
use crate::relay::{RelayManager, MAX_RELAY_CIRCUITS, RELAY_CIRCUIT_TTL};
use crate::relay_e2e::{
    accept_relay_init, decode_relay_payload, encode_relay_payload, packet_kind, RelayE2eInitiator,
};
use crate::rendezvous::{AutoRendezvousState, CoordinatorCandidate};
use crate::routing_cache::{load_routing_hints, new_cache_entry, save_routing_hints};
use crate::security::{CookieGuard, ReplayGuard};
use crate::session::{respond_handshake, PendingHandshake, SecurePayload, SecureSession};
use anyhow::{anyhow, Context, Result};
use rand::random;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::path::PathBuf;
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
const DHT_FORWARD_COOLDOWN: Duration = Duration::from_millis(250);
const MAX_SEEN_DHT_QUERIES: usize = 2_048;
const MAX_RELAY_INBOX_CELLS: usize = 256;

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

#[derive(Debug, Clone)]
struct ActiveDhtQuery {
    target_node_id: String,
    expires_at: Instant,
}

#[derive(Debug, Clone)]
struct ReverseDhtRoute {
    previous_endpoint: SocketAddr,
    expires_at: Instant,
}

#[derive(Debug, Clone)]
struct RelayPath {
    peer_node_id: String,
    expires_at: Instant,
    next_send_sequence: u64,
    highest_receive_sequence: Option<u64>,
}

#[derive(Debug, Clone)]
struct PendingRelayAccept {
    peer_node_id: String,
    expires_at: Instant,
}

#[derive(Debug, Clone)]
pub struct RelayDeliveredCell {
    pub relay_endpoint: SocketAddr,
    pub circuit_id: u64,
    pub peer_node_id: String,
    pub sequence: u64,
    pub opaque_payload_hex: String,
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
    routing: RoutingTable,
    pending_dht_queries: HashSet<String>,
    active_dht_queries: HashMap<u64, ActiveDhtQuery>,
    seen_dht_queries: HashMap<(String, u64), Instant>,
    reverse_dht_routes: HashMap<(String, u64), ReverseDhtRoute>,
    last_dht_query_start: HashMap<String, Instant>,
    last_dht_forward: HashMap<SocketAddr, Instant>,
    discovery_candidates: HashMap<SocketAddr, Instant>,
    routing_cache_path: Option<PathBuf>,
    relay_manager: RelayManager,
    queued_relays: HashMap<SocketAddr, Vec<String>>,
    pending_relay_requests: HashMap<u64, (SocketAddr, String)>,
    pending_relay_accepts: HashMap<(SocketAddr, u64), PendingRelayAccept>,
    relay_paths: HashMap<(SocketAddr, u64), RelayPath>,
    relay_e2e_pending: HashMap<(SocketAddr, u64), RelayE2eInitiator>,
    relay_e2e_sessions: HashMap<(SocketAddr, u64), SecureSession>,
    punch_relay_candidates: HashMap<u64, SocketAddr>,
    relay_inbox: VecDeque<RelayDeliveredCell>,
    hello_interval: Duration,
}

impl KonoNode {
    pub async fn bind(
        identity: NodeIdentity,
        bind_addr: SocketAddr,
        bootstrap_peers: Vec<SocketAddr>,
        hello_interval: Duration,
    ) -> Result<Self> {
        let local_node_id = identity.node_id();
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
            routing: RoutingTable::new(&local_node_id),
            pending_dht_queries: HashSet::new(),
            active_dht_queries: HashMap::new(),
            seen_dht_queries: HashMap::new(),
            reverse_dht_routes: HashMap::new(),
            last_dht_query_start: HashMap::new(),
            last_dht_forward: HashMap::new(),
            discovery_candidates: HashMap::new(),
            routing_cache_path: None,
            relay_manager: RelayManager::default(),
            queued_relays: HashMap::new(),
            pending_relay_requests: HashMap::new(),
            pending_relay_accepts: HashMap::new(),
            relay_paths: HashMap::new(),
            relay_e2e_pending: HashMap::new(),
            relay_e2e_sessions: HashMap::new(),
            punch_relay_candidates: HashMap::new(),
            relay_inbox: VecDeque::new(),
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

    pub fn queue_relay(&mut self, relay_endpoint: SocketAddr, target_node_id: String) {
        self.queued_relays
            .entry(relay_endpoint)
            .or_default()
            .push(target_node_id);
    }

    pub fn configure_routing_cache(&mut self, path: PathBuf) -> Result<usize> {
        let hints = load_routing_hints(&path)?;
        let mut loaded = 0_usize;

        for hint in hints {
            let Ok(endpoint) = hint.endpoint.parse::<SocketAddr>() else {
                continue;
            };
            if !self.bootstrap_peers.contains(&endpoint) {
                self.bootstrap_peers.push(endpoint);
                loaded += 1;
            }
        }

        self.routing_cache_path = Some(path);
        Ok(loaded)
    }

    pub fn take_relay_cells(&mut self) -> Vec<RelayDeliveredCell> {
        self.relay_inbox.drain(..).collect()
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
                    if let Err(error) = self.persist_routing_cache() {
                        debug!(%error, "routing cache persistence failed");
                    }
                }
                _ = punch_ticker.tick() => {
                    self.drive_punch_attempts().await;
                }
                _ = rendezvous_ticker.tick() => {
                    self.drive_auto_rendezvous().await;
                    self.drive_dht_queries().await;
                }
                _ = tokio::signal::ctrl_c() => {
                    if let Err(error) = self.persist_routing_cache() {
                        debug!(%error, "routing cache persistence failed during shutdown");
                    }
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
                self.routing
                    .observe(sender_node_id.clone(), source, Instant::now());

                info!(
                    peer = %sender_node_id,
                    %source,
                    %session_id,
                    "encrypted KNP session established as responder"
                );

                self.flush_rendezvous_requests(source).await?;
                self.flush_filter_test_request(source).await?;
                self.flush_relay_requests(source).await?;
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
                self.flush_relay_requests(source).await?;
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
                self.punch_relay_candidates.remove(&punch_token);
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
                self.punch_relay_candidates.remove(&punch_token);

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
            SecurePayload::DhtFind {
                query_id,
                origin_node_id,
                target_node_id,
                hops_remaining,
            } => {
                if hops_remaining > DHT_MAX_HOPS
                    || !plausible_node_id(&origin_node_id)
                    || !plausible_node_id(&target_node_id)
                {
                    return Ok(());
                }

                let now = Instant::now();
                self.seen_dht_queries
                    .retain(|_, expires_at| *expires_at > now);
                self.reverse_dht_routes
                    .retain(|_, route| route.expires_at > now);

                let query_key = (origin_node_id.clone(), query_id);
                if self
                    .seen_dht_queries
                    .get(&query_key)
                    .is_some_and(|expires_at| *expires_at > now)
                    || self.seen_dht_queries.len() >= MAX_SEEN_DHT_QUERIES
                {
                    return Ok(());
                }

                self.seen_dht_queries
                    .insert(query_key.clone(), now + DHT_QUERY_TIMEOUT);

                if origin_node_id != self.node_id() {
                    self.reverse_dht_routes.insert(
                        query_key.clone(),
                        ReverseDhtRoute {
                            previous_endpoint: source,
                            expires_at: now + DHT_QUERY_TIMEOUT,
                        },
                    );
                }

                let mut records = Vec::new();
                let mut exact_found = false;

                if target_node_id == self.node_id() {
                    if let Some(record) = self.build_own_dht_record()? {
                        exact_found = true;
                        records.push(record);
                    }
                } else if let Some(record) = self.dht.get(&target_node_id) {
                    exact_found = true;
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
                        query_id,
                        origin_node_id: origin_node_id.clone(),
                        target_node_id: target_node_id.clone(),
                        records,
                    },
                )
                .await?;

                let can_forward = self
                    .last_dht_forward
                    .get(&source)
                    .is_none_or(|last| now.duration_since(*last) >= DHT_FORWARD_COOLDOWN);

                if !exact_found && hops_remaining > 0 && can_forward {
                    self.last_dht_forward.insert(source, now);
                    let mut forwarded = 0_usize;

                    for candidate in self.routing.nearest(&target_node_id, DHT_QUERY_FANOUT + 2) {
                        if candidate.endpoint == source
                            || candidate.node_id == origin_node_id
                            || !self.sessions.contains_key(&candidate.endpoint)
                        {
                            continue;
                        }

                        self.send_secure_payload(
                            candidate.endpoint,
                            SecurePayload::DhtFind {
                                query_id,
                                origin_node_id: origin_node_id.clone(),
                                target_node_id: target_node_id.clone(),
                                hops_remaining: hops_remaining - 1,
                            },
                        )
                        .await?;

                        forwarded += 1;
                        if forwarded >= DHT_QUERY_FANOUT {
                            break;
                        }
                    }
                }
            }
            SecurePayload::DhtNodes {
                query_id,
                origin_node_id,
                target_node_id,
                records,
            } => {
                if records.len() > DHT_RESPONSE_LIMIT
                    || !plausible_node_id(&origin_node_id)
                    || !plausible_node_id(&target_node_id)
                {
                    debug!(
                        peer = %sender_node_id,
                        count = records.len(),
                        "rejected invalid DHT response"
                    );
                    return Ok(());
                }

                for record in &records {
                    if self.dht.upsert(record.clone()).is_err() {
                        continue;
                    }
                }

                if origin_node_id == self.node_id() {
                    if self.pending_dht_queries.contains(&target_node_id) {
                        if let Some(current) = self.dht.get(&target_node_id).cloned() {
                            self.active_dht_queries.remove(&query_id);
                            self.activate_dht_record(&current).await?;
                        }
                    }
                } else {
                    let query_key = (origin_node_id.clone(), query_id);
                    let reverse = self.reverse_dht_routes.get(&query_key).cloned();
                    if let Some(reverse) = reverse {
                        if reverse.expires_at > Instant::now()
                            && reverse.previous_endpoint != source
                            && self.sessions.contains_key(&reverse.previous_endpoint)
                        {
                            self.send_secure_payload(
                                reverse.previous_endpoint,
                                SecurePayload::DhtNodes {
                                    query_id,
                                    origin_node_id,
                                    target_node_id,
                                    records,
                                },
                            )
                            .await?;
                        }
                    }
                }
            }
            SecurePayload::RelayOpen {
                circuit_id,
                target_node_id,
            } => {
                let Some(target_endpoint) = self.peer_endpoint_by_node_id(&target_node_id) else {
                    self.send_secure_payload(source, SecurePayload::RelayReject { circuit_id })
                        .await?;
                    return Ok(());
                };

                if target_endpoint == source || !self.sessions.contains_key(&target_endpoint) {
                    self.send_secure_payload(source, SecurePayload::RelayReject { circuit_id })
                        .await?;
                    return Ok(());
                }

                match self.relay_manager.open(
                    circuit_id,
                    source,
                    sender_node_id.to_owned(),
                    target_endpoint,
                    target_node_id.clone(),
                    Instant::now(),
                ) {
                    Ok(()) => {
                        self.send_secure_payload(
                            target_endpoint,
                            SecurePayload::RelayOffer {
                                circuit_id,
                                origin_node_id: sender_node_id.to_owned(),
                            },
                        )
                        .await?;
                        info!(
                            circuit_id,
                            origin = %sender_node_id,
                            target = %target_node_id,
                            "relay circuit awaiting target consent"
                        );
                    }
                    Err(error) => {
                        debug!(circuit_id, %error, "relay open rejected");
                        self.send_secure_payload(source, SecurePayload::RelayReject { circuit_id })
                            .await?;
                    }
                }
            }
            SecurePayload::RelayOffer {
                circuit_id,
                origin_node_id,
            } => {
                if !plausible_node_id(&origin_node_id)
                    || origin_node_id == self.node_id()
                    || self.pending_relay_accepts.len() >= MAX_RELAY_CIRCUITS
                {
                    return Ok(());
                }

                self.pending_relay_accepts.insert(
                    (source, circuit_id),
                    PendingRelayAccept {
                        peer_node_id: origin_node_id.clone(),
                        expires_at: Instant::now() + RELAY_CIRCUIT_TTL,
                    },
                );

                self.send_secure_payload(
                    source,
                    SecurePayload::RelayAccept {
                        circuit_id,
                        origin_node_id,
                    },
                )
                .await?;
            }
            SecurePayload::RelayAccept {
                circuit_id,
                origin_node_id,
            } => {
                let accepted =
                    self.relay_manager
                        .accept(circuit_id, source, sender_node_id, Instant::now());

                let Ok((origin_endpoint, expected_origin_node_id)) = accepted else {
                    return Ok(());
                };
                if expected_origin_node_id != origin_node_id {
                    self.relay_manager.close(circuit_id, source, sender_node_id);
                    return Ok(());
                }

                self.send_secure_payload(
                    origin_endpoint,
                    SecurePayload::RelayReady {
                        circuit_id,
                        peer_node_id: sender_node_id.to_owned(),
                    },
                )
                .await?;
                self.send_secure_payload(
                    source,
                    SecurePayload::RelayReady {
                        circuit_id,
                        peer_node_id: origin_node_id,
                    },
                )
                .await?;

                info!(
                    circuit_id,
                    origin = %expected_origin_node_id,
                    target = %sender_node_id,
                    "cooperative relay circuit active"
                );
            }
            SecurePayload::RelayReady {
                circuit_id,
                peer_node_id,
            } => {
                if !plausible_node_id(&peer_node_id) {
                    return Ok(());
                }

                let origin_valid = self.pending_relay_requests.remove(&circuit_id).is_some_and(
                    |(relay_endpoint, requested_peer)| {
                        relay_endpoint == source && requested_peer == peer_node_id
                    },
                );
                let target_valid = self
                    .pending_relay_accepts
                    .remove(&(source, circuit_id))
                    .is_some_and(|pending| {
                        pending.expires_at > Instant::now() && pending.peer_node_id == peer_node_id
                    });

                if !origin_valid && !target_valid {
                    return Ok(());
                }

                self.relay_paths.insert(
                    (source, circuit_id),
                    RelayPath {
                        peer_node_id: peer_node_id.clone(),
                        expires_at: Instant::now() + RELAY_CIRCUIT_TTL,
                        next_send_sequence: 0,
                        highest_receive_sequence: None,
                    },
                );

                let local_node_id = self.node_id();
                if local_node_id.as_str() < peer_node_id.as_str() {
                    let (pending, init) =
                        RelayE2eInitiator::begin(&self.identity, circuit_id, peer_node_id.clone())?;
                    self.relay_e2e_pending.insert((source, circuit_id), pending);
                    self.send_relay_inner(source, circuit_id, init).await?;
                }

                info!(
                    relay = %sender_node_id,
                    peer = %peer_node_id,
                    circuit_id,
                    "relay path ready; end-to-end inner handshake started"
                );
            }
            SecurePayload::RelayCell {
                circuit_id,
                sequence,
                opaque_payload_hex,
            } => {
                if self.relay_manager.get(circuit_id).is_some() {
                    match self.relay_manager.forward(
                        circuit_id,
                        source,
                        sender_node_id,
                        sequence,
                        opaque_payload_hex,
                        Instant::now(),
                    ) {
                        Ok(forward) => {
                            self.send_secure_payload(
                                forward.destination,
                                SecurePayload::RelayCell {
                                    circuit_id: forward.circuit_id,
                                    sequence: forward.sequence,
                                    opaque_payload_hex: forward.opaque_payload_hex,
                                },
                            )
                            .await?;
                        }
                        Err(error) => {
                            debug!(circuit_id, %error, "relay cell rejected");
                        }
                    }
                } else if self.relay_paths.contains_key(&(source, circuit_id)) {
                    let peer_node_id = {
                        let Some(path) = self.relay_paths.get_mut(&(source, circuit_id)) else {
                            return Ok(());
                        };
                        if path.expires_at <= Instant::now()
                            || path
                                .highest_receive_sequence
                                .is_some_and(|highest| sequence <= highest)
                        {
                            return Ok(());
                        }

                        path.highest_receive_sequence = Some(sequence);
                        path.expires_at = Instant::now() + RELAY_CIRCUIT_TTL;
                        path.peer_node_id.clone()
                    };

                    let raw = match hex::decode(&opaque_payload_hex) {
                        Ok(raw) => raw,
                        Err(_) => return Ok(()),
                    };
                    if raw.is_empty() || raw.len() > crate::relay::MAX_RELAY_CELL_BYTES {
                        return Ok(());
                    }

                    if let Err(error) = self
                        .handle_relay_inner(source, circuit_id, &peer_node_id, &raw)
                        .await
                    {
                        debug!(
                            relay = %sender_node_id,
                            peer = %peer_node_id,
                            circuit_id,
                            %error,
                            "relay inner packet rejected"
                        );
                    }
                }
            }
            SecurePayload::RelayClose { circuit_id } => {
                if let Some((other_endpoint, _)) =
                    self.relay_manager.close(circuit_id, source, sender_node_id)
                {
                    self.send_secure_payload(
                        other_endpoint,
                        SecurePayload::RelayClose { circuit_id },
                    )
                    .await?;
                } else {
                    self.relay_paths.remove(&(source, circuit_id));
                    self.relay_e2e_pending.remove(&(source, circuit_id));
                    self.relay_e2e_sessions.remove(&(source, circuit_id));
                    self.pending_relay_requests.remove(&circuit_id);
                    self.pending_relay_accepts.remove(&(source, circuit_id));
                }
            }
            SecurePayload::RelayReject { circuit_id } => {
                self.pending_relay_requests.remove(&circuit_id);
                self.pending_relay_accepts.remove(&(source, circuit_id));
                self.relay_paths.remove(&(source, circuit_id));
                self.relay_e2e_pending.remove(&(source, circuit_id));
                self.relay_e2e_sessions.remove(&(source, circuit_id));
                debug!(relay = %sender_node_id, circuit_id, "relay request rejected");
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
                self.punch_relay_candidates.insert(punch_token, source);

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

    async fn flush_relay_requests(&mut self, relay_endpoint: SocketAddr) -> Result<()> {
        let Some(targets) = self.queued_relays.remove(&relay_endpoint) else {
            return Ok(());
        };

        for target_node_id in targets {
            self.start_relay_request(relay_endpoint, &target_node_id)
                .await?;
        }

        Ok(())
    }

    async fn start_relay_request(
        &mut self,
        relay_endpoint: SocketAddr,
        target_node_id: &str,
    ) -> Result<Option<u64>> {
        if !plausible_node_id(target_node_id)
            || target_node_id == self.node_id()
            || !self.sessions.contains_key(&relay_endpoint)
        {
            return Ok(None);
        }

        if self.relay_paths.iter().any(|((endpoint, _), path)| {
            *endpoint == relay_endpoint
                && path.peer_node_id == target_node_id
                && path.expires_at > Instant::now()
        }) || self
            .pending_relay_requests
            .values()
            .any(|(endpoint, peer)| *endpoint == relay_endpoint && peer == target_node_id)
        {
            return Ok(None);
        }

        let mut circuit_id: u64 = random();
        while self.pending_relay_requests.contains_key(&circuit_id) {
            circuit_id = random();
        }

        self.pending_relay_requests
            .insert(circuit_id, (relay_endpoint, target_node_id.to_owned()));

        if let Err(error) = self
            .send_secure_payload(
                relay_endpoint,
                SecurePayload::RelayOpen {
                    circuit_id,
                    target_node_id: target_node_id.to_owned(),
                },
            )
            .await
        {
            self.pending_relay_requests.remove(&circuit_id);
            return Err(error);
        }

        info!(
            %relay_endpoint,
            target = %target_node_id,
            circuit_id,
            "requested cooperative relay circuit"
        );

        Ok(Some(circuit_id))
    }

    async fn send_relay_inner(
        &mut self,
        relay_endpoint: SocketAddr,
        circuit_id: u64,
        encoded: Vec<u8>,
    ) -> Result<()> {
        if encoded.is_empty() || encoded.len() > crate::relay::MAX_RELAY_CELL_BYTES {
            return Err(anyhow!("relay inner packet size is invalid"));
        }

        let sequence = {
            let path = self
                .relay_paths
                .get_mut(&(relay_endpoint, circuit_id))
                .ok_or_else(|| anyhow!("relay path not found"))?;

            if path.expires_at <= Instant::now() {
                return Err(anyhow!("relay path expired"));
            }

            let sequence = path.next_send_sequence;
            path.next_send_sequence = sequence
                .checked_add(1)
                .ok_or_else(|| anyhow!("relay transport sequence exhausted"))?;
            path.expires_at = Instant::now() + RELAY_CIRCUIT_TTL;
            sequence
        };

        self.send_secure_payload(
            relay_endpoint,
            SecurePayload::RelayCell {
                circuit_id,
                sequence,
                opaque_payload_hex: hex::encode(encoded),
            },
        )
        .await
    }

    async fn handle_relay_inner(
        &mut self,
        relay_endpoint: SocketAddr,
        circuit_id: u64,
        peer_node_id: &str,
        encoded: &[u8],
    ) -> Result<()> {
        let key = (relay_endpoint, circuit_id);

        match packet_kind(encoded)? {
            "init" => {
                if self.relay_e2e_sessions.contains_key(&key) {
                    return Ok(());
                }

                let (session, ack) =
                    accept_relay_init(&self.identity, circuit_id, peer_node_id, encoded)?;
                let session_id = session.session_id().to_owned();
                self.relay_e2e_sessions.insert(key, session);
                self.send_relay_inner(relay_endpoint, circuit_id, ack)
                    .await?;

                info!(
                    %relay_endpoint,
                    peer = %peer_node_id,
                    circuit_id,
                    %session_id,
                    "relay inner end-to-end session established as responder"
                );
            }
            "ack" => {
                let Some(pending) = self.relay_e2e_pending.remove(&key) else {
                    return Ok(());
                };
                let mut session = pending.complete(&self.identity, encoded)?;
                let session_id = session.session_id().to_owned();
                let ping_token: u64 = random();
                let ping =
                    encode_relay_payload(&mut session, &SecurePayload::Ping { token: ping_token })?;
                self.relay_e2e_sessions.insert(key, session);
                self.send_relay_inner(relay_endpoint, circuit_id, ping)
                    .await?;

                info!(
                    %relay_endpoint,
                    peer = %peer_node_id,
                    circuit_id,
                    %session_id,
                    "relay inner end-to-end session established as initiator"
                );
            }
            "data" => {
                let payload = {
                    let Some(session) = self.relay_e2e_sessions.get_mut(&key) else {
                        return Ok(());
                    };
                    decode_relay_payload(session, encoded)?
                };

                match payload {
                    SecurePayload::Ping { token } => {
                        let pong = {
                            let session = self
                                .relay_e2e_sessions
                                .get_mut(&key)
                                .ok_or_else(|| anyhow!("relay E2E session disappeared"))?;
                            encode_relay_payload(session, &SecurePayload::Pong { token })?
                        };
                        self.send_relay_inner(relay_endpoint, circuit_id, pong)
                            .await?;
                    }
                    SecurePayload::Pong { token } => {
                        debug!(
                            %relay_endpoint,
                            peer = %peer_node_id,
                            circuit_id,
                            token,
                            "relay E2E pong received"
                        );
                    }
                    _ => {
                        debug!(
                            %relay_endpoint,
                            peer = %peer_node_id,
                            circuit_id,
                            "ignored unsupported relay inner secure payload"
                        );
                    }
                }
            }
            _ => return Err(anyhow!("unknown relay inner packet kind")),
        }

        Ok(())
    }

    fn persist_routing_cache(&self) -> Result<()> {
        let Some(path) = &self.routing_cache_path else {
            return Ok(());
        };

        let mut entries = Vec::new();
        for endpoint in self.sessions.keys() {
            let Some(peer) = self.peers.get(endpoint) else {
                continue;
            };
            entries.push(new_cache_entry(peer.node_id.clone(), *endpoint)?);
        }

        save_routing_hints(path, &entries)
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

    async fn drive_dht_queries(&mut self) {
        let now = Instant::now();

        self.active_dht_queries
            .retain(|_, query| query.expires_at > now);
        self.seen_dht_queries
            .retain(|_, expires_at| *expires_at > now);
        self.reverse_dht_routes
            .retain(|_, route| route.expires_at > now);

        let targets: Vec<String> = self.pending_dht_queries.iter().cloned().collect();
        for target_node_id in targets {
            if self.peer_endpoint_by_node_id(&target_node_id).is_some() {
                self.pending_dht_queries.remove(&target_node_id);
                continue;
            }

            if let Some(record) = self.dht.get(&target_node_id).cloned() {
                if let Err(error) = self.activate_dht_record(&record).await {
                    debug!(target = %target_node_id, %error, "cached exact DHT activation failed");
                }
                continue;
            }

            if self
                .active_dht_queries
                .values()
                .any(|query| query.target_node_id == target_node_id)
            {
                continue;
            }

            if self
                .last_dht_query_start
                .get(&target_node_id)
                .is_some_and(|last| now.duration_since(*last) < DHT_QUERY_RETRY_DELAY)
            {
                continue;
            }

            let candidates = self.routing.nearest(&target_node_id, DHT_QUERY_FANOUT);
            if candidates.is_empty() {
                continue;
            }

            let query_id: u64 = random();
            let origin_node_id = self.node_id();
            let query_key = (origin_node_id.clone(), query_id);

            self.active_dht_queries.insert(
                query_id,
                ActiveDhtQuery {
                    target_node_id: target_node_id.clone(),
                    expires_at: now + DHT_QUERY_TIMEOUT,
                },
            );
            self.seen_dht_queries
                .insert(query_key, now + DHT_QUERY_TIMEOUT);
            self.last_dht_query_start
                .insert(target_node_id.clone(), now);

            let mut sent = 0_usize;
            for candidate in candidates {
                if !self.sessions.contains_key(&candidate.endpoint) {
                    continue;
                }

                match self
                    .send_secure_payload(
                        candidate.endpoint,
                        SecurePayload::DhtFind {
                            query_id,
                            origin_node_id: origin_node_id.clone(),
                            target_node_id: target_node_id.clone(),
                            hops_remaining: DHT_MAX_HOPS,
                        },
                    )
                    .await
                {
                    Ok(()) => sent += 1,
                    Err(error) => {
                        debug!(
                            peer = %candidate.node_id,
                            endpoint = %candidate.endpoint,
                            target = %target_node_id,
                            %error,
                            "multi-hop DHT query send failed"
                        );
                    }
                }
            }

            if sent == 0 {
                self.active_dht_queries.remove(&query_id);
            } else {
                debug!(
                    query_id,
                    target = %target_node_id,
                    fanout = sent,
                    max_hops = DHT_MAX_HOPS,
                    "started bounded multi-hop DHT query"
                );
            }
        }
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

        for target_node_id in self.pending_dht_queries.clone() {
            self.last_dht_query_start.remove(&target_node_id);
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
                let target_node_id = schedule.expected_node_id().to_owned();
                let relay_candidate = self.punch_relay_candidates.remove(&token);
                let local_node_id = self.node_id();
                let mut relay_started = false;

                if local_node_id.as_str() < target_node_id.as_str()
                    && self.peer_endpoint_by_node_id(&target_node_id).is_none()
                {
                    if let Some(relay_endpoint) = relay_candidate {
                        if self.sessions.contains_key(&relay_endpoint) {
                            match self
                                .start_relay_request(relay_endpoint, &target_node_id)
                                .await
                            {
                                Ok(Some(circuit_id)) => {
                                    relay_started = true;
                                    info!(
                                        %relay_endpoint,
                                        target = %target_node_id,
                                        circuit_id,
                                        "hole punch failed; automatic relay fallback started"
                                    );
                                }
                                Ok(None) => {}
                                Err(error) => {
                                    debug!(
                                        %relay_endpoint,
                                        target = %target_node_id,
                                        %error,
                                        "automatic relay fallback failed to start"
                                    );
                                }
                            }
                        }
                    }
                }

                if let Some(state) = self.auto_rendezvous.get_mut(&target_node_id) {
                    if relay_started {
                        state.defer(Instant::now(), Duration::from_secs(10));
                    } else {
                        state.hurry(Instant::now());
                    }
                }

                info!(
                    peer = %target_node_id,
                    candidate = %schedule.candidate_endpoint(),
                    punch_token = token,
                    attempts = schedule.attempts_sent(),
                    relay_started,
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
            self.routing.remove_endpoint(previous_endpoint);
        }

        if let Some(existing) = self.peers.get(&source) {
            if existing.node_id != envelope.sender_node_id {
                self.sessions.remove(&source);
                self.pending_sessions.remove(&source);
                self.routing.remove_endpoint(source);
            }
        }

        if !self.peers.contains_key(&source) && self.peers.len() >= MAX_ACTIVE_PEERS {
            self.evict_oldest_peer();
        }

        self.discovery_candidates.remove(&source);
        self.pending_dht_queries.remove(&envelope.sender_node_id);
        self.active_dht_queries
            .retain(|_, query| query.target_node_id != envelope.sender_node_id);
        self.last_dht_query_start.remove(&envelope.sender_node_id);
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
            self.routing.remove_endpoint(endpoint);
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
        let active_session_endpoints: HashSet<SocketAddr> = self.sessions.keys().copied().collect();
        self.routing.retain_endpoints(&active_session_endpoints);
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
        self.relay_paths
            .retain(|_, path| path.expires_at > Instant::now());
        self.relay_e2e_pending
            .retain(|key, _| self.relay_paths.contains_key(key));
        self.relay_e2e_sessions
            .retain(|key, _| self.relay_paths.contains_key(key));
        self.pending_relay_accepts
            .retain(|_, pending| pending.expires_at > Instant::now());
        let expired_relay = self.relay_manager.expire(Instant::now());
        if expired_relay > 0 {
            debug!(expired_relay, "expired idle relay circuits");
        }
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

fn plausible_node_id(node_id: &str) -> bool {
    node_id.len() == 44
        && node_id.starts_with("knp1")
        && node_id[4..].bytes().all(|byte| byte.is_ascii_hexdigit())
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
        "bounded-multihop-dht".to_owned(),
        "k-bucket-routing".to_owned(),
        "persistent-routing-hints".to_owned(),
        "cooperative-relay-control".to_owned(),
        "opaque-relay-cells".to_owned(),
        "relay-e2e-session".to_owned(),
        "punch-to-relay-fallback".to_owned(),
        "consent-filter-probe".to_owned(),
        "udp-punch-probe".to_owned(),
        "udp-punch-burst-v1".to_owned(),
        "secure-ping-pong".to_owned(),
    ]
}
