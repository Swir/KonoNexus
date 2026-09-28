use crate::dht::{
    endpoint_publishable, DhtTable, PeerRecord, RoutingTable, DHT_MAX_HOPS, DHT_QUERY_FANOUT,
    DHT_QUERY_RETRY_DELAY, DHT_QUERY_TIMEOUT, DHT_RESPONSE_LIMIT,
};
use crate::identity::NodeIdentity;
use crate::nat::{FilterProbeAuthorization, NatFilteringEvidence, NatMappingBehavior, NatProfile};
use crate::protocol::{MessageBody, WireEnvelope, MAX_PACKET_SIZE};
use crate::punch::{PunchSchedule, PUNCH_AUTH_TTL};
use crate::relay::{RelayManager, MAX_RELAY_CIRCUITS, RELAY_CIRCUIT_TTL};
use crate::relay_app::{
    RelayAppDeliveryFailure, RelayAppDeliveryReceipt, RelayAppEvent, RelayAppManager,
    RelayAppMessage, RelayAppReceiveStatus,
};
use crate::relay_e2e::{
    accept_relay_init, decode_relay_payload, encode_relay_payload, encode_relay_payload_on_session,
    packet_kind, RelayE2eInitiator,
};
use crate::rendezvous::{AutoRendezvousState, CoordinatorCandidate};
use crate::routing_cache::{load_routing_hints, new_cache_entry, save_routing_hints};
use crate::security::{CookieGuard, ReplayGuard, SequenceWindow};
use crate::session::{respond_handshake, PendingHandshake, SecurePayload, SessionSlot};
use anyhow::{anyhow, Context, Result};
use rand::random;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
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
const RELAY_APP_BURST_PER_TICK: usize = 4;
const MAX_RELAY_APP_HANDLE_CAPACITY: usize = 1_024;
const SESSION_HANDSHAKE_RETRY_DELAY: Duration = Duration::from_secs(1);
const SESSION_HANDSHAKE_MAX_ATTEMPTS: u8 = 4;
const SESSION_RESPONDER_ACK_TTL: Duration = Duration::from_secs(10);
const MAX_SESSION_RESPONDER_ACKS: usize = 256;
const SESSION_REKEY_INTERVAL: Duration = Duration::from_secs(10 * 60);
const SESSION_REKEY_GRACE: Duration = Duration::from_secs(30);
const SESSION_REKEY_RETRY_DELAY: Duration = Duration::from_secs(1);
const SESSION_REKEY_MAX_ATTEMPTS: u8 = 4;
const SESSION_REKEY_ACK_TTL: Duration = Duration::from_secs(10);
const MAX_SESSION_REKEY_ACKS: usize = 256;
const AUTO_RELAY_MAX_CANDIDATES: usize = 3;
const AUTO_RELAY_RETRY_DELAY: Duration = Duration::from_secs(2);
const AUTO_RELAY_STATE_TTL: Duration = Duration::from_secs(30);
const RELAY_E2E_REKEY_INTERVAL: Duration = Duration::from_secs(10 * 60);
const RELAY_E2E_REKEY_GRACE: Duration = Duration::from_secs(30);
const RELAY_E2E_REKEY_RETRY_DELAY: Duration = Duration::from_secs(1);
const RELAY_E2E_REKEY_MAX_ATTEMPTS: u8 = 4;
const RELAY_E2E_REKEY_ACK_TTL: Duration = Duration::from_secs(10);
const MAX_RELAY_E2E_REKEY_ACKS: usize = 256;

#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub node_id: String,
    pub public_key: String,
    pub endpoint: SocketAddr,
    pub first_seen: Instant,
    pub last_seen: Instant,
    pub observed_external_endpoint: Option<String>,
}

enum RelayAppCommand {
    Send {
        peer_node_id: String,
        data: Vec<u8>,
        response: oneshot::Sender<std::result::Result<u64, String>>,
    },
}

pub struct RelayAppHandle {
    command_tx: mpsc::Sender<RelayAppCommand>,
    message_rx: mpsc::Receiver<RelayAppMessage>,
    receipt_rx: mpsc::Receiver<RelayAppDeliveryReceipt>,
    failure_rx: mpsc::Receiver<RelayAppDeliveryFailure>,
}

impl RelayAppHandle {
    pub async fn send(&self, peer_node_id: String, data: Vec<u8>) -> Result<u64> {
        let (response_tx, response_rx) = oneshot::channel();
        self.command_tx
            .send(RelayAppCommand::Send {
                peer_node_id,
                data,
                response: response_tx,
            })
            .await
            .map_err(|_| anyhow!("KonoNexus relay application runtime is closed"))?;

        response_rx
            .await
            .map_err(|_| anyhow!("KonoNexus relay application response channel closed"))?
            .map_err(anyhow::Error::msg)
    }

    pub async fn recv(&mut self) -> Option<RelayAppMessage> {
        self.message_rx.recv().await
    }

    pub async fn recv_receipt(&mut self) -> Option<RelayAppDeliveryReceipt> {
        self.receipt_rx.recv().await
    }

    pub async fn recv_failure(&mut self) -> Option<RelayAppDeliveryFailure> {
        self.failure_rx.recv().await
    }

    pub async fn next_event(&mut self) -> Option<RelayAppEvent> {
        tokio::select! {
            message = self.message_rx.recv() => message.map(RelayAppEvent::Message),
            receipt = self.receipt_rx.recv() => receipt.map(RelayAppEvent::Delivered),
            failure = self.failure_rx.recv() => failure.map(RelayAppEvent::Failed),
        }
    }
}

struct PendingSessionAttempt {
    pending: PendingHandshake,
    handshake_id: u64,
    peer_node_id: String,
    ephemeral_public_key: String,
    attempts: u8,
    next_retry_at: Instant,
}

#[derive(Debug, Clone)]
struct ResponderSessionAck {
    peer_node_id: String,
    initiator_public_key: String,
    responder_public_key: String,
    expires_at: Instant,
}

struct PendingRekeyAttempt {
    pending: PendingHandshake,
    rekey_id: u64,
    peer_node_id: String,
    ephemeral_public_key: String,
    attempts: u8,
    next_retry_at: Instant,
}

#[derive(Debug, Clone)]
struct ResponderRekeyAck {
    peer_node_id: String,
    initiator_public_key: String,
    responder_public_key: String,
    expires_at: Instant,
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
    receive_window: SequenceWindow,
}

#[derive(Debug, Clone)]
struct PendingRelayAccept {
    peer_node_id: String,
    expires_at: Instant,
}

struct PendingRelayE2eRekey {
    pending: PendingHandshake,
    rekey_id: u64,
    peer_node_id: String,
    ephemeral_public_key: String,
    attempts: u8,
    next_retry_at: Instant,
}

#[derive(Debug, Clone)]
struct ResponderRelayE2eRekeyAck {
    peer_node_id: String,
    initiator_public_key: String,
    responder_public_key: String,
    expires_at: Instant,
}

#[derive(Debug, Clone)]
struct AutoRelayFallback {
    preferred: Option<SocketAddr>,
    tried: HashSet<SocketAddr>,
    next_attempt_at: Instant,
    expires_at: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AppTransport {
    Direct(SocketAddr),
    Relay {
        relay_endpoint: SocketAddr,
        circuit_id: u64,
    },
}

fn preferred_app_transport(
    direct: Option<SocketAddr>,
    relay: Option<(SocketAddr, u64)>,
) -> Option<AppTransport> {
    direct.map(AppTransport::Direct).or_else(|| {
        relay.map(|(relay_endpoint, circuit_id)| AppTransport::Relay {
            relay_endpoint,
            circuit_id,
        })
    })
}

pub struct KonoNode {
    identity: NodeIdentity,
    socket: Arc<UdpSocket>,
    bootstrap_peers: Vec<SocketAddr>,
    peers: HashMap<SocketAddr, PeerInfo>,
    cookie_cache: HashMap<SocketAddr, String>,
    replay_guard: ReplayGuard,
    cookie_guard: CookieGuard,
    pending_sessions: HashMap<SocketAddr, PendingSessionAttempt>,
    responder_session_acks: HashMap<(SocketAddr, u64), ResponderSessionAck>,
    sessions: HashMap<SocketAddr, SessionSlot>,
    confirmed_sessions: HashSet<SocketAddr>,
    pending_rekeys: HashMap<SocketAddr, PendingRekeyAttempt>,
    responder_rekey_acks: HashMap<(SocketAddr, u64), ResponderRekeyAck>,
    last_rekey: HashMap<SocketAddr, Instant>,
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
    auto_relay_fallbacks: HashMap<String, AutoRelayFallback>,
    relay_paths: HashMap<(SocketAddr, u64), RelayPath>,
    relay_e2e_pending: HashMap<(SocketAddr, u64), RelayE2eInitiator>,
    relay_e2e_sessions: HashMap<(SocketAddr, u64), SessionSlot>,
    pending_relay_e2e_rekeys: HashMap<(SocketAddr, u64), PendingRelayE2eRekey>,
    responder_relay_e2e_rekey_acks: HashMap<(SocketAddr, u64, u64), ResponderRelayE2eRekeyAck>,
    last_relay_e2e_rekey: HashMap<(SocketAddr, u64), Instant>,
    relay_app: RelayAppManager,
    relay_app_command_rx: Option<mpsc::Receiver<RelayAppCommand>>,
    relay_app_event_tx: Option<mpsc::Sender<RelayAppMessage>>,
    relay_app_receipt_tx: Option<mpsc::Sender<RelayAppDeliveryReceipt>>,
    relay_app_failure_tx: Option<mpsc::Sender<RelayAppDeliveryFailure>>,
    punch_relay_candidates: HashMap<u64, SocketAddr>,
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
            responder_session_acks: HashMap::new(),
            sessions: HashMap::new(),
            confirmed_sessions: HashSet::new(),
            pending_rekeys: HashMap::new(),
            responder_rekey_acks: HashMap::new(),
            last_rekey: HashMap::new(),
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
            auto_relay_fallbacks: HashMap::new(),
            relay_paths: HashMap::new(),
            relay_e2e_pending: HashMap::new(),
            relay_e2e_sessions: HashMap::new(),
            pending_relay_e2e_rekeys: HashMap::new(),
            responder_relay_e2e_rekey_acks: HashMap::new(),
            last_relay_e2e_rekey: HashMap::new(),
            relay_app: RelayAppManager::default(),
            relay_app_command_rx: None,
            relay_app_event_tx: None,
            relay_app_receipt_tx: None,
            relay_app_failure_tx: None,
            punch_relay_candidates: HashMap::new(),
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

    pub fn configure_relay_app_handle(&mut self, capacity: usize) -> Result<RelayAppHandle> {
        if self.relay_app_command_rx.is_some()
            || self.relay_app_event_tx.is_some()
            || self.relay_app_receipt_tx.is_some()
            || self.relay_app_failure_tx.is_some()
        {
            return Err(anyhow!("relay application handle is already configured"));
        }

        let capacity = capacity.clamp(1, MAX_RELAY_APP_HANDLE_CAPACITY);
        let (command_tx, command_rx) = mpsc::channel(capacity);
        let (event_tx, message_rx) = mpsc::channel(capacity);
        let (receipt_tx, receipt_rx) = mpsc::channel(capacity);
        let (failure_tx, failure_rx) = mpsc::channel(capacity);

        self.relay_app_command_rx = Some(command_rx);
        self.relay_app_event_tx = Some(event_tx);
        self.relay_app_receipt_tx = Some(receipt_tx);
        self.relay_app_failure_tx = Some(failure_tx);

        Ok(RelayAppHandle {
            command_tx,
            message_rx,
            receipt_rx,
            failure_rx,
        })
    }

    pub fn queue_relay_app_message(&mut self, peer_node_id: String, data: Vec<u8>) -> Result<u64> {
        if !plausible_node_id(&peer_node_id) || peer_node_id == self.node_id() {
            return Err(anyhow!("invalid relay application peer NodeID"));
        }
        self.relay_app.queue(peer_node_id, data, Instant::now())
    }

    pub fn take_relay_app_messages(&mut self) -> Vec<RelayAppMessage> {
        self.relay_app.take_completed()
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
        let mut relay_app_command_rx = self.relay_app_command_rx.take();

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
                    self.drive_relay_app().await;
                    self.flush_relay_app_events();
                    self.flush_relay_app_failures();
                }
                _ = rendezvous_ticker.tick() => {
                    self.drive_session_handshakes().await;
                    self.drive_session_rekeys().await;
                    self.drive_relay_e2e_rekeys().await;
                    self.drive_auto_rendezvous().await;
                    self.drive_auto_relay_fallbacks().await;
                    self.drive_dht_queries().await;
                    self.flush_relay_app_events();
                    self.flush_relay_app_failures();
                }
                command = async {
                    match relay_app_command_rx.as_mut() {
                        Some(receiver) => receiver.recv().await,
                        None => std::future::pending::<Option<RelayAppCommand>>().await,
                    }
                } => {
                    match command {
                        Some(command) => self.handle_relay_app_command(command),
                        None => relay_app_command_rx = None,
                    }
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

                let ack_key = (source, handshake_id);
                if let Some(cached) = self.responder_session_acks.get(&ack_key).cloned() {
                    if cached.expires_at > Instant::now()
                        && cached.peer_node_id == sender_node_id
                        && cached.initiator_public_key == ephemeral_public_key
                    {
                        self.send(
                            source,
                            MessageBody::SessionAck {
                                handshake_id,
                                ephemeral_public_key: cached.responder_public_key,
                            },
                        )
                        .await?;
                        debug!(
                            peer = %sender_node_id,
                            %source,
                            handshake_id,
                            "re-sent cached session ack"
                        );
                        return Ok(());
                    }
                }

                self.pending_sessions.remove(&source);
                let (session, responder_public_key) = respond_handshake(
                    &local_node_id,
                    &sender_node_id,
                    handshake_id,
                    &ephemeral_public_key,
                )?;
                let session_id = session.session_id().to_owned();

                if self.responder_session_acks.len() >= MAX_SESSION_RESPONDER_ACKS {
                    if let Some(oldest) = self
                        .responder_session_acks
                        .iter()
                        .min_by_key(|(_, state)| state.expires_at)
                        .map(|(key, _)| *key)
                    {
                        self.responder_session_acks.remove(&oldest);
                    }
                }

                self.responder_session_acks.insert(
                    ack_key,
                    ResponderSessionAck {
                        peer_node_id: sender_node_id.clone(),
                        initiator_public_key: ephemeral_public_key.clone(),
                        responder_public_key: responder_public_key.clone(),
                        expires_at: Instant::now() + SESSION_RESPONDER_ACK_TTL,
                    },
                );

                self.send(
                    source,
                    MessageBody::SessionAck {
                        handshake_id,
                        ephemeral_public_key: responder_public_key,
                    },
                )
                .await?;
                self.sessions.insert(source, SessionSlot::new(session));
                self.routing
                    .observe(sender_node_id.clone(), source, Instant::now());

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
                let valid_pending = self.pending_sessions.get(&source).is_some_and(|attempt| {
                    attempt.handshake_id == handshake_id && attempt.peer_node_id == sender_node_id
                });
                if !valid_pending {
                    debug!(%source, handshake_id, "ignoring unexpected session ack");
                    return Ok(());
                }

                let attempt = self
                    .pending_sessions
                    .remove(&source)
                    .expect("pending session checked above");
                let mut session = attempt
                    .pending
                    .complete(&self.node_id(), &ephemeral_public_key)?;
                let session_id = session.session_id().to_owned();
                let frame = session.encrypt(&SecurePayload::Ping { token: random() })?;
                self.sessions.insert(source, SessionSlot::new(session));
                self.confirmed_sessions.insert(source);
                self.last_rekey.insert(source, Instant::now());

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
                    Some(session) => {
                        session.decrypt(&session_id, sequence, &ciphertext, Instant::now())?
                    }
                    None => {
                        debug!(%source, "ignoring secure frame without established session");
                        return Ok(());
                    }
                };

                let newly_confirmed = self.confirmed_sessions.insert(source);
                if newly_confirmed {
                    self.last_rekey.insert(source, Instant::now());
                    self.flush_rendezvous_requests(source).await?;
                    self.flush_filter_test_request(source).await?;
                    self.flush_relay_requests(source).await?;
                    self.sync_dht_peer(source).await?;
                    info!(
                        peer = %sender_node_id,
                        %source,
                        "encrypted session confirmed by authenticated frame"
                    );
                }

                self.handle_secure_payload(source, &sender_node_id, &session_id, payload)
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
                if self.peers.contains_key(&source) && !self.confirmed_sessions.contains(&source) {
                    self.record_peer(&envelope, source);
                    self.send(source, MessageBody::Pong { token }).await?;
                }
            }
            MessageBody::Pong { token } => {
                if self.peers.contains_key(&source) && !self.confirmed_sessions.contains(&source) {
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
        incoming_session_id: &str,
        payload: SecurePayload,
    ) -> Result<()> {
        match payload {
            SecurePayload::SessionRekeyInit {
                rekey_id,
                ephemeral_public_key,
            } => {
                let local_node_id = self.node_id();
                if local_node_id.as_str() < sender_node_id {
                    debug!(
                        peer = %sender_node_id,
                        %source,
                        rekey_id,
                        "ignored rekey init from non-designated initiator"
                    );
                    return Ok(());
                }

                let ack_key = (source, rekey_id);
                if let Some(cached) = self.responder_rekey_acks.get(&ack_key).cloned() {
                    if cached.expires_at > Instant::now()
                        && cached.peer_node_id == sender_node_id
                        && cached.initiator_public_key == ephemeral_public_key
                    {
                        if let Some(message) = self.secure_message_on_session(
                            source,
                            incoming_session_id,
                            SecurePayload::SessionRekeyAck {
                                rekey_id,
                                ephemeral_public_key: cached.responder_public_key,
                            },
                        )? {
                            self.send(source, message).await?;
                        }

                        debug!(
                            peer = %sender_node_id,
                            %source,
                            rekey_id,
                            "re-sent cached session rekey ack"
                        );
                        return Ok(());
                    }
                }

                let (new_session, responder_public_key) = respond_handshake(
                    &local_node_id,
                    sender_node_id,
                    rekey_id,
                    &ephemeral_public_key,
                )?;

                if let Some(message) = self.secure_message_on_session(
                    source,
                    incoming_session_id,
                    SecurePayload::SessionRekeyAck {
                        rekey_id,
                        ephemeral_public_key: responder_public_key.clone(),
                    },
                )? {
                    self.send(source, message).await?;
                } else {
                    return Ok(());
                }

                let Some(slot) = self.sessions.get_mut(&source) else {
                    return Ok(());
                };
                slot.rotate(new_session, Instant::now(), SESSION_REKEY_GRACE)?;

                if self.responder_rekey_acks.len() >= MAX_SESSION_REKEY_ACKS {
                    if let Some(oldest) = self
                        .responder_rekey_acks
                        .iter()
                        .min_by_key(|(_, state)| state.expires_at)
                        .map(|(key, _)| *key)
                    {
                        self.responder_rekey_acks.remove(&oldest);
                    }
                }

                self.responder_rekey_acks.insert(
                    ack_key,
                    ResponderRekeyAck {
                        peer_node_id: sender_node_id.to_owned(),
                        initiator_public_key: ephemeral_public_key,
                        responder_public_key,
                        expires_at: Instant::now() + SESSION_REKEY_ACK_TTL,
                    },
                );
                self.last_rekey.insert(source, Instant::now());

                info!(
                    peer = %sender_node_id,
                    %source,
                    rekey_id,
                    session_id = %slot.current_session_id(),
                    "rotated direct KNP session keys as responder"
                );
            }
            SecurePayload::SessionRekeyAck {
                rekey_id,
                ephemeral_public_key,
            } => {
                let valid = self.pending_rekeys.get(&source).is_some_and(|attempt| {
                    attempt.rekey_id == rekey_id && attempt.peer_node_id == sender_node_id
                });
                if !valid {
                    debug!(
                        peer = %sender_node_id,
                        %source,
                        rekey_id,
                        "ignored unexpected session rekey ack"
                    );
                    return Ok(());
                }

                let attempt = self
                    .pending_rekeys
                    .remove(&source)
                    .expect("pending rekey checked above");
                let new_session = attempt
                    .pending
                    .complete(&self.node_id(), &ephemeral_public_key)?;

                let Some(slot) = self.sessions.get_mut(&source) else {
                    return Ok(());
                };
                slot.rotate(new_session, Instant::now(), SESSION_REKEY_GRACE)?;
                self.last_rekey.insert(source, Instant::now());

                info!(
                    peer = %sender_node_id,
                    %source,
                    rekey_id,
                    session_id = %slot.current_session_id(),
                    "rotated direct KNP session keys as initiator"
                );
            }
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
            SecurePayload::RelayAppFragment { fragment } => {
                self.handle_app_fragment(sender_node_id, fragment).await?;
            }
            SecurePayload::RelayAppAck { message_id } => {
                self.handle_app_ack(sender_node_id, message_id);
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

                self.auto_relay_fallbacks.remove(&peer_node_id);

                self.relay_paths.insert(
                    (source, circuit_id),
                    RelayPath {
                        peer_node_id: peer_node_id.clone(),
                        expires_at: Instant::now() + RELAY_CIRCUIT_TTL,
                        next_send_sequence: 0,
                        receive_window: SequenceWindow::default(),
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
                        if path.expires_at <= Instant::now() {
                            return Ok(());
                        }

                        path.receive_window.check_and_record(sequence)?;
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
                    self.pending_relay_e2e_rekeys.remove(&(source, circuit_id));
                    self.responder_relay_e2e_rekey_acks
                        .retain(|(endpoint, cid, _), _| *endpoint != source || *cid != circuit_id);
                    self.last_relay_e2e_rekey.remove(&(source, circuit_id));
                    self.pending_relay_requests.remove(&circuit_id);
                    self.pending_relay_accepts.remove(&(source, circuit_id));
                }
            }
            SecurePayload::RelayReject { circuit_id } => {
                let rejected = self.pending_relay_requests.remove(&circuit_id);
                self.pending_relay_accepts.remove(&(source, circuit_id));
                self.relay_paths.remove(&(source, circuit_id));
                self.relay_e2e_pending.remove(&(source, circuit_id));
                self.relay_e2e_sessions.remove(&(source, circuit_id));
                self.pending_relay_e2e_rekeys.remove(&(source, circuit_id));
                self.responder_relay_e2e_rekey_acks
                    .retain(|(endpoint, cid, _), _| *endpoint != source || *cid != circuit_id);
                self.last_relay_e2e_rekey.remove(&(source, circuit_id));

                if let Some((relay_endpoint, target_node_id)) = rejected {
                    if relay_endpoint == source {
                        if let Some(state) = self.auto_relay_fallbacks.get_mut(&target_node_id) {
                            state.next_attempt_at = Instant::now();
                        }
                    }
                }

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
                self.relay_e2e_sessions
                    .insert(key, SessionSlot::new(session));
                self.last_relay_e2e_rekey.insert(key, Instant::now());
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
                let session = pending.complete(&self.identity, encoded)?;
                let session_id = session.session_id().to_owned();
                let mut slot = SessionSlot::new(session);
                let ping_token: u64 = random();
                let ping =
                    encode_relay_payload(&mut slot, &SecurePayload::Ping { token: ping_token })?;
                self.relay_e2e_sessions.insert(key, slot);
                self.last_relay_e2e_rekey.insert(key, Instant::now());
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
                let (incoming_session_id, payload) = {
                    let Some(session) = self.relay_e2e_sessions.get_mut(&key) else {
                        return Ok(());
                    };
                    decode_relay_payload(session, encoded, Instant::now())?
                };

                match payload {
                    SecurePayload::SessionRekeyInit {
                        rekey_id,
                        ephemeral_public_key,
                    } => {
                        let local_node_id = self.node_id();
                        if local_node_id.as_str() < peer_node_id {
                            debug!(
                                %relay_endpoint,
                                peer = %peer_node_id,
                                circuit_id,
                                rekey_id,
                                "ignored relay E2E rekey init from non-designated initiator"
                            );
                            return Ok(());
                        }

                        let ack_key = (relay_endpoint, circuit_id, rekey_id);
                        if let Some(cached) =
                            self.responder_relay_e2e_rekey_acks.get(&ack_key).cloned()
                        {
                            if cached.expires_at > Instant::now()
                                && cached.peer_node_id == peer_node_id
                                && cached.initiator_public_key == ephemeral_public_key
                            {
                                let ack = {
                                    let Some(slot) = self.relay_e2e_sessions.get_mut(&key) else {
                                        return Ok(());
                                    };
                                    encode_relay_payload_on_session(
                                        slot,
                                        &incoming_session_id,
                                        &SecurePayload::SessionRekeyAck {
                                            rekey_id,
                                            ephemeral_public_key: cached.responder_public_key,
                                        },
                                        Instant::now(),
                                    )?
                                };
                                self.send_relay_inner(relay_endpoint, circuit_id, ack)
                                    .await?;
                                return Ok(());
                            }
                        }

                        let (new_session, responder_public_key) = respond_handshake(
                            &local_node_id,
                            peer_node_id,
                            rekey_id,
                            &ephemeral_public_key,
                        )?;

                        let ack = {
                            let Some(slot) = self.relay_e2e_sessions.get_mut(&key) else {
                                return Ok(());
                            };
                            encode_relay_payload_on_session(
                                slot,
                                &incoming_session_id,
                                &SecurePayload::SessionRekeyAck {
                                    rekey_id,
                                    ephemeral_public_key: responder_public_key.clone(),
                                },
                                Instant::now(),
                            )?
                        };
                        self.send_relay_inner(relay_endpoint, circuit_id, ack)
                            .await?;

                        let Some(slot) = self.relay_e2e_sessions.get_mut(&key) else {
                            return Ok(());
                        };
                        slot.rotate(new_session, Instant::now(), RELAY_E2E_REKEY_GRACE)?;

                        if self.responder_relay_e2e_rekey_acks.len() >= MAX_RELAY_E2E_REKEY_ACKS {
                            if let Some(oldest) = self
                                .responder_relay_e2e_rekey_acks
                                .iter()
                                .min_by_key(|(_, state)| state.expires_at)
                                .map(|(key, _)| *key)
                            {
                                self.responder_relay_e2e_rekey_acks.remove(&oldest);
                            }
                        }

                        self.responder_relay_e2e_rekey_acks.insert(
                            ack_key,
                            ResponderRelayE2eRekeyAck {
                                peer_node_id: peer_node_id.to_owned(),
                                initiator_public_key: ephemeral_public_key,
                                responder_public_key,
                                expires_at: Instant::now() + RELAY_E2E_REKEY_ACK_TTL,
                            },
                        );
                        self.last_relay_e2e_rekey.insert(key, Instant::now());

                        info!(
                            %relay_endpoint,
                            peer = %peer_node_id,
                            circuit_id,
                            rekey_id,
                            session_id = %slot.current_session_id(),
                            "rotated relay E2E session keys as responder"
                        );
                    }
                    SecurePayload::SessionRekeyAck {
                        rekey_id,
                        ephemeral_public_key,
                    } => {
                        let valid =
                            self.pending_relay_e2e_rekeys
                                .get(&key)
                                .is_some_and(|attempt| {
                                    attempt.rekey_id == rekey_id
                                        && attempt.peer_node_id == peer_node_id
                                });
                        if !valid {
                            return Ok(());
                        }

                        let attempt = self
                            .pending_relay_e2e_rekeys
                            .remove(&key)
                            .expect("pending relay E2E rekey checked above");
                        let new_session = attempt
                            .pending
                            .complete(&self.node_id(), &ephemeral_public_key)?;

                        let Some(slot) = self.relay_e2e_sessions.get_mut(&key) else {
                            return Ok(());
                        };
                        slot.rotate(new_session, Instant::now(), RELAY_E2E_REKEY_GRACE)?;
                        self.last_relay_e2e_rekey.insert(key, Instant::now());

                        info!(
                            %relay_endpoint,
                            peer = %peer_node_id,
                            circuit_id,
                            rekey_id,
                            session_id = %slot.current_session_id(),
                            "rotated relay E2E session keys as initiator"
                        );
                    }
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
                    SecurePayload::RelayAppFragment { fragment } => {
                        self.handle_app_fragment(peer_node_id, fragment).await?;
                    }
                    SecurePayload::RelayAppAck { message_id } => {
                        self.handle_app_ack(peer_node_id, message_id);
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

    async fn handle_app_fragment(
        &mut self,
        peer_node_id: &str,
        fragment: crate::relay_app::RelayAppFragment,
    ) -> Result<()> {
        let message_id = fragment.message_id;
        let status = self
            .relay_app
            .accept_fragment(peer_node_id, fragment, Instant::now())?;

        if matches!(
            status,
            RelayAppReceiveStatus::Completed | RelayAppReceiveStatus::DuplicateCompleted
        ) {
            self.send_app_secure_payload(peer_node_id, SecurePayload::RelayAppAck { message_id })
                .await?;
        }

        if status == RelayAppReceiveStatus::Completed {
            self.flush_relay_app_events();
            self.flush_relay_app_failures();
        }

        Ok(())
    }

    fn handle_app_ack(&mut self, peer_node_id: &str, message_id: u64) {
        if self.relay_app.acknowledge(peer_node_id, message_id) {
            if let Some(sender) = self.relay_app_receipt_tx.as_ref() {
                let receipt = RelayAppDeliveryReceipt {
                    peer_node_id: peer_node_id.to_owned(),
                    message_id,
                };
                if let Err(error) = sender.try_send(receipt) {
                    debug!(
                        peer = %peer_node_id,
                        message_id,
                        %error,
                        "delivery receipt channel unavailable"
                    );
                }
            }

            debug!(
                peer = %peer_node_id,
                message_id,
                "application message acknowledged"
            );
        }
    }

    async fn send_app_secure_payload(
        &mut self,
        peer_node_id: &str,
        payload: SecurePayload,
    ) -> Result<bool> {
        let direct = self.direct_app_endpoint_for_peer(peer_node_id);
        let relay = self.relay_e2e_path_for_peer(peer_node_id);

        match preferred_app_transport(direct, relay) {
            Some(AppTransport::Direct(endpoint)) => {
                self.send_secure_payload(endpoint, payload).await?;
                Ok(true)
            }
            Some(AppTransport::Relay {
                relay_endpoint,
                circuit_id,
            }) => {
                let encoded = {
                    let Some(session) = self
                        .relay_e2e_sessions
                        .get_mut(&(relay_endpoint, circuit_id))
                    else {
                        return Ok(false);
                    };
                    encode_relay_payload(session, &payload)?
                };
                self.send_relay_inner(relay_endpoint, circuit_id, encoded)
                    .await?;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    fn direct_app_endpoint_for_peer(&self, peer_node_id: &str) -> Option<SocketAddr> {
        let endpoint = self.peer_endpoint_by_node_id(peer_node_id)?;
        self.confirmed_sessions
            .contains(&endpoint)
            .then_some(endpoint)
    }

    fn handle_relay_app_command(&mut self, command: RelayAppCommand) {
        match command {
            RelayAppCommand::Send {
                peer_node_id,
                data,
                response,
            } => {
                let needs_path = self.direct_app_endpoint_for_peer(&peer_node_id).is_none()
                    && self.relay_e2e_path_for_peer(&peer_node_id).is_none();
                let result = self
                    .queue_relay_app_message(peer_node_id.clone(), data)
                    .map_err(|error| error.to_string());

                if result.is_ok() && needs_path {
                    self.queue_auto_rendezvous(peer_node_id);
                }

                let _ = response.send(result);
            }
        }
    }

    fn flush_relay_app_failures(&mut self) {
        while let Some(failure) = self.relay_app.peek_failure() {
            let result = match self.relay_app_failure_tx.as_ref() {
                Some(sender) => sender.try_send(failure),
                None => break,
            };

            match result {
                Ok(()) => {
                    self.relay_app.pop_failure();
                }
                Err(mpsc::error::TrySendError::Full(_)) => break,
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    self.relay_app_failure_tx = None;
                    break;
                }
            }
        }
    }

    fn flush_relay_app_events(&mut self) {
        while let Some(message) = self.relay_app.peek_completed() {
            let result = match self.relay_app_event_tx.as_ref() {
                Some(sender) => sender.try_send(message),
                None => break,
            };

            match result {
                Ok(()) => {
                    self.relay_app.pop_completed();
                }
                Err(mpsc::error::TrySendError::Full(_)) => break,
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    self.relay_app_event_tx = None;
                    break;
                }
            }
        }
    }

    async fn drive_relay_app(&mut self) {
        let now = Instant::now();
        let restarted = self.relay_app.prepare_retransmissions(now);
        if restarted > 0 {
            debug!(restarted, "processed RelayApp ACK-timeout retransmissions");
        }

        let (expired_inbound, expired_outbound) = self.relay_app.expire(now);
        self.flush_relay_app_failures();
        if expired_inbound > 0 || expired_outbound > 0 {
            debug!(
                expired_inbound,
                expired_outbound, "expired stale relay application queue state"
            );
        }

        let mut ready_peers: HashSet<String> = self
            .relay_e2e_sessions
            .keys()
            .filter_map(|key| {
                let path = self.relay_paths.get(key)?;
                if path.expires_at <= now {
                    return None;
                }
                Some(path.peer_node_id.clone())
            })
            .collect();

        ready_peers.extend(
            self.confirmed_sessions
                .iter()
                .filter_map(|endpoint| self.peers.get(endpoint).map(|peer| peer.node_id.clone())),
        );

        for _ in 0..RELAY_APP_BURST_PER_TICK {
            let Some(outbound) = self.relay_app.peek_next(&ready_peers) else {
                break;
            };

            let payload = SecurePayload::RelayAppFragment {
                fragment: outbound.fragment.clone(),
            };

            match self
                .send_app_secure_payload(&outbound.peer_node_id, payload)
                .await
            {
                Ok(true) => {}
                Ok(false) => break,
                Err(error) => {
                    debug!(
                        peer = %outbound.peer_node_id,
                        %error,
                        "application fragment send failed on selected path"
                    );
                    break;
                }
            }

            if let Err(error) = self.relay_app.mark_fragment_sent(
                outbound.fragment.message_id,
                outbound.fragment.fragment_index,
                now,
            ) {
                debug!(%error, "relay application queue state update failed");
                break;
            }
        }
    }

    fn relay_e2e_path_for_peer(&self, peer_node_id: &str) -> Option<(SocketAddr, u64)> {
        let now = Instant::now();
        self.relay_e2e_sessions.keys().find_map(|key| {
            let path = self.relay_paths.get(key)?;
            (path.peer_node_id == peer_node_id && path.expires_at > now).then_some(*key)
        })
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
                let mut relay_scheduled = false;

                if local_node_id.as_str() < target_node_id.as_str()
                    && self.peer_endpoint_by_node_id(&target_node_id).is_none()
                {
                    self.schedule_auto_relay_fallback(
                        target_node_id.clone(),
                        relay_candidate,
                        Instant::now(),
                    );
                    relay_scheduled = true;
                }

                if let Some(state) = self.auto_rendezvous.get_mut(&target_node_id) {
                    if relay_scheduled {
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
                    relay_scheduled,
                    "UDP punch burst expired without direct-path confirmation"
                );
            }
        }
    }

    fn schedule_auto_relay_fallback(
        &mut self,
        target_node_id: String,
        preferred: Option<SocketAddr>,
        now: Instant,
    ) {
        self.auto_relay_fallbacks
            .entry(target_node_id)
            .and_modify(|state| {
                if state.preferred.is_none() {
                    state.preferred = preferred;
                }
                state.next_attempt_at = now;
                state.expires_at = now + AUTO_RELAY_STATE_TTL;
            })
            .or_insert_with(|| AutoRelayFallback {
                preferred,
                tried: HashSet::new(),
                next_attempt_at: now,
                expires_at: now + AUTO_RELAY_STATE_TTL,
            });
    }

    async fn drive_auto_relay_fallbacks(&mut self) {
        let now = Instant::now();
        let targets: Vec<String> = self.auto_relay_fallbacks.keys().cloned().collect();

        for target_node_id in targets {
            if self.peer_endpoint_by_node_id(&target_node_id).is_some()
                || self
                    .relay_paths
                    .values()
                    .any(|path| path.peer_node_id == target_node_id && path.expires_at > now)
            {
                self.auto_relay_fallbacks.remove(&target_node_id);
                continue;
            }

            if self
                .pending_relay_requests
                .values()
                .any(|(_, target)| target == &target_node_id)
            {
                continue;
            }

            let candidate = {
                let Some(state) = self.auto_relay_fallbacks.get_mut(&target_node_id) else {
                    continue;
                };

                if state.expires_at <= now || state.tried.len() >= AUTO_RELAY_MAX_CANDIDATES {
                    None
                } else if state.next_attempt_at > now {
                    continue;
                } else if let Some(preferred) = state.preferred {
                    if !state.tried.contains(&preferred) && self.sessions.contains_key(&preferred) {
                        Some(preferred)
                    } else {
                        let mut candidates: Vec<(SocketAddr, Instant)> = self
                            .sessions
                            .keys()
                            .filter_map(|endpoint| {
                                if state.tried.contains(endpoint) {
                                    return None;
                                }
                                let peer = self.peers.get(endpoint)?;
                                if peer.node_id == target_node_id {
                                    return None;
                                }
                                Some((*endpoint, peer.first_seen))
                            })
                            .collect();
                        candidates.sort_by_key(|(endpoint, first_seen)| {
                            (
                                if endpoint.is_ipv6() { 0_u8 } else { 1_u8 },
                                *first_seen,
                                *endpoint,
                            )
                        });
                        candidates.first().map(|(endpoint, _)| *endpoint)
                    }
                } else {
                    let mut candidates: Vec<(SocketAddr, Instant)> = self
                        .sessions
                        .keys()
                        .filter_map(|endpoint| {
                            if state.tried.contains(endpoint) {
                                return None;
                            }
                            let peer = self.peers.get(endpoint)?;
                            if peer.node_id == target_node_id {
                                return None;
                            }
                            Some((*endpoint, peer.first_seen))
                        })
                        .collect();
                    candidates.sort_by_key(|(endpoint, first_seen)| {
                        (
                            if endpoint.is_ipv6() { 0_u8 } else { 1_u8 },
                            *first_seen,
                            *endpoint,
                        )
                    });
                    candidates.first().map(|(endpoint, _)| *endpoint)
                }
            };

            let Some(candidate) = candidate else {
                let exhausted =
                    self.auto_relay_fallbacks
                        .get(&target_node_id)
                        .is_some_and(|state| {
                            state.expires_at <= now
                                || state.tried.len() >= AUTO_RELAY_MAX_CANDIDATES
                        });
                if exhausted {
                    self.auto_relay_fallbacks.remove(&target_node_id);
                    debug!(
                        target = %target_node_id,
                        "automatic relay candidates exhausted"
                    );
                }
                continue;
            };

            if let Some(state) = self.auto_relay_fallbacks.get_mut(&target_node_id) {
                state.tried.insert(candidate);
                state.next_attempt_at = now + AUTO_RELAY_RETRY_DELAY;
            }

            match self.start_relay_request(candidate, &target_node_id).await {
                Ok(Some(circuit_id)) => {
                    info!(
                        %candidate,
                        target = %target_node_id,
                        circuit_id,
                        "automatic relay candidate selected"
                    );
                }
                Ok(None) => {
                    if let Some(state) = self.auto_relay_fallbacks.get_mut(&target_node_id) {
                        state.next_attempt_at = now;
                    }
                }
                Err(error) => {
                    debug!(
                        %candidate,
                        target = %target_node_id,
                        %error,
                        "automatic relay candidate failed"
                    );
                    if let Some(state) = self.auto_relay_fallbacks.get_mut(&target_node_id) {
                        state.next_attempt_at = now;
                    }
                }
            }
        }
    }

    async fn drive_relay_e2e_rekeys(&mut self) {
        let now = Instant::now();
        self.responder_relay_e2e_rekey_acks
            .retain(|_, state| state.expires_at > now);
        for session in self.relay_e2e_sessions.values_mut() {
            session.expire_previous(now);
        }

        let due: Vec<(SocketAddr, u64)> = self
            .pending_relay_e2e_rekeys
            .iter()
            .filter(|(_, attempt)| attempt.next_retry_at <= now)
            .map(|(key, _)| *key)
            .collect();

        let mut retries = Vec::new();
        for key in due {
            let Some(attempt) = self.pending_relay_e2e_rekeys.get_mut(&key) else {
                continue;
            };

            if attempt.attempts >= RELAY_E2E_REKEY_MAX_ATTEMPTS {
                let peer_node_id = attempt.peer_node_id.clone();
                self.pending_relay_e2e_rekeys.remove(&key);
                self.last_relay_e2e_rekey.insert(key, now);
                debug!(
                    relay = %key.0,
                    circuit_id = key.1,
                    peer = %peer_node_id,
                    "relay E2E rekey retries exhausted"
                );
                continue;
            }

            attempt.attempts += 1;
            attempt.next_retry_at = now + RELAY_E2E_REKEY_RETRY_DELAY;
            retries.push((
                key,
                attempt.rekey_id,
                attempt.ephemeral_public_key.clone(),
                attempt.peer_node_id.clone(),
                attempt.attempts,
            ));
        }

        for (key, rekey_id, ephemeral_public_key, peer_node_id, attempt) in retries {
            let encoded = {
                let Some(slot) = self.relay_e2e_sessions.get_mut(&key) else {
                    continue;
                };
                match encode_relay_payload(
                    slot,
                    &SecurePayload::SessionRekeyInit {
                        rekey_id,
                        ephemeral_public_key,
                    },
                ) {
                    Ok(encoded) => encoded,
                    Err(error) => {
                        debug!(
                            relay = %key.0,
                            circuit_id = key.1,
                            peer = %peer_node_id,
                            rekey_id,
                            attempt,
                            %error,
                            "relay E2E rekey encode failed"
                        );
                        continue;
                    }
                }
            };

            if let Err(error) = self.send_relay_inner(key.0, key.1, encoded).await {
                debug!(
                    relay = %key.0,
                    circuit_id = key.1,
                    peer = %peer_node_id,
                    rekey_id,
                    attempt,
                    %error,
                    "relay E2E rekey retransmission failed"
                );
            }
        }

        let local_node_id = self.node_id();
        let candidates: Vec<((SocketAddr, u64), String)> = self
            .relay_e2e_sessions
            .keys()
            .filter_map(|key| {
                if self.pending_relay_e2e_rekeys.contains_key(key) {
                    return None;
                }

                let last = self.last_relay_e2e_rekey.get(key)?;
                if now.duration_since(*last) < RELAY_E2E_REKEY_INTERVAL {
                    return None;
                }

                let path = self.relay_paths.get(key)?;
                if local_node_id.as_str() >= path.peer_node_id.as_str() {
                    return None;
                }

                Some((*key, path.peer_node_id.clone()))
            })
            .collect();

        for (key, peer_node_id) in candidates {
            let pending = PendingHandshake::new(peer_node_id.clone());
            let rekey_id = pending.handshake_id();
            let ephemeral_public_key = pending.public_key_hex();

            self.pending_relay_e2e_rekeys.insert(
                key,
                PendingRelayE2eRekey {
                    pending,
                    rekey_id,
                    peer_node_id: peer_node_id.clone(),
                    ephemeral_public_key: ephemeral_public_key.clone(),
                    attempts: 1,
                    next_retry_at: now + RELAY_E2E_REKEY_RETRY_DELAY,
                },
            );

            let encoded = {
                let Some(slot) = self.relay_e2e_sessions.get_mut(&key) else {
                    self.pending_relay_e2e_rekeys.remove(&key);
                    continue;
                };
                encode_relay_payload(
                    slot,
                    &SecurePayload::SessionRekeyInit {
                        rekey_id,
                        ephemeral_public_key,
                    },
                )
            };

            match encoded {
                Ok(encoded) => {
                    if let Err(error) = self.send_relay_inner(key.0, key.1, encoded).await {
                        debug!(
                            relay = %key.0,
                            circuit_id = key.1,
                            peer = %peer_node_id,
                            rekey_id,
                            %error,
                            "initial relay E2E rekey send failed"
                        );
                    }
                }
                Err(error) => {
                    debug!(
                        relay = %key.0,
                        circuit_id = key.1,
                        peer = %peer_node_id,
                        rekey_id,
                        %error,
                        "initial relay E2E rekey encode failed"
                    );
                }
            }
        }
    }

    async fn drive_session_rekeys(&mut self) {
        let now = Instant::now();
        self.responder_rekey_acks
            .retain(|_, state| state.expires_at > now);

        let due: Vec<SocketAddr> = self
            .pending_rekeys
            .iter()
            .filter(|(_, attempt)| attempt.next_retry_at <= now)
            .map(|(endpoint, _)| *endpoint)
            .collect();

        let mut retries = Vec::new();
        for endpoint in due {
            let Some(attempt) = self.pending_rekeys.get_mut(&endpoint) else {
                continue;
            };

            if attempt.attempts >= SESSION_REKEY_MAX_ATTEMPTS {
                let peer_node_id = attempt.peer_node_id.clone();
                self.pending_rekeys.remove(&endpoint);
                self.last_rekey.insert(endpoint, now);
                debug!(
                    %endpoint,
                    peer = %peer_node_id,
                    "session rekey retries exhausted; keeping previous keys"
                );
                continue;
            }

            attempt.attempts += 1;
            attempt.next_retry_at = now + SESSION_REKEY_RETRY_DELAY;
            retries.push((
                endpoint,
                attempt.rekey_id,
                attempt.ephemeral_public_key.clone(),
                attempt.peer_node_id.clone(),
                attempt.attempts,
            ));
        }

        for (endpoint, rekey_id, ephemeral_public_key, peer_node_id, attempt) in retries {
            if let Err(error) = self
                .send_secure_payload(
                    endpoint,
                    SecurePayload::SessionRekeyInit {
                        rekey_id,
                        ephemeral_public_key,
                    },
                )
                .await
            {
                debug!(
                    %endpoint,
                    peer = %peer_node_id,
                    rekey_id,
                    attempt,
                    %error,
                    "session rekey retransmission failed"
                );
            } else {
                debug!(
                    %endpoint,
                    peer = %peer_node_id,
                    rekey_id,
                    attempt,
                    "retransmitted session rekey init"
                );
            }
        }

        let local_node_id = self.node_id();
        let candidates: Vec<(SocketAddr, String)> = self
            .confirmed_sessions
            .iter()
            .filter_map(|endpoint| {
                if self.pending_rekeys.contains_key(endpoint) {
                    return None;
                }

                let last = self.last_rekey.get(endpoint)?;
                if now.duration_since(*last) < SESSION_REKEY_INTERVAL {
                    return None;
                }

                let peer = self.peers.get(endpoint)?;
                if local_node_id.as_str() >= peer.node_id.as_str() {
                    return None;
                }

                Some((*endpoint, peer.node_id.clone()))
            })
            .collect();

        for (endpoint, peer_node_id) in candidates {
            let pending = PendingHandshake::new(peer_node_id.clone());
            let rekey_id = pending.handshake_id();
            let ephemeral_public_key = pending.public_key_hex();

            self.pending_rekeys.insert(
                endpoint,
                PendingRekeyAttempt {
                    pending,
                    rekey_id,
                    peer_node_id: peer_node_id.clone(),
                    ephemeral_public_key: ephemeral_public_key.clone(),
                    attempts: 1,
                    next_retry_at: now + SESSION_REKEY_RETRY_DELAY,
                },
            );

            if let Err(error) = self
                .send_secure_payload(
                    endpoint,
                    SecurePayload::SessionRekeyInit {
                        rekey_id,
                        ephemeral_public_key,
                    },
                )
                .await
            {
                debug!(
                    %endpoint,
                    peer = %peer_node_id,
                    rekey_id,
                    %error,
                    "initial session rekey send failed"
                );
            } else {
                debug!(
                    %endpoint,
                    peer = %peer_node_id,
                    rekey_id,
                    "started direct session key rotation"
                );
            }
        }
    }

    async fn drive_session_handshakes(&mut self) {
        let now = Instant::now();
        self.responder_session_acks
            .retain(|_, state| state.expires_at > now);

        let due: Vec<SocketAddr> = self
            .pending_sessions
            .iter()
            .filter(|(_, attempt)| attempt.next_retry_at <= now)
            .map(|(endpoint, _)| *endpoint)
            .collect();

        for endpoint in due {
            let Some(attempt) = self.pending_sessions.get_mut(&endpoint) else {
                continue;
            };

            if attempt.attempts >= SESSION_HANDSHAKE_MAX_ATTEMPTS {
                let peer = attempt.peer_node_id.clone();
                self.pending_sessions.remove(&endpoint);
                debug!(
                    %endpoint,
                    peer = %peer,
                    "session handshake retries exhausted"
                );
                continue;
            }

            let handshake_id = attempt.handshake_id;
            let ephemeral_public_key = attempt.ephemeral_public_key.clone();
            let peer_node_id = attempt.peer_node_id.clone();
            attempt.attempts += 1;
            attempt.next_retry_at = now + SESSION_HANDSHAKE_RETRY_DELAY;
            let attempt_number = attempt.attempts;

            if let Err(error) = self
                .send(
                    endpoint,
                    MessageBody::SessionInit {
                        handshake_id,
                        ephemeral_public_key,
                    },
                )
                .await
            {
                debug!(
                    %endpoint,
                    peer = %peer_node_id,
                    attempt = attempt_number,
                    %error,
                    "session handshake retransmission failed"
                );
            } else {
                debug!(
                    %endpoint,
                    peer = %peer_node_id,
                    attempt = attempt_number,
                    "retransmitted session init"
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

        self.pending_sessions.insert(
            target,
            PendingSessionAttempt {
                pending,
                handshake_id,
                peer_node_id: peer_node_id.to_owned(),
                ephemeral_public_key: ephemeral_public_key.clone(),
                attempts: 1,
                next_retry_at: Instant::now() + SESSION_HANDSHAKE_RETRY_DELAY,
            },
        );

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

    fn secure_message_on_session(
        &mut self,
        target: SocketAddr,
        session_id: &str,
        payload: SecurePayload,
    ) -> Result<Option<MessageBody>> {
        let Some(session) = self.sessions.get_mut(&target) else {
            return Ok(None);
        };
        let frame = session.encrypt_with_session_id(session_id, &payload, Instant::now())?;
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
            self.responder_session_acks
                .retain(|(endpoint, _), _| *endpoint != previous_endpoint);
            self.sessions.remove(&previous_endpoint);
            self.confirmed_sessions.remove(&previous_endpoint);
            self.pending_rekeys.remove(&previous_endpoint);
            self.responder_rekey_acks
                .retain(|(endpoint, _), _| *endpoint != previous_endpoint);
            self.last_rekey.remove(&previous_endpoint);
            self.routing.remove_endpoint(previous_endpoint);
        }

        if let Some(existing) = self.peers.get(&source) {
            if existing.node_id != envelope.sender_node_id {
                self.sessions.remove(&source);
                self.confirmed_sessions.remove(&source);
                self.pending_sessions.remove(&source);
                self.pending_rekeys.remove(&source);
                self.responder_rekey_acks
                    .retain(|(endpoint, _), _| *endpoint != source);
                self.last_rekey.remove(&source);
                self.responder_session_acks
                    .retain(|(endpoint, _), _| *endpoint != source);
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
        self.auto_relay_fallbacks.remove(&envelope.sender_node_id);

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
            self.responder_session_acks
                .retain(|(ack_endpoint, _), _| *ack_endpoint != endpoint);
            self.sessions.remove(&endpoint);
            self.confirmed_sessions.remove(&endpoint);
            self.pending_rekeys.remove(&endpoint);
            self.responder_rekey_acks
                .retain(|(ack_endpoint, _), _| *ack_endpoint != endpoint);
            self.last_rekey.remove(&endpoint);
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
            let body = if self.confirmed_sessions.contains(&endpoint) {
                self.secure_message(endpoint, SecurePayload::Ping { token })
                    .ok()
                    .flatten()
                    .unwrap_or(MessageBody::Ping { token })
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
        self.confirmed_sessions
            .retain(|endpoint| self.sessions.contains_key(endpoint));
        for session in self.sessions.values_mut() {
            session.expire_previous(Instant::now());
        }
        self.pending_rekeys
            .retain(|endpoint, _| self.sessions.contains_key(endpoint));
        self.responder_rekey_acks.retain(|(endpoint, _), state| {
            self.sessions.contains_key(endpoint) && state.expires_at > Instant::now()
        });
        self.last_rekey
            .retain(|endpoint, _| self.sessions.contains_key(endpoint));
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
        self.pending_relay_e2e_rekeys
            .retain(|key, _| self.relay_paths.contains_key(key));
        self.responder_relay_e2e_rekey_acks
            .retain(|(endpoint, circuit_id, _), state| {
                self.relay_paths.contains_key(&(*endpoint, *circuit_id))
                    && state.expires_at > Instant::now()
            });
        self.last_relay_e2e_rekey
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
        "session-handshake-retry".to_owned(),
        "session-x25519-rekey".to_owned(),
        "session-rekey-grace".to_owned(),
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
        "relay-e2e-rekey".to_owned(),
        "relay-e2e-rekey-grace".to_owned(),
        "relay-app-fragmentation".to_owned(),
        "relay-app-backpressure".to_owned(),
        "direct-relay-app-migration".to_owned(),
        "punch-to-relay-fallback".to_owned(),
        "multi-candidate-relay-fallback".to_owned(),
        "consent-filter-probe".to_owned(),
        "udp-punch-probe".to_owned(),
        "udp-punch-burst-v1".to_owned(),
        "secure-ping-pong".to_owned(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn application_transport_prefers_direct_and_falls_back_to_relay() {
        let direct: SocketAddr = "203.0.113.1:47000".parse().unwrap();
        let relay: SocketAddr = "198.51.100.2:47000".parse().unwrap();

        assert_eq!(
            preferred_app_transport(Some(direct), Some((relay, 7))),
            Some(AppTransport::Direct(direct))
        );
        assert_eq!(
            preferred_app_transport(None, Some((relay, 7))),
            Some(AppTransport::Relay {
                relay_endpoint: relay,
                circuit_id: 7,
            })
        );
        assert_eq!(preferred_app_transport(None, None), None);
    }
}
