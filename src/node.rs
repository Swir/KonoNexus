use crate::candidate_group::{
    CandidateAction, CandidateGroup, CANDIDATE_GROUP_TTL, MAX_ACTIVE_CANDIDATE_GROUPS,
};
use crate::dht::{
    dht_endpoint_publishable, dht_network_group, endpoint_publishable, node_id_closer_to_target,
    prioritize_network_group_diversity, DhtNetworkGroup, DhtTable, EndpointAttestation,
    EndpointAttestationTable, PeerRecord, RoutingTable, DHT_ATTESTATION_RESPONSE_LIMIT,
    DHT_BUCKET_SIZE, DHT_MAX_HOPS, DHT_QUERY_FANOUT, DHT_QUERY_RETRY_DELAY, DHT_QUERY_TIMEOUT,
    DHT_REPLICATION_FANOUT, DHT_REPLICATION_MAX_HOPS, DHT_RESPONSE_LIMIT, DHT_SYNC_REPLICA_LIMIT,
    MIN_ENDPOINT_ATTESTATION_OBSERVERS,
};
use crate::identity::NodeIdentity;
use crate::konomind::PathKind;
use crate::nat::{
    FilterMatrixSnapshot, FilterProbeClass, FilterProbeOutcome, FilteringMatrixAuthorization,
    NatFilteringEvidence, NatMappingBehavior, NatProfile, FILTERING_MATRIX_AUTH_TTL_MS,
    FILTERING_MATRIX_CLOCK_SKEW_MS,
};
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
use crate::rendezvous::{admit_auto_rendezvous_target, AutoRendezvousState, CoordinatorCandidate};
use crate::route::{
    ControlRoute, RelayRouteCandidate, RouteController, MAX_RELAY_ROUTE_CANDIDATES,
};
use crate::routing_cache::{
    load_routing_bucket_snapshot, new_bucket_cache_entry, save_routing_bucket_snapshot,
    MAX_ROUTING_BOOTSTRAP_HINTS,
};
use crate::security::{CookieGuard, ReplayGuard, SequenceWindow};
use crate::session::{
    respond_handshake, FilteringMatrixFailure, PendingHandshake, SecurePayload, SessionSlot,
};
use anyhow::{anyhow, bail, Context, Result};
use rand::random;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tokio::time;
use tracing::{debug, info, warn};

const MAX_ACTIVE_PEERS: usize = 2_048;
const MAX_RELAY_APP_ROUTE_ATTEMPTS: usize = crate::relay_app::MAX_RELAY_APP_OUTBOUND_MESSAGES;
const MAX_PENDING_PUNCHES: usize = 128;
const MAX_PENDING_FILTER_PROBES: usize = 64;
const MAX_PENDING_FILTER_TRIALS: usize = 32;
const RENDEZVOUS_REQUEST_COOLDOWN: Duration = Duration::from_secs(1);
const FILTER_TEST_REQUEST_COOLDOWN: Duration = Duration::from_secs(10);
const FILTER_PROBE_STATE_TTL: Duration = Duration::from_secs(10);
const FILTER_AUTHORIZATION_REPLAY_RETENTION: Duration =
    Duration::from_millis(FILTERING_MATRIX_AUTH_TTL_MS + FILTERING_MATRIX_CLOCK_SKEW_MS);
const FILTER_MATRIX_TRIAL_TTL: Duration = Duration::from_secs(12);
const FILTER_PROBE_RATE_WINDOW: Duration = Duration::from_secs(60);
const FILTER_PROBE_RATE_RETENTION: Duration = Duration::from_secs(10 * 60);
const FILTER_PROBE_COORDINATOR_LIMIT: u16 = 12;
const FILTER_PROBE_TARGET_GROUP_LIMIT: u16 = 32;
const FILTER_PROBE_GLOBAL_LIMIT: u16 = 128;
const FILTER_PROBE_AUTH_ATTEMPT_LIMIT: u16 = 32;
const FILTER_PROBE_AUTH_ATTEMPT_GLOBAL_LIMIT: u16 = 256;
const MAX_FILTER_PROBE_RATE_STATES: usize = 1_024;
const MAX_USED_FILTER_AUTHORIZATIONS: usize = 1_024;
const FILTER_CONTACT_HISTORY_TTL: Duration = Duration::from_secs(10 * 60);
const MAX_FILTER_CONTACT_HISTORY: usize = 4_096;
const DHT_FORWARD_COOLDOWN: Duration = Duration::from_millis(250);
const MAX_SEEN_DHT_QUERIES: usize = 2_048;
const DHT_QUERY_GUARD_RETENTION: Duration = Duration::from_secs(10 * 60);
const MAX_DHT_QUERY_PEER_BUCKETS: usize = 4_096;
const MAX_DHT_QUERY_PREFIX_BUCKETS: usize = 1_024;
const DHT_QUERY_PEER_BURST: u16 = 8;
const DHT_QUERY_PREFIX_BURST: u16 = 32;
const DHT_QUERY_GLOBAL_BURST: u16 = 128;
const DHT_QUERY_PEER_REFILL: Duration = Duration::from_secs(2);
const DHT_QUERY_PREFIX_REFILL: Duration = Duration::from_millis(500);
const DHT_QUERY_GLOBAL_REFILL: Duration = Duration::from_millis(125);
// One first-hop peer can return 1 + 2 + 4 + 8 bounded tree responses at hop depth 3.
const MAX_DHT_RESPONSES_PER_PEER_QUERY: u8 = 15;
const DHT_RESPONSE_CACHE_LIMIT: usize = 2;
const ENDPOINT_ATTESTATION_REFRESH_INTERVAL: Duration = Duration::from_secs(2 * 60);
const MAX_ENDPOINT_ATTESTATION_REFRESHES_PER_TICK: usize = 8;
const DHT_REPLICATION_RATE_WINDOW: Duration = Duration::from_secs(60);
const DHT_REPLICATION_RATE_RETENTION: Duration = Duration::from_secs(10 * 60);
const MAX_DHT_RECORDS_PER_PEER_WINDOW: u16 = 32;
const MAX_DHT_RECORDS_PER_PREFIX_WINDOW: u16 = 96;
// Even 33 skew-overlapping one-minute bursts stay below half the rollback watermark table.
const MAX_DHT_RECORDS_GLOBAL_WINDOW: u16 = 120;
const MAX_DHT_REPLICATION_RATE_WINDOWS: usize = 4_096;
const OWN_DHT_RECORD_REFRESH_INTERVAL: Duration = Duration::from_secs(4 * 60);
const MAX_DHT_REPLICATION_HISTORY: usize = 8_192;
const MAX_PENDING_DHT_REPLICATIONS: usize = 256;
const DHT_OWNER_REPLICATION_RESERVE: usize = DHT_BUCKET_SIZE;
const DHT_REPLICATION_BURST_PER_TICK: usize = 4;
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

#[cfg(test)]
#[derive(Default)]
struct RuntimeMeshCounters {
    replicated_stores: AtomicUsize,
    attestations: AtomicUsize,
    finds: std::sync::Mutex<HashSet<(String, String, u64)>>,
    nodes: std::sync::Mutex<HashSet<(String, String, u64)>>,
    received_records: std::sync::Mutex<HashSet<(String, String)>>,
    attestation_observers: std::sync::Mutex<HashMap<(String, String), HashSet<String>>>,
}

#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub node_id: String,
    pub public_key: String,
    pub endpoint: SocketAddr,
    pub first_seen: Instant,
    pub last_seen: Instant,
    pub observed_external_endpoint: Option<String>,
    pub features: HashSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathMethod {
    Direct,
    HolePunch,
    Relay,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathDiagnostic {
    pub peer_node_id: String,
    pub method: PathMethod,
    pub endpoint: SocketAddr,
}

#[derive(Debug, Clone)]
pub struct NetworkDiagnostics {
    pub local_addr: SocketAddr,
    pub observed_external_endpoint: Option<SocketAddr>,
    pub nat_behavior: NatMappingBehavior,
    pub filtering_evidence: NatFilteringEvidence,
    pub filtering_matrix: FilterMatrixSnapshot,
    pub authenticated_peers: usize,
    pub dht_records: usize,
    pub active_paths: Vec<PathDiagnostic>,
    pub pending_punches: usize,
}

#[derive(Clone)]
pub struct NetworkDiagnosticsHandle {
    inner: Arc<RwLock<NetworkDiagnostics>>,
}

impl NetworkDiagnosticsHandle {
    pub fn snapshot(&self) -> NetworkDiagnostics {
        self.inner
            .read()
            .expect("network diagnostics lock poisoned")
            .clone()
    }
}

enum RelayAppCommand {
    Send {
        peer_node_id: String,
        data: Vec<u8>,
        response: oneshot::Sender<std::result::Result<u64, String>>,
    },
    Connect {
        peer_node_id: String,
        endpoints: Vec<SocketAddr>,
        response: oneshot::Sender<std::result::Result<(), String>>,
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

    pub async fn connect(&self, peer_node_id: String, endpoints: Vec<SocketAddr>) -> Result<()> {
        let (response_tx, response_rx) = oneshot::channel();
        self.command_tx
            .send(RelayAppCommand::Connect {
                peer_node_id,
                endpoints,
                response: response_tx,
            })
            .await
            .map_err(|_| anyhow!("KonoNexus relay application runtime is closed"))?;
        response_rx
            .await
            .map_err(|_| anyhow!("KonoNexus connect response channel closed"))?
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
    authorization: FilteringMatrixAuthorization,
    expires_at: Instant,
}

#[derive(Debug, Clone)]
struct PendingFilterConsent {
    trial_id: u64,
    probe_class: FilterProbeClass,
    probe_token: u64,
    requester_endpoint: SocketAddr,
    requester_node_id: String,
    helper_endpoint: Option<SocketAddr>,
    helper_node_id: String,
    expires_at: Instant,
}

#[derive(Debug, Clone)]
struct PendingFilterTrial {
    coordinator_endpoint: SocketAddr,
    coordinator_node_id: String,
    target_endpoint: SocketAddr,
    seen_classes: HashSet<FilterProbeClass>,
    expires_at: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FilterAuthorizationUseKey {
    target_node_id: String,
    coordinator_node_id: String,
    helper_node_id: String,
    trial_id: u64,
    class: FilterProbeClass,
    probe_token: u64,
}

impl From<&FilteringMatrixAuthorization> for FilterAuthorizationUseKey {
    fn from(authorization: &FilteringMatrixAuthorization) -> Self {
        Self {
            target_node_id: authorization.target_node_id.clone(),
            coordinator_node_id: authorization.coordinator_node_id.clone(),
            helper_node_id: authorization.helper_node_id.clone(),
            trial_id: authorization.trial_id,
            class: authorization.class,
            probe_token: authorization.probe_token,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct FilterProbeRateWindow {
    window_started_at: Instant,
    last_seen: Instant,
    count: u16,
}

impl FilterProbeRateWindow {
    fn new(now: Instant) -> Self {
        Self {
            window_started_at: now,
            last_seen: now,
            count: 0,
        }
    }

    fn count_at(&self, now: Instant) -> u16 {
        if now
            .checked_duration_since(self.window_started_at)
            .is_none_or(|age| age >= FILTER_PROBE_RATE_WINDOW)
        {
            0
        } else {
            self.count
        }
    }

    fn increment_at(&mut self, now: Instant) {
        if now
            .checked_duration_since(self.window_started_at)
            .is_none_or(|age| age >= FILTER_PROBE_RATE_WINDOW)
        {
            self.window_started_at = now;
            self.count = 0;
        }
        self.count = self.count.saturating_add(1);
        self.last_seen = now;
    }
}

#[derive(Debug, Clone)]
struct ActiveDhtQuery {
    target_node_id: String,
    expected_responders: HashMap<SocketAddr, u8>,
    expires_at: Instant,
}

#[derive(Debug, Clone)]
struct ReverseDhtRoute {
    previous_endpoint: SocketAddr,
    target_node_id: String,
    expected_responders: HashMap<SocketAddr, u8>,
    expires_at: Instant,
}

#[derive(Debug, Clone)]
struct DhtDiscoveryCandidate {
    expected_node_id: String,
    expires_at: Instant,
}

#[derive(Debug, Clone)]
struct DhtReplicationRateWindow {
    started_at: Instant,
    events: u16,
    last_seen: Instant,
}

#[derive(Debug, Clone)]
struct DhtQueryTokenBucket {
    tokens: u16,
    last_refill: Instant,
    last_seen: Instant,
}

impl DhtQueryTokenBucket {
    fn full(capacity: u16, now: Instant) -> Self {
        Self {
            tokens: capacity,
            last_refill: now,
            last_seen: now,
        }
    }

    fn try_take(&mut self, capacity: u16, refill_interval: Duration, now: Instant) -> bool {
        let elapsed = now
            .checked_duration_since(self.last_refill)
            .unwrap_or_default();
        let refill_nanos = refill_interval.as_nanos().max(1);
        let refills = elapsed.as_nanos() / refill_nanos;
        if refills > 0 {
            let token_refills =
                u16::try_from(refills.min(u128::from(capacity))).unwrap_or(capacity);
            self.tokens = self.tokens.saturating_add(token_refills).min(capacity);
            let remainder_nanos =
                u64::try_from(elapsed.as_nanos() % refill_nanos).unwrap_or_default();
            self.last_refill = now
                .checked_sub(Duration::from_nanos(remainder_nanos))
                .unwrap_or(now);
        }
        if self.tokens == 0 {
            return false;
        }
        self.tokens -= 1;
        self.last_seen = now;
        true
    }
}

#[derive(Debug, Clone)]
struct DhtReplicationHistory {
    target_node_ids: HashSet<String>,
    transit_target_node_ids: HashSet<String>,
    owner_target_node_ids: HashSet<String>,
    expires_at: Instant,
}

#[derive(Debug, Clone)]
struct PendingDhtReplication {
    target: SocketAddr,
    target_node_id: String,
    record: PeerRecord,
    attestations: Vec<EndpointAttestation>,
    replication_hops_remaining: u8,
    kind: DhtReplicationKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DhtReplicationKind {
    Sync,
    Transit,
    Owner,
}

#[derive(Debug, Clone)]
struct OwnDhtRecord {
    record: PeerRecord,
    endpoint: SocketAddr,
    created_at: Instant,
}

#[derive(Debug, Clone)]
struct RelayPath {
    peer_node_id: String,
    expires_at: Instant,
    next_send_sequence: u64,
    receive_window: SequenceWindow,
}

#[derive(Debug, Default)]
struct RelayAppRouteAttempts {
    entries: HashMap<(String, u64), (ControlRoute, Instant)>,
    order: VecDeque<(String, u64)>,
}

impl RelayAppRouteAttempts {
    fn track(&mut self, key: (String, u64), route: ControlRoute, sent_at: Instant) {
        if self.entries.contains_key(&key) {
            self.order.retain(|stored| stored != &key);
        } else {
            while self.entries.len() >= MAX_RELAY_APP_ROUTE_ATTEMPTS {
                let Some(oldest) = self.order.pop_front() else {
                    break;
                };
                self.entries.remove(&oldest);
            }
        }
        self.order.push_back(key.clone());
        self.entries.insert(key, (route, sent_at));
    }

    fn take(&mut self, key: &(String, u64)) -> Option<(ControlRoute, Instant)> {
        let attempt = self.entries.remove(key);
        self.order.retain(|stored| stored != key);
        attempt
    }

    fn matching_ack_rtt(
        &mut self,
        key: &(String, u64),
        ack_route: ControlRoute,
        now: Instant,
    ) -> Option<(Duration, Instant)> {
        let (attempted_route, sent_at) = self.take(key)?;
        (attempted_route == ack_route).then(|| (now.saturating_duration_since(sent_at), sent_at))
    }
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
    punched_endpoints: HashSet<SocketAddr>,
    queued_rendezvous: HashMap<SocketAddr, Vec<String>>,
    auto_rendezvous: HashMap<String, AutoRendezvousState>,
    queued_filter_tests: HashSet<SocketAddr>,
    pending_filter_trials: HashMap<u64, PendingFilterTrial>,
    pending_filter_probes: HashMap<u64, PendingFilterProbe>,
    pending_filter_consents: HashMap<u64, PendingFilterConsent>,
    used_filter_authorizations: HashMap<FilterAuthorizationUseKey, Instant>,
    filter_probe_auth_attempt_windows: HashMap<String, FilterProbeRateWindow>,
    filter_probe_auth_attempt_global_window: FilterProbeRateWindow,
    filter_probe_coordinator_windows: HashMap<String, FilterProbeRateWindow>,
    filter_probe_target_windows: HashMap<DhtNetworkGroup, FilterProbeRateWindow>,
    filter_probe_global_window: FilterProbeRateWindow,
    recent_egress_ips: HashMap<IpAddr, Instant>,
    filter_contact_history_saturated_until: Option<Instant>,
    last_rendezvous_request: HashMap<SocketAddr, Instant>,
    last_filter_test_request: HashMap<SocketAddr, Instant>,
    dht: DhtTable,
    endpoint_attestations: EndpointAttestationTable,
    last_endpoint_attestation_refresh: HashMap<SocketAddr, Instant>,
    dht_replication_rate_windows: HashMap<String, DhtReplicationRateWindow>,
    dht_query_peer_buckets: HashMap<String, DhtQueryTokenBucket>,
    dht_query_prefix_buckets: HashMap<DhtNetworkGroup, DhtQueryTokenBucket>,
    dht_query_global_bucket: DhtQueryTokenBucket,
    dht_replication_history: HashMap<(String, u64), DhtReplicationHistory>,
    pending_dht_replications: VecDeque<PendingDhtReplication>,
    own_dht_record: Option<OwnDhtRecord>,
    routing: RoutingTable,
    pending_dht_queries: HashSet<String>,
    active_dht_queries: HashMap<u64, ActiveDhtQuery>,
    seen_dht_queries: HashMap<(String, u64), Instant>,
    reverse_dht_routes: HashMap<(String, u64), ReverseDhtRoute>,
    last_dht_query_start: HashMap<String, Instant>,
    last_dht_forward: HashMap<SocketAddr, Instant>,
    discovery_candidates: HashMap<SocketAddr, DhtDiscoveryCandidate>,
    connect_candidate_groups: HashMap<String, CandidateGroup>,
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
    route_controller: RouteController,
    relay_app_route_attempts: RelayAppRouteAttempts,
    punch_relay_candidates: HashMap<u64, SocketAddr>,
    diagnostics: Option<Arc<RwLock<NetworkDiagnostics>>>,
    #[cfg(test)]
    runtime_mesh_counters: Option<Arc<RuntimeMeshCounters>>,
    local_test_mode: bool,
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

        let now = Instant::now();
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
            punched_endpoints: HashSet::new(),
            queued_rendezvous: HashMap::new(),
            auto_rendezvous: HashMap::new(),
            queued_filter_tests: HashSet::new(),
            pending_filter_trials: HashMap::new(),
            pending_filter_probes: HashMap::new(),
            pending_filter_consents: HashMap::new(),
            used_filter_authorizations: HashMap::new(),
            filter_probe_auth_attempt_windows: HashMap::new(),
            filter_probe_auth_attempt_global_window: FilterProbeRateWindow::new(now),
            filter_probe_coordinator_windows: HashMap::new(),
            filter_probe_target_windows: HashMap::new(),
            filter_probe_global_window: FilterProbeRateWindow::new(now),
            recent_egress_ips: HashMap::new(),
            filter_contact_history_saturated_until: None,
            last_rendezvous_request: HashMap::new(),
            last_filter_test_request: HashMap::new(),
            dht: DhtTable::default(),
            endpoint_attestations: EndpointAttestationTable::default(),
            last_endpoint_attestation_refresh: HashMap::new(),
            dht_replication_rate_windows: HashMap::new(),
            dht_query_peer_buckets: HashMap::new(),
            dht_query_prefix_buckets: HashMap::new(),
            dht_query_global_bucket: DhtQueryTokenBucket::full(DHT_QUERY_GLOBAL_BURST, now),
            dht_replication_history: HashMap::new(),
            pending_dht_replications: VecDeque::new(),
            own_dht_record: None,
            routing: RoutingTable::new(&local_node_id),
            pending_dht_queries: HashSet::new(),
            active_dht_queries: HashMap::new(),
            seen_dht_queries: HashMap::new(),
            reverse_dht_routes: HashMap::new(),
            last_dht_query_start: HashMap::new(),
            last_dht_forward: HashMap::new(),
            discovery_candidates: HashMap::new(),
            connect_candidate_groups: HashMap::new(),
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
            route_controller: RouteController::default(),
            relay_app_route_attempts: RelayAppRouteAttempts::default(),
            punch_relay_candidates: HashMap::new(),
            diagnostics: None,
            #[cfg(test)]
            runtime_mesh_counters: None,
            local_test_mode: false,
            hello_interval,
        })
    }

    pub fn set_local_test_mode(&mut self, enabled: bool) {
        self.local_test_mode = enabled;
    }

    pub fn queue_rendezvous(&mut self, coordinator: SocketAddr, target_node_id: String) {
        self.queued_rendezvous
            .entry(coordinator)
            .or_default()
            .push(target_node_id);
    }

    pub fn queue_auto_rendezvous(&mut self, target_node_id: String) {
        let now = Instant::now();
        let expired_targets: Vec<String> = self
            .auto_rendezvous
            .iter()
            .filter_map(|(target, state)| state.expired(now).then_some(target.clone()))
            .collect();
        for expired in expired_targets {
            self.pending_dht_queries.remove(&expired);
        }
        if admit_auto_rendezvous_target(&mut self.auto_rendezvous, target_node_id.clone(), now) {
            self.pending_dht_queries.insert(target_node_id);
        }
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
        let local_node_id = self.node_id();
        let mut hints = load_routing_bucket_snapshot(&path, &local_node_id)?;
        hints.sort_by_key(|entry| std::cmp::Reverse(entry.last_seen_unix_ms));

        let mut loaded = 0_usize;
        for hint in hints.into_iter().take(MAX_ROUTING_BOOTSTRAP_HINTS) {
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

    pub fn configure_diagnostics_handle(&mut self) -> Result<NetworkDiagnosticsHandle> {
        if self.diagnostics.is_some() {
            return Err(anyhow!("network diagnostics handle is already configured"));
        }
        let inner = Arc::new(RwLock::new(self.diagnostics_snapshot()?));
        self.diagnostics = Some(inner.clone());
        Ok(NetworkDiagnosticsHandle { inner })
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

    #[cfg(test)]
    fn set_runtime_mesh_counters(&mut self, counters: Arc<RuntimeMeshCounters>) {
        self.runtime_mesh_counters = Some(counters);
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
                            self.publish_diagnostics();
                        }
                        Err(error) => {
                            warn!(%error, "UDP receive failed");
                        }
                    }
                }
                _ = ticker.tick() => {
                    self.refresh_discovery().await;
                    self.ping_known_peers().await;
                    self.refresh_endpoint_attestations().await;
                    self.expire_stale_state();
                    if let Err(error) = self.persist_routing_cache() {
                        debug!(%error, "routing cache persistence failed");
                    }
                    self.publish_diagnostics();
                }
                _ = punch_ticker.tick() => {
                    self.drive_punch_attempts().await;
                    self.drive_relay_app().await;
                    self.flush_relay_app_events();
                    self.flush_relay_app_failures();
                    self.publish_diagnostics();
                }
                _ = rendezvous_ticker.tick() => {
                    self.expire_filtering_matrix_state();
                    self.drive_session_handshakes().await;
                    self.drive_session_rekeys().await;
                    self.drive_relay_e2e_rekeys().await;
                    self.drive_auto_rendezvous().await;
                    self.drive_connect_candidate_groups().await;
                    self.drive_auto_relay_fallbacks().await;
                    self.drive_dht_queries().await;
                    if let Err(error) = self.queue_own_dht_publication() {
                        debug!(%error, "DHT owner publication planning failed");
                    }
                    self.drive_dht_replications().await;
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
            MessageBody::Hello { cookie, features } => {
                if !self.discovery_identity_matches(source, &sender_node_id) {
                    debug!(
                        %source,
                        peer = %sender_node_id,
                        "rejected DHT discovery response from unexpected identity"
                    );
                    return Ok(());
                }
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
                if let Some(peer) = self.peers.get_mut(&source) {
                    peer.features = features.into_iter().collect();
                }
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
                if self.is_expected_peer(source, &sender_node_id) {
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
                observed_endpoint,
                features,
            } => {
                if !self.is_expected_peer(source, &sender_node_id) {
                    debug!(%source, "ignoring unsolicited HELLO_ACK");
                    return Ok(());
                }

                if features.is_empty() {
                    debug!(peer = %sender_node_id, "HELLO_ACK advertised no capabilities");
                }

                self.record_peer(&envelope, source);
                if let Some(peer) = self.peers.get_mut(&source) {
                    peer.observed_external_endpoint = Some(observed_endpoint.clone());
                    peer.features = features.into_iter().collect();
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
                self.complete_direct_candidate_target(&sender_node_id);

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
                        if session.peer_node_id() != sender_node_id.as_str() {
                            debug!(
                                %source,
                                peer = %sender_node_id,
                                expected_peer = %session.peer_node_id(),
                                "ignoring secure frame from identity not bound to session"
                            );
                            return Ok(());
                        }
                        session.decrypt(&session_id, sequence, &ciphertext, Instant::now())?
                    }
                    None => {
                        debug!(%source, "ignoring secure frame without established session");
                        return Ok(());
                    }
                };

                // A fresh frame that passed signature, identity binding, AEAD
                // and replay checks proves this admitted peer is still active.
                // Rejected/replayed traffic must never extend its idle lease.
                if let Some(peer) = self.peers.get_mut(&source) {
                    peer.last_seen = Instant::now();
                }
                let newly_confirmed = self.confirmed_sessions.insert(source);
                self.routing
                    .observe(sender_node_id.clone(), source, Instant::now());
                if newly_confirmed {
                    self.complete_direct_candidate_target(&sender_node_id);
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
                self.punched_endpoints.insert(source);
                self.pending_punches.remove(&punch_token);
                self.punch_relay_candidates.remove(&punch_token);

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
                self.punched_endpoints.insert(source);
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
                debug!(
                    peer = %sender_node_id,
                    %source,
                    probe_token,
                    "ignored legacy filter probe; matrix-v1 authorization is required"
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
            MessageBody::FilteringMatrixProbe {
                trial_id,
                probe_class,
                probe_token,
            } => {
                let Some(pending) = self.pending_filter_probes.get(&probe_token).cloned() else {
                    debug!(peer = %sender_node_id, %source, probe_token, "ignored unsolicited filtering matrix probe");
                    return Ok(());
                };
                let authorization = &pending.authorization;
                if pending.expires_at <= Instant::now()
                    || authorization.trial_id != trial_id
                    || authorization.class != probe_class
                    || authorization.probe_token != probe_token
                    || authorization.helper_node_id != sender_node_id
                    || !self.filter_probe_endpoint_allowed(source)
                {
                    debug!(peer = %sender_node_id, %source, trial_id, probe_token, "ignored mismatched filtering matrix probe");
                    return Ok(());
                }
                if probe_class == FilterProbeClass::DifferentAddress
                    && (self
                        .peers
                        .keys()
                        .any(|endpoint| ip_equivalent(endpoint.ip(), source.ip()))
                        || self.filter_probe_source_was_contacted(source.ip(), Instant::now()))
                {
                    debug!(peer = %sender_node_id, %source, "different-address helper source was previously contacted");
                    return Ok(());
                }
                if let Err(error) = self.nat_profile.record_filter_probe(
                    authorization,
                    Some(source),
                    FilterProbeOutcome::Observed,
                ) {
                    debug!(peer = %sender_node_id, %source, %error, "rejected filtering matrix evidence");
                    return Ok(());
                }

                self.pending_filter_probes.remove(&probe_token);
                self.send(
                    source,
                    MessageBody::FilteringMatrixProbeAck {
                        trial_id,
                        probe_class,
                        probe_token,
                    },
                )
                .await?;
                info!(
                    helper = %sender_node_id,
                    %source,
                    ?probe_class,
                    trial_id,
                    probe_token,
                    filtering = ?self.nat_profile.filtering_evidence(),
                    "recorded consent-bound filtering matrix observation"
                );
            }
            MessageBody::FilteringMatrixProbeAck {
                trial_id,
                probe_class,
                probe_token,
            } => {
                debug!(peer = %sender_node_id, %source, ?probe_class, trial_id, probe_token, "filtering matrix probe acknowledged");
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
                debug!(peer = %sender_node_id, "legacy filtering probe requested; matrix-v1 is required");
                self.send_secure_payload(source, SecurePayload::FilteringTestUnavailable)
                    .await?;
            }
            SecurePayload::FilteringTestProposal {
                helper_node_id,
                target_endpoint,
                probe_token,
            } => {
                debug!(
                    coordinator = %sender_node_id,
                    %helper_node_id,
                    %target_endpoint,
                    probe_token,
                    "ignored legacy filtering proposal; matrix-v1 is required"
                );
            }
            SecurePayload::FilteringTestConsent { authorization } => {
                debug!(
                    peer = %sender_node_id,
                    probe_token = authorization.probe_token,
                    "ignored legacy filtering consent; matrix-v1 is required"
                );
            }
            SecurePayload::FilteringTestSend { authorization } => {
                debug!(
                    coordinator = %sender_node_id,
                    probe_token = authorization.probe_token,
                    "rejected legacy helper send; matrix-v1 authorization is required"
                );
            }
            SecurePayload::FilteringTestUnavailable => {
                debug!(
                    coordinator = %sender_node_id,
                    "legacy filtering test unavailable from this coordinator"
                );
            }
            SecurePayload::FilteringMatrixRequest { trial_id } => {
                self.handle_filtering_matrix_request(source, sender_node_id, trial_id)
                    .await?;
            }
            SecurePayload::FilteringMatrixProposal {
                trial_id,
                probe_class,
                helper_node_id,
                target_endpoint,
                probe_token,
            } => {
                self.handle_filtering_matrix_proposal(
                    source,
                    sender_node_id,
                    trial_id,
                    probe_class,
                    &helper_node_id,
                    &target_endpoint,
                    probe_token,
                )
                .await?;
            }
            SecurePayload::FilteringMatrixConsent { authorization } => {
                self.handle_filtering_matrix_consent(source, sender_node_id, authorization)
                    .await?;
            }
            SecurePayload::FilteringMatrixSend { authorization } => {
                self.handle_filtering_matrix_send(source, sender_node_id, authorization)
                    .await?;
            }
            SecurePayload::FilteringMatrixSendResult {
                trial_id,
                probe_class,
                probe_token,
                accepted,
                failure,
            } => {
                self.handle_filtering_matrix_send_result(
                    source,
                    sender_node_id,
                    trial_id,
                    probe_class,
                    probe_token,
                    accepted,
                    failure,
                )
                .await?;
            }
            SecurePayload::FilteringMatrixUnavailable {
                trial_id,
                probe_class,
                probe_token,
                failure,
            } => {
                self.handle_filtering_matrix_unavailable(
                    source,
                    sender_node_id,
                    trial_id,
                    probe_class,
                    probe_token,
                    failure,
                );
            }
            SecurePayload::RelayAppFragment { fragment } => {
                self.handle_app_fragment(sender_node_id, fragment).await?;
            }
            SecurePayload::RelayAppAck { message_id } => {
                self.handle_app_ack(
                    sender_node_id,
                    message_id,
                    ControlRoute::Direct(source),
                    Instant::now(),
                );
            }
            SecurePayload::DhtStore {
                record,
                attestations,
                replication_hops_remaining,
            } => {
                if attestations.len() > DHT_ATTESTATION_RESPONSE_LIMIT
                    || replication_hops_remaining > DHT_REPLICATION_MAX_HOPS
                    || (replication_hops_remaining > 0
                        && !self.peer_supports_feature(source, "bounded-dht-replication-v1"))
                {
                    debug!(
                        peer = %sender_node_id,
                        count = attestations.len(),
                        "rejected oversized DHT attestation set"
                    );
                    return Ok(());
                }
                if !self.allow_dht_record_admission(sender_node_id, source, 1, Instant::now()) {
                    debug!(peer = %sender_node_id, "DHT record admission rate-limited");
                    return Ok(());
                }
                if let Err(error) = record.verify() {
                    debug!(peer = %sender_node_id, %error, "rejected invalid DHT peer record");
                    return Ok(());
                }
                let record_node_id = record.node_id.clone();
                let record_was_new = match self.dht.upsert(record.clone()) {
                    Ok(true) => {
                        debug!(
                            peer = %record_node_id,
                            records = self.dht.len(),
                            "stored signed DHT peer record"
                        );
                        true
                    }
                    Ok(false) => false,
                    Err(error) => {
                        debug!(%error, peer = %record_node_id, "rejected DHT peer record");
                        return Ok(());
                    }
                };

                #[cfg(test)]
                if let Some(counters) = &self.runtime_mesh_counters {
                    if replication_hops_remaining > 0 {
                        counters.replicated_stores.fetch_add(1, Ordering::Relaxed);
                    }
                    counters
                        .received_records
                        .lock()
                        .expect("mesh record counter poisoned")
                        .insert((self.node_id(), record_node_id.clone()));
                }

                let stored_attestations = self.store_dht_attestations(attestations);

                if self.pending_dht_queries.contains(&record_node_id) {
                    if let Some(current) = self.dht.get(&record_node_id).cloned() {
                        self.activate_dht_record(&current).await?;
                    }
                }

                if replication_hops_remaining > 0 && (record_was_new || stored_attestations > 0) {
                    if let Some(current) = self.dht.get(&record_node_id).cloned() {
                        self.replicate_dht_record(source, &current, replication_hops_remaining - 1);
                    }
                }
            }
            SecurePayload::DhtAttestation { attestation } => {
                if attestation.observer_node_id != sender_node_id
                    || attestation.subject_node_id != self.node_id()
                {
                    debug!(
                        peer = %sender_node_id,
                        subject = %attestation.subject_node_id,
                        observer = %attestation.observer_node_id,
                        "rejected misbound direct endpoint attestation"
                    );
                    return Ok(());
                }

                #[cfg(test)]
                let subject_node_id = attestation.subject_node_id.clone();
                #[cfg(test)]
                let observer_node_id = attestation.observer_node_id.clone();
                let stored = match self.endpoint_attestations.upsert(attestation) {
                    Ok(true) => {
                        #[cfg(test)]
                        if let Some(counters) = &self.runtime_mesh_counters {
                            counters.attestations.fetch_add(1, Ordering::Relaxed);
                            counters
                                .attestation_observers
                                .lock()
                                .expect("mesh attestation counter poisoned")
                                .entry((self.node_id(), subject_node_id))
                                .or_default()
                                .insert(observer_node_id);
                        }
                        debug!(
                            peer = %sender_node_id,
                            attestations = self.endpoint_attestations.len(),
                            "stored direct endpoint attestation"
                        );
                        true
                    }
                    Ok(false) => false,
                    Err(error) => {
                        debug!(peer = %sender_node_id, %error, "rejected endpoint attestation");
                        false
                    }
                };

                if stored {
                    self.queue_own_dht_publication_to(source)?;
                    self.queue_own_dht_publication()?;
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
                if !self.allow_dht_query(sender_node_id, source, now) {
                    debug!(peer = %sender_node_id, "DHT query ingress rate-limited");
                    return Ok(());
                }
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

                #[cfg(test)]
                if let Some(counters) = &self.runtime_mesh_counters {
                    counters
                        .finds
                        .lock()
                        .expect("mesh DHT find counter poisoned")
                        .insert((origin_node_id.clone(), target_node_id.clone(), query_id));
                }

                if origin_node_id != self.node_id() {
                    self.reverse_dht_routes.insert(
                        query_key.clone(),
                        ReverseDhtRoute {
                            previous_endpoint: source,
                            target_node_id: target_node_id.clone(),
                            expected_responders: HashMap::new(),
                            expires_at: now + DHT_QUERY_TIMEOUT,
                        },
                    );
                }

                let mut records = Vec::new();
                let mut exact_found = false;

                if target_node_id == self.node_id() {
                    if let Some(record) = self.build_own_dht_record()? {
                        exact_found = self.record_has_attested_endpoint(&record);
                        records.push(record);
                    }
                } else if let Some(record) = self.dht.get(&target_node_id) {
                    exact_found = self.record_has_attested_endpoint(record);
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

                let attestations = self.attestations_for_records(&records);

                self.send_secure_payload(
                    source,
                    SecurePayload::DhtNodes {
                        query_id,
                        origin_node_id: origin_node_id.clone(),
                        target_node_id: target_node_id.clone(),
                        records,
                        attestations,
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

                    let eligible: Vec<_> = self
                        .routing
                        .nearest(&target_node_id, self.routing.len())
                        .into_iter()
                        .filter(|candidate| {
                            candidate.endpoint != source
                                && candidate.node_id != origin_node_id
                                && self.sessions.contains_key(&candidate.endpoint)
                        })
                        .collect();

                    for candidate in prioritize_network_group_diversity(eligible) {
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

                        if let Some(route) = self.reverse_dht_routes.get_mut(&query_key) {
                            route.expected_responders.insert(candidate.endpoint, 0);
                        }

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
                attestations,
            } => {
                if records.len() > DHT_RESPONSE_LIMIT
                    || attestations.len() > DHT_ATTESTATION_RESPONSE_LIMIT
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

                let now = Instant::now();
                if !self.accept_dht_response(
                    query_id,
                    &origin_node_id,
                    &target_node_id,
                    source,
                    now,
                ) {
                    debug!(peer = %sender_node_id, query_id, "rejected unsolicited DHT response");
                    return Ok(());
                }

                if records.iter().any(|record| record.verify().is_err()) {
                    debug!(peer = %sender_node_id, query_id, "rejected DHT response with invalid record");
                    return Ok(());
                }
                #[cfg(test)]
                let response_has_exact = records
                    .iter()
                    .any(|record| record.node_id == target_node_id);
                let mut records_to_cache = Vec::new();
                if let Some(exact) = records
                    .iter()
                    .find(|record| record.node_id == target_node_id)
                {
                    records_to_cache.push(exact.clone());
                }
                for record in &records {
                    if records_to_cache.len() >= DHT_RESPONSE_CACHE_LIMIT {
                        break;
                    }
                    if records_to_cache
                        .iter()
                        .any(|cached| cached.node_id == record.node_id)
                    {
                        continue;
                    }
                    records_to_cache.push(record.clone());
                }
                if !self.allow_dht_record_admission(
                    sender_node_id,
                    source,
                    records_to_cache.len().max(1) as u16,
                    now,
                ) {
                    debug!(peer = %sender_node_id, query_id, "DHT response admission rate-limited");
                    return Ok(());
                }

                for record in records_to_cache {
                    #[cfg(test)]
                    let record_node_id = record.node_id.clone();
                    if self.dht.upsert(record).is_err() {
                        continue;
                    }
                    #[cfg(test)]
                    if let Some(counters) = &self.runtime_mesh_counters {
                        counters
                            .received_records
                            .lock()
                            .expect("mesh record counter poisoned")
                            .insert((self.node_id(), record_node_id));
                    }
                }

                self.store_dht_attestations(attestations.clone());

                if origin_node_id == self.node_id() {
                    #[cfg(test)]
                    if let (Some(counters), Some(exact_record)) =
                        (&self.runtime_mesh_counters, self.dht.get(&target_node_id))
                    {
                        if response_has_exact && self.record_has_attested_endpoint(exact_record) {
                            counters
                                .nodes
                                .lock()
                                .expect("mesh DHT nodes counter poisoned")
                                .insert((origin_node_id.clone(), target_node_id.clone(), query_id));
                        }
                    }
                    if self.pending_dht_queries.contains(&target_node_id) {
                        if let Some(current) = self.dht.get(&target_node_id).cloned() {
                            if self.activate_dht_record(&current).await? {
                                self.active_dht_queries.remove(&query_id);
                            }
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
                                    attestations,
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
                } else if let Some(peer_node_id) =
                    self.remove_client_relay_path((source, circuit_id))
                {
                    let recovery_scheduled = self.schedule_auto_relay_failover_if_needed(
                        peer_node_id.clone(),
                        source,
                        Instant::now(),
                    );

                    info!(
                        relay = %sender_node_id,
                        peer = %peer_node_id,
                        circuit_id,
                        recovery_scheduled,
                        "relay path closed; control-plane recovery evaluated"
                    );
                }
            }
            SecurePayload::RelayReject { circuit_id } => {
                let rejected = self.pending_relay_requests.get(&circuit_id).cloned();
                let removed_peer = self.remove_client_relay_path((source, circuit_id));

                if let Some((relay_endpoint, target_node_id)) = rejected {
                    if relay_endpoint == source {
                        self.schedule_auto_relay_failover_if_needed(
                            target_node_id,
                            source,
                            Instant::now(),
                        );
                    }
                } else if let Some(peer_node_id) = removed_peer {
                    self.schedule_auto_relay_failover_if_needed(
                        peer_node_id,
                        source,
                        Instant::now(),
                    );
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

                if !self.rendezvous_candidate_allowed(candidate) {
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
        let expired_targets: Vec<String> = self
            .auto_rendezvous
            .iter()
            .filter_map(|(target, state)| {
                (state.expired(now)
                    && !self
                        .pending_punches
                        .values()
                        .any(|schedule| schedule.expected_node_id() == target))
                .then_some(target.clone())
            })
            .collect();
        for target in expired_targets {
            self.auto_rendezvous.remove(&target);
            self.pending_dht_queries.remove(&target);
            if self.direct_app_endpoint_for_peer(&target).is_none()
                && self.node_id().as_str() < target.as_str()
            {
                self.schedule_auto_relay_fallback(target, None, now);
            }
        }
        let targets: Vec<String> = self.auto_rendezvous.keys().cloned().collect();

        for target_node_id in targets {
            if self.direct_app_endpoint_for_peer(&target_node_id).is_some() {
                self.complete_direct_candidate_target(&target_node_id);
                continue;
            }
            if self.connect_candidate_groups.contains_key(&target_node_id) {
                continue;
            }
            if self
                .pending_sessions
                .values()
                .any(|attempt| attempt.peer_node_id == target_node_id)
            {
                continue;
            }

            let candidates: Vec<CoordinatorCandidate> = self
                .confirmed_sessions
                .iter()
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

            let punch_active = self
                .pending_punches
                .values()
                .any(|schedule| schedule.expected_node_id() == target_node_id);
            let round_exhausted = self
                .auto_rendezvous
                .get(&target_node_id)
                .is_some_and(|state| state.round_exhausted(&candidates));
            if round_exhausted && !punch_active {
                self.auto_rendezvous.remove(&target_node_id);
                self.pending_dht_queries.remove(&target_node_id);
                if self.node_id().as_str() < target_node_id.as_str() {
                    self.schedule_auto_relay_fallback(target_node_id.clone(), None, now);
                }
                info!(
                    target = %target_node_id,
                    coordinators = candidates.len(),
                    "bounded rendezvous candidate round exhausted"
                );
                continue;
            }

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
                        self.handle_app_ack(
                            peer_node_id,
                            message_id,
                            ControlRoute::Relay {
                                relay_endpoint,
                                circuit_id,
                            },
                            Instant::now(),
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

    fn handle_app_ack(
        &mut self,
        peer_node_id: &str,
        message_id: u64,
        route: ControlRoute,
        now: Instant,
    ) {
        if self.relay_app.acknowledge(peer_node_id, message_id) {
            let key = (peer_node_id.to_owned(), message_id);
            if let Some((rtt, sent_at)) = self
                .relay_app_route_attempts
                .matching_ack_rtt(&key, route, now)
            {
                let path = self.konomind_path_for_route(route);
                self.route_controller
                    .report_ack_success(peer_node_id, route, path, rtt, sent_at);
            }
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
    ) -> Result<Option<ControlRoute>> {
        let mut relay_attempts = 0_usize;
        let mut last_relay_error = None;

        loop {
            let direct = self.direct_app_endpoint_for_peer(peer_node_id);
            let relay_candidates = self.relay_e2e_candidates_for_peer(peer_node_id);
            let Some(decision) = self.route_controller.select_at(
                peer_node_id,
                direct,
                relay_candidates.iter().copied(),
                Instant::now(),
            ) else {
                return match last_relay_error {
                    Some(error) => Err(error),
                    None => Ok(None),
                };
            };

            if decision.changed {
                info!(
                    peer = %peer_node_id,
                    generation = decision.generation,
                    route = ?decision.route,
                    "application control-plane route migrated"
                );
            }

            match decision.route {
                ControlRoute::Direct(endpoint) => {
                    match self.send_secure_payload(endpoint, payload.clone()).await {
                        Ok(()) => return Ok(Some(decision.route)),
                        Err(error) => {
                            self.route_controller.report_failure(
                                peer_node_id,
                                decision.route,
                                Instant::now(),
                            );
                            last_relay_error = Some(error);
                        }
                    }
                }
                ControlRoute::Relay {
                    relay_endpoint,
                    circuit_id,
                } => {
                    if relay_attempts >= MAX_RELAY_ROUTE_CANDIDATES {
                        return match last_relay_error {
                            Some(error) => Err(error),
                            None => Ok(None),
                        };
                    }
                    relay_attempts = relay_attempts.saturating_add(1);

                    let encoded = {
                        let Some(session) = self
                            .relay_e2e_sessions
                            .get_mut(&(relay_endpoint, circuit_id))
                        else {
                            self.route_controller.report_failure(
                                peer_node_id,
                                decision.route,
                                Instant::now(),
                            );
                            self.remove_client_relay_path((relay_endpoint, circuit_id));
                            continue;
                        };
                        encode_relay_payload(session, &payload)?
                    };

                    match self
                        .send_relay_inner(relay_endpoint, circuit_id, encoded)
                        .await
                    {
                        Ok(()) => return Ok(Some(decision.route)),
                        Err(error) => {
                            self.route_controller.report_failure(
                                peer_node_id,
                                decision.route,
                                Instant::now(),
                            );
                            let failed_peer =
                                self.remove_client_relay_path((relay_endpoint, circuit_id));
                            if let Some(failed_peer) = failed_peer {
                                self.schedule_auto_relay_failover_if_needed(
                                    failed_peer,
                                    relay_endpoint,
                                    Instant::now(),
                                );
                            }

                            debug!(
                                peer = %peer_node_id,
                                failed_relay = %relay_endpoint,
                                circuit_id,
                                relay_attempts,
                                %error,
                                "application relay send failed; trying next bounded route"
                            );
                            last_relay_error = Some(error);
                        }
                    }
                }
            }
        }
    }

    fn direct_app_endpoint_for_peer(&self, peer_node_id: &str) -> Option<SocketAddr> {
        let endpoint = self.peer_endpoint_by_node_id(peer_node_id)?;
        self.confirmed_sessions
            .contains(&endpoint)
            .then_some(endpoint)
    }

    fn konomind_path_for_route(&self, route: ControlRoute) -> PathKind {
        match route {
            ControlRoute::Direct(endpoint) if self.punched_endpoints.contains(&endpoint) => {
                PathKind::HolePunch
            }
            ControlRoute::Direct(_) => PathKind::Direct,
            ControlRoute::Relay { .. } => PathKind::Relay,
        }
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
            RelayAppCommand::Connect {
                peer_node_id,
                endpoints,
                response,
            } => {
                let result = self
                    .queue_connect(peer_node_id, endpoints)
                    .map_err(|error| format!("{error:#}"));
                let _ = response.send(result);
            }
        }
    }

    fn queue_connect(&mut self, peer_node_id: String, endpoints: Vec<SocketAddr>) -> Result<()> {
        if !plausible_node_id(&peer_node_id) || peer_node_id == self.node_id() {
            bail!("invalid connection target NodeID");
        }
        if endpoints.is_empty() || endpoints.len() > 8 {
            bail!("connection requires between one and eight endpoints");
        }
        for endpoint in &endpoints {
            let ip = endpoint.ip();
            let broadcast = matches!(ip, IpAddr::V4(ip) if ip.is_broadcast());
            let unscoped_ipv6_link_local = matches!(endpoint, SocketAddr::V6(endpoint)
                if endpoint.ip().is_unicast_link_local() && endpoint.scope_id() == 0);
            if endpoint.port() == 0
                || ip.is_unspecified()
                || ip.is_multicast()
                || broadcast
                || unscoped_ipv6_link_local
            {
                bail!("connection endpoint is unusable");
            }
            if self.connect_candidate_groups.iter().any(|(target, group)| {
                target != &peer_node_id && group.candidates().contains(endpoint)
            }) || self
                .discovery_candidates
                .get(endpoint)
                .is_some_and(|candidate| {
                    candidate.expected_node_id.as_str() != peer_node_id.as_str()
                })
            {
                bail!("connection endpoint is already bound to another NodeID");
            }
        }
        if !self.connect_candidate_groups.contains_key(&peer_node_id)
            && self.connect_candidate_groups.len() >= MAX_ACTIVE_CANDIDATE_GROUPS
        {
            bail!("too many active connection candidate groups");
        }
        if let Some(group) = self.connect_candidate_groups.get_mut(&peer_node_id) {
            group.extend(endpoints);
        } else {
            self.connect_candidate_groups.insert(
                peer_node_id.clone(),
                CandidateGroup::new(endpoints, Instant::now()),
            );
        }
        self.pending_dht_queries.insert(peer_node_id);
        Ok(())
    }

    async fn drive_connect_candidate_groups(&mut self) {
        let now = Instant::now();
        let targets: Vec<String> = self.connect_candidate_groups.keys().cloned().collect();
        for target_node_id in targets {
            if self.direct_app_endpoint_for_peer(&target_node_id).is_some() {
                self.complete_direct_candidate_target(&target_node_id);
                continue;
            }

            let action = self
                .connect_candidate_groups
                .get_mut(&target_node_id)
                .and_then(|group| group.next_action(now));
            match action {
                Some(CandidateAction::Try(endpoint)) => {
                    if let Some(existing) = self.discovery_candidates.get_mut(&endpoint) {
                        if existing.expected_node_id != target_node_id {
                            debug!(%endpoint, target = %target_node_id, "candidate endpoint is already identity-bound to another peer");
                            continue;
                        }
                        existing.expires_at = now + CANDIDATE_GROUP_TTL;
                    } else {
                        self.discovery_candidates.insert(
                            endpoint,
                            DhtDiscoveryCandidate {
                                expected_node_id: target_node_id.clone(),
                                expires_at: now + CANDIDATE_GROUP_TTL,
                            },
                        );
                    }
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
                        debug!(%endpoint, target = %target_node_id, %error, "direct candidate HELLO failed");
                    } else {
                        info!(%endpoint, target = %target_node_id, "started bounded direct candidate attempt");
                    }
                }
                Some(CandidateAction::Exhausted) => {
                    self.queue_auto_rendezvous(target_node_id.clone());
                    self.connect_candidate_groups.remove(&target_node_id);
                    info!(target = %target_node_id, "direct candidate group exhausted; rendezvous fallback enabled");
                }
                None => {}
            }
        }
    }

    fn diagnostics_snapshot(&self) -> Result<NetworkDiagnostics> {
        let now = Instant::now();
        let authenticated_peer_ids: HashSet<String> = self
            .confirmed_sessions
            .iter()
            .filter_map(|endpoint| self.peers.get(endpoint))
            .map(|peer| peer.node_id.clone())
            .collect();
        let mut active_paths = Vec::new();
        for peer_node_id in &authenticated_peer_ids {
            if let Some(endpoint) = self.direct_app_endpoint_for_peer(peer_node_id) {
                active_paths.push(PathDiagnostic {
                    peer_node_id: peer_node_id.clone(),
                    method: if self.punched_endpoints.contains(&endpoint) {
                        PathMethod::HolePunch
                    } else {
                        PathMethod::Direct
                    },
                    endpoint,
                });
            }
        }
        for ((relay_endpoint, _), path) in &self.relay_paths {
            if path.expires_at > now
                && self.relay_e2e_path_for_peer(&path.peer_node_id).is_some()
                && !active_paths
                    .iter()
                    .any(|active| active.peer_node_id == path.peer_node_id)
            {
                active_paths.push(PathDiagnostic {
                    peer_node_id: path.peer_node_id.clone(),
                    method: PathMethod::Relay,
                    endpoint: *relay_endpoint,
                });
            }
        }
        active_paths.sort_by(|left, right| left.peer_node_id.cmp(&right.peer_node_id));
        Ok(NetworkDiagnostics {
            local_addr: self.local_addr()?,
            observed_external_endpoint: self.observed_external_endpoint(),
            nat_behavior: self.nat_behavior(),
            filtering_evidence: self.nat_filtering_evidence(),
            filtering_matrix: self.nat_profile.filter_matrix_snapshot(),
            authenticated_peers: authenticated_peer_ids.len(),
            dht_records: self.dht_record_count(),
            active_paths,
            pending_punches: self.pending_punches.len(),
        })
    }

    fn publish_diagnostics(&self) {
        let Some(diagnostics) = &self.diagnostics else {
            return;
        };
        let Ok(snapshot) = self.diagnostics_snapshot() else {
            return;
        };
        if let Ok(mut current) = diagnostics.write() {
            *current = snapshot;
        }
    }

    fn flush_relay_app_failures(&mut self) {
        while let Some(failure) = self.relay_app.peek_failure() {
            let key = (failure.peer_node_id.clone(), failure.message_id);
            if let Some((route, sent_at)) = self.relay_app_route_attempts.take(&key) {
                let now = Instant::now();
                let path = self.konomind_path_for_route(route);
                self.route_controller.report_delivery_failure(
                    &failure.peer_node_id,
                    route,
                    path,
                    now.saturating_duration_since(sent_at),
                    now,
                );
            }
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

            let sent_at = Instant::now();
            match self
                .send_app_secure_payload(&outbound.peer_node_id, payload)
                .await
            {
                Ok(Some(route)) => self.track_relay_app_route_attempt(
                    outbound.peer_node_id.clone(),
                    outbound.fragment.message_id,
                    route,
                    sent_at,
                ),
                Ok(None) => break,
                Err(error) => {
                    self.relay_app_route_attempts
                        .take(&(outbound.peer_node_id.clone(), outbound.fragment.message_id));
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

    fn track_relay_app_route_attempt(
        &mut self,
        peer_node_id: String,
        message_id: u64,
        route: ControlRoute,
        sent_at: Instant,
    ) {
        self.relay_app_route_attempts
            .track((peer_node_id, message_id), route, sent_at);
    }

    fn relay_e2e_candidates_for_peer(&self, peer_node_id: &str) -> Vec<RelayRouteCandidate> {
        let now = Instant::now();
        self.relay_e2e_sessions
            .keys()
            .filter_map(|(relay_endpoint, circuit_id)| {
                let path = self.relay_paths.get(&(*relay_endpoint, *circuit_id))?;
                (path.peer_node_id == peer_node_id && path.expires_at > now)
                    .then_some(RelayRouteCandidate::new(*relay_endpoint, *circuit_id))
            })
            .collect()
    }

    fn relay_e2e_path_for_peer(&self, peer_node_id: &str) -> Option<(SocketAddr, u64)> {
        let mut candidates = self.relay_e2e_candidates_for_peer(peer_node_id);
        candidates.sort_by_key(|candidate| {
            (
                if candidate.relay_endpoint.is_ipv6() {
                    0_u8
                } else {
                    1_u8
                },
                candidate.relay_endpoint,
                candidate.circuit_id,
            )
        });
        candidates
            .first()
            .map(|candidate| (candidate.relay_endpoint, candidate.circuit_id))
    }

    fn remove_client_relay_path(&mut self, key: (SocketAddr, u64)) -> Option<String> {
        let peer_node_id = self.relay_paths.remove(&key).map(|path| path.peer_node_id);
        self.relay_e2e_pending.remove(&key);
        self.relay_e2e_sessions.remove(&key);
        self.pending_relay_e2e_rekeys.remove(&key);
        self.responder_relay_e2e_rekey_acks
            .retain(|(endpoint, circuit_id, _), _| *endpoint != key.0 || *circuit_id != key.1);
        self.last_relay_e2e_rekey.remove(&key);
        self.pending_relay_requests.remove(&key.1);
        self.pending_relay_accepts.remove(&key);

        if let Some(peer_node_id) = peer_node_id.as_deref() {
            self.route_controller
                .invalidate_relay(peer_node_id, key.0, key.1);
        }

        peer_node_id
    }

    fn persist_routing_cache(&self) -> Result<()> {
        let Some(path) = &self.routing_cache_path else {
            return Ok(());
        };

        let local_node_id = self.node_id();
        let now = Instant::now();
        let mut entries = Vec::new();
        for (bucket_index, peer) in self.routing.bucket_entries() {
            let entry = new_bucket_cache_entry(
                &local_node_id,
                peer.node_id,
                peer.endpoint,
                now.saturating_duration_since(peer.last_seen),
            )?;
            if usize::from(entry.bucket_index) != bucket_index {
                continue;
            }
            entries.push(entry);
        }

        save_routing_bucket_snapshot(path, &local_node_id, &entries)
    }

    async fn flush_filter_test_request(&mut self, coordinator: SocketAddr) -> Result<()> {
        if !self.queued_filter_tests.remove(&coordinator) {
            return Ok(());
        }
        if !self.peer_supports_feature(coordinator, "filtering-matrix-v1") {
            debug!(%coordinator, "peer does not support filtering-matrix-v1");
            return Ok(());
        }
        if self.pending_filter_trials.len() >= MAX_PENDING_FILTER_TRIALS {
            debug!(%coordinator, "filtering matrix trial capacity reached");
            return Ok(());
        }

        let Some(coordinator_node_id) = self
            .peers
            .get(&coordinator)
            .map(|peer| peer.node_id.clone())
        else {
            return Ok(());
        };
        let Some(target_endpoint) = self.nat_profile.endpoint_seen_by(&coordinator_node_id) else {
            debug!(%coordinator, "coordinator has not supplied a target mapping observation");
            return Ok(());
        };
        if !self.filter_probe_endpoint_allowed(target_endpoint) {
            debug!(%target_endpoint, "refused filtering matrix for unsafe target mapping");
            return Ok(());
        }

        let Some(trial_id) = (0..8)
            .map(|_| random())
            .find(|trial_id| !self.pending_filter_trials.contains_key(trial_id))
        else {
            return Ok(());
        };
        self.pending_filter_trials.insert(
            trial_id,
            PendingFilterTrial {
                coordinator_endpoint: coordinator,
                coordinator_node_id,
                target_endpoint,
                seen_classes: HashSet::new(),
                expires_at: Instant::now() + FILTER_MATRIX_TRIAL_TTL,
            },
        );

        if let Err(error) = self
            .send_secure_payload(
                coordinator,
                SecurePayload::FilteringMatrixRequest { trial_id },
            )
            .await
        {
            self.pending_filter_trials.remove(&trial_id);
            return Err(error);
        }
        Ok(())
    }

    async fn handle_filtering_matrix_request(
        &mut self,
        requester_endpoint: SocketAddr,
        requester_node_id: &str,
        trial_id: u64,
    ) -> Result<()> {
        let now = Instant::now();
        if !self.confirmed_sessions.contains(&requester_endpoint)
            || !self.peer_supports_feature(requester_endpoint, "filtering-matrix-v1")
        {
            return Ok(());
        }
        if self
            .last_filter_test_request
            .get(&requester_endpoint)
            .is_some_and(|last| now.duration_since(*last) < FILTER_TEST_REQUEST_COOLDOWN)
        {
            return Ok(());
        }
        self.last_filter_test_request
            .insert(requester_endpoint, now);

        if !self.filter_probe_endpoint_allowed(requester_endpoint) {
            self.send_filtering_matrix_unavailable_set(
                requester_endpoint,
                trial_id,
                FilteringMatrixFailure::UnsafeTarget,
            )
            .await;
            return Ok(());
        }

        if self.pending_filter_consents.len().saturating_add(3) > MAX_PENDING_FILTER_PROBES {
            self.send_filtering_matrix_unavailable_set(
                requester_endpoint,
                trial_id,
                FilteringMatrixFailure::Capacity,
            )
            .await;
            return Ok(());
        }

        let mut helpers: Vec<(SocketAddr, String)> = self
            .confirmed_sessions
            .iter()
            .filter(|endpoint| **endpoint != requester_endpoint)
            .filter_map(|endpoint| {
                let peer = self.peers.get(endpoint)?;
                if peer.node_id == requester_node_id
                    || ip_equivalent(endpoint.ip(), requester_endpoint.ip())
                    || !peer.features.contains("filtering-matrix-v1")
                    || !self.filter_probe_endpoint_allowed(*endpoint)
                {
                    return None;
                }
                Some((*endpoint, peer.node_id.clone()))
            })
            .collect();
        helpers.sort_by_key(|(endpoint, node_id)| (*endpoint, node_id.clone()));
        let helper = if helpers.is_empty() {
            None
        } else {
            let index = (trial_id % helpers.len() as u64) as usize;
            Some(helpers[index].clone())
        };

        for probe_class in [
            FilterProbeClass::ContactedEndpoint,
            FilterProbeClass::SameAddressDifferentPort,
            FilterProbeClass::DifferentAddress,
        ] {
            let Some(probe_token) = (0..8)
                .map(|_| random())
                .find(|token| !self.pending_filter_consents.contains_key(token))
            else {
                continue;
            };

            let (helper_endpoint, helper_node_id) = match probe_class {
                FilterProbeClass::ContactedEndpoint
                | FilterProbeClass::SameAddressDifferentPort => (None, self.node_id()),
                FilterProbeClass::DifferentAddress => {
                    let Some((endpoint, node_id)) = helper.clone() else {
                        let _ = self
                            .send_secure_payload(
                                requester_endpoint,
                                SecurePayload::FilteringMatrixUnavailable {
                                    trial_id,
                                    probe_class,
                                    probe_token,
                                    failure: FilteringMatrixFailure::NoHelper,
                                },
                            )
                            .await;
                        continue;
                    };
                    (Some(endpoint), node_id)
                }
            };

            self.pending_filter_consents.insert(
                probe_token,
                PendingFilterConsent {
                    trial_id,
                    probe_class,
                    probe_token,
                    requester_endpoint,
                    requester_node_id: requester_node_id.to_owned(),
                    helper_endpoint,
                    helper_node_id: helper_node_id.clone(),
                    expires_at: now + FILTER_PROBE_STATE_TTL,
                },
            );
            self.send_secure_payload(
                requester_endpoint,
                SecurePayload::FilteringMatrixProposal {
                    trial_id,
                    probe_class,
                    helper_node_id,
                    target_endpoint: requester_endpoint.to_string(),
                    probe_token,
                },
            )
            .await?;
        }
        Ok(())
    }

    async fn send_filtering_matrix_unavailable_set(
        &mut self,
        requester_endpoint: SocketAddr,
        trial_id: u64,
        failure: FilteringMatrixFailure,
    ) {
        for probe_class in [
            FilterProbeClass::ContactedEndpoint,
            FilterProbeClass::SameAddressDifferentPort,
            FilterProbeClass::DifferentAddress,
        ] {
            let payload = SecurePayload::FilteringMatrixUnavailable {
                trial_id,
                probe_class,
                probe_token: random(),
                failure,
            };
            if let Err(error) = self.send_secure_payload(requester_endpoint, payload).await {
                debug!(%requester_endpoint, %error, "failed to report unavailable filtering matrix cell");
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_filtering_matrix_proposal(
        &mut self,
        coordinator: SocketAddr,
        coordinator_node_id: &str,
        trial_id: u64,
        probe_class: FilterProbeClass,
        helper_node_id: &str,
        target_endpoint_text: &str,
        probe_token: u64,
    ) -> Result<()> {
        if self.pending_filter_probes.len() >= MAX_PENDING_FILTER_PROBES {
            return Ok(());
        }

        let Some(trial) = self.pending_filter_trials.get(&trial_id).cloned() else {
            return Ok(());
        };
        let Ok(target_endpoint) = target_endpoint_text.parse::<SocketAddr>() else {
            return Ok(());
        };
        if target_endpoint.to_string() != target_endpoint_text
            || trial.expires_at <= Instant::now()
            || trial.coordinator_endpoint != coordinator
            || trial.coordinator_node_id != coordinator_node_id
            || trial.target_endpoint != target_endpoint
            || self.nat_profile.endpoint_seen_by(coordinator_node_id) != Some(target_endpoint)
            || !self.filter_probe_endpoint_allowed(target_endpoint)
            || trial.seen_classes.contains(&probe_class)
            || self.pending_filter_probes.contains_key(&probe_token)
            || self.pending_filter_probes.values().any(|pending| {
                pending.authorization.trial_id == trial_id
                    && pending.authorization.class == probe_class
            })
        {
            return Ok(());
        }

        let helper_valid = match probe_class {
            FilterProbeClass::ContactedEndpoint | FilterProbeClass::SameAddressDifferentPort => {
                helper_node_id == coordinator_node_id
            }
            FilterProbeClass::DifferentAddress => {
                helper_node_id != coordinator_node_id
                    && plausible_node_id(helper_node_id)
                    && self.peer_endpoint_by_node_id(helper_node_id).is_none()
            }
        };
        if !helper_valid {
            return Ok(());
        }

        let authorization = FilteringMatrixAuthorization::signed(
            &self.identity,
            target_endpoint,
            coordinator_node_id.to_owned(),
            coordinator,
            helper_node_id.to_owned(),
            probe_class,
            trial_id,
            probe_token,
        )?;
        self.pending_filter_probes.insert(
            probe_token,
            PendingFilterProbe {
                authorization: authorization.clone(),
                expires_at: Instant::now() + FILTER_PROBE_STATE_TTL,
            },
        );

        if let Some(trial) = self.pending_filter_trials.get_mut(&trial_id) {
            trial.seen_classes.insert(probe_class);
        }
        if let Err(error) = self
            .send_secure_payload(
                coordinator,
                SecurePayload::FilteringMatrixConsent {
                    authorization: authorization.clone(),
                },
            )
            .await
        {
            self.pending_filter_probes.remove(&probe_token);
            let _ = self.nat_profile.record_filter_probe(
                &authorization,
                None,
                FilterProbeOutcome::SendFailed,
            );
            return Err(error);
        }
        Ok(())
    }

    async fn handle_filtering_matrix_consent(
        &mut self,
        requester_endpoint: SocketAddr,
        sender_node_id: &str,
        authorization: FilteringMatrixAuthorization,
    ) -> Result<()> {
        let Some(pending) = self
            .pending_filter_consents
            .get(&authorization.probe_token)
            .cloned()
        else {
            return Ok(());
        };

        let now = Instant::now();
        if pending.expires_at <= now
            || pending.requester_endpoint != requester_endpoint
            || pending.requester_node_id != sender_node_id
            || pending.trial_id != authorization.trial_id
            || pending.probe_class != authorization.class
            || pending.probe_token != authorization.probe_token
            || pending.helper_node_id != authorization.helper_node_id
            || authorization.target_node_id != sender_node_id
            || authorization.target_endpoint != pending.requester_endpoint.to_string()
            || authorization.coordinator_node_id != self.node_id()
        {
            return Ok(());
        }
        if !self.allow_filter_probe_auth_attempt(sender_node_id, now)
            || authorization.verify().is_err()
        {
            return Ok(());
        }

        match pending.probe_class {
            FilterProbeClass::ContactedEndpoint | FilterProbeClass::SameAddressDifferentPort => {
                let result = self.send_authorized_filter_probe(&authorization).await;
                self.pending_filter_consents
                    .remove(&authorization.probe_token);
                if let Err(failure) = result {
                    let _ = self
                        .send_secure_payload(
                            requester_endpoint,
                            SecurePayload::FilteringMatrixUnavailable {
                                trial_id: authorization.trial_id,
                                probe_class: authorization.class,
                                probe_token: authorization.probe_token,
                                failure,
                            },
                        )
                        .await;
                }
            }
            FilterProbeClass::DifferentAddress => {
                let Some(helper_endpoint) = pending.helper_endpoint else {
                    return Ok(());
                };
                if !self.confirmed_sessions.contains(&helper_endpoint)
                    || !self.peer_supports_feature(helper_endpoint, "filtering-matrix-v1")
                {
                    self.pending_filter_consents
                        .remove(&authorization.probe_token);
                    let _ = self
                        .send_secure_payload(
                            requester_endpoint,
                            SecurePayload::FilteringMatrixUnavailable {
                                trial_id: authorization.trial_id,
                                probe_class: authorization.class,
                                probe_token: authorization.probe_token,
                                failure: FilteringMatrixFailure::NoHelper,
                            },
                        )
                        .await;
                    return Ok(());
                }
                if self
                    .send_secure_payload(
                        helper_endpoint,
                        SecurePayload::FilteringMatrixSend { authorization },
                    )
                    .await
                    .is_err()
                {
                    self.pending_filter_consents.remove(&pending.probe_token);
                    let _ = self
                        .send_secure_payload(
                            requester_endpoint,
                            SecurePayload::FilteringMatrixUnavailable {
                                trial_id: pending.trial_id,
                                probe_class: pending.probe_class,
                                probe_token: pending.probe_token,
                                failure: FilteringMatrixFailure::SendFailed,
                            },
                        )
                        .await;
                }
            }
        }
        Ok(())
    }

    async fn handle_filtering_matrix_send(
        &mut self,
        coordinator: SocketAddr,
        coordinator_node_id: &str,
        authorization: FilteringMatrixAuthorization,
    ) -> Result<()> {
        let session_valid = self.confirmed_sessions.contains(&coordinator)
            && self.peer_supports_feature(coordinator, "filtering-matrix-v1");
        let relationship_valid = authorization.coordinator_node_id == coordinator_node_id
            && authorization.helper_node_id == self.node_id()
            && authorization.class == FilterProbeClass::DifferentAddress
            && self
                .peer_endpoint_by_node_id(&authorization.target_node_id)
                .is_none();
        let result = if !session_valid {
            Err(FilteringMatrixFailure::Unsupported)
        } else if !self.allow_filter_probe_auth_attempt(coordinator_node_id, Instant::now()) {
            Err(FilteringMatrixFailure::RateLimited)
        } else if !relationship_valid {
            Err(FilteringMatrixFailure::Unsupported)
        } else {
            self.send_authorized_filter_probe(&authorization).await
        };

        let (accepted, failure) = match result {
            Ok(()) => (true, None),
            Err(failure) => (false, Some(failure)),
        };
        if let Err(error) = self
            .send_secure_payload(
                coordinator,
                SecurePayload::FilteringMatrixSendResult {
                    trial_id: authorization.trial_id,
                    probe_class: authorization.class,
                    probe_token: authorization.probe_token,
                    accepted,
                    failure,
                },
            )
            .await
        {
            debug!(%coordinator, %error, "failed to return filtering helper send result");
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_filtering_matrix_send_result(
        &mut self,
        helper_endpoint: SocketAddr,
        helper_node_id: &str,
        trial_id: u64,
        probe_class: FilterProbeClass,
        probe_token: u64,
        accepted: bool,
        failure: Option<FilteringMatrixFailure>,
    ) -> Result<()> {
        let Some(pending) = self.pending_filter_consents.get(&probe_token).cloned() else {
            return Ok(());
        };
        if pending.trial_id != trial_id
            || pending.probe_class != probe_class
            || pending.probe_class != FilterProbeClass::DifferentAddress
            || pending.helper_endpoint != Some(helper_endpoint)
            || pending.helper_node_id != helper_node_id
            || pending.expires_at <= Instant::now()
            || accepted == failure.is_some()
        {
            return Ok(());
        }
        self.pending_filter_consents.remove(&probe_token);
        if !accepted {
            self.send_secure_payload(
                pending.requester_endpoint,
                SecurePayload::FilteringMatrixUnavailable {
                    trial_id,
                    probe_class,
                    probe_token,
                    failure: failure.unwrap_or(FilteringMatrixFailure::SendFailed),
                },
            )
            .await?;
        }
        Ok(())
    }

    fn handle_filtering_matrix_unavailable(
        &mut self,
        coordinator: SocketAddr,
        coordinator_node_id: &str,
        trial_id: u64,
        probe_class: FilterProbeClass,
        probe_token: u64,
        failure: FilteringMatrixFailure,
    ) {
        let Some(trial) = self.pending_filter_trials.get(&trial_id).cloned() else {
            return;
        };
        if trial.coordinator_endpoint != coordinator
            || trial.coordinator_node_id != coordinator_node_id
            || trial.expires_at <= Instant::now()
        {
            return;
        }

        let authorization = match self.pending_filter_probes.get(&probe_token) {
            Some(pending)
                if pending.authorization.trial_id == trial_id
                    && pending.authorization.class == probe_class =>
            {
                self.pending_filter_probes
                    .remove(&probe_token)
                    .map(|pending| pending.authorization)
            }
            Some(_) => return,
            None => FilteringMatrixAuthorization::signed(
                &self.identity,
                trial.target_endpoint,
                trial.coordinator_node_id.clone(),
                trial.coordinator_endpoint,
                trial.coordinator_node_id.clone(),
                probe_class,
                trial_id,
                probe_token,
            )
            .ok(),
        };
        let Some(authorization) = authorization else {
            return;
        };
        if let Some(trial) = self.pending_filter_trials.get_mut(&trial_id) {
            trial.seen_classes.insert(probe_class);
        }
        let outcome = if failure == FilteringMatrixFailure::SendFailed {
            FilterProbeOutcome::SendFailed
        } else {
            FilterProbeOutcome::Unavailable
        };
        if let Err(error) = self
            .nat_profile
            .record_filter_probe(&authorization, None, outcome)
        {
            debug!(%error, ?failure, "failed to record unavailable filtering matrix cell");
        }
    }

    async fn send_authorized_filter_probe(
        &mut self,
        authorization: &FilteringMatrixAuthorization,
    ) -> std::result::Result<(), FilteringMatrixFailure> {
        authorization
            .verify()
            .map_err(|_| FilteringMatrixFailure::Unsupported)?;
        if authorization.helper_node_id != self.node_id() {
            return Err(FilteringMatrixFailure::Unsupported);
        }
        let target = authorization
            .target_endpoint
            .parse::<SocketAddr>()
            .map_err(|_| FilteringMatrixFailure::UnsafeTarget)?;
        if !self.filter_probe_endpoint_allowed(target) {
            return Err(FilteringMatrixFailure::UnsafeTarget);
        }
        let use_key = FilterAuthorizationUseKey::from(authorization);
        let now = Instant::now();
        self.used_filter_authorizations
            .retain(|_, expires_at| *expires_at > now);
        if self.used_filter_authorizations.contains_key(&use_key) {
            return Err(FilteringMatrixFailure::Replay);
        }
        if self.used_filter_authorizations.len() >= MAX_USED_FILTER_AUTHORIZATIONS {
            return Err(FilteringMatrixFailure::Capacity);
        }
        if !self.allow_filter_probe(&authorization.coordinator_node_id, target, now) {
            return Err(FilteringMatrixFailure::RateLimited);
        }
        self.used_filter_authorizations
            .insert(use_key, now + FILTER_AUTHORIZATION_REPLAY_RETENTION);

        let body = MessageBody::FilteringMatrixProbe {
            trial_id: authorization.trial_id,
            probe_class: authorization.class,
            probe_token: authorization.probe_token,
        };
        let send = match authorization.class {
            FilterProbeClass::SameAddressDifferentPort => {
                self.send_from_alternate_port(target, body).await
            }
            FilterProbeClass::ContactedEndpoint | FilterProbeClass::DifferentAddress => {
                self.send(target, body).await
            }
        };
        send.map_err(|_| FilteringMatrixFailure::SendFailed)
    }

    fn allow_filter_probe_auth_attempt(&mut self, sender_node_id: &str, now: Instant) -> bool {
        self.filter_probe_auth_attempt_windows.retain(|_, window| {
            now.checked_duration_since(window.last_seen)
                .is_some_and(|age| age < FILTER_PROBE_RATE_RETENTION)
        });
        let sender_count = self
            .filter_probe_auth_attempt_windows
            .get(sender_node_id)
            .map_or(0, |window| window.count_at(now));
        if sender_count >= FILTER_PROBE_AUTH_ATTEMPT_LIMIT
            || self.filter_probe_auth_attempt_global_window.count_at(now)
                >= FILTER_PROBE_AUTH_ATTEMPT_GLOBAL_LIMIT
            || (!self
                .filter_probe_auth_attempt_windows
                .contains_key(sender_node_id)
                && self.filter_probe_auth_attempt_windows.len() >= MAX_FILTER_PROBE_RATE_STATES)
        {
            return false;
        }

        self.filter_probe_auth_attempt_windows
            .entry(sender_node_id.to_owned())
            .or_insert_with(|| FilterProbeRateWindow::new(now))
            .increment_at(now);
        self.filter_probe_auth_attempt_global_window
            .increment_at(now);
        true
    }

    async fn send_from_alternate_port(
        &mut self,
        target: SocketAddr,
        body: MessageBody,
    ) -> Result<()> {
        let bind = match target {
            SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        };
        let socket = UdpSocket::bind(bind).await.with_context(|| {
            format!("failed to bind alternate filtering probe socket at {bind}")
        })?;
        let envelope = WireEnvelope::signed(&self.identity, random(), body)?;
        let bytes = envelope.encode()?;
        self.remember_filter_contact(target.ip(), Instant::now());
        socket.send_to(&bytes, target).await.with_context(|| {
            format!("failed to send alternate-port filtering probe to {target}")
        })?;
        Ok(())
    }

    fn allow_filter_probe(
        &mut self,
        coordinator_node_id: &str,
        target: SocketAddr,
        now: Instant,
    ) -> bool {
        self.filter_probe_coordinator_windows.retain(|_, window| {
            now.checked_duration_since(window.last_seen)
                .is_some_and(|age| age < FILTER_PROBE_RATE_RETENTION)
        });
        self.filter_probe_target_windows.retain(|_, window| {
            now.checked_duration_since(window.last_seen)
                .is_some_and(|age| age < FILTER_PROBE_RATE_RETENTION)
        });
        let target_group = dht_network_group(target.ip());
        let coordinator_count = self
            .filter_probe_coordinator_windows
            .get(coordinator_node_id)
            .map_or(0, |window| window.count_at(now));
        let target_count = self
            .filter_probe_target_windows
            .get(&target_group)
            .map_or(0, |window| window.count_at(now));
        if coordinator_count >= FILTER_PROBE_COORDINATOR_LIMIT
            || target_count >= FILTER_PROBE_TARGET_GROUP_LIMIT
            || self.filter_probe_global_window.count_at(now) >= FILTER_PROBE_GLOBAL_LIMIT
            || (!self
                .filter_probe_coordinator_windows
                .contains_key(coordinator_node_id)
                && self.filter_probe_coordinator_windows.len() >= MAX_FILTER_PROBE_RATE_STATES)
            || (!self.filter_probe_target_windows.contains_key(&target_group)
                && self.filter_probe_target_windows.len() >= MAX_FILTER_PROBE_RATE_STATES)
        {
            return false;
        }

        self.filter_probe_coordinator_windows
            .entry(coordinator_node_id.to_owned())
            .or_insert_with(|| FilterProbeRateWindow::new(now))
            .increment_at(now);
        self.filter_probe_target_windows
            .entry(target_group)
            .or_insert_with(|| FilterProbeRateWindow::new(now))
            .increment_at(now);
        self.filter_probe_global_window.increment_at(now);
        true
    }

    fn filter_probe_endpoint_allowed(&self, endpoint: SocketAddr) -> bool {
        endpoint_publishable(endpoint)
            || (self.local_test_mode && endpoint.port() != 0 && endpoint.ip().is_loopback())
    }

    fn remember_filter_contact(&mut self, ip: IpAddr, now: Instant) {
        let ip = normalized_ip(ip);
        if let Some(contacted_at) = self.recent_egress_ips.get_mut(&ip) {
            *contacted_at = now;
            return;
        }
        if self.recent_egress_ips.len() >= MAX_FILTER_CONTACT_HISTORY {
            let saturated_until = now + FILTER_CONTACT_HISTORY_TTL;
            self.filter_contact_history_saturated_until = Some(
                self.filter_contact_history_saturated_until
                    .map_or(saturated_until, |existing| existing.max(saturated_until)),
            );
            return;
        }
        self.recent_egress_ips.insert(ip, now);
    }

    fn filter_probe_source_was_contacted(&self, ip: IpAddr, now: Instant) -> bool {
        self.filter_contact_history_saturated_until
            .is_some_and(|saturated_until| saturated_until > now)
            || self
                .recent_egress_ips
                .get(&normalized_ip(ip))
                .and_then(|contacted_at| now.checked_duration_since(*contacted_at))
                .is_some_and(|age| age < FILTER_CONTACT_HISTORY_TTL)
    }

    fn expire_filtering_matrix_state(&mut self) {
        let now = Instant::now();
        let expired_probes: Vec<u64> = self
            .pending_filter_probes
            .iter()
            .filter(|(_, pending)| pending.expires_at <= now)
            .map(|(token, _)| *token)
            .collect();
        for token in expired_probes {
            if let Some(pending) = self.pending_filter_probes.remove(&token) {
                // The wire authorization is intentionally short lived. Refresh only
                // its timestamped signature before recording the local timeout; all
                // trial, endpoint, helper, class, and token bindings stay identical.
                let authorization = pending.authorization;
                let refreshed = authorization
                    .target_endpoint
                    .parse::<SocketAddr>()
                    .ok()
                    .zip(
                        authorization
                            .coordinator_baseline_endpoint
                            .parse::<SocketAddr>()
                            .ok(),
                    )
                    .and_then(|(target_endpoint, coordinator_baseline_endpoint)| {
                        FilteringMatrixAuthorization::signed(
                            &self.identity,
                            target_endpoint,
                            authorization.coordinator_node_id,
                            coordinator_baseline_endpoint,
                            authorization.helper_node_id,
                            authorization.class,
                            authorization.trial_id,
                            authorization.probe_token,
                        )
                        .ok()
                    });
                let Some(refreshed) = refreshed else {
                    debug!(
                        probe_token = token,
                        "failed to refresh filtering matrix timeout authorization"
                    );
                    continue;
                };
                if let Err(error) = self.nat_profile.record_filter_probe(
                    &refreshed,
                    None,
                    FilterProbeOutcome::TimedOut,
                ) {
                    debug!(%error, probe_token = token, "failed to record filtering matrix timeout");
                }
            }
        }

        self.pending_filter_consents
            .retain(|_, pending| pending.expires_at > now);
        self.used_filter_authorizations
            .retain(|_, expires_at| *expires_at > now);
        self.filter_probe_auth_attempt_windows.retain(|_, window| {
            now.checked_duration_since(window.last_seen)
                .is_some_and(|age| age < FILTER_PROBE_RATE_RETENTION)
        });
        self.filter_probe_coordinator_windows.retain(|_, window| {
            now.checked_duration_since(window.last_seen)
                .is_some_and(|age| age < FILTER_PROBE_RATE_RETENTION)
        });
        self.filter_probe_target_windows.retain(|_, window| {
            now.checked_duration_since(window.last_seen)
                .is_some_and(|age| age < FILTER_PROBE_RATE_RETENTION)
        });
        self.recent_egress_ips.retain(|_, contacted_at| {
            now.checked_duration_since(*contacted_at)
                .is_some_and(|age| age < FILTER_CONTACT_HISTORY_TTL)
        });
        if self
            .filter_contact_history_saturated_until
            .is_some_and(|saturated_until| saturated_until <= now)
        {
            self.filter_contact_history_saturated_until = None;
        }

        let expired_trials: Vec<u64> = self
            .pending_filter_trials
            .iter()
            .filter(|(_, trial)| trial.expires_at <= now)
            .map(|(trial_id, _)| *trial_id)
            .collect();
        for trial_id in expired_trials {
            let Some(trial) = self.pending_filter_trials.remove(&trial_id) else {
                continue;
            };
            for probe_class in [
                FilterProbeClass::ContactedEndpoint,
                FilterProbeClass::SameAddressDifferentPort,
                FilterProbeClass::DifferentAddress,
            ] {
                if trial.seen_classes.contains(&probe_class) {
                    continue;
                }
                let Ok(authorization) = FilteringMatrixAuthorization::signed(
                    &self.identity,
                    trial.target_endpoint,
                    trial.coordinator_node_id.clone(),
                    trial.coordinator_endpoint,
                    trial.coordinator_node_id.clone(),
                    probe_class,
                    trial_id,
                    random(),
                ) else {
                    continue;
                };
                if let Err(error) = self.nat_profile.record_filter_probe(
                    &authorization,
                    None,
                    FilterProbeOutcome::TimedOut,
                ) {
                    debug!(%error, trial_id, ?probe_class, "failed to record missing filtering matrix proposal");
                }
            }
        }
        self.nat_profile.expire_filter_matrix_at(Instant::now());
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
                match self.activate_dht_record(&record).await {
                    Ok(true) => continue,
                    Ok(false) => {}
                    Err(error) => {
                        debug!(target = %target_node_id, %error, "cached exact DHT activation failed");
                    }
                }
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

            let eligible: Vec<_> = self
                .routing
                .nearest(&target_node_id, self.routing.len())
                .into_iter()
                .filter(|candidate| self.sessions.contains_key(&candidate.endpoint))
                .collect();
            let candidates = prioritize_network_group_diversity(eligible);
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
                    expected_responders: HashMap::new(),
                    expires_at: now + DHT_QUERY_TIMEOUT,
                },
            );
            self.seen_dht_queries
                .insert(query_key, now + DHT_QUERY_TIMEOUT);
            self.last_dht_query_start
                .insert(target_node_id.clone(), now);

            let mut sent = 0_usize;
            for candidate in candidates {
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
                    Ok(()) => {
                        sent += 1;
                        if let Some(query) = self.active_dht_queries.get_mut(&query_id) {
                            query.expected_responders.insert(candidate.endpoint, 0);
                        }
                        if sent >= DHT_QUERY_FANOUT {
                            break;
                        }
                    }
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

    fn build_own_dht_record(&mut self) -> Result<Option<PeerRecord>> {
        let Some(endpoint) = self.nat_profile.preferred_endpoint() else {
            self.own_dht_record = None;
            return Ok(None);
        };
        if !dht_endpoint_publishable(endpoint) {
            self.own_dht_record = None;
            return Ok(None);
        }

        let now = Instant::now();
        if let Some(cached) = &self.own_dht_record {
            if cached.endpoint == endpoint
                && now.duration_since(cached.created_at) < OWN_DHT_RECORD_REFRESH_INTERVAL
                && cached.record.verify().is_ok()
            {
                return Ok(Some(cached.record.clone()));
            }
        }

        let record = match &self.own_dht_record {
            Some(previous) => {
                PeerRecord::signed_after(&self.identity, vec![endpoint], previous.record.sequence)?
            }
            None => PeerRecord::signed(&self.identity, vec![endpoint])?,
        };
        self.own_dht_record = Some(OwnDhtRecord {
            record: record.clone(),
            endpoint,
            created_at: now,
        });
        Ok(Some(record))
    }

    async fn sync_dht_peer(&mut self, peer: SocketAddr) -> Result<()> {
        self.issue_endpoint_attestation(peer).await?;

        if let Some(peer_node_id) = self.peers.get(&peer).map(|info| info.node_id.clone()) {
            for history in self.dht_replication_history.values_mut() {
                history.target_node_ids.remove(&peer_node_id);
            }
        }
        self.queue_own_dht_publication_to(peer)?;
        self.queue_own_dht_publication()?;

        for target_node_id in self.pending_dht_queries.clone() {
            self.last_dht_query_start.remove(&target_node_id);
        }

        self.sync_dht_replicas(peer);

        Ok(())
    }

    fn sync_dht_replicas(&mut self, peer: SocketAddr) {
        let Some(peer_info) = self.peers.get(&peer) else {
            return;
        };
        if !peer_info.features.contains("bounded-dht-replication-v1") {
            return;
        }
        let peer_node_id = peer_info.node_id.clone();
        let local_node_id = self.node_id();
        let records = self.dht.nearest(&peer_node_id, DHT_SYNC_REPLICA_LIMIT + 2);
        let mut sent = 0_usize;

        for record in records {
            if record.node_id == local_node_id || !self.record_has_attested_endpoint(&record) {
                continue;
            }
            let attestations = self
                .endpoint_attestations
                .for_record(&record, DHT_ATTESTATION_RESPONSE_LIMIT);
            if self.queue_dht_replication(
                peer,
                peer_node_id.clone(),
                record,
                attestations,
                0,
                DhtReplicationKind::Sync,
            ) {
                sent += 1;
            }
            if sent >= DHT_SYNC_REPLICA_LIMIT {
                break;
            }
        }
    }

    async fn issue_endpoint_attestation(&mut self, peer: SocketAddr) -> Result<()> {
        if !dht_endpoint_publishable(peer) {
            return Ok(());
        }
        let Some(peer_node_id) = self.peers.get(&peer).map(|info| info.node_id.clone()) else {
            return Ok(());
        };
        if !self.peer_supports_feature(peer, "endpoint-attestations-v1") {
            return Ok(());
        }

        let attestation = EndpointAttestation::signed(&self.identity, peer_node_id, peer)?;
        self.endpoint_attestations.upsert(attestation.clone())?;
        self.send_secure_payload(peer, SecurePayload::DhtAttestation { attestation })
            .await?;
        self.last_endpoint_attestation_refresh
            .insert(peer, Instant::now());
        Ok(())
    }

    async fn refresh_endpoint_attestations(&mut self) {
        let now = Instant::now();
        let mut due: Vec<SocketAddr> = self
            .confirmed_sessions
            .iter()
            .copied()
            .filter(|peer| {
                dht_endpoint_publishable(*peer)
                    && self
                        .last_endpoint_attestation_refresh
                        .get(peer)
                        .is_none_or(|last| {
                            now.duration_since(*last) >= ENDPOINT_ATTESTATION_REFRESH_INTERVAL
                        })
            })
            .collect();
        due.sort_unstable();
        due.truncate(MAX_ENDPOINT_ATTESTATION_REFRESHES_PER_TICK);

        for peer in due {
            if let Err(error) = self.issue_endpoint_attestation(peer).await {
                debug!(%peer, %error, "endpoint attestation refresh failed");
            }
        }
    }

    async fn activate_dht_record(&mut self, record: &PeerRecord) -> Result<bool> {
        if !self.pending_dht_queries.contains(&record.node_id) {
            return Ok(false);
        }

        let attested_endpoints = self
            .endpoint_attestations
            .attested_endpoints(record, MIN_ENDPOINT_ATTESTATION_OBSERVERS);
        if attested_endpoints.is_empty() {
            debug!(
                target = %record.node_id,
                "deferred DHT activation without independent endpoint attestation"
            );
            return Ok(false);
        }

        if !self.connect_candidate_groups.contains_key(&record.node_id)
            && self.connect_candidate_groups.len() >= MAX_ACTIVE_CANDIDATE_GROUPS
        {
            return Ok(false);
        }
        let candidates: Vec<SocketAddr> = attested_endpoints
            .into_iter()
            .filter(|endpoint| {
                !self.connect_candidate_groups.iter().any(|(target, other)| {
                    target != &record.node_id && other.candidates().contains(endpoint)
                }) && self
                    .discovery_candidates
                    .get(endpoint)
                    .is_none_or(|candidate| candidate.expected_node_id == record.node_id)
            })
            .collect();
        if candidates.is_empty() {
            return Ok(false);
        }
        if let Some(group) = self.connect_candidate_groups.get_mut(&record.node_id) {
            group.extend(candidates);
        } else {
            self.connect_candidate_groups.insert(
                record.node_id.clone(),
                CandidateGroup::new(candidates, Instant::now()),
            );
        }
        Ok(true)
    }

    fn record_has_attested_endpoint(&self, record: &PeerRecord) -> bool {
        !self
            .endpoint_attestations
            .attested_endpoints(record, MIN_ENDPOINT_ATTESTATION_OBSERVERS)
            .is_empty()
    }

    fn attestations_for_records(&self, records: &[PeerRecord]) -> Vec<EndpointAttestation> {
        let mut attestations = Vec::new();
        for record in records {
            let remaining = DHT_ATTESTATION_RESPONSE_LIMIT.saturating_sub(attestations.len());
            if remaining == 0 {
                break;
            }
            attestations.extend(self.endpoint_attestations.for_record(record, remaining));
        }
        attestations
    }

    fn queue_own_dht_publication(&mut self) -> Result<()> {
        let Some(record) = self.build_own_dht_record()? else {
            return Ok(());
        };
        if !self.record_has_attested_endpoint(&record) {
            return Ok(());
        }

        let attestations = self
            .endpoint_attestations
            .for_record(&record, DHT_ATTESTATION_RESPONSE_LIMIT);
        if self
            .dht_replication_history
            .get(&(record.node_id.clone(), record.sequence))
            .is_some_and(|history| {
                history.owner_target_node_ids.len() >= DHT_OWNER_REPLICATION_RESERVE
            })
        {
            return Ok(());
        }
        let local_node_id = self.node_id();
        let eligible: Vec<_> = self
            .routing
            .nearest(&local_node_id, self.routing.len())
            .into_iter()
            .filter(|candidate| {
                self.confirmed_sessions.contains(&candidate.endpoint)
                    && self.peer_supports_feature(candidate.endpoint, "bounded-dht-replication-v1")
            })
            .collect();
        let candidates = prioritize_network_group_diversity(eligible);
        let mut queued = 0_usize;
        for candidate in candidates {
            if self.queue_dht_replication(
                candidate.endpoint,
                candidate.node_id,
                record.clone(),
                attestations.clone(),
                DHT_REPLICATION_MAX_HOPS,
                DhtReplicationKind::Owner,
            ) {
                queued += 1;
            }
            if queued >= DHT_BUCKET_SIZE {
                break;
            }
        }
        Ok(())
    }

    fn queue_own_dht_publication_to(&mut self, peer: SocketAddr) -> Result<()> {
        if !self.confirmed_sessions.contains(&peer) {
            return Ok(());
        }
        let Some(peer_node_id) = self.peers.get(&peer).map(|info| info.node_id.clone()) else {
            return Ok(());
        };
        let Some(record) = self.build_own_dht_record()? else {
            return Ok(());
        };
        if !self.record_has_attested_endpoint(&record) {
            return Ok(());
        }
        let attestations = self
            .endpoint_attestations
            .for_record(&record, DHT_ATTESTATION_RESPONSE_LIMIT);
        let replication_hops_remaining =
            if self.peer_supports_feature(peer, "bounded-dht-replication-v1") {
                DHT_REPLICATION_MAX_HOPS
            } else {
                0
            };
        self.queue_dht_replication(
            peer,
            peer_node_id,
            record,
            attestations,
            replication_hops_remaining,
            DhtReplicationKind::Owner,
        );
        Ok(())
    }

    fn replicate_dht_record(
        &mut self,
        source: SocketAddr,
        record: &PeerRecord,
        replication_hops_remaining: u8,
    ) {
        if !self.record_has_attested_endpoint(record) {
            return;
        }
        let attestations = self
            .endpoint_attestations
            .for_record(record, DHT_ATTESTATION_RESPONSE_LIMIT);
        let local_node_id = self.node_id();
        let eligible: Vec<_> = self
            .routing
            .nearest(&record.node_id, self.routing.len())
            .into_iter()
            .filter(|candidate| {
                candidate.endpoint != source
                    && candidate.node_id != record.node_id
                    && node_id_closer_to_target(&candidate.node_id, &local_node_id, &record.node_id)
                    && self.confirmed_sessions.contains(&candidate.endpoint)
                    && self.peer_supports_feature(candidate.endpoint, "bounded-dht-replication-v1")
            })
            .collect();
        let candidates = prioritize_network_group_diversity(eligible);
        let mut queued = 0_usize;

        for candidate in candidates {
            if self.queue_dht_replication(
                candidate.endpoint,
                candidate.node_id,
                record.clone(),
                attestations.clone(),
                replication_hops_remaining,
                DhtReplicationKind::Transit,
            ) {
                queued += 1;
            }
            if queued >= DHT_REPLICATION_FANOUT {
                break;
            }
        }
    }

    fn queue_dht_replication(
        &mut self,
        target: SocketAddr,
        target_node_id: String,
        record: PeerRecord,
        attestations: Vec<EndpointAttestation>,
        replication_hops_remaining: u8,
        kind: DhtReplicationKind,
    ) -> bool {
        let owner_priority = kind == DhtReplicationKind::Owner;
        let transit_forward = kind == DhtReplicationKind::Transit;
        let queue_limit = if owner_priority {
            MAX_PENDING_DHT_REPLICATIONS
        } else {
            MAX_PENDING_DHT_REPLICATIONS.saturating_sub(DHT_OWNER_REPLICATION_RESERVE)
        };
        if self.pending_dht_replications.len() >= queue_limit
            || record.verify().is_err()
            || attestations.len() > DHT_ATTESTATION_RESPONSE_LIMIT
        {
            return false;
        }

        let now = Instant::now();
        self.dht_replication_history
            .retain(|(node_id, sequence), history| {
                history.expires_at > now
                    && (node_id != &record.node_id || *sequence == record.sequence)
            });
        let key = (record.node_id.clone(), record.sequence);
        if !self.dht_replication_history.contains_key(&key)
            && self.dht_replication_history.len() >= MAX_DHT_REPLICATION_HISTORY
        {
            return false;
        }
        let history =
            self.dht_replication_history
                .entry(key)
                .or_insert_with(|| DhtReplicationHistory {
                    target_node_ids: HashSet::new(),
                    transit_target_node_ids: HashSet::new(),
                    owner_target_node_ids: HashSet::new(),
                    expires_at: now + Duration::from_secs(30 * 60),
                });
        if history.target_node_ids.contains(&target_node_id)
            || (transit_forward
                && !history.transit_target_node_ids.contains(&target_node_id)
                && history.transit_target_node_ids.len() >= DHT_REPLICATION_FANOUT)
            || (owner_priority
                && !history.owner_target_node_ids.contains(&target_node_id)
                && history.owner_target_node_ids.len() >= DHT_OWNER_REPLICATION_RESERVE)
        {
            return false;
        }
        history.target_node_ids.insert(target_node_id.clone());
        if transit_forward {
            history
                .transit_target_node_ids
                .insert(target_node_id.clone());
        }
        if owner_priority {
            history.owner_target_node_ids.insert(target_node_id.clone());
        }

        let pending = PendingDhtReplication {
            target,
            target_node_id,
            record,
            attestations,
            replication_hops_remaining,
            kind,
        };
        if owner_priority {
            self.pending_dht_replications.push_front(pending);
        } else {
            self.pending_dht_replications.push_back(pending);
        }
        true
    }

    async fn drive_dht_replications(&mut self) {
        let mut sent_targets = HashSet::new();
        let mut inspected = 0_usize;
        let initial_len = self.pending_dht_replications.len();

        while sent_targets.len() < DHT_REPLICATION_BURST_PER_TICK && inspected < initial_len {
            let Some(pending) = self.pending_dht_replications.pop_front() else {
                break;
            };
            inspected += 1;
            if !sent_targets.insert(pending.target) {
                self.pending_dht_replications.push_back(pending);
                continue;
            }

            let current_record = if pending.record.node_id == self.node_id() {
                self.own_dht_record.as_ref().is_some_and(|current| {
                    current.record.sequence == pending.record.sequence
                        && current.record.signature == pending.record.signature
                })
            } else {
                self.dht.get(&pending.record.node_id).is_some_and(|record| {
                    record.sequence == pending.record.sequence
                        && record.signature == pending.record.signature
                })
            };
            let eligible = current_record
                && pending.record.verify().is_ok()
                && self.record_has_attested_endpoint(&pending.record)
                && self.confirmed_sessions.contains(&pending.target)
                && (pending.replication_hops_remaining == 0
                    || self.peer_supports_feature(pending.target, "bounded-dht-replication-v1"));
            if !eligible {
                if let Some(history) = self
                    .dht_replication_history
                    .get_mut(&(pending.record.node_id.clone(), pending.record.sequence))
                {
                    history.target_node_ids.remove(&pending.target_node_id);
                    if pending.kind == DhtReplicationKind::Transit {
                        history
                            .transit_target_node_ids
                            .remove(&pending.target_node_id);
                    }
                    if pending.kind == DhtReplicationKind::Owner {
                        history
                            .owner_target_node_ids
                            .remove(&pending.target_node_id);
                    }
                }
                continue;
            }

            let result = self
                .send_secure_payload(
                    pending.target,
                    SecurePayload::DhtStore {
                        record: pending.record.clone(),
                        attestations: pending.attestations,
                        replication_hops_remaining: pending.replication_hops_remaining,
                    },
                )
                .await;
            if let Err(error) = result {
                if let Some(history) = self
                    .dht_replication_history
                    .get_mut(&(pending.record.node_id.clone(), pending.record.sequence))
                {
                    history.target_node_ids.remove(&pending.target_node_id);
                    if pending.kind == DhtReplicationKind::Transit {
                        history
                            .transit_target_node_ids
                            .remove(&pending.target_node_id);
                    }
                    if pending.kind == DhtReplicationKind::Owner {
                        history
                            .owner_target_node_ids
                            .remove(&pending.target_node_id);
                    }
                }
                debug!(
                    target = %pending.target,
                    peer = %pending.target_node_id,
                    %error,
                    "DHT replication send failed"
                );
            }
        }
    }

    fn accept_dht_response(
        &mut self,
        query_id: u64,
        origin_node_id: &str,
        target_node_id: &str,
        source: SocketAddr,
        now: Instant,
    ) -> bool {
        if origin_node_id == self.node_id() {
            let Some(query) = self.active_dht_queries.get_mut(&query_id) else {
                return false;
            };
            if query.expires_at <= now || query.target_node_id != target_node_id {
                return false;
            }
            let Some(responses) = query.expected_responders.get_mut(&source) else {
                return false;
            };
            if *responses >= MAX_DHT_RESPONSES_PER_PEER_QUERY {
                return false;
            }
            *responses += 1;
            return true;
        }

        let Some(route) = self
            .reverse_dht_routes
            .get_mut(&(origin_node_id.to_owned(), query_id))
        else {
            return false;
        };
        if route.expires_at <= now || route.target_node_id != target_node_id {
            return false;
        }
        let Some(responses) = route.expected_responders.get_mut(&source) else {
            return false;
        };
        if *responses >= MAX_DHT_RESPONSES_PER_PEER_QUERY {
            return false;
        }
        *responses += 1;
        true
    }

    fn allow_dht_query(&mut self, sender_node_id: &str, source: SocketAddr, now: Instant) -> bool {
        let peer_key = sender_node_id.to_owned();
        let prefix_key = dht_network_group(source.ip());
        if (!self.dht_query_peer_buckets.contains_key(&peer_key)
            && self.dht_query_peer_buckets.len() >= MAX_DHT_QUERY_PEER_BUCKETS)
            || (!self.dht_query_prefix_buckets.contains_key(&prefix_key)
                && self.dht_query_prefix_buckets.len() >= MAX_DHT_QUERY_PREFIX_BUCKETS)
        {
            return false;
        }

        let mut peer = self
            .dht_query_peer_buckets
            .get(&peer_key)
            .cloned()
            .unwrap_or_else(|| DhtQueryTokenBucket::full(DHT_QUERY_PEER_BURST, now));
        let mut prefix = self
            .dht_query_prefix_buckets
            .get(&prefix_key)
            .cloned()
            .unwrap_or_else(|| DhtQueryTokenBucket::full(DHT_QUERY_PREFIX_BURST, now));
        let mut global = self.dht_query_global_bucket.clone();

        if !peer.try_take(DHT_QUERY_PEER_BURST, DHT_QUERY_PEER_REFILL, now)
            || !prefix.try_take(DHT_QUERY_PREFIX_BURST, DHT_QUERY_PREFIX_REFILL, now)
            || !global.try_take(DHT_QUERY_GLOBAL_BURST, DHT_QUERY_GLOBAL_REFILL, now)
        {
            return false;
        }

        self.dht_query_peer_buckets.insert(peer_key, peer);
        self.dht_query_prefix_buckets.insert(prefix_key, prefix);
        self.dht_query_global_bucket = global;
        true
    }

    fn expire_dht_query_guard_at(&mut self, now: Instant) {
        self.dht_query_peer_buckets
            .retain(|_, bucket| now.duration_since(bucket.last_seen) < DHT_QUERY_GUARD_RETENTION);
        self.dht_query_prefix_buckets
            .retain(|_, bucket| now.duration_since(bucket.last_seen) < DHT_QUERY_GUARD_RETENTION);
        self.last_dht_forward
            .retain(|_, last| now.duration_since(*last) < DHT_QUERY_GUARD_RETENTION);
    }

    fn allow_dht_record_admission(
        &mut self,
        sender_node_id: &str,
        source: SocketAddr,
        cost: u16,
        now: Instant,
    ) -> bool {
        let keys = [
            (
                format!("peer:{sender_node_id}"),
                MAX_DHT_RECORDS_PER_PEER_WINDOW,
            ),
            (
                format!("prefix:{}", dht_network_group(source.ip())),
                MAX_DHT_RECORDS_PER_PREFIX_WINDOW,
            ),
            ("global".to_owned(), MAX_DHT_RECORDS_GLOBAL_WINDOW),
        ];
        let missing = keys
            .iter()
            .filter(|(key, _)| !self.dht_replication_rate_windows.contains_key(key))
            .count();
        if self
            .dht_replication_rate_windows
            .len()
            .saturating_add(missing)
            > MAX_DHT_REPLICATION_RATE_WINDOWS
        {
            return false;
        }

        for (key, limit) in &keys {
            let events = self
                .dht_replication_rate_windows
                .get(key)
                .filter(|window| {
                    now.duration_since(window.started_at) < DHT_REPLICATION_RATE_WINDOW
                })
                .map_or(0, |window| window.events);
            if events.saturating_add(cost) > *limit {
                return false;
            }
        }

        for (key, _) in keys {
            let window =
                self.dht_replication_rate_windows
                    .entry(key)
                    .or_insert(DhtReplicationRateWindow {
                        started_at: now,
                        events: 0,
                        last_seen: now,
                    });
            if now.duration_since(window.started_at) >= DHT_REPLICATION_RATE_WINDOW {
                window.started_at = now;
                window.events = 0;
            }
            window.events = window.events.saturating_add(cost);
            window.last_seen = now;
        }
        true
    }

    fn store_dht_attestations(&mut self, attestations: Vec<EndpointAttestation>) -> usize {
        let mut stored = 0_usize;
        for attestation in attestations {
            let matches_current_record = self
                .dht
                .get(&attestation.subject_node_id)
                .is_some_and(|record| record.endpoints.contains(&attestation.endpoint));
            if !matches_current_record {
                continue;
            }

            match self.endpoint_attestations.upsert(attestation) {
                Ok(true) => stored += 1,
                Ok(false) => {}
                Err(error) => debug!(%error, "rejected DHT endpoint attestation"),
            }
        }
        stored
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

    fn rendezvous_candidate_allowed(&self, endpoint: SocketAddr) -> bool {
        PunchSchedule::candidate_allowed(endpoint)
            || (self.local_test_mode && endpoint.port() != 0 && endpoint.ip().is_loopback())
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
                let sibling_active = self
                    .pending_punches
                    .values()
                    .any(|other| other.expected_node_id() == target_node_id);
                let auto_managed = self.auto_rendezvous.contains_key(&target_node_id);

                if !auto_managed
                    && !sibling_active
                    && local_node_id.as_str() < target_node_id.as_str()
                    && self.direct_app_endpoint_for_peer(&target_node_id).is_none()
                {
                    self.schedule_auto_relay_fallback(
                        target_node_id.clone(),
                        relay_candidate,
                        Instant::now(),
                    );
                    relay_scheduled = true;
                }

                if let Some(state) = self.auto_rendezvous.get_mut(&target_node_id) {
                    state.hurry(Instant::now());
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

    fn has_usable_relay_path_for_peer(&self, peer_node_id: &str, now: Instant) -> bool {
        self.relay_e2e_sessions.keys().any(|key| {
            self.relay_paths
                .get(key)
                .is_some_and(|path| path.peer_node_id == peer_node_id && path.expires_at > now)
        })
    }

    fn schedule_auto_relay_failover(
        &mut self,
        target_node_id: String,
        failed_relay: SocketAddr,
        now: Instant,
    ) {
        self.schedule_auto_relay_fallback(target_node_id.clone(), None, now);
        if let Some(state) = self.auto_relay_fallbacks.get_mut(&target_node_id) {
            state.tried.insert(failed_relay);
            state.next_attempt_at = now;
        }
    }

    fn schedule_auto_relay_failover_if_needed(
        &mut self,
        target_node_id: String,
        failed_relay: SocketAddr,
        now: Instant,
    ) -> bool {
        if self.direct_app_endpoint_for_peer(&target_node_id).is_some()
            || self.has_usable_relay_path_for_peer(&target_node_id, now)
        {
            self.auto_relay_fallbacks.remove(&target_node_id);
            return false;
        }

        self.schedule_auto_relay_failover(target_node_id, failed_relay, now);
        true
    }

    async fn drive_auto_relay_fallbacks(&mut self) {
        let now = Instant::now();
        let targets: Vec<String> = self.auto_relay_fallbacks.keys().cloned().collect();

        for target_node_id in targets {
            if self.direct_app_endpoint_for_peer(&target_node_id).is_some()
                || self.has_usable_relay_path_for_peer(&target_node_id, now)
            {
                self.auto_relay_fallbacks.remove(&target_node_id);
                continue;
            }

            if self
                .pending_punches
                .values()
                .any(|schedule| schedule.expected_node_id() == target_node_id)
                || self
                    .pending_sessions
                    .values()
                    .any(|attempt| attempt.peer_node_id == target_node_id)
                || self.connect_candidate_groups.contains_key(&target_node_id)
                || self.auto_rendezvous.contains_key(&target_node_id)
            {
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
            .filter(|(_, peer)| peer.node_id == node_id)
            .min_by_key(|(endpoint, _)| {
                (
                    if self.confirmed_sessions.contains(*endpoint) {
                        0_u8
                    } else {
                        1_u8
                    },
                    if is_native_ipv6_endpoint(**endpoint) {
                        0_u8
                    } else {
                        1_u8
                    },
                    **endpoint,
                )
            })
            .map(|(endpoint, _)| *endpoint)
    }

    fn peer_supports_feature(&self, endpoint: SocketAddr, feature: &str) -> bool {
        self.peers
            .get(&endpoint)
            .is_some_and(|peer| peer.features.contains(feature))
    }

    fn is_expected_endpoint(&self, source: SocketAddr) -> bool {
        self.bootstrap_peers.contains(&source)
            || self.peers.contains_key(&source)
            || self.cookie_cache.contains_key(&source)
            || self.discovery_candidates.contains_key(&source)
    }

    fn is_expected_peer(&self, source: SocketAddr, node_id: &str) -> bool {
        self.is_expected_endpoint(source) && self.discovery_identity_matches(source, node_id)
    }

    fn discovery_identity_matches(&self, source: SocketAddr, node_id: &str) -> bool {
        self.peers
            .get(&source)
            .is_none_or(|peer| peer.node_id == node_id)
            && self
                .discovery_candidates
                .get(&source)
                .is_none_or(|candidate| candidate.expected_node_id == node_id)
    }

    fn record_peer(&mut self, envelope: &WireEnvelope, source: SocketAddr) {
        let previous_endpoint = self
            .peers
            .iter()
            .find(|(endpoint, peer)| {
                **endpoint != source
                    && peer.node_id == envelope.sender_node_id
                    && is_native_ipv6_endpoint(**endpoint) == is_native_ipv6_endpoint(source)
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
                features: HashSet::new(),
            });
    }

    fn complete_direct_candidate_target(&mut self, peer_node_id: &str) {
        if let Some(mut group) = self.connect_candidate_groups.remove(peer_node_id) {
            group.complete();
            for endpoint in group.candidates() {
                self.discovery_candidates.remove(endpoint);
            }
        }

        let cancelled_punches: Vec<u64> = self
            .pending_punches
            .iter()
            .filter_map(|(token, schedule)| {
                (schedule.expected_node_id() == peer_node_id).then_some(*token)
            })
            .collect();
        for token in cancelled_punches {
            self.pending_punches.remove(&token);
            self.punch_relay_candidates.remove(&token);
        }

        self.pending_sessions
            .retain(|_, attempt| attempt.peer_node_id != peer_node_id);
        self.pending_relay_requests
            .retain(|_, (_, target)| target != peer_node_id);
        self.pending_dht_queries.remove(peer_node_id);
        self.active_dht_queries
            .retain(|_, query| query.target_node_id != peer_node_id);
        self.last_dht_query_start.remove(peer_node_id);
        self.auto_rendezvous.remove(peer_node_id);
        self.auto_relay_fallbacks.remove(peer_node_id);
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

    async fn refresh_discovery(&mut self) {
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
        self.last_endpoint_attestation_refresh
            .retain(|endpoint, _| self.sessions.contains_key(endpoint));
        let now = Instant::now();
        self.dht_replication_rate_windows.retain(|_, window| {
            now.duration_since(window.last_seen) < DHT_REPLICATION_RATE_RETENTION
        });
        self.expire_dht_query_guard_at(now);
        self.dht_replication_history
            .retain(|_, history| history.expires_at > now);
        self.pending_dht_replications
            .retain(|pending| pending.record.verify().is_ok());
        let active_session_endpoints: HashSet<SocketAddr> = self.sessions.keys().copied().collect();
        self.routing.retain_endpoints(&active_session_endpoints);
        self.expire_filtering_matrix_state();
        self.last_rendezvous_request
            .retain(|_, last| last.elapsed() < Duration::from_secs(60));
        self.last_filter_test_request
            .retain(|_, last| last.elapsed() < Duration::from_secs(60));
        self.discovery_candidates
            .retain(|_, candidate| candidate.expires_at > Instant::now());
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
        let expired_attestations = self.endpoint_attestations.expire();
        if expired_attestations > 0 {
            debug!(
                expired_attestations,
                "expired stale DHT endpoint attestations"
            );
        }
        let removed = before.saturating_sub(self.peers.len());
        if removed > 0 {
            debug!(removed, "expired stale peers");
        }
    }

    async fn send(&mut self, target: SocketAddr, body: MessageBody) -> Result<()> {
        let envelope = WireEnvelope::signed(&self.identity, random(), body)?;
        let bytes = envelope.encode()?;
        self.remember_filter_contact(target.ip(), Instant::now());
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

fn ip_equivalent(left: IpAddr, right: IpAddr) -> bool {
    normalized_ip(left) == normalized_ip(right)
}

fn normalized_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
        ip => ip,
    }
}

fn is_native_ipv6_endpoint(endpoint: SocketAddr) -> bool {
    matches!(endpoint.ip(), IpAddr::V6(ip) if ip.to_ipv4_mapped().is_none())
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
        "endpoint-attestations-v1".to_owned(),
        "bounded-dht-replication-v1".to_owned(),
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
        "filtering-matrix-v1".to_owned(),
        "udp-punch-probe".to_owned(),
        "udp-punch-burst-v1".to_owned(),
        "secure-ping-pong".to_owned(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dht::TestLoopbackDhtEndpoints;
    use crate::nat::FilterCellStatus;
    use std::sync::atomic::Ordering;

    struct MeshTaskGuard(Vec<Option<tokio::task::JoinHandle<anyhow::Result<()>>>>);

    impl Drop for MeshTaskGuard {
        fn drop(&mut self) {
            for task in self.0.iter().flatten() {
                task.abort();
            }
        }
    }

    async fn wait_for_mesh_condition(
        timeout: Duration,
        mut condition: impl FnMut() -> bool,
        message: &str,
        timeout_detail: impl Fn() -> String,
    ) {
        if time::timeout(timeout, async {
            loop {
                if condition() {
                    return;
                }
                time::sleep(Duration::from_millis(40)).await;
            }
        })
        .await
        .is_err()
        {
            panic!("timed out waiting for {message}: {}", timeout_detail());
        }
    }

    async fn deliver_between_mesh_leaves(
        sender: &mut RelayAppHandle,
        receiver: &mut RelayAppHandle,
        sender_node_id: &str,
        target_node_id: &str,
        counters: &RuntimeMeshCounters,
        payload: Vec<u8>,
    ) {
        let message_id = sender
            .send(target_node_id.to_owned(), payload.clone())
            .await
            .unwrap();
        let (received, receipt) = tokio::join!(
            time::timeout(Duration::from_secs(45), async {
                loop {
                    if let Some(incoming) = receiver.recv().await {
                        if incoming.peer_node_id == sender_node_id && incoming.data == payload {
                            break incoming;
                        }
                    }
                }
            }),
            time::timeout(Duration::from_secs(45), async {
                loop {
                    if let Some(delivered) = sender.recv_receipt().await {
                        if delivered.peer_node_id == target_node_id
                            && delivered.message_id == message_id
                        {
                            break delivered;
                        }
                    }
                }
            })
        );
        assert!(
            received.is_ok(),
            "timed out receiving RelayApp payload from {sender_node_id} to {target_node_id}; correlated FINDs {}; exact NODES responses {}; records received at sender {}",
            counters
                .finds
                .lock()
                .expect("mesh DHT find counter poisoned")
                .iter()
                .filter(|(origin, target, _)| {
                    origin == sender_node_id && target == target_node_id
                })
                .count(),
            counters
                .nodes
                .lock()
                .expect("mesh DHT nodes counter poisoned")
                .iter()
                .filter(|(origin, target, _)| {
                    origin == sender_node_id && target == target_node_id
                })
                .count(),
            counters
                .received_records
                .lock()
                .expect("mesh record counter poisoned")
                .contains(&(sender_node_id.to_owned(), target_node_id.to_owned()))
        );
        assert_eq!(received.unwrap().data, payload);
        assert_eq!(receipt.unwrap().message_id, message_id);
    }

    fn two_mesh_apps_mut(
        apps: &mut [Option<RelayAppHandle>],
        source: usize,
        target: usize,
    ) -> (&mut RelayAppHandle, &mut RelayAppHandle) {
        assert_ne!(source, target);
        if source < target {
            let (left, right) = apps.split_at_mut(target);
            (left[source].as_mut().unwrap(), right[0].as_mut().unwrap())
        } else {
            let (left, right) = apps.split_at_mut(source);
            (right[0].as_mut().unwrap(), left[target].as_mut().unwrap())
        }
    }

    fn select_mesh_lookup_pair(
        preferred: (usize, usize),
        sources: &[usize],
        targets: &[usize],
        resolvers: &[usize],
        node_ids: &[String],
        counters: &RuntimeMeshCounters,
    ) -> (usize, usize) {
        let known_records = counters
            .received_records
            .lock()
            .expect("mesh record counter poisoned");
        let mut candidates = Vec::new();
        if sources.contains(&preferred.0)
            && targets.contains(&preferred.1)
            && preferred.0 != preferred.1
        {
            candidates.push(preferred);
        }
        candidates.extend(sources.iter().flat_map(|source| {
            targets
                .iter()
                .copied()
                .filter(move |target| source != target)
                .map(move |target| (*source, target))
        }));
        candidates
            .into_iter()
            .find(|(source, target)| {
                !known_records.contains(&(node_ids[*source].clone(), node_ids[*target].clone()))
                    && resolvers.iter().any(|resolver| {
                        known_records
                            .contains(&(node_ids[*resolver].clone(), node_ids[*target].clone()))
                    })
            })
            .expect("no non-neighbor leaf pair with an uncached source and a live resolver record")
    }

    fn assert_mesh_lookup_was_correlated(
        source_node_id: &str,
        target_node_id: &str,
        counters: &RuntimeMeshCounters,
    ) {
        let query_ids: Vec<_> = counters
            .finds
            .lock()
            .expect("mesh DHT find counter poisoned")
            .iter()
            .filter_map(|(origin, target, query_id)| {
                (origin == source_node_id && target == target_node_id).then_some(*query_id)
            })
            .collect();
        let responses = counters
            .nodes
            .lock()
            .expect("mesh DHT nodes counter poisoned");
        assert!(query_ids.iter().any(|query_id| {
            responses.contains(&(
                source_node_id.to_owned(),
                target_node_id.to_owned(),
                *query_id,
            ))
        }));
    }

    #[tokio::test]
    async fn authenticated_app_ack_learns_the_actual_punched_path() {
        let mut node = KonoNode::bind(
            NodeIdentity::generate(),
            "127.0.0.1:0".parse().unwrap(),
            Vec::new(),
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        let peer = "knp1peer";
        let endpoint: SocketAddr = "127.0.0.2:47000".parse().unwrap();
        let route = ControlRoute::Direct(endpoint);
        let sent_at = Instant::now();
        let message_id = node
            .relay_app
            .queue(peer.to_owned(), vec![1_u8], sent_at)
            .unwrap();

        node.punched_endpoints.insert(endpoint);
        node.track_relay_app_route_attempt(peer.to_owned(), message_id, route, sent_at);
        node.handle_app_ack(peer, message_id, route, sent_at + Duration::from_millis(25));

        let learned = node.route_controller.path_learning(PathKind::HolePunch);
        assert_eq!((learned.samples, learned.successes), (1, 1));
        assert_eq!(learned.average_rtt_ms, 25.0);
        assert_eq!(learned.average_packet_loss, 0.0);
        assert!(node.relay_app_route_attempts.entries.is_empty());
    }

    #[tokio::test]
    async fn exhausted_delivery_learns_the_actual_relay_path() {
        let mut node = KonoNode::bind(
            NodeIdentity::generate(),
            "127.0.0.1:0".parse().unwrap(),
            Vec::new(),
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        let peer = "knp1peer";
        let route = ControlRoute::Relay {
            relay_endpoint: "127.0.0.3:47000".parse().unwrap(),
            circuit_id: 9,
        };
        let sent_at = Instant::now();
        let message_id = node
            .relay_app
            .queue(peer.to_owned(), vec![1_u8], sent_at)
            .unwrap();
        node.track_relay_app_route_attempt(peer.to_owned(), message_id, route, sent_at);
        let (_events, expired) = node
            .relay_app
            .expire(sent_at + Duration::from_secs(24 * 60 * 60));
        assert_eq!(expired, 1);
        let (failure_tx, _failure_rx) = mpsc::channel(1);
        node.relay_app_failure_tx = Some(failure_tx);

        node.flush_relay_app_failures();

        let learned = node.route_controller.path_learning(PathKind::Relay);
        assert_eq!((learned.samples, learned.successes), (1, 0));
        assert_eq!(learned.average_packet_loss, 1.0);
        assert!(node.relay_app_route_attempts.entries.is_empty());
    }

    #[test]
    fn relay_app_ack_sample_requires_latest_attempt_route_match() {
        let mut attempts = RelayAppRouteAttempts::default();
        let key = ("peer".to_owned(), 7);
        let start = Instant::now();
        let first = ControlRoute::Relay {
            relay_endpoint: "127.0.0.1:47000".parse().unwrap(),
            circuit_id: 1,
        };
        let latest = ControlRoute::Direct("127.0.0.2:47000".parse().unwrap());
        attempts.track(key.clone(), first, start);
        attempts.track(key.clone(), latest, start + Duration::from_millis(10));

        assert_eq!(
            attempts.matching_ack_rtt(&key, first, start + Duration::from_millis(20)),
            None
        );
        assert_eq!(attempts.entries.len(), 0);
        attempts.track(key.clone(), latest, start + Duration::from_millis(10));
        assert_eq!(
            attempts.matching_ack_rtt(&key, latest, start + Duration::from_millis(30)),
            Some((Duration::from_millis(20), start + Duration::from_millis(10)))
        );
    }

    #[test]
    fn relay_app_route_attempt_tracking_stays_within_outbound_bound() {
        let mut attempts = RelayAppRouteAttempts::default();
        let route = ControlRoute::Direct("127.0.0.2:47000".parse().unwrap());
        let now = Instant::now();
        for message_id in 0..=MAX_RELAY_APP_ROUTE_ATTEMPTS {
            attempts.track(("peer".to_owned(), message_id as u64), route, now);
        }
        assert_eq!(attempts.entries.len(), MAX_RELAY_APP_ROUTE_ATTEMPTS);
        assert_eq!(attempts.order.len(), MAX_RELAY_APP_ROUTE_ATTEMPTS);
        assert!(!attempts.entries.contains_key(&("peer".to_owned(), 0)));
    }

    #[tokio::test]
    async fn local_test_mode_allows_loopback_rendezvous_only_when_enabled() {
        let identity = NodeIdentity::generate();
        let mut node = KonoNode::bind(
            identity,
            "127.0.0.1:0".parse().unwrap(),
            Vec::new(),
            Duration::from_secs(1),
        )
        .await
        .unwrap();

        let loopback: SocketAddr = "127.0.0.1:47000".parse().unwrap();
        assert!(!node.rendezvous_candidate_allowed(loopback));

        node.set_local_test_mode(true);
        assert!(node.rendezvous_candidate_allowed(loopback));
        assert!(!node.rendezvous_candidate_allowed("0.0.0.0:47000".parse().unwrap()));
    }

    #[tokio::test]
    async fn dht_discovery_candidate_is_bound_to_expected_node_identity() {
        let identity = NodeIdentity::generate();
        let mut node = KonoNode::bind(
            identity,
            "127.0.0.1:0".parse().unwrap(),
            Vec::new(),
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        let endpoint: SocketAddr = "8.8.8.8:47000".parse().unwrap();
        let expected = NodeIdentity::generate().node_id();
        let unexpected = NodeIdentity::generate().node_id();
        node.discovery_candidates.insert(
            endpoint,
            DhtDiscoveryCandidate {
                expected_node_id: expected.clone(),
                expires_at: Instant::now() + CANDIDATE_GROUP_TTL,
            },
        );

        assert!(node.is_expected_peer(endpoint, &expected));
        assert!(!node.is_expected_peer(endpoint, &unexpected));
    }

    #[tokio::test]
    async fn connect_candidate_rejects_wrong_identity_before_peer_admission() {
        let mut node = KonoNode::bind(
            NodeIdentity::generate(),
            "127.0.0.1:0".parse().unwrap(),
            Vec::new(),
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        let endpoint: SocketAddr = "127.0.0.1:47000".parse().unwrap();
        let expected = NodeIdentity::generate().node_id();
        let impostor = NodeIdentity::generate();
        node.queue_connect(expected, vec![endpoint]).unwrap();
        node.drive_connect_candidate_groups().await;
        assert!(node.discovery_candidates.contains_key(&endpoint));
        let packet = WireEnvelope::signed(
            &impostor,
            42,
            MessageBody::HelloAck {
                observed_endpoint: endpoint.to_string(),
                features: Vec::new(),
            },
        )
        .unwrap()
        .encode()
        .unwrap();

        node.handle_datagram(&packet, endpoint).await.unwrap();
        assert!(!node.peers.contains_key(&endpoint));
    }

    #[tokio::test]
    async fn explicit_connect_prioritizes_ipv6_before_candidate_cap() {
        let mut node = KonoNode::bind(
            NodeIdentity::generate(),
            "127.0.0.1:0".parse().unwrap(),
            Vec::new(),
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        let target = NodeIdentity::generate().node_id();
        let ipv4_first: SocketAddr = "8.8.8.8:47001".parse().unwrap();
        let ipv4_second: SocketAddr = "1.1.1.1:47002".parse().unwrap();
        let ipv6: SocketAddr = "[2001:4860:4860::8888]:47003".parse().unwrap();

        node.queue_connect(
            target.clone(),
            vec![
                ipv4_first,
                ipv4_second,
                ipv6,
                "9.9.9.9:47004".parse().unwrap(),
            ],
        )
        .unwrap();

        assert_eq!(
            node.connect_candidate_groups[&target].candidates(),
            &[ipv6, ipv4_first, ipv4_second]
        );
    }

    #[tokio::test]
    async fn explicit_connect_rejects_unscoped_ipv6_link_local_before_planning() {
        let mut node = KonoNode::bind(
            NodeIdentity::generate(),
            "127.0.0.1:0".parse().unwrap(),
            Vec::new(),
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        let target = NodeIdentity::generate().node_id();
        let unscoped_link_local = SocketAddr::V6(std::net::SocketAddrV6::new(
            "fe80::1".parse().unwrap(),
            47000,
            0,
            0,
        ));
        let scoped_link_local = SocketAddr::V6(std::net::SocketAddrV6::new(
            "fe80::1".parse().unwrap(),
            47001,
            0,
            3,
        ));

        assert!(node
            .queue_connect(target.clone(), vec![unscoped_link_local])
            .is_err());
        node.queue_connect(target.clone(), vec![scoped_link_local])
            .unwrap();

        assert_eq!(
            node.connect_candidate_groups[&target].candidates(),
            &[scoped_link_local]
        );
    }

    #[tokio::test]
    async fn dht_activation_prioritizes_only_exactly_attested_ipv6_endpoints() {
        let mut node = KonoNode::bind(
            NodeIdentity::generate(),
            "127.0.0.1:0".parse().unwrap(),
            Vec::new(),
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        let target_identity = NodeIdentity::generate();
        let target_node_id = target_identity.node_id();
        let ipv4_first: SocketAddr = "8.8.8.8:47001".parse().unwrap();
        let ipv4_second: SocketAddr = "1.1.1.1:47002".parse().unwrap();
        let ipv6_first: SocketAddr = "[2001:4860:4860::8888]:47003".parse().unwrap();
        let ipv6_second: SocketAddr = "[2606:4700:4700::1111]:47004".parse().unwrap();
        let record = PeerRecord::signed(
            &target_identity,
            vec![ipv4_first, ipv4_second, ipv6_first, ipv6_second],
        )
        .unwrap();

        for endpoint in [ipv4_first, ipv4_second, ipv6_first] {
            for _ in 0..MIN_ENDPOINT_ATTESTATION_OBSERVERS {
                let observer = NodeIdentity::generate();
                node.endpoint_attestations
                    .upsert(
                        EndpointAttestation::signed(&observer, target_node_id.clone(), endpoint)
                            .unwrap(),
                    )
                    .unwrap();
            }
        }
        node.pending_dht_queries.insert(target_node_id.clone());

        assert!(node.activate_dht_record(&record).await.unwrap());
        assert_eq!(
            node.connect_candidate_groups[&target_node_id].candidates(),
            &[ipv6_first, ipv4_second, ipv4_first]
        );
    }

    #[tokio::test]
    async fn connect_candidate_state_is_globally_bounded_and_endpoint_bound() {
        let mut node = KonoNode::bind(
            NodeIdentity::generate(),
            "127.0.0.1:0".parse().unwrap(),
            Vec::new(),
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        let first_endpoint: SocketAddr = "192.0.2.1:20000".parse().unwrap();
        node.queue_connect(format!("knp1{:040x}", 1), vec![first_endpoint])
            .unwrap();
        assert!(node
            .queue_connect(format!("knp1{:040x}", 2), vec![first_endpoint])
            .is_err());

        for index in 2..=MAX_ACTIVE_CANDIDATE_GROUPS {
            let endpoint: SocketAddr = format!("192.0.2.1:{}", 20_000 + index).parse().unwrap();
            node.queue_connect(format!("knp1{index:040x}"), vec![endpoint])
                .unwrap();
        }

        assert_eq!(
            node.connect_candidate_groups.len(),
            MAX_ACTIVE_CANDIDATE_GROUPS
        );
        assert!(node
            .queue_connect(
                format!("knp1{:040x}", MAX_ACTIVE_CANDIDATE_GROUPS + 1),
                vec!["192.0.2.1:30000".parse().unwrap()],
            )
            .is_err());
    }

    #[tokio::test]
    async fn authenticated_connect_candidate_cancels_remaining_exact_attempts() {
        let expected = NodeIdentity::generate();
        let target_node_id = expected.node_id();
        let first: SocketAddr = "127.0.0.1:47001".parse().unwrap();
        let second: SocketAddr = "127.0.0.1:47002".parse().unwrap();
        let mut node = KonoNode::bind(
            NodeIdentity::generate(),
            "127.0.0.1:0".parse().unwrap(),
            Vec::new(),
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        node.queue_connect(target_node_id.clone(), vec![first, second])
            .unwrap();
        node.drive_connect_candidate_groups().await;

        let packet = WireEnvelope::signed(
            &expected,
            43,
            MessageBody::HelloAck {
                observed_endpoint: first.to_string(),
                features: local_features(),
            },
        )
        .unwrap()
        .encode()
        .unwrap();
        node.handle_datagram(&packet, first).await.unwrap();

        assert!(node.connect_candidate_groups.contains_key(&target_node_id));
        node.confirmed_sessions.insert(first);
        node.complete_direct_candidate_target(&target_node_id);

        assert!(!node.connect_candidate_groups.contains_key(&target_node_id));
        assert!(!node.discovery_candidates.contains_key(&first));
        assert!(!node.discovery_candidates.contains_key(&second));
    }

    #[tokio::test]
    async fn authenticated_encrypted_activity_refreshes_peer_liveness_only_after_validation() {
        let mut node = KonoNode::bind(
            NodeIdentity::generate(),
            "127.0.0.1:0".parse().unwrap(),
            Vec::new(),
            Duration::from_millis(100),
        )
        .await
        .unwrap();
        let peer = NodeIdentity::generate();
        let endpoint: SocketAddr = "127.0.0.1:42001".parse().unwrap();
        let pending = PendingHandshake::new(node.node_id());
        let (local_session, public_key) = respond_handshake(
            &node.node_id(),
            &peer.node_id(),
            pending.handshake_id(),
            &pending.public_key_hex(),
        )
        .unwrap();
        let mut remote_session = pending.complete(&peer.node_id(), &public_key).unwrap();
        let admission = WireEnvelope::signed(&peer, 1, MessageBody::Ping { token: 1 }).unwrap();
        node.record_peer(&admission, endpoint);
        node.sessions
            .insert(endpoint, SessionSlot::new(local_session));
        node.confirmed_sessions.insert(endpoint);
        // Advance the recorded age, not the runtime clock or timeout. No sleep,
        // extra HELLO, weaker peer TTL or external network is needed.
        let old = Instant::now() - Duration::from_secs(2);
        node.peers.get_mut(&endpoint).unwrap().last_seen = old;
        let frame = remote_session
            .encrypt(&SecurePayload::Pong { token: 7 })
            .unwrap();
        let body = MessageBody::Encrypted {
            session_id: frame.session_id,
            sequence: frame.sequence,
            ciphertext: frame.ciphertext,
        };
        let valid = WireEnvelope::signed(&peer, 2, body.clone())
            .unwrap()
            .encode()
            .unwrap();
        let before = Instant::now();
        node.handle_datagram(&valid, endpoint).await.unwrap();
        assert!(
            node.peers[&endpoint].last_seen >= before,
            "authenticated encrypted activity must refresh the peer lease"
        );
        node.expire_stale_state();
        assert!(node.peers.contains_key(&endpoint));
        assert!(node.sessions.contains_key(&endpoint));

        node.peers.get_mut(&endpoint).unwrap().last_seen = old;
        assert!(node.handle_datagram(&valid, endpoint).await.is_err());
        assert_eq!(
            node.peers[&endpoint].last_seen, old,
            "replayed outer packet cannot renew"
        );
        let replay = WireEnvelope::signed(&peer, 3, body.clone())
            .unwrap()
            .encode()
            .unwrap();
        assert!(node.handle_datagram(&replay, endpoint).await.is_err());
        assert_eq!(
            node.peers[&endpoint].last_seen, old,
            "replayed session frame cannot renew"
        );

        let impostor = NodeIdentity::generate();
        let wrong_peer = WireEnvelope::signed(&impostor, 4, body.clone())
            .unwrap()
            .encode()
            .unwrap();
        node.handle_datagram(&wrong_peer, endpoint).await.unwrap();
        assert_eq!(
            node.peers[&endpoint].last_seen, old,
            "unbound identity cannot renew"
        );
        let unknown: SocketAddr = "127.0.0.1:42002".parse().unwrap();
        let unadmitted = WireEnvelope::signed(&peer, 5, body)
            .unwrap()
            .encode()
            .unwrap();
        node.handle_datagram(&unadmitted, unknown).await.unwrap();
        assert!(!node.peers.contains_key(&unknown));
        assert_eq!(node.peers[&endpoint].last_seen, old);

        let frame = remote_session
            .encrypt(&SecurePayload::Pong { token: 8 })
            .unwrap();
        let tampered = WireEnvelope::signed(
            &peer,
            6,
            MessageBody::Encrypted {
                session_id: frame.session_id,
                sequence: frame.sequence,
                ciphertext: "00".into(),
            },
        )
        .unwrap()
        .encode()
        .unwrap();
        assert!(node.handle_datagram(&tampered, endpoint).await.is_err());
        assert_eq!(
            node.peers[&endpoint].last_seen, old,
            "invalid ciphertext cannot renew"
        );
        node.expire_stale_state();
        assert!(
            !node.peers.contains_key(&endpoint),
            "rejected traffic cannot keep an idle peer alive"
        );
        assert!(!node.sessions.contains_key(&endpoint));
    }

    #[tokio::test]
    async fn authenticated_native_ipv6_preempts_ipv4_with_runtime_fallback() {
        let mut node = KonoNode::bind(
            NodeIdentity::generate(),
            "127.0.0.1:0".parse().unwrap(),
            Vec::new(),
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        let peer = NodeIdentity::generate();
        let peer_node_id = peer.node_id();
        let ipv4: SocketAddr = "192.0.2.10:47000".parse().unwrap();
        let ipv6: SocketAddr = "[2001:db8::10]:47000".parse().unwrap();
        let ipv4_envelope = WireEnvelope::signed(&peer, 1, MessageBody::Ping { token: 1 }).unwrap();
        let ipv6_envelope = WireEnvelope::signed(&peer, 2, MessageBody::Ping { token: 2 }).unwrap();

        node.record_peer(&ipv4_envelope, ipv4);
        node.confirmed_sessions.insert(ipv4);
        assert_eq!(node.direct_app_endpoint_for_peer(&peer_node_id), Some(ipv4));
        let direct = node.direct_app_endpoint_for_peer(&peer_node_id);
        let first = node
            .route_controller
            .select(&peer_node_id, direct, std::iter::empty())
            .unwrap();
        assert_eq!(first.route, ControlRoute::Direct(ipv4));
        assert_eq!(first.generation, 1);

        node.record_peer(&ipv6_envelope, ipv6);
        node.confirmed_sessions.insert(ipv6);
        assert!(node.peers.contains_key(&ipv4));
        assert!(node.peers.contains_key(&ipv6));
        assert_eq!(node.direct_app_endpoint_for_peer(&peer_node_id), Some(ipv6));
        let direct = node.direct_app_endpoint_for_peer(&peer_node_id);
        let preferred = node
            .route_controller
            .select(&peer_node_id, direct, std::iter::empty())
            .unwrap();
        assert_eq!(preferred.route, ControlRoute::Direct(ipv6));
        assert_eq!(preferred.generation, 2);
        assert!(preferred.changed);
        let diagnostics = node.diagnostics_snapshot().unwrap();
        assert_eq!(diagnostics.authenticated_peers, 1);
        assert_eq!(
            diagnostics.active_paths,
            vec![PathDiagnostic {
                peer_node_id: peer_node_id.clone(),
                method: PathMethod::Direct,
                endpoint: ipv6,
            }]
        );

        node.confirmed_sessions.remove(&ipv6);
        assert_eq!(node.direct_app_endpoint_for_peer(&peer_node_id), Some(ipv4));
        let direct = node.direct_app_endpoint_for_peer(&peer_node_id);
        let fallback = node
            .route_controller
            .select(&peer_node_id, direct, std::iter::empty())
            .unwrap();
        assert_eq!(fallback.route, ControlRoute::Direct(ipv4));
        assert_eq!(fallback.generation, 3);
        assert!(fallback.changed);
        assert_eq!(
            node.diagnostics_snapshot().unwrap().active_paths,
            vec![PathDiagnostic {
                peer_node_id,
                method: PathMethod::Direct,
                endpoint: ipv4,
            }]
        );
    }

    #[tokio::test]
    async fn peer_admission_keeps_one_endpoint_per_address_family() {
        let mut node = KonoNode::bind(
            NodeIdentity::generate(),
            "127.0.0.1:0".parse().unwrap(),
            Vec::new(),
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        let peer = NodeIdentity::generate();
        let old_ipv4: SocketAddr = "192.0.2.10:47000".parse().unwrap();
        let new_ipv4: SocketAddr = "192.0.2.11:47000".parse().unwrap();
        let ipv6: SocketAddr = "[2001:db8::10]:47000".parse().unwrap();

        let old_v4_envelope =
            WireEnvelope::signed(&peer, 1, MessageBody::Ping { token: 1 }).unwrap();
        let v6_envelope = WireEnvelope::signed(&peer, 2, MessageBody::Ping { token: 2 }).unwrap();
        let new_v4_envelope =
            WireEnvelope::signed(&peer, 3, MessageBody::Ping { token: 3 }).unwrap();

        node.record_peer(&old_v4_envelope, old_ipv4);
        node.confirmed_sessions.insert(old_ipv4);
        node.record_peer(&v6_envelope, ipv6);
        node.confirmed_sessions.insert(ipv6);
        node.record_peer(&new_v4_envelope, new_ipv4);

        assert!(!node.peers.contains_key(&old_ipv4));
        assert!(!node.confirmed_sessions.contains(&old_ipv4));
        assert!(node.peers.contains_key(&new_ipv4));
        assert!(node.peers.contains_key(&ipv6));
        assert!(node.confirmed_sessions.contains(&ipv6));
        assert_eq!(
            node.peers
                .values()
                .filter(|known| known.node_id == peer.node_id())
                .count(),
            2
        );
    }

    #[tokio::test]
    async fn relay_loss_migrates_to_authenticated_sibling_without_redial() {
        let mut node = KonoNode::bind(
            NodeIdentity::generate(),
            "127.0.0.1:0".parse().unwrap(),
            Vec::new(),
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        let peer_node_id = NodeIdentity::generate().node_id();
        let relay_one: SocketAddr = "127.0.0.10:47000".parse().unwrap();
        let relay_two: SocketAddr = "127.0.0.11:47000".parse().unwrap();
        let now = Instant::now();

        for (relay_endpoint, circuit_id) in [(relay_one, 1_u64), (relay_two, 2_u64)] {
            let local_node_id = node.node_id();
            let pending = PendingHandshake::new(local_node_id.clone());
            let (session, _) = respond_handshake(
                &local_node_id,
                &peer_node_id,
                pending.handshake_id(),
                &pending.public_key_hex(),
            )
            .unwrap();
            node.relay_paths.insert(
                (relay_endpoint, circuit_id),
                RelayPath {
                    peer_node_id: peer_node_id.clone(),
                    expires_at: now + RELAY_CIRCUIT_TTL,
                    next_send_sequence: 0,
                    receive_window: SequenceWindow::default(),
                },
            );
            node.relay_e2e_sessions
                .insert((relay_endpoint, circuit_id), SessionSlot::new(session));
        }

        let first_candidates = node.relay_e2e_candidates_for_peer(&peer_node_id);
        let first = node
            .route_controller
            .select(&peer_node_id, None, first_candidates)
            .unwrap();
        assert_eq!(
            first.route,
            ControlRoute::Relay {
                relay_endpoint: relay_one,
                circuit_id: 1,
            }
        );

        assert_eq!(
            node.remove_client_relay_path((relay_one, 1)).as_deref(),
            Some(peer_node_id.as_str())
        );
        assert!(!node.schedule_auto_relay_failover_if_needed(peer_node_id.clone(), relay_one, now,));
        assert!(!node.auto_relay_fallbacks.contains_key(&peer_node_id));

        let second_candidates = node.relay_e2e_candidates_for_peer(&peer_node_id);
        let second = node
            .route_controller
            .select(&peer_node_id, None, second_candidates)
            .unwrap();
        assert_eq!(
            second.route,
            ControlRoute::Relay {
                relay_endpoint: relay_two,
                circuit_id: 2,
            }
        );
        assert!(second.changed);
        assert!(second.generation > first.generation);

        node.remove_client_relay_path((relay_two, 2));
        assert!(node.schedule_auto_relay_failover_if_needed(peer_node_id.clone(), relay_two, now,));
        assert_eq!(
            node.auto_relay_fallbacks[&peer_node_id].tried,
            HashSet::from([relay_two])
        );
    }

    #[tokio::test]
    async fn relay_path_without_e2e_session_does_not_suppress_recovery() {
        let mut node = KonoNode::bind(
            NodeIdentity::generate(),
            "127.0.0.1:0".parse().unwrap(),
            Vec::new(),
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        let peer_node_id = NodeIdentity::generate().node_id();
        let relay_endpoint: SocketAddr = "127.0.0.12:47000".parse().unwrap();
        let now = Instant::now();

        node.relay_paths.insert(
            (relay_endpoint, 7),
            RelayPath {
                peer_node_id: peer_node_id.clone(),
                expires_at: now + RELAY_CIRCUIT_TTL,
                next_send_sequence: 0,
                receive_window: SequenceWindow::default(),
            },
        );

        assert!(!node.has_usable_relay_path_for_peer(&peer_node_id, now));
        assert!(node.schedule_auto_relay_failover_if_needed(
            peer_node_id.clone(),
            relay_endpoint,
            now,
        ));
        assert!(node.auto_relay_fallbacks.contains_key(&peer_node_id));
    }

    #[tokio::test]
    async fn dht_record_admission_is_bounded_per_authenticated_identity() {
        let identity = NodeIdentity::generate();
        let mut node = KonoNode::bind(
            identity,
            "127.0.0.1:0".parse().unwrap(),
            Vec::new(),
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        let sender_node_id = NodeIdentity::generate().node_id();
        let source: SocketAddr = "8.8.8.8:47000".parse().unwrap();
        let now = Instant::now();

        for _ in 0..MAX_DHT_RECORDS_PER_PEER_WINDOW {
            assert!(node.allow_dht_record_admission(&sender_node_id, source, 1, now));
        }
        assert!(!node.allow_dht_record_admission(&sender_node_id, source, 1, now));
        assert!(node.allow_dht_record_admission(
            &sender_node_id,
            source,
            1,
            now + DHT_REPLICATION_RATE_WINDOW
        ));
    }

    #[tokio::test]
    async fn invalid_dht_stores_consume_admission_budget_before_signature_work() {
        let local_identity = NodeIdentity::generate();
        let sender_node_id = NodeIdentity::generate().node_id();
        let record_identity = NodeIdentity::generate();
        let source: SocketAddr = "8.8.8.8:47000".parse().unwrap();
        let valid_record =
            PeerRecord::signed(&record_identity, vec!["1.1.1.1:47000".parse().unwrap()]).unwrap();
        let mut invalid_record = valid_record.clone();
        invalid_record.signature = "00".to_owned();
        let mut node = KonoNode::bind(
            local_identity,
            "127.0.0.1:0".parse().unwrap(),
            Vec::new(),
            Duration::from_secs(1),
        )
        .await
        .unwrap();

        for _ in 0..MAX_DHT_RECORDS_PER_PEER_WINDOW {
            node.handle_secure_payload(
                source,
                &sender_node_id,
                "test-session",
                SecurePayload::DhtStore {
                    record: invalid_record.clone(),
                    attestations: Vec::new(),
                    replication_hops_remaining: 0,
                },
            )
            .await
            .unwrap();
        }

        node.handle_secure_payload(
            source,
            &sender_node_id,
            "test-session",
            SecurePayload::DhtStore {
                record: valid_record.clone(),
                attestations: Vec::new(),
                replication_hops_remaining: 0,
            },
        )
        .await
        .unwrap();

        assert!(node.dht.get(&valid_record.node_id).is_none());
    }

    #[test]
    fn dht_query_token_bucket_refills_at_exact_boundary() {
        let now = Instant::now();
        let mut bucket = DhtQueryTokenBucket::full(2, now);

        assert!(bucket.try_take(2, Duration::from_secs(2), now));
        assert!(bucket.try_take(2, Duration::from_secs(2), now));
        assert!(!bucket.try_take(2, Duration::from_secs(2), now));
        assert!(!bucket.try_take(
            2,
            Duration::from_secs(2),
            now + Duration::from_millis(1_999)
        ));
        assert!(bucket.try_take(2, Duration::from_secs(2), now + Duration::from_secs(2)));

        let long_idle = now + Duration::from_secs(72 * 60 * 60);
        assert!(bucket.try_take(2, Duration::from_secs(2), long_idle));
        assert!(bucket.try_take(2, Duration::from_secs(2), long_idle));
        assert!(!bucket.try_take(2, Duration::from_secs(2), long_idle));
    }

    #[tokio::test]
    async fn dht_query_guard_shares_prefix_budget_and_retains_peer_debt() {
        let identity = NodeIdentity::generate();
        let mut node = KonoNode::bind(
            identity,
            "127.0.0.1:0".parse().unwrap(),
            Vec::new(),
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        let now = Instant::now();
        let source: SocketAddr = "8.8.8.8:47000".parse().unwrap();
        let first = NodeIdentity::generate().node_id();

        for _ in 0..DHT_QUERY_PEER_BURST {
            assert!(node.allow_dht_query(&first, source, now));
        }
        assert!(!node.allow_dht_query(&first, "8.8.8.8:47001".parse().unwrap(), now));

        for port in 47_002..47_005 {
            let peer = NodeIdentity::generate().node_id();
            let endpoint = format!("8.8.8.9:{port}").parse().unwrap();
            for _ in 0..DHT_QUERY_PEER_BURST {
                assert!(node.allow_dht_query(&peer, endpoint, now));
            }
        }
        assert!(!node.allow_dht_query(
            &NodeIdentity::generate().node_id(),
            "8.8.8.10:47006".parse().unwrap(),
            now
        ));
        assert!(node.allow_dht_query(&first, source, now + DHT_QUERY_PEER_REFILL));
    }

    #[tokio::test]
    async fn session_init_does_not_enter_routing_before_encrypted_confirmation() {
        let local_identity = NodeIdentity::generate();
        let local_node_id = local_identity.node_id();
        let peer_identity = NodeIdentity::generate();
        let peer_node_id = peer_identity.node_id();
        let source: SocketAddr = "127.0.0.1:47000".parse().unwrap();
        let now = Instant::now();
        let pending = PendingHandshake::new(local_node_id);
        let handshake_id = pending.handshake_id();
        let envelope = WireEnvelope::signed(
            &peer_identity,
            1,
            MessageBody::SessionInit {
                handshake_id,
                ephemeral_public_key: pending.public_key_hex(),
            },
        )
        .unwrap()
        .encode()
        .unwrap();

        let mut node = KonoNode::bind(
            local_identity,
            "127.0.0.1:0".parse().unwrap(),
            Vec::new(),
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        node.peers.insert(
            source,
            PeerInfo {
                node_id: peer_node_id,
                public_key: peer_identity.public_key_hex(),
                endpoint: source,
                first_seen: now,
                last_seen: now,
                observed_external_endpoint: None,
                features: HashSet::new(),
            },
        );

        node.handle_datagram(&envelope, source).await.unwrap();

        assert!(node.sessions.contains_key(&source));
        assert!(!node.confirmed_sessions.contains(&source));
        assert!(node.routing.is_empty());
    }

    #[tokio::test]
    async fn encrypted_payload_requires_outer_sender_to_match_session_identity() {
        let local_identity = NodeIdentity::generate();
        let local_node_id = local_identity.node_id();
        let peer_identity = NodeIdentity::generate();
        let peer_node_id = peer_identity.node_id();
        let unrelated_identity = NodeIdentity::generate();
        let source: SocketAddr = "127.0.0.1:47000".parse().unwrap();
        let now = Instant::now();

        let pending = PendingHandshake::new(local_node_id.clone());
        let handshake_id = pending.handshake_id();
        let initiator_public_key = pending.public_key_hex();
        let (receiver_session, responder_public_key) = respond_handshake(
            &local_node_id,
            &peer_node_id,
            handshake_id,
            &initiator_public_key,
        )
        .unwrap();
        let mut sender_session = pending
            .complete(&peer_node_id, &responder_public_key)
            .unwrap();
        let frame = sender_session
            .encrypt(&SecurePayload::Pong { token: 7 })
            .unwrap();

        let mut node = KonoNode::bind(
            local_identity,
            "127.0.0.1:0".parse().unwrap(),
            Vec::new(),
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        node.peers.insert(
            source,
            PeerInfo {
                node_id: peer_node_id.clone(),
                public_key: peer_identity.public_key_hex(),
                endpoint: source,
                first_seen: now,
                last_seen: now,
                observed_external_endpoint: None,
                features: HashSet::new(),
            },
        );
        node.sessions
            .insert(source, SessionSlot::new(receiver_session));

        let mismatched = WireEnvelope::signed(
            &unrelated_identity,
            1,
            MessageBody::Encrypted {
                session_id: frame.session_id.clone(),
                sequence: frame.sequence,
                ciphertext: frame.ciphertext.clone(),
            },
        )
        .unwrap()
        .encode()
        .unwrap();
        node.handle_datagram(&mismatched, source).await.unwrap();

        assert!(!node.confirmed_sessions.contains(&source));
        assert!(node.routing.is_empty());

        let correctly_bound = WireEnvelope::signed(
            &peer_identity,
            2,
            MessageBody::Encrypted {
                session_id: frame.session_id,
                sequence: frame.sequence,
                ciphertext: frame.ciphertext,
            },
        )
        .unwrap()
        .encode()
        .unwrap();
        node.handle_datagram(&correctly_bound, source)
            .await
            .unwrap();

        assert!(node.confirmed_sessions.contains(&source));
        assert_eq!(node.routing.len(), 1);
    }

    #[tokio::test]
    async fn own_dht_record_is_stable_until_refresh_or_endpoint_change() {
        let identity = NodeIdentity::generate();
        let mut node = KonoNode::bind(
            identity,
            "127.0.0.1:0".parse().unwrap(),
            Vec::new(),
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        let first_endpoint: SocketAddr = "8.8.8.8:47000".parse().unwrap();
        node.nat_profile
            .observe("observer-a".to_owned(), first_endpoint);

        let first = node.build_own_dht_record().unwrap().unwrap();
        let repeated = node.build_own_dht_record().unwrap().unwrap();
        assert_eq!(first, repeated);

        node.own_dht_record.as_mut().unwrap().created_at =
            Instant::now() - OWN_DHT_RECORD_REFRESH_INTERVAL;
        let refreshed = node.build_own_dht_record().unwrap().unwrap();
        assert_ne!(first.signature, refreshed.signature);

        let second_endpoint: SocketAddr = "1.1.1.1:47000".parse().unwrap();
        node.nat_profile
            .observe("observer-a".to_owned(), second_endpoint);
        let changed = node.build_own_dht_record().unwrap().unwrap();
        assert_eq!(changed.endpoints, vec![second_endpoint.to_string()]);
    }

    #[tokio::test]
    async fn replication_queue_reserves_capacity_for_owner_publication() {
        let identity = NodeIdentity::generate();
        let record = PeerRecord::signed(&identity, vec!["8.8.8.8:47000".parse().unwrap()]).unwrap();
        let mut node = KonoNode::bind(
            identity,
            "127.0.0.1:0".parse().unwrap(),
            Vec::new(),
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        let ordinary_limit = MAX_PENDING_DHT_REPLICATIONS - DHT_OWNER_REPLICATION_RESERVE;

        for index in 0..ordinary_limit {
            let target = format!("8.8.8.{}:{}", (index % 250) + 1, 20_000 + index)
                .parse()
                .unwrap();
            assert!(node.queue_dht_replication(
                target,
                format!("ordinary-{index}"),
                record.clone(),
                Vec::new(),
                0,
                DhtReplicationKind::Sync,
            ));
        }
        assert!(!node.queue_dht_replication(
            "1.1.1.1:47000".parse().unwrap(),
            "ordinary-overflow".to_owned(),
            record.clone(),
            Vec::new(),
            0,
            DhtReplicationKind::Sync,
        ));
        assert!(node.queue_dht_replication(
            "1.0.0.1:47000".parse().unwrap(),
            "owner-priority".to_owned(),
            record,
            Vec::new(),
            DHT_REPLICATION_MAX_HOPS,
            DhtReplicationKind::Owner,
        ));
        assert_eq!(node.pending_dht_replications.len(), ordinary_limit + 1);
        assert_eq!(
            node.pending_dht_replications
                .front()
                .map(|pending| pending.target_node_id.as_str()),
            Some("owner-priority")
        );
    }

    #[tokio::test]
    async fn filtering_matrix_sender_uses_bound_and_alternate_ports_and_consumes_tokens_once() {
        let identity = NodeIdentity::generate();
        let mut node = KonoNode::bind(
            identity,
            "127.0.0.1:0".parse().unwrap(),
            Vec::new(),
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        node.set_local_test_mode(true);

        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_endpoint = receiver.local_addr().unwrap();
        let baseline = node.local_addr().unwrap();
        let helper_node_id = node.node_id();
        let target_identity = NodeIdentity::generate();

        let contacted = FilteringMatrixAuthorization::signed(
            &target_identity,
            target_endpoint,
            helper_node_id.clone(),
            baseline,
            helper_node_id.clone(),
            FilterProbeClass::ContactedEndpoint,
            41,
            401,
        )
        .unwrap();
        let replay_key = FilterAuthorizationUseKey::from(&contacted);
        let replay_window_started_at = Instant::now();
        node.send_authorized_filter_probe(&contacted).await.unwrap();
        let replay_deadline = node.used_filter_authorizations[&replay_key];
        assert!(
            replay_deadline >= replay_window_started_at + FILTER_AUTHORIZATION_REPLAY_RETENTION
        );
        assert!(replay_deadline > replay_window_started_at + FILTER_PROBE_STATE_TTL);

        let mut packet = vec![0_u8; MAX_PACKET_SIZE];
        let (length, source) =
            time::timeout(Duration::from_secs(1), receiver.recv_from(&mut packet))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(source, baseline);
        let envelope = WireEnvelope::decode(&packet[..length]).unwrap();
        envelope.verify().unwrap();
        assert!(matches!(
            envelope.body,
            MessageBody::FilteringMatrixProbe {
                trial_id: 41,
                probe_class: FilterProbeClass::ContactedEndpoint,
                probe_token: 401,
            }
        ));
        assert_eq!(
            node.send_authorized_filter_probe(&contacted).await,
            Err(FilteringMatrixFailure::Replay)
        );
        let reissued = FilteringMatrixAuthorization::signed_at(
            &target_identity,
            target_endpoint,
            node.node_id(),
            baseline,
            node.node_id(),
            FilterProbeClass::ContactedEndpoint,
            41,
            401,
            contacted.issued_unix_ms + 1,
        )
        .unwrap();
        assert_ne!(reissued.signature, contacted.signature);
        assert_eq!(
            node.send_authorized_filter_probe(&reissued).await,
            Err(FilteringMatrixFailure::Replay)
        );
        assert!(
            time::timeout(Duration::from_millis(50), receiver.recv_from(&mut packet))
                .await
                .is_err()
        );

        let same_token_other_target = FilteringMatrixAuthorization::signed(
            &NodeIdentity::generate(),
            target_endpoint,
            node.node_id(),
            baseline,
            node.node_id(),
            FilterProbeClass::ContactedEndpoint,
            42,
            401,
        )
        .unwrap();
        node.send_authorized_filter_probe(&same_token_other_target)
            .await
            .unwrap();
        time::timeout(Duration::from_secs(1), receiver.recv_from(&mut packet))
            .await
            .unwrap()
            .unwrap();

        let alternate = FilteringMatrixAuthorization::signed(
            &target_identity,
            target_endpoint,
            helper_node_id.clone(),
            baseline,
            helper_node_id,
            FilterProbeClass::SameAddressDifferentPort,
            41,
            402,
        )
        .unwrap();
        node.send_authorized_filter_probe(&alternate).await.unwrap();
        let (length, source) =
            time::timeout(Duration::from_secs(1), receiver.recv_from(&mut packet))
                .await
                .unwrap()
                .unwrap();
        assert!(ip_equivalent(source.ip(), baseline.ip()));
        assert_ne!(source.port(), baseline.port());
        let envelope = WireEnvelope::decode(&packet[..length]).unwrap();
        envelope.verify().unwrap();
        assert!(matches!(
            envelope.body,
            MessageBody::FilteringMatrixProbe {
                trial_id: 41,
                probe_class: FilterProbeClass::SameAddressDifferentPort,
                probe_token: 402,
            }
        ));
        assert_eq!(
            node.send_authorized_filter_probe(&alternate).await,
            Err(FilteringMatrixFailure::Replay)
        );
    }

    #[tokio::test]
    async fn filtering_matrix_sender_rejects_non_public_targets_outside_test_mode() {
        let identity = NodeIdentity::generate();
        let mut node = KonoNode::bind(
            identity,
            "127.0.0.1:0".parse().unwrap(),
            Vec::new(),
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        let helper_node_id = node.node_id();
        let authorization = FilteringMatrixAuthorization::signed(
            &NodeIdentity::generate(),
            "10.0.0.20:47000".parse().unwrap(),
            helper_node_id.clone(),
            node.local_addr().unwrap(),
            helper_node_id,
            FilterProbeClass::ContactedEndpoint,
            51,
            501,
        )
        .unwrap();

        assert_eq!(
            node.send_authorized_filter_probe(&authorization).await,
            Err(FilteringMatrixFailure::UnsafeTarget)
        );
        assert!(node.used_filter_authorizations.is_empty());
    }

    #[tokio::test]
    async fn filtering_matrix_rejects_unsolicited_proposals() {
        let identity = NodeIdentity::generate();
        let mut node = KonoNode::bind(
            identity,
            "127.0.0.1:0".parse().unwrap(),
            Vec::new(),
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        node.set_local_test_mode(true);

        node.handle_filtering_matrix_proposal(
            "127.0.0.1:47000".parse().unwrap(),
            &NodeIdentity::generate().node_id(),
            61,
            FilterProbeClass::DifferentAddress,
            &NodeIdentity::generate().node_id(),
            "127.0.0.1:47001",
            601,
        )
        .await
        .unwrap();

        assert!(node.pending_filter_probes.is_empty());
    }

    #[tokio::test]
    async fn filtering_matrix_receive_binds_helper_trial_class_and_token() {
        let identity = NodeIdentity::generate();
        let mut node = KonoNode::bind(
            identity,
            "127.0.0.1:0".parse().unwrap(),
            Vec::new(),
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        node.set_local_test_mode(true);
        let target_endpoint = node.local_addr().unwrap();
        let coordinator_node_id = NodeIdentity::generate().node_id();
        node.nat_profile
            .observe(coordinator_node_id.clone(), target_endpoint);
        let helper_identity = NodeIdentity::generate();
        let helper_node_id = helper_identity.node_id();
        let trial_id = 62;
        let probe_token = 602;
        let authorization = FilteringMatrixAuthorization::signed(
            &node.identity,
            target_endpoint,
            coordinator_node_id,
            "127.0.0.3:47000".parse().unwrap(),
            helper_node_id,
            FilterProbeClass::DifferentAddress,
            trial_id,
            probe_token,
        )
        .unwrap();
        node.pending_filter_probes.insert(
            probe_token,
            PendingFilterProbe {
                authorization,
                expires_at: Instant::now() + FILTER_PROBE_STATE_TTL,
            },
        );
        let source: SocketAddr = "127.0.0.2:39000".parse().unwrap();

        for (nonce, sender, body) in [
            (
                1,
                &helper_identity,
                MessageBody::FilteringMatrixProbe {
                    trial_id: trial_id + 1,
                    probe_class: FilterProbeClass::DifferentAddress,
                    probe_token,
                },
            ),
            (
                2,
                &helper_identity,
                MessageBody::FilteringMatrixProbe {
                    trial_id,
                    probe_class: FilterProbeClass::SameAddressDifferentPort,
                    probe_token,
                },
            ),
            (
                3,
                &helper_identity,
                MessageBody::FilteringMatrixProbe {
                    trial_id,
                    probe_class: FilterProbeClass::DifferentAddress,
                    probe_token: probe_token + 1,
                },
            ),
        ] {
            let packet = WireEnvelope::signed(sender, nonce, body)
                .unwrap()
                .encode()
                .unwrap();
            node.handle_datagram(&packet, source).await.unwrap();
            assert!(node.pending_filter_probes.contains_key(&probe_token));
        }

        let wrong_sender = NodeIdentity::generate();
        let packet = WireEnvelope::signed(
            &wrong_sender,
            4,
            MessageBody::FilteringMatrixProbe {
                trial_id,
                probe_class: FilterProbeClass::DifferentAddress,
                probe_token,
            },
        )
        .unwrap()
        .encode()
        .unwrap();
        node.handle_datagram(&packet, source).await.unwrap();
        assert!(node.pending_filter_probes.contains_key(&probe_token));

        let packet = WireEnvelope::signed(
            &helper_identity,
            5,
            MessageBody::FilteringMatrixProbe {
                trial_id,
                probe_class: FilterProbeClass::DifferentAddress,
                probe_token,
            },
        )
        .unwrap()
        .encode()
        .unwrap();
        node.handle_datagram(&packet, source).await.unwrap();

        assert!(!node.pending_filter_probes.contains_key(&probe_token));
        assert_eq!(
            node.nat_profile.filter_matrix_snapshot().different_address,
            FilterCellStatus::Observed
        );
    }

    #[tokio::test]
    async fn filtering_matrix_expiry_records_an_inconclusive_timeout() {
        let identity = NodeIdentity::generate();
        let mut node = KonoNode::bind(
            identity,
            "127.0.0.1:0".parse().unwrap(),
            Vec::new(),
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        let coordinator_node_id = NodeIdentity::generate().node_id();
        let target_endpoint: SocketAddr = "127.0.0.1:47010".parse().unwrap();
        node.nat_profile
            .observe(coordinator_node_id.clone(), target_endpoint);
        let current_unix_ms = u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .unwrap();
        let authorization = FilteringMatrixAuthorization::signed_at(
            &node.identity,
            target_endpoint,
            coordinator_node_id.clone(),
            "127.0.0.1:47011".parse().unwrap(),
            coordinator_node_id,
            FilterProbeClass::ContactedEndpoint,
            71,
            701,
            current_unix_ms.saturating_sub(FILTERING_MATRIX_AUTH_TTL_MS + 1),
        )
        .unwrap();
        assert!(authorization.verify().is_err());
        node.pending_filter_probes.insert(
            authorization.probe_token,
            PendingFilterProbe {
                authorization,
                expires_at: Instant::now() - Duration::from_millis(1),
            },
        );

        node.expire_filtering_matrix_state();

        assert!(node.pending_filter_probes.is_empty());
        assert_eq!(
            node.nat_profile.filter_matrix_snapshot().contacted_endpoint,
            FilterCellStatus::InconclusiveTimedOut
        );
    }

    #[tokio::test]
    async fn mismatched_filtering_unavailable_preserves_the_pending_cell() {
        let identity = NodeIdentity::generate();
        let mut node = KonoNode::bind(
            identity,
            "127.0.0.1:0".parse().unwrap(),
            Vec::new(),
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        let coordinator_node_id = NodeIdentity::generate().node_id();
        let coordinator_endpoint: SocketAddr = "127.0.0.1:47011".parse().unwrap();
        let target_endpoint: SocketAddr = "127.0.0.1:47010".parse().unwrap();
        let trial_id = 72;
        let probe_token = 702;
        node.nat_profile
            .observe(coordinator_node_id.clone(), target_endpoint);
        let authorization = FilteringMatrixAuthorization::signed(
            &node.identity,
            target_endpoint,
            coordinator_node_id.clone(),
            coordinator_endpoint,
            coordinator_node_id.clone(),
            FilterProbeClass::ContactedEndpoint,
            trial_id,
            probe_token,
        )
        .unwrap();
        node.pending_filter_trials.insert(
            trial_id,
            PendingFilterTrial {
                coordinator_endpoint,
                coordinator_node_id: coordinator_node_id.clone(),
                target_endpoint,
                seen_classes: HashSet::from([FilterProbeClass::ContactedEndpoint]),
                expires_at: Instant::now() + FILTER_MATRIX_TRIAL_TTL,
            },
        );
        node.pending_filter_probes.insert(
            probe_token,
            PendingFilterProbe {
                authorization,
                expires_at: Instant::now() + FILTER_PROBE_STATE_TTL,
            },
        );

        node.handle_filtering_matrix_unavailable(
            coordinator_endpoint,
            &coordinator_node_id,
            trial_id,
            FilterProbeClass::SameAddressDifferentPort,
            probe_token,
            FilteringMatrixFailure::NoHelper,
        );

        assert!(node.pending_filter_probes.contains_key(&probe_token));
        node.pending_filter_probes
            .get_mut(&probe_token)
            .unwrap()
            .expires_at = Instant::now() - Duration::from_millis(1);
        node.expire_filtering_matrix_state();
        assert_eq!(
            node.nat_profile.filter_matrix_snapshot().contacted_endpoint,
            FilterCellStatus::InconclusiveTimedOut
        );
    }

    #[tokio::test]
    async fn filtering_matrix_rate_limits_each_coordinator_window() {
        let identity = NodeIdentity::generate();
        let mut node = KonoNode::bind(
            identity,
            "127.0.0.1:0".parse().unwrap(),
            Vec::new(),
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        let now = Instant::now();
        let target: SocketAddr = "8.8.8.8:47000".parse().unwrap();

        for _ in 0..FILTER_PROBE_COORDINATOR_LIMIT {
            assert!(node.allow_filter_probe("coordinator", target, now));
        }
        assert!(!node.allow_filter_probe("coordinator", target, now));
        let helper_node_id = node.node_id();
        let authorization = FilteringMatrixAuthorization::signed(
            &NodeIdentity::generate(),
            target,
            "coordinator".to_owned(),
            node.local_addr().unwrap(),
            helper_node_id,
            FilterProbeClass::ContactedEndpoint,
            81,
            801,
        )
        .unwrap();
        assert_eq!(
            node.send_authorized_filter_probe(&authorization).await,
            Err(FilteringMatrixFailure::RateLimited)
        );
        assert!(node.used_filter_authorizations.is_empty());
        assert!(node.allow_filter_probe("coordinator", target, now + FILTER_PROBE_RATE_WINDOW));
    }

    #[tokio::test]
    async fn filtering_matrix_tracks_egress_without_admitting_a_peer() {
        let identity = NodeIdentity::generate();
        let mut node = KonoNode::bind(
            identity,
            "127.0.0.1:0".parse().unwrap(),
            Vec::new(),
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let endpoint = receiver.local_addr().unwrap();

        node.send(endpoint, MessageBody::Ping { token: 901 })
            .await
            .unwrap();

        assert!(!node.peers.contains_key(&endpoint));
        let now = Instant::now();
        assert!(node.filter_probe_source_was_contacted(endpoint.ip(), now));
        assert!(!node
            .filter_probe_source_was_contacted(endpoint.ip(), now + FILTER_CONTACT_HISTORY_TTL));

        node.recent_egress_ips.clear();
        let prefix = 0x2001_0db8_0000_0000_0000_0000_0000_0000_u128;
        for index in 0..MAX_FILTER_CONTACT_HISTORY {
            node.remember_filter_contact(IpAddr::V6(Ipv6Addr::from(prefix + index as u128)), now);
        }
        let oldest = IpAddr::V6(Ipv6Addr::from(prefix));
        let overflow = IpAddr::V6(Ipv6Addr::from(prefix + MAX_FILTER_CONTACT_HISTORY as u128));
        node.remember_filter_contact(overflow, now);
        assert_eq!(node.recent_egress_ips.len(), MAX_FILTER_CONTACT_HISTORY);
        assert!(node.recent_egress_ips.contains_key(&oldest));
        assert!(!node.recent_egress_ips.contains_key(&overflow));
        assert!(node.filter_probe_source_was_contacted(overflow, now));
    }

    #[tokio::test]
    async fn filtering_matrix_bounds_signature_verification_attempts() {
        let identity = NodeIdentity::generate();
        let mut node = KonoNode::bind(
            identity,
            "127.0.0.1:0".parse().unwrap(),
            Vec::new(),
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        let now = Instant::now();

        for _ in 0..FILTER_PROBE_AUTH_ATTEMPT_LIMIT {
            assert!(node.allow_filter_probe_auth_attempt("sender", now));
        }
        assert!(!node.allow_filter_probe_auth_attempt("sender", now));
        assert!(node.allow_filter_probe_auth_attempt("sender", now + FILTER_PROBE_RATE_WINDOW));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn live_large_mesh_converges_and_recovers_from_churn() {
        const NODE_COUNT: usize = 32;
        const LEAF_COUNT: usize = 30;
        const HUB_COUNT: usize = 2;
        const HELLO_INTERVAL: Duration = Duration::from_secs(2);
        const MESH_TIMEOUT: Duration = Duration::from_secs(60);

        assert!(!endpoint_publishable("127.0.0.1:47000".parse().unwrap()));
        let counters = Arc::new(RuntimeMeshCounters::default());
        let mut nodes = Vec::with_capacity(NODE_COUNT);

        for _ in 0..NODE_COUNT {
            let mut node = KonoNode::bind(
                NodeIdentity::generate(),
                "127.0.0.1:0".parse().unwrap(),
                Vec::new(),
                HELLO_INTERVAL,
            )
            .await
            .unwrap();
            let node_id = node.node_id();
            let endpoint = node.local_addr().unwrap();
            let app = node.configure_relay_app_handle(8).unwrap();
            let diagnostics = node.configure_diagnostics_handle().unwrap();
            node.set_runtime_mesh_counters(counters.clone());
            nodes.push((node, node_id, endpoint, app, diagnostics));
        }

        let endpoints: Vec<_> = nodes.iter().map(|entry| entry.2).collect();
        let _loopback_dht_policy = TestLoopbackDhtEndpoints::register(endpoints.clone());

        let hubs: Vec<_> = (LEAF_COUNT..NODE_COUNT).collect();
        for (node, _, _, _, _) in nodes.iter_mut().take(LEAF_COUNT) {
            node.bootstrap_peers = hubs.iter().map(|hub| endpoints[*hub]).collect();
        }

        let node_ids: Vec<_> = nodes.iter().map(|entry| entry.1.clone()).collect();
        let mut nodes: Vec<_> = nodes.into_iter().map(Some).collect();
        let mut apps: Vec<_> = (0..NODE_COUNT).map(|_| None).collect();
        let mut diagnostics: Vec<_> = (0..NODE_COUNT).map(|_| None).collect();
        let mut tasks: Vec<_> = (0..NODE_COUNT).map(|_| None).collect();
        for (index, node_slot) in nodes.iter_mut().enumerate().skip(LEAF_COUNT) {
            let (node, _, _, app, diagnostic) = node_slot.take().unwrap();
            apps[index] = Some(app);
            diagnostics[index] = Some(diagnostic);
            tasks[index] = Some(tokio::spawn(node.run()));
        }
        time::sleep(Duration::from_millis(200)).await;
        for (leaf, node_slot) in nodes.iter_mut().enumerate().take(LEAF_COUNT) {
            let (node, _, _, app, diagnostic) = node_slot.take().unwrap();
            apps[leaf] = Some(app);
            diagnostics[leaf] = Some(diagnostic);
            tasks[leaf] = Some(tokio::spawn(node.run()));
            time::sleep(Duration::from_millis(250)).await;
        }
        let mut apps: Vec<_> = apps.into_iter().map(Option::unwrap).map(Some).collect();
        let diagnostics: Vec<_> = diagnostics.into_iter().map(Option::unwrap).collect();
        let mut tasks = MeshTaskGuard(tasks);

        wait_for_mesh_condition(
            MESH_TIMEOUT,
            || {
                diagnostics
                    .iter()
                    .take(LEAF_COUNT)
                    .all(|handle| handle.snapshot().authenticated_peers == HUB_COUNT)
                    && diagnostics
                        .iter()
                        .skip(LEAF_COUNT)
                        .all(|handle| handle.snapshot().authenticated_peers == LEAF_COUNT)
            },
            "all leaf-to-hub sessions to authenticate",
            || {
                let leaf_counts: Vec<_> = diagnostics
                    .iter()
                    .take(LEAF_COUNT)
                    .map(|handle| handle.snapshot().authenticated_peers)
                    .collect();
                let hub_counts: Vec<_> = diagnostics
                    .iter()
                    .skip(LEAF_COUNT)
                    .map(|handle| handle.snapshot().authenticated_peers)
                    .collect();
                let finished_tasks: Vec<_> = tasks
                    .0
                    .iter()
                    .enumerate()
                    .filter_map(|(index, task)| {
                        task.as_ref()
                            .is_some_and(|task| task.is_finished())
                            .then_some(index)
                    })
                    .collect();
                format!(
                    "leaf peer counts {leaf_counts:?}; hub peer counts {hub_counts:?}; finished tasks {finished_tasks:?}"
                )
            },
        )
        .await;
        wait_for_mesh_condition(
            MESH_TIMEOUT,
            || counters.replicated_stores.load(Ordering::Relaxed) > 0,
            "a bounded DHT replication store to traverse the runtime mesh",
            || {
                format!(
                    "replicated store count {}",
                    counters.replicated_stores.load(Ordering::Relaxed)
                )
            },
        )
        .await;
        wait_for_mesh_condition(
            MESH_TIMEOUT,
            || {
                let observers = counters
                    .attestation_observers
                    .lock()
                    .expect("mesh attestation counter poisoned");
                node_ids.iter().all(|node_id| {
                    observers
                        .get(&(node_id.clone(), node_id.clone()))
                        .is_some_and(|identities| identities.len() >= 2)
                })
            },
            "two independent accepted attestations for every loopback endpoint",
            || {
                format!(
                    "accepted attestation count {}",
                    counters.attestations.load(Ordering::Relaxed)
                )
            },
        )
        .await;
        assert!(counters.attestations.load(Ordering::Relaxed) >= NODE_COUNT * 2);

        let stopped: HashSet<usize> = (0..NODE_COUNT).filter(|index| index % 3 == 0).collect();
        let stopped_leaves: Vec<_> = (0..LEAF_COUNT)
            .filter(|index| stopped.contains(index))
            .collect();
        let surviving_leaves: Vec<_> = (0..LEAF_COUNT)
            .filter(|index| !stopped.contains(index))
            .collect();
        let (before_source, before_target) = select_mesh_lookup_pair(
            (2, 3),
            &surviving_leaves,
            &stopped_leaves,
            &hubs,
            &node_ids,
            &counters,
        );
        let (before_sender, before_receiver) =
            two_mesh_apps_mut(&mut apps, before_source, before_target);
        deliver_between_mesh_leaves(
            before_sender,
            before_receiver,
            &node_ids[before_source],
            &node_ids[before_target],
            &counters,
            b"alpha.23 live mesh before churn".to_vec(),
        )
        .await;
        assert_mesh_lookup_was_correlated(
            &node_ids[before_source],
            &node_ids[before_target],
            &counters,
        );

        for index in &stopped {
            if let Some(task) = tasks.0[*index].take() {
                task.abort();
                let _ = task.await;
            }
            apps[*index] = None;
        }

        let surviving_leaf_count = (0..LEAF_COUNT)
            .filter(|index| !stopped.contains(index))
            .count();
        let surviving_hubs: Vec<_> = hubs
            .iter()
            .copied()
            .filter(|index| !stopped.contains(index))
            .collect();
        wait_for_mesh_condition(
            MESH_TIMEOUT,
            || {
                (0..LEAF_COUNT).all(|index| {
                    stopped.contains(&index)
                        || diagnostics[index].snapshot().authenticated_peers == surviving_hubs.len()
                }) && surviving_hubs.iter().all(|index| {
                    diagnostics[*index].snapshot().authenticated_peers == surviving_leaf_count
                })
            },
            "HELLO expiry and survivor reconvergence",
            || {
                let leaf_counts: Vec<_> = diagnostics
                    .iter()
                    .take(LEAF_COUNT)
                    .map(|handle| handle.snapshot().authenticated_peers)
                    .collect();
                let hub_counts: Vec<_> = diagnostics
                    .iter()
                    .skip(LEAF_COUNT)
                    .map(|handle| handle.snapshot().authenticated_peers)
                    .collect();
                format!("leaf peer counts {leaf_counts:?}; hub peer counts {hub_counts:?}")
            },
        )
        .await;

        let surviving_leaves: Vec<_> = (0..LEAF_COUNT)
            .filter(|index| !stopped.contains(index))
            .collect();
        let (after_source, after_target) = select_mesh_lookup_pair(
            (1, 17),
            &surviving_leaves,
            &surviving_leaves,
            &surviving_hubs,
            &node_ids,
            &counters,
        );
        assert!(!stopped.contains(&after_source) && !stopped.contains(&after_target));
        let (after_sender, after_receiver) =
            two_mesh_apps_mut(&mut apps, after_source, after_target);
        deliver_between_mesh_leaves(
            after_sender,
            after_receiver,
            &node_ids[after_source],
            &node_ids[after_target],
            &counters,
            b"alpha.23 live mesh after churn".to_vec(),
        )
        .await;
        assert_mesh_lookup_was_correlated(
            &node_ids[after_source],
            &node_ids[after_target],
            &counters,
        );

        for (index, diagnostic) in diagnostics.iter().enumerate().take(NODE_COUNT) {
            if stopped.contains(&index) {
                continue;
            }
            let snapshot = diagnostic.snapshot();
            if index < LEAF_COUNT {
                assert!((surviving_hubs.len()..=HUB_COUNT).contains(&snapshot.authenticated_peers));
            } else {
                assert_eq!(snapshot.authenticated_peers, surviving_leaf_count);
            }
            assert!(snapshot.dht_records <= crate::dht::DEFAULT_DHT_MAX_RECORDS);
            let stopped_endpoints: HashSet<_> =
                stopped.iter().map(|index| endpoints[*index]).collect();
            assert!(snapshot
                .active_paths
                .iter()
                .all(|path| !stopped_endpoints.contains(&path.endpoint)));
        }

        for task in &mut tasks.0 {
            if let Some(task) = task.take() {
                task.abort();
                let _ = task.await;
            }
        }
    }
}
