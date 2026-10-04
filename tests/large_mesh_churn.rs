use kononexus::dht::{
    DEFAULT_DHT_MAX_RECORDS, DHT_BUCKET_COUNT, DHT_BUCKET_NETWORK_GROUP_LIMIT, DHT_BUCKET_SIZE,
};
use kononexus::{
    node_id_closer_to_target, DhtTable, NodeIdentity, PeerRecord, RoutingTable, DHT_MAX_HOPS,
    DHT_QUERY_FANOUT, DHT_REPLICATION_FANOUT, DHT_REPLICATION_MAX_HOPS, DHT_RESPONSE_LIMIT,
};
use std::collections::{HashSet, VecDeque};
use std::net::SocketAddr;
use std::path::Path;
use std::time::{Duration, Instant};

const NODE_COUNT: usize = 64;
const FAILED_NODE_COUNT: usize = NODE_COUNT / 3;
const OWNER_REPLICATION_FANOUT: usize = DHT_BUCKET_SIZE;

struct SimNode {
    id: String,
    endpoint: SocketAddr,
    routing: RoutingTable,
    dht: DhtTable,
    own_record: PeerRecord,
    active: bool,
}

fn endpoint(index: usize) -> SocketAddr {
    format!("8.0.{}.1:47000", index + 1).parse().unwrap()
}

fn identity(index: usize, state_dir: &Path) -> NodeIdentity {
    std::fs::create_dir_all(&state_dir).unwrap();
    let path = state_dir.join(format!("node-{index}.key"));
    let mut secret = [0_u8; 32];
    secret[..8].copy_from_slice(&(index as u64 + 1).to_le_bytes());
    std::fs::write(&path, hex::encode(secret)).unwrap();
    NodeIdentity::load_or_create(&path).unwrap()
}

fn start_node(
    index: usize,
    known: &[usize],
    nodes: &mut Vec<SimNode>,
    state_dir: &Path,
    now: Instant,
) {
    let identity = identity(index, state_dir);
    let id = identity.node_id();
    let address = endpoint(index);
    let own_record = PeerRecord::signed(&identity, vec![address]).unwrap();
    let mut node = SimNode {
        id: id.clone(),
        endpoint: address,
        routing: RoutingTable::new(&id),
        dht: DhtTable::default(),
        own_record: own_record.clone(),
        active: true,
    };
    node.dht.upsert(own_record).unwrap();

    // Joining uses one bootstrap contact and the peer list it returns, as a DHT join does.
    // Each actual contact teaches both ends the other node and a bounded set of known peers.
    if !known.is_empty() {
        let bootstrap = known[(index.wrapping_mul(7) + 3) % known.len()];
        let discovered = nodes[bootstrap]
            .routing
            .nearest_diverse(&id, DHT_RESPONSE_LIMIT);
        observe_contact(&mut node, &mut nodes[bootstrap], now);
        for peer in discovered {
            let Some(peer_index) = nodes
                .iter()
                .position(|candidate| candidate.id == peer.node_id)
            else {
                continue;
            };
            if nodes[peer_index].active {
                let peer = &nodes[peer_index];
                node.routing.observe(peer.id.clone(), peer.endpoint, now);
            }
        }
    }
    nodes.push(node);
}

fn observe_contact(left: &mut SimNode, right: &mut SimNode, now: Instant) {
    left.routing.observe(right.id.clone(), right.endpoint, now);
    right.routing.observe(left.id.clone(), left.endpoint, now);
}

fn exchange_bounded_peer_lists(nodes: &mut [SimNode], now: Instant) {
    // A round models authenticated contacts followed by the same bounded nearest-peer
    // response used by the runtime. Snapshot first so iteration order cannot mutate a
    // response while it is being consumed.
    let snapshots: Vec<Vec<(String, SocketAddr)>> = nodes
        .iter()
        .map(|node| {
            if node.active {
                node.routing
                    .bucket_entries()
                    .into_iter()
                    .map(|(_, peer)| (peer.node_id, peer.endpoint))
                    .collect()
            } else {
                Vec::new()
            }
        })
        .collect();
    let active_endpoints: HashSet<SocketAddr> = nodes
        .iter()
        .filter(|node| node.active)
        .map(|node| node.endpoint)
        .collect();
    for node in nodes.iter_mut().filter(|node| node.active) {
        node.routing.retain_endpoints(&active_endpoints);
    }

    let mut contacts = Vec::new();
    for (index, node) in nodes.iter().enumerate().filter(|(_, node)| node.active) {
        for (peer_id, _) in &snapshots[index] {
            if let Some(peer_index) = nodes.iter().position(|peer| peer.id == *peer_id) {
                if peer_index != index && nodes[peer_index].active {
                    let closest = nodes[peer_index]
                        .routing
                        .nearest_diverse(&node.id, DHT_RESPONSE_LIMIT)
                        .into_iter()
                        .map(|peer| (peer.node_id, peer.endpoint))
                        .collect::<Vec<_>>();
                    contacts.push((index, peer_index, node.id.clone(), closest));
                }
            }
        }
    }
    for (left, right, target_id, returned) in contacts {
        let (left_node, right_node) = two_mut(nodes, left, right);
        observe_contact(left_node, right_node, now);
        for (peer_id, peer_endpoint) in returned {
            if peer_id != target_id {
                // Receiving a peer list teaches its contents without claiming direct
                // liveness; the next round attempts authenticated contact.
                left_node.routing.observe(peer_id, peer_endpoint, now);
            }
        }
    }
}

fn two_mut<T>(slice: &mut [T], first: usize, second: usize) -> (&mut T, &mut T) {
    assert_ne!(first, second);
    if first < second {
        let (left, right) = slice.split_at_mut(second);
        (&mut left[first], &mut right[0])
    } else {
        let (left, right) = slice.split_at_mut(first);
        (&mut right[0], &mut left[second])
    }
}

fn lookup_record(nodes: &[SimNode], start: usize, target: &str) -> Option<PeerRecord> {
    let mut visited = HashSet::new();
    let mut frontier = VecDeque::from([(start, 0_u8)]);
    while let Some((index, hop)) = frontier.pop_front() {
        if !nodes[index].active || !visited.insert(index) {
            continue;
        }
        if let Some(record) = nodes[index].dht.get(target) {
            return Some(record.clone());
        }
        if hop >= DHT_MAX_HOPS {
            continue;
        }
        let candidates = nodes[index]
            .routing
            .nearest_diverse(target, DHT_RESPONSE_LIMIT);
        let mut closer = Vec::new();
        for peer in candidates {
            if let Some(peer_index) = nodes.iter().position(|node| node.id == peer.node_id) {
                if nodes[peer_index].active
                    && !visited.contains(&peer_index)
                    && node_id_closer_to_target(&nodes[peer_index].id, &nodes[index].id, target)
                {
                    closer.push(peer_index);
                }
            }
        }
        frontier.extend(
            closer
                .into_iter()
                .take(DHT_QUERY_FANOUT)
                .map(|peer_index| (peer_index, hop + 1)),
        );
    }
    None
}

fn replicate_owner_records(nodes: &mut [SimNode]) {
    let owners: Vec<(usize, String, PeerRecord)> = nodes
        .iter()
        .enumerate()
        .filter(|(_, node)| node.active)
        .map(|(index, node)| (index, node.id.clone(), node.own_record.clone()))
        .collect();
    for (owner, owner_id, record) in owners {
        let mut visited = HashSet::from([owner]);
        let mut frontier = VecDeque::from([(owner, DHT_REPLICATION_MAX_HOPS)]);
        while let Some((source, hops_remaining)) = frontier.pop_front() {
            if !nodes[source].active || (source != owner && hops_remaining == 0) {
                continue;
            }
            let limit = if source == owner {
                OWNER_REPLICATION_FANOUT
            } else {
                DHT_REPLICATION_FANOUT
            };
            let candidates = nodes[source]
                .routing
                .nearest_diverse(&owner_id, DHT_RESPONSE_LIMIT);
            let mut forwarded = 0;
            for candidate in candidates {
                if let Some(replica) = nodes.iter().position(|node| node.id == candidate.node_id) {
                    if replica == source
                        || !nodes[replica].active
                        || (source != owner
                            && !node_id_closer_to_target(
                                &nodes[replica].id,
                                &nodes[source].id,
                                &owner_id,
                            ))
                        || !visited.insert(replica)
                    {
                        continue;
                    }
                    nodes[replica].dht.upsert(record.clone()).unwrap();
                    let next_hops_remaining = if source == owner {
                        hops_remaining
                    } else {
                        hops_remaining - 1
                    };
                    frontier.push_back((replica, next_hops_remaining));
                    forwarded += 1;
                    if forwarded == limit {
                        break;
                    }
                }
            }
        }
    }
}

fn assert_bounded_and_diverse(nodes: &[SimNode]) {
    for node in nodes.iter().filter(|node| node.active) {
        let entries = node.routing.bucket_entries();
        let mut per_bucket = std::collections::HashMap::new();
        for (bucket, peer) in &entries {
            let counts = per_bucket.entry(*bucket).or_insert_with(Vec::new);
            counts.push((peer.endpoint.ip(), peer.node_id.as_str()));
        }
        assert!(
            entries.len() <= DHT_BUCKET_COUNT * DHT_BUCKET_SIZE,
            "routing table exceeded bucket bound"
        );
        for peers in per_bucket.values() {
            assert!(peers.len() <= DHT_BUCKET_SIZE);
            for (position, (ip, _)) in peers.iter().enumerate() {
                let group = match ip {
                    std::net::IpAddr::V4(ip) => (ip.octets()[0], ip.octets()[1], ip.octets()[2]),
                    std::net::IpAddr::V6(_) => unreachable!(),
                };
                let same_group = peers[..=position]
                    .iter()
                    .filter(|(candidate, _)| match candidate {
                        std::net::IpAddr::V4(candidate) => {
                            let octets = candidate.octets();
                            group == (octets[0], octets[1], octets[2])
                        }
                        std::net::IpAddr::V6(_) => false,
                    })
                    .count();
                assert!(
                    same_group <= DHT_BUCKET_NETWORK_GROUP_LIMIT,
                    "bucket exceeded /24 diversity limit"
                );
            }
        }
        assert!(
            node.dht.len() <= DEFAULT_DHT_MAX_RECORDS,
            "DHT record table exceeded its bound"
        );
    }
}

// This deterministic simulator exercises the production routing and record-table
// algorithms with bounded peer-list, lookup, and replication fanout. It does not run
// UDP/session transport and makes no WAN interoperability claim.
#[test]
fn large_mesh_algorithm_simulator_converges_recovers_from_churn_and_keeps_state_bounded() {
    let state_dir = std::env::temp_dir().join(format!(
        "kononexus-large-mesh-churn-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    let mut nodes = Vec::with_capacity(NODE_COUNT);
    let initial: Vec<usize> = Vec::new();
    start_node(0, &initial, &mut nodes, &state_dir, Instant::now());
    for index in 1..NODE_COUNT {
        let known: Vec<usize> = (0..index).collect();
        start_node(
            index,
            &known,
            &mut nodes,
            &state_dir,
            Instant::now() + Duration::from_millis(index as u64),
        );
    }

    let now = Instant::now();
    for round in 0..8 {
        exchange_bounded_peer_lists(&mut nodes, now + Duration::from_millis(round));
    }
    assert_bounded_and_diverse(&nodes);
    replicate_owner_records(&mut nodes);

    let surviving: Vec<usize> = (0..NODE_COUNT)
        .filter(|index| *index >= FAILED_NODE_COUNT)
        .collect();
    for (offset, start) in surviving.iter().take(8).enumerate() {
        let target = &nodes[surviving[(offset + 13) % surviving.len()]].id;
        let record = lookup_record(&nodes, *start, target);
        assert!(
            record.is_some(),
            "pre-churn lookup failed for a surviving owner"
        );
    }

    for node in nodes.iter_mut().take(FAILED_NODE_COUNT) {
        node.active = false;
    }
    for round in 0..8 {
        exchange_bounded_peer_lists(
            &mut nodes,
            now + Duration::from_secs(1) + Duration::from_millis(round),
        );
    }
    replicate_owner_records(&mut nodes);
    assert_bounded_and_diverse(&nodes);

    for (offset, start) in surviving.iter().enumerate() {
        let owner = surviving[(offset + 11) % surviving.len()];
        let record = lookup_record(&nodes, *start, &nodes[owner].id);
        assert!(
            record.is_some(),
            "post-churn lookup failed for a surviving owner"
        );
    }
    let _ = std::fs::remove_dir_all(state_dir);
}
