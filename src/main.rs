use anyhow::{Context, Result};
use clap::Parser;
use kononexus::{KonoNode, NodeIdentity};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Clone)]
struct RendezvousSpec {
    coordinator: SocketAddr,
    target_node_id: String,
}

#[derive(Debug, Clone)]
struct RelaySpec {
    relay_endpoint: SocketAddr,
    target_node_id: String,
}

#[derive(Debug, Parser)]
#[command(
    name = "kononexus",
    version,
    about = "KonoNexus Protocol (KNP) experimental serverless mesh node"
)]
struct Args {
    #[arg(long, default_value = "0.0.0.0:47000")]
    bind: SocketAddr,

    #[arg(long = "peer")]
    peers: Vec<SocketAddr>,

    #[arg(
        long = "rendezvous",
        value_parser = parse_rendezvous,
        help = "Experimental direct-path request: COORDINATOR_ADDR=TARGET_NODE_ID"
    )]
    rendezvous: Vec<RendezvousSpec>,

    #[arg(
        long = "connect-node",
        help = "Automatically try encrypted peers as rendezvous coordinators for this target NodeID"
    )]
    connect_nodes: Vec<String>,

    #[arg(
        long = "filter-test",
        help = "Run one consent-based NAT filtering evidence test through this coordinator"
    )]
    filter_tests: Vec<SocketAddr>,

    #[arg(
        long = "relay-via",
        value_parser = parse_relay,
        help = "Request cooperative relay: RELAY_ADDR=TARGET_NODE_ID"
    )]
    relays: Vec<RelaySpec>,

    #[arg(long)]
    identity: Option<PathBuf>,

    #[arg(
        long,
        help = "Persistent routing hint cache path; defaults next to identity.key"
    )]
    routing_cache: Option<PathBuf>,

    #[arg(long, default_value_t = 20)]
    hello_interval: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("kononexus=info")),
        )
        .with_target(false)
        .compact()
        .init();

    let args = Args::parse();
    let identity_path = args.identity.unwrap_or_else(default_identity_path);
    let routing_cache_path = args
        .routing_cache
        .unwrap_or_else(|| default_routing_cache_path(&identity_path));
    let identity = NodeIdentity::load_or_create(&identity_path)
        .with_context(|| format!("unable to initialize {}", identity_path.display()))?;

    info!(
        node_id = %identity.node_id(),
        identity = %identity_path.display(),
        "identity ready"
    );

    let mut node = KonoNode::bind(
        identity,
        args.bind,
        args.peers,
        Duration::from_secs(args.hello_interval.max(2)),
    )
    .await?;

    let cached_hints = node
        .configure_routing_cache(routing_cache_path.clone())
        .with_context(|| {
            format!(
                "unable to initialize routing cache {}",
                routing_cache_path.display()
            )
        })?;
    if cached_hints > 0 {
        info!(
            cached_hints,
            routing_cache = %routing_cache_path.display(),
            "loaded persistent routing hints"
        );
    }

    for request in args.rendezvous {
        node.queue_rendezvous(request.coordinator, request.target_node_id);
    }
    for target_node_id in args.connect_nodes {
        if !target_node_id.trim().is_empty() {
            node.queue_auto_rendezvous(target_node_id);
        }
    }
    for coordinator in args.filter_tests {
        node.queue_filter_test(coordinator);
    }
    for relay in args.relays {
        node.queue_relay(relay.relay_endpoint, relay.target_node_id);
    }

    node.run().await
}

fn parse_rendezvous(value: &str) -> Result<RendezvousSpec, String> {
    let (coordinator, target_node_id) = value
        .split_once('=')
        .ok_or_else(|| "expected COORDINATOR_ADDR=TARGET_NODE_ID".to_owned())?;
    let coordinator = coordinator
        .parse::<SocketAddr>()
        .map_err(|error| format!("invalid coordinator address: {error}"))?;
    if target_node_id.trim().is_empty() {
        return Err("target NodeID cannot be empty".to_owned());
    }

    Ok(RendezvousSpec {
        coordinator,
        target_node_id: target_node_id.to_owned(),
    })
}

fn parse_relay(value: &str) -> Result<RelaySpec, String> {
    let (relay_endpoint, target_node_id) = value
        .split_once('=')
        .ok_or_else(|| "expected RELAY_ADDR=TARGET_NODE_ID".to_owned())?;
    let relay_endpoint = relay_endpoint
        .parse::<SocketAddr>()
        .map_err(|error| format!("invalid relay address: {error}"))?;
    if target_node_id.trim().is_empty() {
        return Err("target NodeID cannot be empty".to_owned());
    }

    Ok(RelaySpec {
        relay_endpoint,
        target_node_id: target_node_id.to_owned(),
    })
}

fn default_routing_cache_path(identity_path: &std::path::Path) -> PathBuf {
    identity_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join("routing-cache.json")
}

fn default_identity_path() -> PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("KonoNexus")
        .join("identity.key")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rendezvous_parser_accepts_endpoint_and_node_id() {
        let parsed =
            parse_rendezvous("127.0.0.1:47000=knp1abc").expect("rendezvous spec should parse");
        assert_eq!(parsed.coordinator, "127.0.0.1:47000".parse().unwrap());
        assert_eq!(parsed.target_node_id, "knp1abc");
    }

    #[test]
    fn rendezvous_parser_rejects_missing_target() {
        assert!(parse_rendezvous("127.0.0.1:47000=").is_err());
    }

    #[test]
    fn relay_parser_accepts_endpoint_and_node_id() {
        let parsed = parse_relay("127.0.0.1:47000=knp1abc").expect("relay spec should parse");
        assert_eq!(parsed.relay_endpoint, "127.0.0.1:47000".parse().unwrap());
        assert_eq!(parsed.target_node_id, "knp1abc");
    }

    #[test]
    fn default_cache_path_is_next_to_identity() {
        let identity = PathBuf::from("data/KonoNexus/identity.key");
        assert_eq!(
            default_routing_cache_path(&identity),
            PathBuf::from("data/KonoNexus/routing-cache.json")
        );
    }
}
