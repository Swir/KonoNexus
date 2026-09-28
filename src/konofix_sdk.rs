use crate::{KonoNode, NodeIdentity, RelayAppEvent, RelayAppHandle};
use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::task::JoinHandle;

#[derive(Debug, Clone)]
pub struct KonofixSdkConfig {
    pub bind_addr: SocketAddr,
    pub seed_peers: Vec<SocketAddr>,
    pub identity_path: PathBuf,
    pub routing_cache_path: Option<PathBuf>,
    pub hello_interval: Duration,
    pub event_capacity: usize,
    pub local_test_mode: bool,
}

impl KonofixSdkConfig {
    pub fn new(identity_path: PathBuf) -> Self {
        Self {
            bind_addr: "0.0.0.0:47000"
                .parse()
                .expect("static KonoNexus bind address is valid"),
            seed_peers: Vec::new(),
            identity_path,
            routing_cache_path: None,
            hello_interval: Duration::from_secs(2),
            event_capacity: 64,
            local_test_mode: false,
        }
    }

    pub fn with_bind(mut self, bind_addr: SocketAddr) -> Self {
        self.bind_addr = bind_addr;
        self
    }

    pub fn with_seed_peer(mut self, peer: SocketAddr) -> Self {
        self.seed_peers.push(peer);
        self
    }

    pub fn with_seed_peers(mut self, peers: Vec<SocketAddr>) -> Self {
        self.seed_peers = peers;
        self
    }

    pub fn with_routing_cache(mut self, path: PathBuf) -> Self {
        self.routing_cache_path = Some(path);
        self
    }

    pub fn with_hello_interval(mut self, interval: Duration) -> Self {
        self.hello_interval = interval.max(Duration::from_millis(100));
        self
    }

    pub fn with_event_capacity(mut self, capacity: usize) -> Self {
        self.event_capacity = capacity.max(1);
        self
    }

    pub fn with_local_test_mode(mut self, enabled: bool) -> Self {
        self.local_test_mode = enabled;
        self
    }
}

pub struct KonofixTransport {
    node_id: String,
    local_addr: SocketAddr,
    app: RelayAppHandle,
    task: JoinHandle<Result<()>>,
}

impl KonofixTransport {
    pub async fn spawn(config: KonofixSdkConfig) -> Result<Self> {
        let identity = NodeIdentity::load_or_create(&config.identity_path)
            .with_context(|| format!("unable to initialize {}", config.identity_path.display()))?;
        let node_id = identity.node_id();

        let mut node = KonoNode::bind(
            identity,
            config.bind_addr,
            config.seed_peers,
            config.hello_interval,
        )
        .await?;

        node.set_local_test_mode(config.local_test_mode);

        let local_addr = node.local_addr()?;
        let routing_cache_path = config
            .routing_cache_path
            .unwrap_or_else(|| default_routing_cache_path(&config.identity_path));
        node.configure_routing_cache(routing_cache_path)?;

        let app = node.configure_relay_app_handle(config.event_capacity)?;
        let task = tokio::spawn(node.run());

        Ok(Self {
            node_id,
            local_addr,
            app,
            task,
        })
    }

    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn is_finished(&self) -> bool {
        self.task.is_finished()
    }

    pub async fn send(&self, peer_node_id: impl Into<String>, data: Vec<u8>) -> Result<u64> {
        self.app.send(peer_node_id.into(), data).await
    }

    pub async fn next_event(&mut self) -> Option<RelayAppEvent> {
        self.app.next_event().await
    }

    pub async fn shutdown(mut self) {
        self.task.abort();
        let _ = (&mut self.task).await;
    }
}

impl Drop for KonofixTransport {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn default_routing_cache_path(identity_path: &Path) -> PathBuf {
    identity_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("routing-cache.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routing_cache_defaults_next_to_identity() {
        let identity = PathBuf::from("state/node-a.key");
        assert_eq!(
            default_routing_cache_path(&identity),
            PathBuf::from("state/routing-cache.json")
        );
    }
}
