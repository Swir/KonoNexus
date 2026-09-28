use anyhow::{Context, Result};
use clap::Parser;
use kononexus::{KonoNode, NodeIdentity};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;
use tracing::info;
use tracing_subscriber::EnvFilter;

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

    #[arg(long)]
    identity: Option<PathBuf>,

    #[arg(long, default_value_t = 20)]
    hello_interval: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("kononexus=info")),
        )
        .with_target(false)
        .compact()
        .init();

    let args = Args::parse();
    let identity_path = args.identity.unwrap_or_else(default_identity_path);
    let identity = NodeIdentity::load_or_create(&identity_path)
        .with_context(|| format!("unable to initialize {}", identity_path.display()))?;

    info!(
        node_id = %identity.node_id(),
        identity = %identity_path.display(),
        "identity ready"
    );

    let node = KonoNode::bind(
        identity,
        args.bind,
        args.peers,
        Duration::from_secs(args.hello_interval.max(2)),
    )
    .await?;

    node.run().await
}

fn default_identity_path() -> PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("KonoNexus")
        .join("identity.key")
}
