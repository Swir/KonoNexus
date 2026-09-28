use anyhow::{Context, Result};
use clap::Parser;
use kononexus::{KonofixSdkConfig, KonofixTransport, RelayAppEvent};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;
use tokio::time;

#[derive(Debug, Parser)]
#[command(
    name = "kononexus-probe",
    version,
    about = "KonoNexus external multi-PC test probe"
)]
struct Args {
    #[arg(long, default_value = "0.0.0.0:47000")]
    bind: SocketAddr,

    #[arg(long = "peer")]
    peers: Vec<SocketAddr>,

    #[arg(long)]
    identity: PathBuf,

    #[arg(long)]
    routing_cache: Option<PathBuf>,

    #[arg(long, default_value_t = 2)]
    hello_interval: u64,

    #[arg(long)]
    target: Option<String>,

    #[arg(long)]
    message: Option<String>,

    #[arg(long, default_value_t = 120)]
    run_seconds: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("kononexus=info")),
        )
        .with_target(false)
        .compact()
        .init();

    let args = Args::parse();

    let mut config = KonofixSdkConfig::new(args.identity.clone())
        .with_bind(args.bind)
        .with_seed_peers(args.peers)
        .with_hello_interval(Duration::from_secs(args.hello_interval.max(1)))
        .with_event_capacity(128);

    if let Some(path) = args.routing_cache {
        config = config.with_routing_cache(path);
    }

    let mut transport = KonofixTransport::spawn(config)
        .await
        .context("failed to start KonoNexus probe")?;

    println!("NODE_ID={}", transport.node_id());
    println!("LOCAL_ADDR={}", transport.local_addr());
    println!("READY=1");

    if let (Some(target), Some(message)) = (args.target, args.message) {
        let message_id = transport
            .send(target.clone(), message.into_bytes())
            .await
            .with_context(|| format!("failed to queue message for {target}"))?;
        println!("QUEUED message_id={message_id} target={target}");
    }

    let deadline = time::Instant::now() + Duration::from_secs(args.run_seconds.max(1));

    loop {
        tokio::select! {
            _ = time::sleep_until(deadline) => {
                println!("DONE=timeout");
                break;
            }
            event = transport.next_event() => {
                match event {
                    Some(RelayAppEvent::Message(message)) => {
                        println!(
                            "RECV peer={} message_id={} bytes={} text={}",
                            message.peer_node_id,
                            message.message_id,
                            message.data.len(),
                            String::from_utf8_lossy(&message.data)
                        );
                    }
                    Some(RelayAppEvent::Delivered(receipt)) => {
                        println!(
                            "DELIVERED peer={} message_id={}",
                            receipt.peer_node_id,
                            receipt.message_id
                        );
                    }
                    Some(RelayAppEvent::Failed(failure)) => {
                        println!(
                            "FAILED peer={} message_id={} reason={:?}",
                            failure.peer_node_id,
                            failure.message_id,
                            failure.reason
                        );
                    }
                    None => {
                        println!("DONE=runtime_closed");
                        break;
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => {
                println!("DONE=ctrl_c");
                break;
            }
        }
    }

    transport.shutdown().await;
    Ok(())
}
