use anyhow::{anyhow, Result};
use clap::Parser;
use kononexus::{KonofixSdkConfig, KonofixTransport, RelayAppEvent};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;
use tokio::time;

#[derive(Debug, Parser)]
#[command(
    name = "knp-test-agent",
    version,
    about = "KonoNexus multi-computer transport test agent"
)]
struct Args {
    #[arg(long, default_value = "0.0.0.0:47000")]
    bind: SocketAddr,

    #[arg(long = "peer")]
    peers: Vec<SocketAddr>,

    #[arg(long)]
    identity: Option<PathBuf>,

    #[arg(long)]
    routing_cache: Option<PathBuf>,

    #[arg(long, default_value_t = 2)]
    hello_interval: u64,

    #[arg(long)]
    target: Option<String>,

    #[arg(long)]
    send_text: Option<String>,

    #[arg(long)]
    expect_text: Option<String>,

    #[arg(long)]
    timeout: Option<u64>,

    #[arg(long)]
    stay: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    if args.target.is_some() != args.send_text.is_some() {
        return Err(anyhow!(
            "--target and --send-text must be supplied together"
        ));
    }

    let identity_path = args
        .identity
        .unwrap_or_else(|| default_identity_path(args.bind));
    let mut config = KonofixSdkConfig::new(identity_path)
        .with_bind(args.bind)
        .with_seed_peers(args.peers)
        .with_hello_interval(Duration::from_secs(args.hello_interval.max(1)))
        .with_event_capacity(128);

    if let Some(path) = args.routing_cache {
        config = config.with_routing_cache(path);
    }

    let mut transport = KonofixTransport::spawn(config).await?;
    println!(
        "KNP_TEST_AGENT_READY node_id={} bind={}",
        transport.node_id(),
        transport.local_addr()
    );

    let sent = match (args.target, args.send_text) {
        (Some(target), Some(text)) => {
            let message_id = transport.send(target.clone(), text.into_bytes()).await?;
            println!(
                "KNP_TEST_SEND_QUEUED target={} message_id={}",
                target, message_id
            );
            Some((target, message_id))
        }
        _ => None,
    };

    let timeout_seconds = args.timeout.unwrap_or_else(|| {
        if sent.is_some() || args.expect_text.is_some() {
            60
        } else {
            0
        }
    });

    let deadline = async {
        if timeout_seconds == 0 {
            std::future::pending::<()>().await;
        } else {
            time::sleep(Duration::from_secs(timeout_seconds)).await;
        }
    };
    tokio::pin!(deadline);

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                println!("KNP_TEST_AGENT_STOP");
                break;
            }
            _ = &mut deadline => {
                if sent.is_some() || args.expect_text.is_some() {
                    transport.shutdown().await;
                    return Err(anyhow!("KNP_TEST_TIMEOUT"));
                }
                break;
            }
            event = transport.next_event() => {
                let Some(event) = event else {
                    return Err(anyhow!("KNP_TEST_RUNTIME_CLOSED"));
                };

                match event {
                    RelayAppEvent::Message(message) => {
                        let text = String::from_utf8_lossy(&message.data);
                        println!(
                            "KNP_TEST_RECEIVED peer={} message_id={} bytes={} text={}",
                            message.peer_node_id,
                            message.message_id,
                            message.data.len(),
                            text
                        );

                        if args.expect_text.as_deref() == Some(text.as_ref()) {
                            println!(
                                "KNP_TEST_PASS receive peer={} message_id={}",
                                message.peer_node_id,
                                message.message_id
                            );
                            if sent.is_none() || !args.stay {
                                break;
                            }
                        }
                    }
                    RelayAppEvent::Delivered(receipt) => {
                        println!(
                            "KNP_TEST_DELIVERED peer={} message_id={}",
                            receipt.peer_node_id,
                            receipt.message_id
                        );

                        if sent
                            .as_ref()
                            .is_some_and(|(peer, id)| {
                                peer == &receipt.peer_node_id && *id == receipt.message_id
                            })
                        {
                            println!(
                                "KNP_TEST_PASS delivery peer={} message_id={}",
                                receipt.peer_node_id,
                                receipt.message_id
                            );
                            if !args.stay {
                                break;
                            }
                        }
                    }
                    RelayAppEvent::Failed(failure) => {
                        println!(
                            "KNP_TEST_FAIL peer={} message_id={} reason={:?}",
                            failure.peer_node_id,
                            failure.message_id,
                            failure.reason
                        );
                        if sent
                            .as_ref()
                            .is_some_and(|(peer, id)| {
                                peer == &failure.peer_node_id && *id == failure.message_id
                            })
                        {
                            transport.shutdown().await;
                            return Err(anyhow!("KNP_TEST_DELIVERY_FAILED"));
                        }
                    }
                }
            }
        }
    }

    transport.shutdown().await;
    Ok(())
}

fn default_identity_path(bind: SocketAddr) -> PathBuf {
    let port = bind.port();
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("KonoNexus")
        .join("test-agent")
        .join(format!("identity-{port}.key"))
}
