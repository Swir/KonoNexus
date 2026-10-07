use anyhow::{Context, Result};
use clap::Parser;
use kononexus::{
    KonofixSdkConfig, KonofixTransport, RelayAppEvent, SignedWanTestReport, WanTestMatrixManifest,
    WanTestPairBundle, WanTestScenario,
};
use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
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
    identity: Option<PathBuf>,

    #[arg(long)]
    routing_cache: Option<PathBuf>,

    #[arg(long, default_value_t = 2)]
    hello_interval: u64,

    #[arg(long)]
    target: Option<String>,

    #[arg(long)]
    message: Option<String>,

    #[arg(long, default_value_t = 3600)]
    run_seconds: u64,

    #[arg(long, value_name = "PATH")]
    verify_report: Option<PathBuf>,

    #[arg(long, value_name = "PATH")]
    verify_pair: Option<PathBuf>,

    #[arg(long, value_names = ["REPORT_A", "REPORT_B"], num_args = 2)]
    pair_report: Vec<PathBuf>,

    #[arg(long, value_name = "SCENARIO")]
    scenario: Option<WanTestScenario>,

    #[arg(long, value_name = "DESCRIPTION")]
    network_label: Option<String>,

    #[arg(long, value_name = "PATH")]
    pair_output: Option<PathBuf>,

    #[arg(long, value_name = "PATH")]
    verify_matrix: Option<PathBuf>,

    #[arg(long, value_name = "PAIR_PATH")]
    matrix_pair: Vec<PathBuf>,

    #[arg(long, value_name = "PATH")]
    matrix_output: Option<PathBuf>,
}

#[tokio::main]
async fn main() {
    let interactive = std::env::args_os().len() == 1;
    if let Err(error) = run().await {
        eprintln!();
        eprintln!("KONONEXUS ERROR: {error:#}");
        if interactive {
            eprintln!();
            eprintln!("Nacisnij ENTER aby zamknac okno...");
            let mut line = String::new();
            let _ = io::stdin().read_line(&mut line);
        }
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("kononexus=info")),
        )
        .with_target(false)
        .compact()
        .init();

    let args = Args::parse();
    let interactive = std::env::args_os().len() == 1;

    if let Some(path) = args.verify_report.as_deref() {
        let report = SignedWanTestReport::read_verified(path)?;
        println!("REPORT_VALID=1");
        println!(
            "REPORT_SCHEMA={}@{}",
            report.evidence.domain, report.evidence.version
        );
        println!("LOCAL_NODE_ID={}", report.evidence.local_node_id);
        println!("TARGET_NODE_ID={}", report.evidence.target_node_id);
        println!(
            "DELIVERY_PASSED={}",
            u8::from(report.evidence.delivery_passed)
        );
        println!(
            "WAN_MATRIX_ELIGIBLE={}",
            u8::from(report.evidence.eligible_for_wan_matrix)
        );
        println!(
            "SAMPLES={}/{} LOSS_PERCENT={:.1} RTT_MS={:.1}",
            report.evidence.metrics.delivered,
            report.evidence.metrics.sent,
            report.evidence.metrics.packet_loss_percent,
            report.evidence.metrics.average_rtt_ms
        );
        return Ok(());
    }

    if let Some(path) = args.verify_pair.as_deref() {
        let bundle = WanTestPairBundle::read_verified(path)?;
        println!("PAIR_VALID=1");
        println!("PAIR_SCHEMA={}@{}", bundle.domain, bundle.version);
        println!("SCENARIO={}", bundle.scenario);
        println!("NETWORK_LABEL={}", bundle.network_label);
        println!("NODE_A={}", bundle.report_a.evidence.local_node_id);
        println!("NODE_B={}", bundle.report_b.evidence.local_node_id);
        println!("TIMESTAMP_SKEW_MS={}", bundle.timestamp_skew_ms);
        println!(
            "MATRIX_ROW_ELIGIBLE={}",
            u8::from(bundle.matrix_row_eligible)
        );
        println!("REPORT_A_SHA256={}", bundle.report_a_sha256);
        println!("REPORT_B_SHA256={}", bundle.report_b_sha256);
        return Ok(());
    }

    if let Some(path) = args.verify_matrix.as_deref() {
        let manifest = WanTestMatrixManifest::read_verified(path)?;
        println!("MATRIX_VALID=1");
        println!("MATRIX_SCHEMA={}@{}", manifest.domain, manifest.version);
        println!("BUNDLE_COUNT={}", manifest.bundles.len());
        println!(
            "MISSING_SCENARIOS={}",
            scenario_list(&manifest.missing_scenarios)
        );
        println!(
            "INELIGIBLE_SCENARIOS={}",
            scenario_list(&manifest.ineligible_scenarios)
        );
        println!(
            "MANUAL_REVIEW_READY={}",
            u8::from(manifest.ready_for_manual_review)
        );
        return Ok(());
    }

    if !args.matrix_pair.is_empty() {
        let output = args
            .matrix_output
            .as_deref()
            .context("--matrix-output is required with --matrix-pair")?;
        let bundles = args
            .matrix_pair
            .iter()
            .map(|path| WanTestPairBundle::read_verified(path))
            .collect::<Result<Vec<_>>>()?;
        let manifest = WanTestMatrixManifest::new(bundles)?;
        manifest.write_atomic(output)?;
        println!("MATRIX_CREATED={}", output.display());
        println!("BUNDLE_COUNT={}", manifest.bundles.len());
        println!(
            "MISSING_SCENARIOS={}",
            scenario_list(&manifest.missing_scenarios)
        );
        println!(
            "INELIGIBLE_SCENARIOS={}",
            scenario_list(&manifest.ineligible_scenarios)
        );
        println!(
            "MANUAL_REVIEW_READY={}",
            u8::from(manifest.ready_for_manual_review)
        );
        return Ok(());
    }

    if !args.pair_report.is_empty() {
        let scenario = args
            .scenario
            .context("--scenario is required with --pair-report")?;
        let network_label = args
            .network_label
            .as_deref()
            .context("--network-label is required with --pair-report")?;
        let output = args
            .pair_output
            .as_deref()
            .context("--pair-output is required with --pair-report")?;
        let report_a = SignedWanTestReport::read_verified(&args.pair_report[0])?;
        let report_b = SignedWanTestReport::read_verified(&args.pair_report[1])?;
        let bundle = WanTestPairBundle::new(report_a, report_b, scenario, network_label)?;
        bundle.write_atomic(output)?;
        println!("PAIR_CREATED={}", output.display());
        println!(
            "MATRIX_ROW_ELIGIBLE={}",
            u8::from(bundle.matrix_row_eligible)
        );
        println!("REPORT_A_SHA256={}", bundle.report_a_sha256);
        println!("REPORT_B_SHA256={}", bundle.report_b_sha256);
        return Ok(());
    }

    if args.scenario.is_some()
        || args.network_label.is_some()
        || args.pair_output.is_some()
        || args.matrix_output.is_some()
    {
        anyhow::bail!(
            "pair metadata requires --pair-report, and --matrix-output requires --matrix-pair"
        );
    }

    let identity_path = args.identity.unwrap_or(default_identity_path()?);

    println!("===============================================");
    println!(" KonoNexus {} TEST PROBE", env!("CARGO_PKG_VERSION"));
    println!(" Windows / multi-PC network test");
    println!("===============================================");
    println!("IDENTITY={}", identity_path.display());
    if let Some(ip) = local_ip_hint() {
        println!("LAN_IP_HINT={ip}");
    }

    let mut peers = args.peers;
    let mut target = args.target;
    let mut message = args.message;
    let mut run_seconds = args.run_seconds;

    if interactive {
        println!();
        println!("Wybierz tryb:");
        println!("  1 = Pierwszy PC / nasluch");
        println!("  2 = Drugi PC / polacz i wyslij test");
        println!();
        print!("Wybor [1]: ");
        flush_stdout();
        let choice = read_line_trimmed().unwrap_or_default();

        if choice == "2" {
            println!();
            print!("IP pierwszego PC: ");
            flush_stdout();
            let ip = read_line_trimmed().context("nie podano IP pierwszego PC")?;
            let peer: SocketAddr = format!("{ip}:47000")
                .parse()
                .context("nieprawidlowy adres IP pierwszego PC")?;
            peers.push(peer);

            print!("NODE_ID pierwszego PC: ");
            flush_stdout();
            let node_id = read_line_trimmed().context("nie podano NODE_ID")?;
            if node_id.trim().is_empty() {
                anyhow::bail!("NODE_ID nie moze byc pusty");
            }
            target = Some(node_id);

            print!("Wiadomosc testowa [HELLO KONONEXUS]: ");
            flush_stdout();
            let entered = read_line_trimmed().unwrap_or_default();
            message = Some(if entered.is_empty() {
                "HELLO KONONEXUS".to_owned()
            } else {
                entered
            });
            run_seconds = 600;
        } else {
            run_seconds = 3600;
        }
    }

    let mut config = KonofixSdkConfig::new(identity_path.clone())
        .with_bind(args.bind)
        .with_seed_peers(peers)
        .with_hello_interval(Duration::from_secs(args.hello_interval.max(1)))
        .with_event_capacity(128);

    if let Some(path) = args.routing_cache {
        config = config.with_routing_cache(path);
    }

    let mut transport = KonofixTransport::spawn(config)
        .await
        .context("failed to start KonoNexus probe")?;

    println!();
    println!("NODE_ID={}", transport.node_id());
    println!("LOCAL_ADDR={}", transport.local_addr());
    println!("READY=1");
    println!();
    println!("Zostaw to okno otwarte.");
    println!("Skopiuj NODE_ID i podeslij go do testu drugiego PC.");
    println!("Aby zakonczyc: Ctrl+C albo zamknij okno.");
    println!();

    if let (Some(target), Some(message)) = (target, message) {
        let message_id = transport
            .send(target.clone(), message.into_bytes())
            .await
            .with_context(|| format!("failed to queue message for {target}"))?;
        println!("QUEUED message_id={message_id} target={target}");
    }

    let deadline = time::Instant::now() + Duration::from_secs(run_seconds.max(1));

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

fn scenario_list(scenarios: &[WanTestScenario]) -> String {
    if scenarios.is_empty() {
        "none".to_owned()
    } else {
        scenarios
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",")
    }
}

fn flush_stdout() {
    use std::io::Write;
    let _ = io::stdout().flush();
}

fn read_line_trimmed() -> Option<String> {
    let mut line = String::new();
    io::stdin().read_line(&mut line).ok()?;
    Some(line.trim().to_owned())
}

fn local_ip_hint() -> Option<IpAddr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    Some(socket.local_addr().ok()?.ip())
}

fn default_identity_path() -> Result<PathBuf> {
    let exe = std::env::current_exe().context("cannot locate kononexus_probe.exe")?;
    Ok(exe
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("kononexus-probe.key"))
}
