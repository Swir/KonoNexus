use anyhow::{Context, Result};
use clap::Parser;
use kononexus::{
    KonofixSdkEventEnvelope, KonofixSdkRequest, KonofixSdkResponse, KonofixTransport,
    MAX_SDK_JSON_LINE_BYTES, MAX_SDK_REQUEST_ID_BYTES,
};
use serde_json::Value;
use std::io::{self, BufRead, Read, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::thread;
use tokio::sync::mpsc;

enum HostInput {
    Line(String),
    Invalid(String),
    IoError(io::Error),
}

#[derive(Debug, Parser)]
#[command(
    name = "kononexus_sdk_host",
    about = "JSON Lines process host for the KonoNexus application SDK"
)]
struct Args {
    #[arg(long)]
    identity: PathBuf,

    #[arg(long, default_value = "0.0.0.0:47000")]
    bind: SocketAddr,

    #[arg(long = "peer")]
    seed_peers: Vec<SocketAddr>,

    #[arg(long)]
    routing_cache: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let mut config = kononexus::KonofixSdkConfig::new(args.identity)
        .with_bind(args.bind)
        .with_seed_peers(args.seed_peers);
    if let Some(path) = args.routing_cache {
        config = config.with_routing_cache(path);
    }

    let mut transport = KonofixTransport::spawn(config).await?;
    eprintln!(
        "KONONEXUS_SDK_HOST_READY node_id={} local_addr={}",
        transport.node_id(),
        transport.local_addr()
    );

    let (input_tx, mut input_rx) = mpsc::channel::<HostInput>(64);
    let _input_thread = thread::spawn(move || {
        let mut stdin = io::BufReader::new(io::stdin().lock());
        loop {
            let input = match read_bounded_line(&mut stdin) {
                Ok(Some(Ok(line))) => HostInput::Line(line),
                Ok(Some(Err(error))) => HostInput::Invalid(error),
                Ok(None) => break,
                Err(error) => HostInput::IoError(error),
            };
            let terminal = matches!(input, HostInput::IoError(_));
            if input_tx.blocking_send(input).is_err() || terminal {
                break;
            }
        }
    });

    loop {
        tokio::select! {
            input = input_rx.recv() => match input {
                Some(HostInput::Line(line)) if line.trim().is_empty() => {}
                Some(HostInput::Line(line)) => handle_request(&transport, &line).await?,
                Some(HostInput::Invalid(error)) => emit_json(
                    &KonofixSdkResponse::rejected(
                        "invalid-request",
                        "invalid_request",
                        error,
                    ).to_json()?
                )?,
                Some(HostInput::IoError(error)) => {
                    return Err(error).context("unable to read SDK host stdin")
                },
                None => break,
            },
            event = transport.next_event() => match event {
                Some(event) => emit_json(&KonofixSdkEventEnvelope::from_relay_event(event).to_json()?)?,
                None => anyhow::bail!("KonoNexus runtime event channel closed"),
            },
            signal = tokio::signal::ctrl_c() => {
                signal.context("unable to install Ctrl+C handler")?;
                break;
            }
        }
    }

    transport.shutdown().await;
    Ok(())
}

async fn handle_request(transport: &KonofixTransport, line: &str) -> Result<()> {
    let response = match KonofixSdkRequest::from_json_verified(line) {
        Ok(request) => request.execute(transport).await?,
        Err(error) => KonofixSdkResponse::rejected(
            request_id_hint(line),
            "invalid_request",
            printable_error(&error),
        ),
    };
    emit_json(&response.to_json()?)
}

fn request_id_hint(line: &str) -> String {
    serde_json::from_str::<Value>(line)
        .ok()
        .and_then(|value| value.get("request_id")?.as_str().map(str::to_owned))
        .filter(|value| {
            !value.is_empty()
                && value.len() <= MAX_SDK_REQUEST_ID_BYTES
                && !value.chars().any(char::is_control)
        })
        .unwrap_or_else(|| "invalid-request".to_owned())
}

fn printable_error(error: &anyhow::Error) -> String {
    error
        .to_string()
        .chars()
        .filter(|character| !character.is_control())
        .collect()
}

fn read_bounded_line(reader: &mut impl BufRead) -> io::Result<Option<Result<String, String>>> {
    read_bounded_line_with_limit(reader, MAX_SDK_JSON_LINE_BYTES)
}

fn read_bounded_line_with_limit(
    reader: &mut impl BufRead,
    limit: usize,
) -> io::Result<Option<Result<String, String>>> {
    let mut bytes = Vec::new();
    let read = (&mut *reader)
        .take((limit + 3) as u64)
        .read_until(b'\n', &mut bytes)?;
    if read == 0 {
        return Ok(None);
    }

    let ended = bytes.last() == Some(&b'\n');
    if ended {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
    if bytes.len() > limit {
        if !ended {
            drain_line(reader)?;
        }
        return Ok(Some(Err(format!(
            "SDK request line exceeds {limit} bytes"
        ))));
    }

    Ok(Some(String::from_utf8(bytes).map_err(|_| {
        "SDK request line is not valid UTF-8".to_owned()
    })))
}

fn drain_line(reader: &mut impl BufRead) -> io::Result<()> {
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Ok(());
        }
        if let Some(index) = available.iter().position(|byte| *byte == b'\n') {
            reader.consume(index + 1);
            return Ok(());
        }
        let length = available.len();
        reader.consume(length);
    }
}

fn emit_json(json: &str) -> Result<()> {
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    writeln!(stdout, "{json}").context("unable to write SDK host stdout")?;
    stdout.flush().context("unable to flush SDK host stdout")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_id_hint_is_bounded_and_printable() {
        assert_eq!(request_id_hint(r#"{"request_id":"abc-123"}"#), "abc-123");
        assert_eq!(request_id_hint("not-json"), "invalid-request");
        assert_eq!(
            request_id_hint(r#"{"request_id":"bad\nvalue"}"#),
            "invalid-request"
        );
    }

    #[test]
    fn printable_error_removes_line_breaks() {
        let error = anyhow::anyhow!("first\nsecond");
        assert_eq!(printable_error(&error), "firstsecond");
    }

    #[test]
    fn bounded_reader_recovers_after_oversized_line() {
        let input = format!("{}\nnext\n", "x".repeat(12));
        let mut reader = io::BufReader::new(input.as_bytes());
        assert!(read_bounded_line_with_limit(&mut reader, 8)
            .unwrap()
            .unwrap()
            .is_err());
        assert_eq!(
            read_bounded_line_with_limit(&mut reader, 8)
                .unwrap()
                .unwrap()
                .unwrap(),
            "next"
        );
    }
}
