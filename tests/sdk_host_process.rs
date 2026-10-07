use kononexus::{KonofixSdkRequest, KonofixSdkResponse, KonofixSdkResult};
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

#[test]
fn sdk_host_rejects_bad_input_and_accepts_send_without_restarting() {
    let state_dir = std::env::temp_dir().join(format!(
        "kononexus-sdk-host-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::create_dir_all(&state_dir).unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_kononexus_sdk_host"))
        .args([
            "--identity",
            state_dir.join("host.key").to_str().unwrap(),
            "--routing-cache",
            state_dir.join("routing.json").to_str().unwrap(),
            "--bind",
            "127.0.0.1:0",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    let invalid = r#"{"domain":"kononexus/sdk-bridge","version":2,"request_id":"bad-1","command":{"type":"send","peer_node_id":"knp1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","data_base64":"aGk="}}"#;
    let valid = KonofixSdkRequest::new_send(
        "send-1",
        "knp1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        b"hello from process host",
    )
    .to_json()
    .unwrap();

    let mut stdin = child.stdin.take().unwrap();
    writeln!(stdin, "{invalid}").unwrap();
    writeln!(stdin, "{valid}").unwrap();
    stdin.flush().unwrap();

    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    let rejected = KonofixSdkResponse::from_json_verified(line.trim()).unwrap();
    assert_eq!(rejected.request_id, "bad-1");
    assert!(matches!(
        rejected.result,
        KonofixSdkResult::Rejected { ref code, .. } if code == "invalid_request"
    ));

    line.clear();
    stdout.read_line(&mut line).unwrap();
    let accepted = KonofixSdkResponse::from_json_verified(line.trim()).unwrap();
    assert_eq!(accepted.request_id, "send-1");
    assert!(matches!(accepted.result, KonofixSdkResult::Sent { .. }));

    drop(stdin);
    assert!(child.wait().unwrap().success());
    let _ = std::fs::remove_dir_all(state_dir);
}
