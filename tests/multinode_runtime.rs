use base64::{engine::general_purpose::STANDARD, Engine as _};
use kononexus::{
    KonofixSdkConfig, KonofixSdkEvent, KonofixSdkEventEnvelope, KonofixSdkRequest,
    KonofixSdkResult, KonofixTransport, RelayAppEvent,
};
use std::path::PathBuf;
use std::time::Duration;
use tokio::time;

fn unique_state_dir() -> PathBuf {
    std::env::temp_dir().join(format!(
        "kononexus-multinode-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    ))
}

async fn wait_for_message(transport: &mut KonofixTransport, peer_node_id: &str, expected: &[u8]) {
    time::timeout(Duration::from_secs(15), async {
        loop {
            match transport.next_event().await {
                Some(RelayAppEvent::Message(message))
                    if message.peer_node_id == peer_node_id && message.data == expected =>
                {
                    break;
                }
                Some(RelayAppEvent::Failed(failure)) => {
                    panic!(
                        "unexpected delivery failure from {}: {:?}",
                        failure.peer_node_id, failure.reason
                    );
                }
                Some(_) => {}
                None => panic!("KonoNexus runtime closed while waiting for message"),
            }
        }
    })
    .await
    .expect("timed out waiting for KonoNexus message");
}

async fn wait_for_receipt(transport: &mut KonofixTransport, peer_node_id: &str, message_id: u64) {
    time::timeout(Duration::from_secs(15), async {
        loop {
            match transport.next_event().await {
                Some(RelayAppEvent::Delivered(receipt))
                    if receipt.peer_node_id == peer_node_id && receipt.message_id == message_id =>
                {
                    break;
                }
                Some(RelayAppEvent::Failed(failure)) if failure.message_id == message_id => {
                    panic!(
                        "message {} to {} failed: {:?}",
                        failure.message_id, failure.peer_node_id, failure.reason
                    );
                }
                Some(_) => {}
                None => panic!("KonoNexus runtime closed while waiting for receipt"),
            }
        }
    })
    .await
    .expect("timed out waiting for KonoNexus delivery receipt");
}

async fn wait_for_sdk_message(
    transport: &mut KonofixTransport,
    peer_node_id: &str,
    expected: &[u8],
) {
    time::timeout(Duration::from_secs(15), async {
        loop {
            let event = transport
                .next_event()
                .await
                .map(KonofixSdkEventEnvelope::from_relay_event)
                .expect("KonoNexus runtime closed while waiting for SDK event");
            let encoded = event.to_json().expect("SDK event must encode");
            let decoded = KonofixSdkEventEnvelope::from_json_verified(&encoded)
                .expect("SDK event must round-trip");
            match decoded.event {
                KonofixSdkEvent::Message {
                    peer_node_id: actual_peer,
                    data_base64,
                    ..
                } if actual_peer == peer_node_id
                    && STANDARD.decode(&data_base64).unwrap() == expected =>
                {
                    break;
                }
                KonofixSdkEvent::Failed { reason, .. } => {
                    panic!("unexpected SDK delivery failure: {reason:?}");
                }
                _ => {}
            }
        }
    })
    .await
    .expect("timed out waiting for KonoNexus SDK message");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_node_runtime_discovers_and_delivers_across_mesh() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("kononexus=debug")
        .with_test_writer()
        .try_init();

    let state_dir = unique_state_dir();
    std::fs::create_dir_all(&state_dir).unwrap();

    let config_a = KonofixSdkConfig::new(state_dir.join("a.key"))
        .with_bind("127.0.0.1:0".parse().unwrap())
        .with_routing_cache(state_dir.join("a-routing.json"))
        .with_hello_interval(Duration::from_millis(250))
        .with_local_test_mode(true);
    let mut a = KonofixTransport::spawn(config_a).await.unwrap();
    let a_node_id = a.node_id().to_owned();
    let a_addr = a.local_addr();

    let config_b = KonofixSdkConfig::new(state_dir.join("b.key"))
        .with_bind("127.0.0.1:0".parse().unwrap())
        .with_seed_peer(a_addr)
        .with_routing_cache(state_dir.join("b-routing.json"))
        .with_hello_interval(Duration::from_millis(250))
        .with_local_test_mode(true);
    let mut b = KonofixTransport::spawn(config_b).await.unwrap();
    let b_node_id = b.node_id().to_owned();

    let config_c = KonofixSdkConfig::new(state_dir.join("c.key"))
        .with_bind("127.0.0.1:0".parse().unwrap())
        .with_seed_peer(a_addr)
        .with_routing_cache(state_dir.join("c-routing.json"))
        .with_hello_interval(Duration::from_millis(250))
        .with_local_test_mode(true);
    let mut c = KonofixTransport::spawn(config_c).await.unwrap();
    let c_node_id = c.node_id().to_owned();

    let prime_b = b
        .send(a_node_id.clone(), b"prime-b".to_vec())
        .await
        .unwrap();
    wait_for_message(&mut a, &b_node_id, b"prime-b").await;
    wait_for_receipt(&mut b, &a_node_id, prime_b).await;

    let prime_c = c
        .send(a_node_id.clone(), b"prime-c".to_vec())
        .await
        .unwrap();
    wait_for_message(&mut a, &c_node_id, b"prime-c").await;
    wait_for_receipt(&mut c, &a_node_id, prime_c).await;

    let mesh_request = KonofixSdkRequest::new_send("mesh-b-to-c", &c_node_id, b"mesh-b-to-c");
    let mesh_response = mesh_request.execute(&b).await.unwrap();
    let mesh_message = match mesh_response.result {
        KonofixSdkResult::Sent { message_id } => message_id,
        result => panic!("SDK send was not accepted: {result:?}"),
    };

    wait_for_sdk_message(&mut c, &b_node_id, b"mesh-b-to-c").await;
    wait_for_receipt(&mut b, &c_node_id, mesh_message).await;

    assert!(!a.is_finished());
    assert!(!b.is_finished());
    assert!(!c.is_finished());

    a.shutdown().await;
    b.shutdown().await;
    c.shutdown().await;

    let _ = std::fs::remove_dir_all(state_dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_node_ipv6_runtime_delivers_and_receipts() {
    let state_dir = unique_state_dir();
    std::fs::create_dir_all(&state_dir).unwrap();

    let config_a = KonofixSdkConfig::new(state_dir.join("ipv6-a.key"))
        .with_bind("[::1]:0".parse().unwrap())
        .with_routing_cache(state_dir.join("ipv6-a-routing.json"))
        .with_hello_interval(Duration::from_millis(250))
        .with_local_test_mode(true);
    let mut a = KonofixTransport::spawn(config_a).await.unwrap();
    let a_node_id = a.node_id().to_owned();
    let a_addr = a.local_addr();
    assert!(a_addr.is_ipv6());

    let config_b = KonofixSdkConfig::new(state_dir.join("ipv6-b.key"))
        .with_bind("[::1]:0".parse().unwrap())
        .with_routing_cache(state_dir.join("ipv6-b-routing.json"))
        .with_hello_interval(Duration::from_millis(250))
        .with_local_test_mode(true);
    let mut b = KonofixTransport::spawn(config_b).await.unwrap();
    let b_node_id = b.node_id().to_owned();
    assert!(b.local_addr().is_ipv6());
    b.connect(a_node_id.clone(), vec![a_addr]).await.unwrap();

    let message_id = b
        .send(a_node_id.clone(), b"ipv6-runtime".to_vec())
        .await
        .unwrap();
    wait_for_message(&mut a, &b_node_id, b"ipv6-runtime").await;
    wait_for_receipt(&mut b, &a_node_id, message_id).await;

    assert!(!a.is_finished());
    assert!(!b.is_finished());

    a.shutdown().await;
    b.shutdown().await;
    let _ = std::fs::remove_dir_all(state_dir);
}
