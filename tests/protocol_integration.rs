use kononexus::{MessageBody, NodeIdentity, WireEnvelope};

#[tokio::test]
async fn zero_hello_interval_is_rejected_before_runtime_start() {
    let result = kononexus::KonoNode::bind(
        NodeIdentity::generate(),
        "127.0.0.1:0".parse().unwrap(),
        Vec::new(),
        std::time::Duration::ZERO,
    )
    .await;
    let error = result
        .err()
        .expect("zero interval must return an error, not spawn a panicking task");
    assert!(error.to_string().contains("hello interval"));
}

#[test]
fn independently_created_nodes_have_distinct_ids() {
    let a = NodeIdentity::generate();
    let b = NodeIdentity::generate();
    assert_ne!(a.node_id(), b.node_id());
}

#[test]
fn another_node_can_verify_a_signed_packet() {
    let sender = NodeIdentity::generate();
    let packet = WireEnvelope::signed(
        &sender,
        0xC0FFEE,
        MessageBody::Hello {
            features: vec!["knp/1".into()],
            cookie: None,
        },
    )
    .expect("packet should sign");

    let serialized = packet.encode().expect("packet should encode");
    let decoded = WireEnvelope::decode(&serialized).expect("packet should decode");
    decoded.verify().expect("signature should verify");
}
