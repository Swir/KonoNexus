use kononexus::{MessageBody, NodeIdentity, WireEnvelope};

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
        },
    )
    .expect("packet should sign");

    let serialized = packet.encode().expect("packet should encode");
    let decoded = WireEnvelope::decode(&serialized).expect("packet should decode");
    decoded.verify().expect("signature should verify");
}
