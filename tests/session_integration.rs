use kononexus::{respond_handshake, PendingHandshake, SecurePayload};

#[test]
fn independent_peers_can_exchange_authenticated_encrypted_payloads() {
    let pending = PendingHandshake::new("knp1-peer-b".to_owned());
    let handshake_id = pending.handshake_id();
    let initiator_public = pending.public_key_hex();

    let (mut responder, responder_public) = respond_handshake(
        "knp1-peer-b",
        "knp1-peer-a",
        handshake_id,
        &initiator_public,
    )
    .expect("responder handshake should succeed");

    let mut initiator = pending
        .complete("knp1-peer-a", &responder_public)
        .expect("initiator handshake should succeed");

    let outbound = initiator
        .encrypt(&SecurePayload::Ping { token: 1234 })
        .expect("encryption should succeed");
    let inbound = responder
        .decrypt(
            &outbound.session_id,
            outbound.sequence,
            &outbound.ciphertext,
        )
        .expect("decryption should succeed");

    assert_eq!(inbound, SecurePayload::Ping { token: 1234 });
    assert_eq!(initiator.session_id(), responder.session_id());
}
