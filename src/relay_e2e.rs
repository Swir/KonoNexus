use crate::identity::{node_id_from_public_key, NodeIdentity, PUBLIC_KEY_LEN, SIGNATURE_LEN};
use crate::relay::MAX_RELAY_CELL_BYTES;
use crate::session::{respond_handshake, PendingHandshake, SecurePayload, SecureSession};
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

pub const MAX_RELAY_INNER_PACKET_BYTES: usize = MAX_RELAY_CELL_BYTES;
const RELAY_E2E_CONTEXT: &str = "knp-relay-e2e-v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum RelayInnerPacket {
    SessionInit {
        circuit_id: u64,
        sender_node_id: String,
        sender_public_key: String,
        recipient_node_id: String,
        handshake_id: u64,
        ephemeral_public_key: String,
        signature: String,
    },
    SessionAck {
        circuit_id: u64,
        sender_node_id: String,
        sender_public_key: String,
        recipient_node_id: String,
        handshake_id: u64,
        ephemeral_public_key: String,
        signature: String,
    },
    Data {
        session_id: String,
        sequence: u64,
        ciphertext: String,
    },
}

#[derive(Debug, Serialize)]
struct UnsignedRelayHandshake<'a> {
    context: &'static str,
    kind: &'static str,
    circuit_id: u64,
    sender_node_id: &'a str,
    sender_public_key: &'a str,
    recipient_node_id: &'a str,
    handshake_id: u64,
    ephemeral_public_key: &'a str,
}

pub struct RelayE2eInitiator {
    circuit_id: u64,
    peer_node_id: String,
    pending: PendingHandshake,
}

impl RelayE2eInitiator {
    pub fn begin(
        identity: &NodeIdentity,
        circuit_id: u64,
        peer_node_id: String,
    ) -> Result<(Self, Vec<u8>)> {
        let pending = PendingHandshake::new(peer_node_id.clone());
        let handshake_id = pending.handshake_id();
        let ephemeral_public_key = pending.public_key_hex();
        let sender_node_id = identity.node_id();
        let sender_public_key = identity.public_key_hex();

        let init_fields = UnsignedRelayHandshake {
            context: RELAY_E2E_CONTEXT,
            kind: "init",
            circuit_id,
            sender_node_id: &sender_node_id,
            sender_public_key: &sender_public_key,
            recipient_node_id: &peer_node_id,
            handshake_id,
            ephemeral_public_key: &ephemeral_public_key,
        };
        let signature = sign_handshake(identity, &init_fields)?;

        let packet = RelayInnerPacket::SessionInit {
            circuit_id,
            sender_node_id,
            sender_public_key,
            recipient_node_id: peer_node_id.clone(),
            handshake_id,
            ephemeral_public_key,
            signature,
        };

        Ok((
            Self {
                circuit_id,
                peer_node_id,
                pending,
            },
            encode_packet(&packet)?,
        ))
    }

    pub fn complete(self, identity: &NodeIdentity, encoded_ack: &[u8]) -> Result<SecureSession> {
        let packet = decode_packet(encoded_ack)?;
        let RelayInnerPacket::SessionAck {
            circuit_id,
            sender_node_id,
            sender_public_key,
            recipient_node_id,
            handshake_id,
            ephemeral_public_key,
            signature,
        } = packet
        else {
            bail!("expected relay inner session ack");
        };

        if circuit_id != self.circuit_id
            || sender_node_id != self.peer_node_id
            || recipient_node_id != identity.node_id()
            || handshake_id != self.pending.handshake_id()
        {
            bail!("relay inner ack does not match pending handshake");
        }

        let ack_fields = UnsignedRelayHandshake {
            context: RELAY_E2E_CONTEXT,
            kind: "ack",
            circuit_id,
            sender_node_id: &sender_node_id,
            sender_public_key: &sender_public_key,
            recipient_node_id: &recipient_node_id,
            handshake_id,
            ephemeral_public_key: &ephemeral_public_key,
        };
        verify_handshake(&ack_fields, &signature)?;

        self.pending
            .complete(&identity.node_id(), &ephemeral_public_key)
    }
}

pub fn accept_relay_init(
    identity: &NodeIdentity,
    circuit_id: u64,
    expected_peer_node_id: &str,
    encoded_init: &[u8],
) -> Result<(SecureSession, Vec<u8>)> {
    let packet = decode_packet(encoded_init)?;
    let RelayInnerPacket::SessionInit {
        circuit_id: packet_circuit_id,
        sender_node_id,
        sender_public_key,
        recipient_node_id,
        handshake_id,
        ephemeral_public_key,
        signature,
    } = packet
    else {
        bail!("expected relay inner session init");
    };

    if packet_circuit_id != circuit_id
        || sender_node_id != expected_peer_node_id
        || recipient_node_id != identity.node_id()
    {
        bail!("relay inner init does not match relay path");
    }

    let init_fields = UnsignedRelayHandshake {
        context: RELAY_E2E_CONTEXT,
        kind: "init",
        circuit_id: packet_circuit_id,
        sender_node_id: &sender_node_id,
        sender_public_key: &sender_public_key,
        recipient_node_id: &recipient_node_id,
        handshake_id,
        ephemeral_public_key: &ephemeral_public_key,
    };
    verify_handshake(&init_fields, &signature)?;

    let (session, responder_public_key) = respond_handshake(
        &identity.node_id(),
        &sender_node_id,
        handshake_id,
        &ephemeral_public_key,
    )?;

    let local_node_id = identity.node_id();
    let local_public_key = identity.public_key_hex();
    let ack_fields = UnsignedRelayHandshake {
        context: RELAY_E2E_CONTEXT,
        kind: "ack",
        circuit_id,
        sender_node_id: &local_node_id,
        sender_public_key: &local_public_key,
        recipient_node_id: &sender_node_id,
        handshake_id,
        ephemeral_public_key: &responder_public_key,
    };
    let ack_signature = sign_handshake(identity, &ack_fields)?;

    let ack = RelayInnerPacket::SessionAck {
        circuit_id,
        sender_node_id: local_node_id,
        sender_public_key: local_public_key,
        recipient_node_id: sender_node_id,
        handshake_id,
        ephemeral_public_key: responder_public_key,
        signature: ack_signature,
    };

    Ok((session, encode_packet(&ack)?))
}

pub fn encode_relay_payload(
    session: &mut SecureSession,
    payload: &SecurePayload,
) -> Result<Vec<u8>> {
    let frame = session.encrypt(payload)?;
    encode_packet(&RelayInnerPacket::Data {
        session_id: frame.session_id,
        sequence: frame.sequence,
        ciphertext: frame.ciphertext,
    })
}

pub fn decode_relay_payload(session: &mut SecureSession, encoded: &[u8]) -> Result<SecurePayload> {
    let packet = decode_packet(encoded)?;
    let RelayInnerPacket::Data {
        session_id,
        sequence,
        ciphertext,
    } = packet
    else {
        bail!("expected relay inner data packet");
    };

    session.decrypt(&session_id, sequence, &ciphertext)
}

pub fn packet_kind(encoded: &[u8]) -> Result<&'static str> {
    match decode_packet(encoded)? {
        RelayInnerPacket::SessionInit { .. } => Ok("init"),
        RelayInnerPacket::SessionAck { .. } => Ok("ack"),
        RelayInnerPacket::Data { .. } => Ok("data"),
    }
}

fn sign_handshake(identity: &NodeIdentity, fields: &UnsignedRelayHandshake<'_>) -> Result<String> {
    let bytes = serde_json::to_vec(fields).context("failed to serialize relay inner handshake")?;
    Ok(hex::encode(identity.sign(&bytes)))
}

fn verify_handshake(fields: &UnsignedRelayHandshake<'_>, signature: &str) -> Result<()> {
    let raw_public = hex::decode(fields.sender_public_key)
        .context("relay inner sender public key is not valid hex")?;
    let public_key: [u8; PUBLIC_KEY_LEN] = raw_public
        .try_into()
        .map_err(|_| anyhow!("relay inner public key must be 32 bytes"))?;

    if node_id_from_public_key(&public_key) != fields.sender_node_id {
        bail!("relay inner NodeID/public-key mismatch");
    }

    let raw_signature = hex::decode(signature).context("relay inner signature is not valid hex")?;
    let signature: [u8; SIGNATURE_LEN] = raw_signature
        .try_into()
        .map_err(|_| anyhow!("relay inner signature must be 64 bytes"))?;

    let bytes = serde_json::to_vec(fields).context("failed to serialize relay inner handshake")?;
    NodeIdentity::verify_with_public_key(&public_key, &bytes, &signature)
}

fn encode_packet(packet: &RelayInnerPacket) -> Result<Vec<u8>> {
    let encoded = serde_json::to_vec(packet).context("failed to encode relay inner packet")?;
    if encoded.len() > MAX_RELAY_INNER_PACKET_BYTES {
        bail!("relay inner packet exceeds maximum size");
    }
    Ok(encoded)
}

fn decode_packet(encoded: &[u8]) -> Result<RelayInnerPacket> {
    if encoded.len() > MAX_RELAY_INNER_PACKET_BYTES {
        bail!("relay inner packet exceeds maximum size");
    }
    serde_json::from_slice(encoded).context("failed to decode relay inner packet")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn establish() -> (SecureSession, SecureSession) {
        let a = NodeIdentity::generate();
        let b = NodeIdentity::generate();
        let (initiator, init) =
            RelayE2eInitiator::begin(&a, 77, b.node_id()).expect("init should build");
        let (responder, ack) =
            accept_relay_init(&b, 77, &a.node_id(), &init).expect("target should accept");
        let origin = initiator
            .complete(&a, &ack)
            .expect("origin should complete");
        (origin, responder)
    }

    #[test]
    fn relay_inner_handshake_derives_end_to_end_session() {
        let (mut a, mut b) = establish();
        assert_eq!(a.session_id(), b.session_id());

        let encoded = encode_relay_payload(&mut a, &SecurePayload::Ping { token: 9 }).unwrap();
        let decoded = decode_relay_payload(&mut b, &encoded).unwrap();
        assert_eq!(decoded, SecurePayload::Ping { token: 9 });
    }

    #[test]
    fn relay_inner_handshake_is_bound_to_circuit() {
        let a = NodeIdentity::generate();
        let b = NodeIdentity::generate();
        let (_, init) = RelayE2eInitiator::begin(&a, 77, b.node_id()).unwrap();

        assert!(accept_relay_init(&b, 78, &a.node_id(), &init).is_err());
    }

    #[test]
    fn relay_inner_handshake_rejects_wrong_expected_peer() {
        let a = NodeIdentity::generate();
        let b = NodeIdentity::generate();
        let c = NodeIdentity::generate();
        let (_, init) = RelayE2eInitiator::begin(&a, 77, b.node_id()).unwrap();

        assert!(accept_relay_init(&b, 77, &c.node_id(), &init).is_err());
    }

    #[test]
    fn tampered_inner_data_is_rejected() {
        let (mut a, mut b) = establish();
        let mut encoded = encode_relay_payload(&mut a, &SecurePayload::Ping { token: 12 }).unwrap();
        let last = encoded.len() - 2;
        encoded[last] ^= 1;

        assert!(decode_relay_payload(&mut b, &encoded).is_err());
    }
}
