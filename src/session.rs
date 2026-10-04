use crate::dht::{EndpointAttestation, PeerRecord};
use crate::nat::FilterProbeAuthorization;
use crate::relay_app::RelayAppFragment;
use crate::security::SequenceWindow;
use anyhow::{anyhow, bail, Context, Result};
use chacha20poly1305::{
    aead::{Aead, Payload},
    ChaCha20Poly1305, KeyInit, Nonce,
};
use hkdf::Hkdf;
use rand::random;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

const SESSION_CONTEXT: &[u8] = b"knp-session-v1";
const SESSION_KEY_INFO: &[u8] = b"knp-session-directional-keys-v1";
const FRAME_CONTEXT: &[u8] = b"knp-secure-frame-v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum SecurePayload {
    Ping {
        token: u64,
    },
    Pong {
        token: u64,
    },
    RendezvousRequest {
        target_node_id: String,
    },
    RendezvousOffer {
        peer_node_id: String,
        candidate_endpoint: String,
        punch_token: u64,
    },
    RendezvousMiss {
        target_node_id: String,
    },
    FilteringTestRequest,
    FilteringTestProposal {
        helper_node_id: String,
        target_endpoint: String,
        probe_token: u64,
    },
    FilteringTestConsent {
        authorization: FilterProbeAuthorization,
    },
    FilteringTestSend {
        authorization: FilterProbeAuthorization,
    },
    FilteringTestUnavailable,
    DhtStore {
        record: PeerRecord,
        #[serde(default)]
        attestations: Vec<EndpointAttestation>,
        #[serde(default)]
        replication_hops_remaining: u8,
    },
    DhtAttestation {
        attestation: EndpointAttestation,
    },
    DhtFind {
        query_id: u64,
        origin_node_id: String,
        target_node_id: String,
        hops_remaining: u8,
    },
    DhtNodes {
        query_id: u64,
        origin_node_id: String,
        target_node_id: String,
        records: Vec<PeerRecord>,
        #[serde(default)]
        attestations: Vec<EndpointAttestation>,
    },
    RelayOpen {
        circuit_id: u64,
        target_node_id: String,
    },
    RelayOffer {
        circuit_id: u64,
        origin_node_id: String,
    },
    RelayAccept {
        circuit_id: u64,
        origin_node_id: String,
    },
    RelayReady {
        circuit_id: u64,
        peer_node_id: String,
    },
    RelayCell {
        circuit_id: u64,
        sequence: u64,
        opaque_payload_hex: String,
    },
    RelayClose {
        circuit_id: u64,
    },
    RelayReject {
        circuit_id: u64,
    },
    RelayAppFragment {
        fragment: RelayAppFragment,
    },
    RelayAppAck {
        message_id: u64,
    },
    SessionRekeyInit {
        rekey_id: u64,
        ephemeral_public_key: String,
    },
    SessionRekeyAck {
        rekey_id: u64,
        ephemeral_public_key: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedFrame {
    pub session_id: String,
    pub sequence: u64,
    pub ciphertext: String,
}

pub struct PendingHandshake {
    handshake_id: u64,
    secret: StaticSecret,
    public_key: [u8; 32],
    peer_node_id: String,
}

impl PendingHandshake {
    pub fn new(peer_node_id: String) -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&secret).to_bytes();

        Self {
            handshake_id: random(),
            secret,
            public_key,
            peer_node_id,
        }
    }

    pub fn handshake_id(&self) -> u64 {
        self.handshake_id
    }

    pub fn peer_node_id(&self) -> &str {
        &self.peer_node_id
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key)
    }

    pub fn complete(
        self,
        local_node_id: &str,
        responder_public_key_hex: &str,
    ) -> Result<SecureSession> {
        let responder_public = parse_public_key(responder_public_key_hex)?;
        let shared = self.secret.diffie_hellman(&responder_public);
        reject_all_zero_shared_secret(shared.as_bytes())?;

        derive_session(
            Role::Initiator,
            local_node_id,
            &self.peer_node_id,
            self.handshake_id,
            &self.public_key,
            responder_public.as_bytes(),
            shared.as_bytes(),
        )
    }
}

pub fn respond_handshake(
    local_node_id: &str,
    initiator_node_id: &str,
    handshake_id: u64,
    initiator_public_key_hex: &str,
) -> Result<(SecureSession, String)> {
    let initiator_public = parse_public_key(initiator_public_key_hex)?;
    let secret = StaticSecret::random_from_rng(OsRng);
    let responder_public = PublicKey::from(&secret);
    let shared = secret.diffie_hellman(&initiator_public);
    reject_all_zero_shared_secret(shared.as_bytes())?;

    let session = derive_session(
        Role::Responder,
        initiator_node_id,
        local_node_id,
        handshake_id,
        initiator_public.as_bytes(),
        responder_public.as_bytes(),
        shared.as_bytes(),
    )?;

    Ok((session, hex::encode(responder_public.as_bytes())))
}

pub struct SecureSession {
    session_id: String,
    peer_node_id: String,
    send_key: [u8; 32],
    receive_key: [u8; 32],
    next_send_sequence: u64,
    receive_window: SequenceWindow,
}

impl SecureSession {
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn peer_node_id(&self) -> &str {
        &self.peer_node_id
    }

    pub fn encrypt(&mut self, payload: &SecurePayload) -> Result<EncryptedFrame> {
        let sequence = self.next_send_sequence;
        let plaintext =
            serde_json::to_vec(payload).context("failed to serialize secure KNP payload")?;
        let nonce_bytes = frame_nonce(sequence);
        let aad = frame_aad(&self.session_id, sequence);
        let cipher = ChaCha20Poly1305::new_from_slice(&self.send_key)
            .map_err(|_| anyhow!("invalid KNP send key length"))?;
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: &plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| anyhow!("failed to encrypt KNP secure frame"))?;

        self.next_send_sequence = sequence
            .checked_add(1)
            .ok_or_else(|| anyhow!("KNP secure send sequence exhausted"))?;

        Ok(EncryptedFrame {
            session_id: self.session_id.clone(),
            sequence,
            ciphertext: hex::encode(ciphertext),
        })
    }

    pub fn decrypt(
        &mut self,
        session_id: &str,
        sequence: u64,
        ciphertext_hex: &str,
    ) -> Result<SecurePayload> {
        if session_id != self.session_id {
            bail!("KNP secure frame session id mismatch");
        }

        self.receive_window.check(sequence)?;

        let ciphertext =
            hex::decode(ciphertext_hex).context("secure frame ciphertext is not valid hex")?;
        let nonce_bytes = frame_nonce(sequence);
        let aad = frame_aad(&self.session_id, sequence);
        let cipher = ChaCha20Poly1305::new_from_slice(&self.receive_key)
            .map_err(|_| anyhow!("invalid KNP receive key length"))?;
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| anyhow!("KNP secure frame authentication failed"))?;
        let payload = serde_json::from_slice(&plaintext)
            .context("failed to decode authenticated KNP secure payload")?;

        self.receive_window.record(sequence)?;
        Ok(payload)
    }
}

impl Drop for SecureSession {
    fn drop(&mut self) {
        self.send_key.zeroize();
        self.receive_key.zeroize();
    }
}

pub struct SessionSlot {
    current: SecureSession,
    previous: Option<(SecureSession, Instant)>,
}

impl SessionSlot {
    pub fn new(current: SecureSession) -> Self {
        Self {
            current,
            previous: None,
        }
    }

    pub fn current_session_id(&self) -> &str {
        self.current.session_id()
    }

    pub fn peer_node_id(&self) -> &str {
        self.current.peer_node_id()
    }

    pub fn encrypt(&mut self, payload: &SecurePayload) -> Result<EncryptedFrame> {
        self.current.encrypt(payload)
    }

    pub fn encrypt_with_session_id(
        &mut self,
        session_id: &str,
        payload: &SecurePayload,
        now: Instant,
    ) -> Result<EncryptedFrame> {
        self.expire_previous(now);

        if self.current.session_id() == session_id {
            return self.current.encrypt(payload);
        }

        if let Some((previous, expires_at)) = self.previous.as_mut() {
            if *expires_at > now && previous.session_id() == session_id {
                return previous.encrypt(payload);
            }
        }

        bail!("requested KNP session id is not active");
    }

    pub fn decrypt(
        &mut self,
        session_id: &str,
        sequence: u64,
        ciphertext_hex: &str,
        now: Instant,
    ) -> Result<SecurePayload> {
        self.expire_previous(now);

        if self.current.session_id() == session_id {
            return self.current.decrypt(session_id, sequence, ciphertext_hex);
        }

        if let Some((previous, expires_at)) = self.previous.as_mut() {
            if *expires_at > now && previous.session_id() == session_id {
                return previous.decrypt(session_id, sequence, ciphertext_hex);
            }
        }

        bail!("KNP secure frame session id is not active");
    }

    pub fn rotate(
        &mut self,
        new_session: SecureSession,
        now: Instant,
        grace: Duration,
    ) -> Result<()> {
        if self.current.peer_node_id() != new_session.peer_node_id() {
            bail!("cannot rotate KNP session to a different peer identity");
        }

        let old = std::mem::replace(&mut self.current, new_session);
        self.previous = Some((old, now + grace));
        Ok(())
    }

    pub fn expire_previous(&mut self, now: Instant) {
        if self
            .previous
            .as_ref()
            .is_some_and(|(_, expires_at)| *expires_at <= now)
        {
            self.previous = None;
        }
    }

    pub fn has_previous(&self) -> bool {
        self.previous.is_some()
    }
}

#[derive(Clone, Copy)]
enum Role {
    Initiator,
    Responder,
}

fn derive_session(
    role: Role,
    initiator_node_id: &str,
    responder_node_id: &str,
    handshake_id: u64,
    initiator_public: &[u8; 32],
    responder_public: &[u8; 32],
    shared_secret: &[u8; 32],
) -> Result<SecureSession> {
    let transcript_hash = transcript_hash(
        initiator_node_id,
        responder_node_id,
        handshake_id,
        initiator_public,
        responder_public,
    );

    let hkdf = Hkdf::<Sha256>::new(Some(&transcript_hash), shared_secret);
    let mut key_material = [0_u8; 64];
    hkdf.expand(SESSION_KEY_INFO, &mut key_material)
        .map_err(|_| anyhow!("failed to derive KNP session keys"))?;

    let mut initiator_to_responder = [0_u8; 32];
    let mut responder_to_initiator = [0_u8; 32];
    initiator_to_responder.copy_from_slice(&key_material[..32]);
    responder_to_initiator.copy_from_slice(&key_material[32..]);
    key_material.zeroize();

    let (send_key, receive_key, peer_node_id) = match role {
        Role::Initiator => (
            initiator_to_responder,
            responder_to_initiator,
            responder_node_id.to_owned(),
        ),
        Role::Responder => (
            responder_to_initiator,
            initiator_to_responder,
            initiator_node_id.to_owned(),
        ),
    };

    Ok(SecureSession {
        session_id: hex::encode(&transcript_hash[..16]),
        peer_node_id,
        send_key,
        receive_key,
        next_send_sequence: 0,
        receive_window: SequenceWindow::default(),
    })
}

fn transcript_hash(
    initiator_node_id: &str,
    responder_node_id: &str,
    handshake_id: u64,
    initiator_public: &[u8; 32],
    responder_public: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SESSION_CONTEXT);
    update_len_prefixed(&mut hasher, initiator_node_id.as_bytes());
    update_len_prefixed(&mut hasher, responder_node_id.as_bytes());
    hasher.update(handshake_id.to_be_bytes());
    hasher.update(initiator_public);
    hasher.update(responder_public);
    hasher.finalize().into()
}

fn update_len_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    hasher.update(len.to_be_bytes());
    hasher.update(bytes);
}

fn parse_public_key(encoded: &str) -> Result<PublicKey> {
    let raw = hex::decode(encoded).context("X25519 public key is not valid hex")?;
    let bytes: [u8; 32] = raw
        .try_into()
        .map_err(|_| anyhow!("X25519 public key must be 32 bytes"))?;
    Ok(PublicKey::from(bytes))
}

fn reject_all_zero_shared_secret(shared_secret: &[u8; 32]) -> Result<()> {
    if shared_secret.iter().all(|byte| *byte == 0) {
        bail!("rejected invalid X25519 shared secret");
    }
    Ok(())
}

fn frame_nonce(sequence: u64) -> [u8; 12] {
    let mut nonce = [0_u8; 12];
    nonce[..4].copy_from_slice(b"KNP1");
    nonce[4..].copy_from_slice(&sequence.to_be_bytes());
    nonce
}

fn frame_aad(session_id: &str, sequence: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(FRAME_CONTEXT.len() + session_id.len() + 8);
    aad.extend_from_slice(FRAME_CONTEXT);
    aad.extend_from_slice(session_id.as_bytes());
    aad.extend_from_slice(&sequence.to_be_bytes());
    aad
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dht::{EndpointAttestation, PeerRecord, DHT_ATTESTATION_RESPONSE_LIMIT};
    use crate::identity::NodeIdentity;
    use crate::protocol::{MessageBody, WireEnvelope, MAX_PACKET_SIZE};

    fn session_pair() -> (SecureSession, SecureSession) {
        let pending = PendingHandshake::new("node-b".to_owned());
        let handshake_id = pending.handshake_id();
        let initiator_public = pending.public_key_hex();
        let (responder, responder_public) =
            respond_handshake("node-b", "node-a", handshake_id, &initiator_public).unwrap();
        let initiator = pending.complete("node-a", &responder_public).unwrap();

        (initiator, responder)
    }

    #[test]
    fn handshake_derives_matching_directional_sessions() {
        let (mut initiator, mut responder) = session_pair();
        assert_eq!(initiator.session_id(), responder.session_id());

        let frame = initiator
            .encrypt(&SecurePayload::Ping { token: 7 })
            .unwrap();
        let payload = responder
            .decrypt(&frame.session_id, frame.sequence, &frame.ciphertext)
            .unwrap();
        assert_eq!(payload, SecurePayload::Ping { token: 7 });

        let reply = responder
            .encrypt(&SecurePayload::Pong { token: 7 })
            .unwrap();
        let payload = initiator
            .decrypt(&reply.session_id, reply.sequence, &reply.ciphertext)
            .unwrap();
        assert_eq!(payload, SecurePayload::Pong { token: 7 });
    }

    #[test]
    fn maximum_dht_attestation_response_fits_wire_packet_bound() {
        let subjects: Vec<NodeIdentity> = (0..8).map(|_| NodeIdentity::generate()).collect();
        let records: Vec<PeerRecord> = subjects
            .iter()
            .enumerate()
            .map(|(index, identity)| {
                PeerRecord::signed(
                    identity,
                    (0..4)
                        .map(|endpoint_index| {
                            format!(
                                "[2001:4860:{index:04x}:{endpoint_index:04x}:ffff:ffff:ffff:ffff]:65535"
                            )
                            .parse()
                            .unwrap()
                        })
                        .collect(),
                )
                .unwrap()
            })
            .collect();
        let endpoint = records[0].socket_endpoints()[0];
        let attestations: Vec<EndpointAttestation> = (0..DHT_ATTESTATION_RESPONSE_LIMIT)
            .map(|_| {
                EndpointAttestation::signed(
                    &NodeIdentity::generate(),
                    records[0].node_id.clone(),
                    endpoint,
                )
                .unwrap()
            })
            .collect();
        let (mut initiator, _) = session_pair();
        let frame = initiator
            .encrypt(&SecurePayload::DhtNodes {
                query_id: u64::MAX,
                origin_node_id: records[0].node_id.clone(),
                target_node_id: records[1].node_id.clone(),
                records,
                attestations,
            })
            .unwrap();
        let envelope = WireEnvelope::signed(
            &NodeIdentity::generate(),
            u64::MAX,
            MessageBody::Encrypted {
                session_id: frame.session_id,
                sequence: frame.sequence,
                ciphertext: frame.ciphertext,
            },
        )
        .unwrap();

        assert!(envelope.encode().unwrap().len() <= MAX_PACKET_SIZE);
    }

    #[test]
    fn legacy_dht_store_without_attestations_decodes_with_empty_evidence() {
        let identity = NodeIdentity::generate();
        let record = PeerRecord::signed(&identity, vec!["8.8.8.8:47000".parse().unwrap()]).unwrap();
        let legacy = serde_json::json!({
            "type": "dht_store",
            "data": { "record": record }
        });

        let decoded: SecurePayload = serde_json::from_value(legacy).unwrap();
        assert!(matches!(
            decoded,
            SecurePayload::DhtStore {
                attestations,
                replication_hops_remaining: 0,
                ..
            } if attestations.is_empty()
        ));
    }

    #[test]
    fn dht_store_round_trip_preserves_replication_budget() {
        let identity = NodeIdentity::generate();
        let record =
            PeerRecord::signed(&identity, vec!["8.8.8.8:47000".parse().unwrap()]).unwrap();
        let payload = SecurePayload::DhtStore {
            record,
            attestations: Vec::new(),
            replication_hops_remaining: 2,
        };
        let (mut initiator, mut responder) = session_pair();
        let frame = initiator.encrypt(&payload).unwrap();

        assert_eq!(
            responder
                .decrypt(&frame.session_id, frame.sequence, &frame.ciphertext)
                .unwrap(),
            payload
        );
    }

    #[test]
    fn secure_frames_accept_bounded_udp_reordering() {
        let (mut initiator, mut responder) = session_pair();
        let first = initiator
            .encrypt(&SecurePayload::Ping { token: 1 })
            .unwrap();
        let second = initiator
            .encrypt(&SecurePayload::Ping { token: 2 })
            .unwrap();
        let third = initiator
            .encrypt(&SecurePayload::Ping { token: 3 })
            .unwrap();

        assert_eq!(
            responder
                .decrypt(&third.session_id, third.sequence, &third.ciphertext)
                .unwrap(),
            SecurePayload::Ping { token: 3 }
        );
        assert_eq!(
            responder
                .decrypt(&first.session_id, first.sequence, &first.ciphertext)
                .unwrap(),
            SecurePayload::Ping { token: 1 }
        );
        assert_eq!(
            responder
                .decrypt(&second.session_id, second.sequence, &second.ciphertext)
                .unwrap(),
            SecurePayload::Ping { token: 2 }
        );
    }

    #[test]
    fn secure_frame_replay_is_rejected() {
        let (mut initiator, mut responder) = session_pair();
        let frame = initiator
            .encrypt(&SecurePayload::Ping { token: 42 })
            .unwrap();

        responder
            .decrypt(&frame.session_id, frame.sequence, &frame.ciphertext)
            .unwrap();
        assert!(responder
            .decrypt(&frame.session_id, frame.sequence, &frame.ciphertext)
            .is_err());
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let (mut initiator, mut responder) = session_pair();
        let mut frame = initiator
            .encrypt(&SecurePayload::Ping { token: 99 })
            .unwrap();
        let replacement = if frame.ciphertext.starts_with('0') {
            "1"
        } else {
            "0"
        };
        frame.ciphertext.replace_range(..1, replacement);

        assert!(responder
            .decrypt(&frame.session_id, frame.sequence, &frame.ciphertext)
            .is_err());
    }

    #[test]
    fn session_slot_accepts_old_inflight_frames_during_rekey_grace() {
        let (mut old_a, old_b) = session_pair();
        let inflight = old_a.encrypt(&SecurePayload::Ping { token: 77 }).unwrap();

        let pending = PendingHandshake::new("node-b".to_owned());
        let rekey_id = pending.handshake_id();
        let initiator_public = pending.public_key_hex();
        let (new_b, responder_public) =
            respond_handshake("node-b", "node-a", rekey_id, &initiator_public).unwrap();
        let new_a = pending.complete("node-a", &responder_public).unwrap();

        let now = Instant::now();
        let mut slot_a = SessionSlot::new(old_a);
        let mut slot_b = SessionSlot::new(old_b);
        slot_a.rotate(new_a, now, Duration::from_secs(30)).unwrap();
        slot_b.rotate(new_b, now, Duration::from_secs(30)).unwrap();

        assert_eq!(
            slot_b
                .decrypt(
                    &inflight.session_id,
                    inflight.sequence,
                    &inflight.ciphertext,
                    now
                )
                .unwrap(),
            SecurePayload::Ping { token: 77 }
        );

        let new_frame = slot_a.encrypt(&SecurePayload::Ping { token: 88 }).unwrap();
        assert_eq!(
            slot_b
                .decrypt(
                    &new_frame.session_id,
                    new_frame.sequence,
                    &new_frame.ciphertext,
                    now
                )
                .unwrap(),
            SecurePayload::Ping { token: 88 }
        );

        assert!(slot_b.has_previous());
        slot_b.expire_previous(now + Duration::from_secs(31));
        assert!(!slot_b.has_previous());
    }

    #[test]
    fn all_zero_remote_public_key_is_rejected() {
        let pending = PendingHandshake::new("node-b".to_owned());
        assert!(pending.complete("node-a", &"00".repeat(32)).is_err());
    }
}
