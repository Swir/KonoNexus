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
    highest_receive_sequence: Option<u64>,
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

        if self
            .highest_receive_sequence
            .is_some_and(|highest| sequence <= highest)
        {
            bail!("KNP secure frame sequence replay or reordering rejected");
        }

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

        self.highest_receive_sequence = Some(sequence);
        Ok(payload)
    }
}

impl Drop for SecureSession {
    fn drop(&mut self) {
        self.send_key.zeroize();
        self.receive_key.zeroize();
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
        highest_receive_sequence: None,
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
    fn all_zero_remote_public_key_is_rejected() {
        let pending = PendingHandshake::new("node-b".to_owned());
        assert!(pending.complete("node-a", &"00".repeat(32)).is_err());
    }
}
