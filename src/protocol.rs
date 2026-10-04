use crate::identity::{node_id_from_public_key, NodeIdentity, PUBLIC_KEY_LEN, SIGNATURE_LEN};
use crate::nat::FilterProbeClass;
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

pub const KNP_VERSION: u16 = 1;
pub const MAX_PACKET_SIZE: usize = 16 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum MessageBody {
    Hello {
        features: Vec<String>,
        cookie: Option<String>,
    },
    CookieChallenge {
        cookie: String,
    },
    HelloAck {
        observed_endpoint: String,
        features: Vec<String>,
    },
    SessionInit {
        handshake_id: u64,
        ephemeral_public_key: String,
    },
    SessionAck {
        handshake_id: u64,
        ephemeral_public_key: String,
    },
    Encrypted {
        session_id: String,
        sequence: u64,
        ciphertext: String,
    },
    PunchProbe {
        punch_token: u64,
    },
    PunchAck {
        punch_token: u64,
        observed_endpoint: String,
    },
    FilterProbe {
        probe_token: u64,
    },
    FilterProbeAck {
        probe_token: u64,
    },
    FilteringMatrixProbe {
        trial_id: u64,
        probe_class: FilterProbeClass,
        probe_token: u64,
    },
    FilteringMatrixProbeAck {
        trial_id: u64,
        probe_class: FilterProbeClass,
        probe_token: u64,
    },
    Ping {
        token: u64,
    },
    Pong {
        token: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireEnvelope {
    pub version: u16,
    pub sender_node_id: String,
    pub sender_public_key: String,
    pub timestamp_unix_ms: u64,
    pub nonce: u64,
    pub body: MessageBody,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize)]
struct UnsignedEnvelope<'a> {
    version: u16,
    sender_node_id: &'a str,
    sender_public_key: &'a str,
    timestamp_unix_ms: u64,
    nonce: u64,
    body: &'a MessageBody,
}

impl WireEnvelope {
    pub fn signed(identity: &NodeIdentity, nonce: u64, body: MessageBody) -> Result<Self> {
        let sender_node_id = identity.node_id();
        let sender_public_key = identity.public_key_hex();
        let timestamp_unix_ms = now_unix_ms()?;

        let mut envelope = Self {
            version: KNP_VERSION,
            sender_node_id,
            sender_public_key,
            timestamp_unix_ms,
            nonce,
            body,
            signature: String::new(),
        };

        let payload = envelope.signing_bytes()?;
        envelope.signature = hex::encode(identity.sign(&payload));
        Ok(envelope)
    }

    pub fn verify(&self) -> Result<()> {
        if self.version != KNP_VERSION {
            bail!(
                "unsupported KNP version {}; expected {}",
                self.version,
                KNP_VERSION
            );
        }

        let public_key_raw =
            hex::decode(&self.sender_public_key).context("public key is not valid hex")?;
        let public_key: [u8; PUBLIC_KEY_LEN] = public_key_raw
            .try_into()
            .map_err(|_| anyhow!("public key must be 32 bytes"))?;

        let expected_node_id = node_id_from_public_key(&public_key);
        if self.sender_node_id != expected_node_id {
            bail!("sender node id does not match sender public key");
        }

        let signature_raw = hex::decode(&self.signature).context("signature is not valid hex")?;
        let signature: [u8; SIGNATURE_LEN] = signature_raw
            .try_into()
            .map_err(|_| anyhow!("signature must be 64 bytes"))?;

        let payload = self.signing_bytes()?;
        NodeIdentity::verify_with_public_key(&public_key, &payload, &signature)
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let bytes = serde_json::to_vec(self).context("failed to serialize KNP envelope")?;
        if bytes.len() > MAX_PACKET_SIZE {
            bail!("KNP packet exceeds maximum packet size");
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_PACKET_SIZE {
            bail!("KNP packet exceeds maximum packet size");
        }
        serde_json::from_slice(bytes).context("failed to decode KNP envelope")
    }

    fn signing_bytes(&self) -> Result<Vec<u8>> {
        let unsigned = UnsignedEnvelope {
            version: self.version,
            sender_node_id: &self.sender_node_id,
            sender_public_key: &self.sender_public_key,
            timestamp_unix_ms: self.timestamp_unix_ms,
            nonce: self.nonce,
            body: &self.body,
        };
        serde_json::to_vec(&unsigned).context("failed to serialize signing payload")
    }
}

fn now_unix_ms() -> Result<u64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?;
    Ok(duration.as_millis().try_into().unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_envelope_verifies() {
        let identity = NodeIdentity::generate();
        let envelope = WireEnvelope::signed(&identity, 7, MessageBody::Ping { token: 42 })
            .expect("signing should work");

        envelope.verify().expect("envelope should verify");
    }

    #[test]
    fn tampering_breaks_signature() {
        let identity = NodeIdentity::generate();
        let mut envelope = WireEnvelope::signed(&identity, 7, MessageBody::Ping { token: 42 })
            .expect("signing should work");

        envelope.body = MessageBody::Ping { token: 43 };
        assert!(envelope.verify().is_err());
    }

    #[test]
    fn encode_decode_round_trip() {
        let identity = NodeIdentity::generate();
        let envelope = WireEnvelope::signed(
            &identity,
            123,
            MessageBody::Hello {
                features: vec!["signed-discovery".to_owned()],
                cookie: None,
            },
        )
        .expect("signing should work");

        let encoded = envelope.encode().expect("encode should work");
        let decoded = WireEnvelope::decode(&encoded).expect("decode should work");

        assert_eq!(decoded.sender_node_id, envelope.sender_node_id);
        assert_eq!(decoded.body, envelope.body);
        decoded.verify().expect("decoded packet should verify");
    }

    #[test]
    fn filtering_matrix_probe_variants_round_trip_with_signatures() {
        let identity = NodeIdentity::generate();
        let variants = [
            MessageBody::FilteringMatrixProbe {
                trial_id: 7,
                probe_class: FilterProbeClass::DifferentAddress,
                probe_token: 11,
            },
            MessageBody::FilteringMatrixProbeAck {
                trial_id: 7,
                probe_class: FilterProbeClass::SameAddressDifferentPort,
                probe_token: 12,
            },
        ];

        for (nonce, body) in variants.into_iter().enumerate() {
            let envelope = WireEnvelope::signed(&identity, nonce as u64, body).unwrap();
            let decoded = WireEnvelope::decode(&envelope.encode().unwrap()).unwrap();
            assert_eq!(decoded.body, envelope.body);
            decoded.verify().unwrap();
        }
    }
}
