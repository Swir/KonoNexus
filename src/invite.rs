use crate::identity::{node_id_from_public_key, NodeIdentity, PUBLIC_KEY_LEN, SIGNATURE_LEN};
use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};

const INVITE_PREFIX: &str = "KNX1.";
const INVITE_TTL_MS: u64 = 24 * 60 * 60 * 1_000;
const MAX_INVITE_ENDPOINTS: usize = 8;
const MAX_INVITE_CODE_BYTES: usize = 8 * 1_024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InviteCode {
    pub version: u8,
    pub node_id: String,
    pub public_key: String,
    pub endpoints: Vec<String>,
    pub issued_unix_ms: u64,
    pub expires_unix_ms: u64,
    pub signature: String,
}

#[derive(Serialize)]
struct UnsignedInvite<'a> {
    version: u8,
    node_id: &'a str,
    public_key: &'a str,
    endpoints: &'a [String],
    issued_unix_ms: u64,
    expires_unix_ms: u64,
}

impl InviteCode {
    pub fn signed(identity: &NodeIdentity, endpoints: Vec<SocketAddr>) -> Result<Self> {
        let endpoints = normalize_endpoints(endpoints)?;
        if endpoints.is_empty() {
            bail!("invite requires at least one usable endpoint");
        }

        let issued_unix_ms = unix_time_ms()?;
        let mut invite = Self {
            version: 1,
            node_id: identity.node_id(),
            public_key: identity.public_key_hex(),
            endpoints,
            issued_unix_ms,
            expires_unix_ms: issued_unix_ms.saturating_add(INVITE_TTL_MS),
            signature: String::new(),
        };
        invite.signature = hex::encode(identity.sign(&invite.signing_bytes()?));
        Ok(invite)
    }

    pub fn encode(&self) -> Result<String> {
        self.verify()?;
        let payload = serde_json::to_vec(self).context("failed to serialize invite")?;
        if payload.len() > MAX_INVITE_CODE_BYTES {
            bail!("invite is too large");
        }
        Ok(format!(
            "{INVITE_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(payload)
        ))
    }

    pub fn decode(code: &str) -> Result<Self> {
        let compact: String = code
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();
        let encoded = compact
            .strip_prefix(INVITE_PREFIX)
            .context("invite must start with KNX1.")?;
        if encoded.len() > MAX_INVITE_CODE_BYTES * 2 {
            bail!("invite is too large");
        }
        let payload = URL_SAFE_NO_PAD
            .decode(encoded)
            .context("invite payload is not valid base64url")?;
        let invite: Self = serde_json::from_slice(&payload).context("invite payload is invalid")?;
        invite.verify()?;
        Ok(invite)
    }

    pub fn socket_endpoints(&self) -> Vec<SocketAddr> {
        self.endpoints
            .iter()
            .filter_map(|endpoint| endpoint.parse().ok())
            .collect()
    }

    pub fn verify(&self) -> Result<()> {
        if self.version != 1 {
            bail!("unsupported invite version");
        }
        if unix_time_ms()? > self.expires_unix_ms || self.expires_unix_ms < self.issued_unix_ms {
            bail!("invite expired");
        }
        if self.expires_unix_ms.saturating_sub(self.issued_unix_ms) > INVITE_TTL_MS {
            bail!("invite lifetime exceeds the allowed limit");
        }
        let parsed: Vec<SocketAddr> = self
            .endpoints
            .iter()
            .map(|endpoint| endpoint.parse().context("invite endpoint is invalid"))
            .collect::<Result<_>>()?;
        if parsed.is_empty() || parsed.len() > MAX_INVITE_ENDPOINTS {
            bail!("invite endpoint count is invalid");
        }
        normalize_endpoints(parsed)?;

        let public_key_raw =
            hex::decode(&self.public_key).context("invite public key is invalid")?;
        let public_key: [u8; PUBLIC_KEY_LEN] = public_key_raw
            .try_into()
            .map_err(|_| anyhow!("invite public key must be 32 bytes"))?;
        if node_id_from_public_key(&public_key) != self.node_id {
            bail!("invite NodeID/public-key mismatch");
        }
        let signature_raw = hex::decode(&self.signature).context("invite signature is invalid")?;
        let signature: [u8; SIGNATURE_LEN] = signature_raw
            .try_into()
            .map_err(|_| anyhow!("invite signature must be 64 bytes"))?;
        NodeIdentity::verify_with_public_key(&public_key, &self.signing_bytes()?, &signature)
    }

    fn signing_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(&UnsignedInvite {
            version: self.version,
            node_id: &self.node_id,
            public_key: &self.public_key,
            endpoints: &self.endpoints,
            issued_unix_ms: self.issued_unix_ms,
            expires_unix_ms: self.expires_unix_ms,
        })
        .context("failed to serialize invite signature payload")
    }
}

fn normalize_endpoints(endpoints: Vec<SocketAddr>) -> Result<Vec<String>> {
    if endpoints.len() > MAX_INVITE_ENDPOINTS {
        bail!("too many invite endpoints");
    }
    let mut normalized = Vec::with_capacity(endpoints.len());
    for endpoint in endpoints {
        if endpoint.port() == 0 || endpoint.ip().is_unspecified() || is_unsafe_ip(endpoint.ip()) {
            bail!("invite contains an unusable endpoint");
        }
        normalized.push(endpoint.to_string());
    }
    normalized.sort();
    normalized.dedup();
    Ok(normalized)
}

fn is_unsafe_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_broadcast() || ip.is_multicast() || ip.is_unspecified(),
        IpAddr::V6(ip) => ip.is_multicast() || ip.is_unspecified(),
    }
}

fn unix_time_ms() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_invite_round_trip() {
        let identity = NodeIdentity::generate();
        let invite = InviteCode::signed(
            &identity,
            vec![
                "192.168.1.10:47000".parse().unwrap(),
                "203.0.113.5:47000".parse().unwrap(),
            ],
        )
        .unwrap();
        let decoded = InviteCode::decode(&invite.encode().unwrap()).unwrap();
        assert_eq!(decoded.node_id, identity.node_id());
        assert_eq!(decoded.socket_endpoints().len(), 2);
    }

    #[test]
    fn tampered_invite_is_rejected() {
        let identity = NodeIdentity::generate();
        let mut invite =
            InviteCode::signed(&identity, vec!["192.168.1.10:47000".parse().unwrap()]).unwrap();
        invite.endpoints[0] = "198.51.100.4:47000".into();
        assert!(invite.encode().is_err());
    }
}
