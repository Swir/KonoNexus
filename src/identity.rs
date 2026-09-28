use anyhow::{anyhow, Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

pub const PUBLIC_KEY_LEN: usize = 32;
pub const SECRET_KEY_LEN: usize = 32;
pub const SIGNATURE_LEN: usize = 64;

pub struct NodeIdentity {
    signing_key: SigningKey,
}

impl NodeIdentity {
    pub fn generate() -> Self {
        Self {
            signing_key: SigningKey::generate(&mut OsRng),
        }
    }

    pub fn load_or_create(path: &Path) -> Result<Self> {
        if path.exists() {
            let encoded = fs::read_to_string(path)
                .with_context(|| format!("failed to read identity {}", path.display()))?;
            let raw = hex::decode(encoded.trim()).context("identity key is not valid hex")?;
            let key_bytes: [u8; SECRET_KEY_LEN] = raw
                .try_into()
                .map_err(|_| anyhow!("identity key must contain exactly 32 bytes"))?;
            return Ok(Self {
                signing_key: SigningKey::from_bytes(&key_bytes),
            });
        }

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }

        let identity = Self::generate();
        fs::write(path, hex::encode(identity.signing_key.to_bytes()))
            .with_context(|| format!("failed to write identity {}", path.display()))?;

        Ok(identity)
    }

    pub fn public_key_bytes(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.signing_key.verifying_key().to_bytes()
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key_bytes())
    }

    pub fn node_id(&self) -> String {
        node_id_from_public_key(&self.public_key_bytes())
    }

    pub fn sign(&self, payload: &[u8]) -> [u8; SIGNATURE_LEN] {
        self.signing_key.sign(payload).to_bytes()
    }

    pub fn verify_with_public_key(
        public_key: &[u8; PUBLIC_KEY_LEN],
        payload: &[u8],
        signature: &[u8; SIGNATURE_LEN],
    ) -> Result<()> {
        let verifying_key =
            VerifyingKey::from_bytes(public_key).context("invalid Ed25519 public key")?;
        let signature = Signature::from_bytes(signature);
        verifying_key
            .verify(payload, &signature)
            .context("invalid KNP signature")
    }
}

pub fn node_id_from_public_key(public_key: &[u8; PUBLIC_KEY_LEN]) -> String {
    let digest = Sha256::digest(public_key);
    format!("knp1{}", hex::encode(&digest[..20]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_signatures_round_trip() {
        let identity = NodeIdentity::generate();
        let message = b"kono-nexus-test";
        let signature = identity.sign(message);

        NodeIdentity::verify_with_public_key(
            &identity.public_key_bytes(),
            message,
            &signature,
        )
        .expect("signature should verify");
    }

    #[test]
    fn node_id_is_stable_for_a_public_key() {
        let identity = NodeIdentity::generate();
        assert_eq!(
            identity.node_id(),
            node_id_from_public_key(&identity.public_key_bytes())
        );
        assert!(identity.node_id().starts_with("knp1"));
    }
}
