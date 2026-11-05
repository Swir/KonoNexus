use anyhow::{anyhow, Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{ErrorKind, Write};
use std::path::Path;
use zeroize::Zeroizing;

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
        match fs::read_to_string(path) {
            Ok(encoded) => return Self::from_encoded(Zeroizing::new(encoded)),
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to read identity {}", path.display()))
            }
        }

        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;

        let identity = Self::generate();
        // Publish a complete key without replacing one created by another process.
        // NamedTempFile also creates owner-only files on Unix (0600).
        let mut pending = tempfile::NamedTempFile::new_in(parent)
            .context("failed to create temporary identity file")?;
        let secret = Zeroizing::new(identity.signing_key.to_bytes());
        let encoded = Zeroizing::new(hex::encode(secret.as_ref()));
        pending
            .write_all(encoded.as_bytes())
            .context("failed to write identity")?;
        pending
            .as_file()
            .sync_all()
            .context("failed to sync identity")?;
        match pending.persist_noclobber(path) {
            Ok(_) => Ok(identity),
            Err(error) if error.error.kind() == ErrorKind::AlreadyExists => {
                let encoded = fs::read_to_string(path)
                    .with_context(|| format!("failed to read identity {}", path.display()))?;
                Self::from_encoded(Zeroizing::new(encoded))
            }
            Err(error) => Err(error.error)
                .with_context(|| format!("failed to publish identity {}", path.display())),
        }
    }

    fn from_encoded(encoded: Zeroizing<String>) -> Result<Self> {
        let raw =
            Zeroizing::new(hex::decode(encoded.trim()).context("identity key is not valid hex")?);
        let key_bytes: &[u8; SECRET_KEY_LEN] = raw
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("identity key must contain exactly 32 bytes"))?;
        Ok(Self {
            signing_key: SigningKey::from_bytes(key_bytes),
        })
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
    fn concurrent_first_start_keeps_one_persistent_identity() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("identity.key");
        let barrier = std::sync::Barrier::new(16);
        let ids = std::thread::scope(|scope| {
            let workers: Vec<_> = (0..16)
                .map(|_| {
                    scope.spawn(|| {
                        barrier.wait();
                        NodeIdentity::load_or_create(&path).unwrap().node_id()
                    })
                })
                .collect();
            workers
                .into_iter()
                .map(|worker| worker.join().unwrap())
                .collect::<Vec<_>>()
        });
        let persisted = NodeIdentity::load_or_create(&path).unwrap().node_id();
        assert!(ids.iter().all(|id| id == &persisted));
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[test]
    fn invalid_existing_identity_is_never_replaced() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("identity.key");
        fs::write(&path, "incomplete-key").unwrap();
        assert!(NodeIdentity::load_or_create(&path).is_err());
        assert_eq!(fs::read_to_string(path).unwrap(), "incomplete-key");
    }

    #[cfg(unix)]
    #[test]
    fn new_identity_is_private_to_its_owner() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("identity.key");
        NodeIdentity::load_or_create(&path).unwrap();
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn identity_signatures_round_trip() {
        let identity = NodeIdentity::generate();
        let message = b"kono-nexus-test";
        let signature = identity.sign(message);

        NodeIdentity::verify_with_public_key(&identity.public_key_bytes(), message, &signature)
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
