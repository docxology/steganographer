//! Managed signing identities and local revocation-policy I/O.

use anyhow::Context;
use std::path::Path;
use steganographer_core::crypto::decode_hex_array;
use steganographer_core::revocation::{check_known_revocations, RevocationList};
use zeroize::Zeroizing;

pub(crate) const DEFAULT_REVOKED_LIST: &str = "keys/revoked.json";

/// Only an omitted, genuinely absent default list is optional. Explicit paths,
/// malformed files, unreadable files, and dangling symlinks always fail closed.
pub(crate) fn load_revocations(explicit_path: Option<&str>) -> anyhow::Result<RevocationList> {
    let path = Path::new(explicit_path.unwrap_or(DEFAULT_REVOKED_LIST));
    let content = match std::fs::read_to_string(path) {
        Ok(content) => content,
        Err(error)
            if explicit_path.is_none()
                && error.kind() == std::io::ErrorKind::NotFound
                && matches!(std::fs::symlink_metadata(path), Err(error) if error.kind() == std::io::ErrorKind::NotFound) =>
        {
            return Ok(RevocationList::default());
        }
        Err(error) => {
            return Err(error).with_context(|| {
                crate::envelope::UsageError(format!(
                    "Cannot read revoked-keys list {}",
                    path.display()
                ))
            });
        }
    };
    serde_json::from_str(&content).with_context(|| {
        crate::envelope::UsageError(format!("Malformed revoked-keys list {}", path.display()))
    })
}

/// Private input and decoded seed are zeroized; known compromised identities
/// cannot be used by any managed CLI signing surface.
pub(crate) fn load_signing_key(path: &Path) -> anyhow::Result<ed25519_dalek::SigningKey> {
    let encoded = Zeroizing::new(std::fs::read_to_string(path).with_context(|| {
        crate::envelope::UsageError(format!("Cannot read signing key {}", path.display()))
    })?);
    let seed =
        Zeroizing::new(decode_hex_array::<32>(encoded.trim()).context("Invalid signing key")?);
    let key = ed25519_dalek::SigningKey::from_bytes(&seed);
    check_known_revocations(key.verifying_key().as_bytes())?;
    Ok(key)
}
