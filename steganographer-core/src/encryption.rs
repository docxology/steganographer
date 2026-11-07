//! Payload encryption using ChaCha20-Poly1305 AEAD.
//!
//! Provides authenticated encryption for steganographic payloads before
//! they are embedded into media. This ensures that even if an attacker
//! extracts the LSB data, they cannot read or forge the payload without
//! the encryption key.
//!
//! ## Design
//!
//! - **Algorithm**: ChaCha20-Poly1305 (RFC 8439) — authenticated encryption
//!   with associated data (AEAD).
//! - **Key**: 32 bytes (256-bit), shared between encoder and verifier.
//! - **Raw STG3 v1 nonce**: `BLAKE3(salt(4) ‖ packet_id(16))[..12]`.
//!   Raw callers MUST supply a fresh packet identifier for every encryption
//!   under a key; the four-byte salt alone is not sufficient nonce entropy.
//! - **Raw output**: `salt(4) || ciphertext || tag(16)`, unchanged for STG3.
//! - **Legacy output**: [`encrypt_legacy`] adds a strict versioned header and
//!   fresh random 128-bit identifier, carried with the ciphertext.
//!
//! ## Security Notes
//!
//! - Never reuse a packet identifier under a key with the raw [`encrypt`] API.
//!   Random identifiers should contain at least 128 bits of entropy.
//!   [`encrypt_legacy`] generates this identifier internally.
//! - The encryption key is separate from the signing key, though both
//!   can be derived from the same master secret via HKDF or similar.

use chacha20poly1305::{
    aead::{Aead, AeadInOut, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{decode_hex, encode_hex};

/// Size of the encryption key in bytes (256-bit).
pub const KEY_SIZE: usize = 32;

/// Size of the Poly1305 authentication tag in bytes.
pub const TAG_SIZE: usize = 16;

/// Nonce size for ChaCha20-Poly1305 (96-bit).
pub const NONCE_SIZE: usize = 12;

/// Size of the random salt prepended to ciphertext (32-bit).
pub const SALT_SIZE: usize = 4;

const LEGACY_MAGIC: [u8; 4] = *b"STGE";
const LEGACY_VERSION: u8 = 1;
const LEGACY_HEADER_SIZE: usize = 4 + 1 + 16;
/// Bytes added by [`encrypt_legacy`]: magic, version, identifier, salt and tag.
pub const LEGACY_ENCRYPTION_OVERHEAD: usize = LEGACY_HEADER_SIZE + SALT_SIZE + TAG_SIZE;

/// An encryption key for payload encryption.
#[derive(Clone)]
pub struct EncryptionKey([u8; KEY_SIZE]);

impl EncryptionKey {
    /// Generate a fresh random encryption key.
    pub fn generate() -> Self {
        let mut key = Zeroizing::new([0u8; KEY_SIZE]);
        OsRng.fill_bytes(key.as_mut());
        Self(*key)
    }

    /// Create from raw 32 bytes.
    pub fn from_bytes(bytes: &[u8; KEY_SIZE]) -> Self {
        Self(*bytes)
    }

    /// Create from a hex-encoded string.
    pub fn from_hex(hex: &str) -> anyhow::Result<Self> {
        anyhow::ensure!(
            hex.len() == KEY_SIZE * 2,
            "Encryption key must be {} hex characters",
            KEY_SIZE * 2
        );
        let bytes = Zeroizing::new(decode_hex(hex)?);
        Ok(Self(bytes.as_slice().try_into()?))
    }

    /// Export as raw bytes.
    pub fn as_bytes(&self) -> &[u8; KEY_SIZE] {
        &self.0
    }

    /// Export as a redacted hex preview (first two bytes only). Safe to log;
    /// use [`EncryptionKey::expose_hex`] when the raw key material is genuinely
    /// required.
    pub fn to_hex(&self) -> String {
        format!("{:02x}{:02x}…", self.0[0], self.0[1])
    }

    /// Export the full hex string. Explicit opt-in: only call this when the
    /// caller must print or store the raw key material (e.g. handing a newly
    /// generated key to the user).
    pub fn expose_hex(&self) -> String {
        encode_hex(&self.0)
    }
}

impl Drop for EncryptionKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for EncryptionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EncryptionKey(redacted)")
    }
}

/// Derive the 12-byte AEAD nonce from a fresh 4-byte random salt and the
/// 16-byte packet identifier: `BLAKE3(salt ‖ packet_id)[..12]`.
///
/// A fresh identifier per encryption under a key is a caller requirement:
/// the four-byte salt does not make repeated identifiers safe.
fn derive_nonce(salt: &[u8; SALT_SIZE], packet_id: &[u8; 16]) -> [u8; NONCE_SIZE] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(salt);
    hasher.update(packet_id);
    let hash = hasher.finalize();
    let mut nonce = [0u8; NONCE_SIZE];
    nonce.copy_from_slice(&hash.as_bytes()[..NONCE_SIZE]);
    nonce
}

/// Encrypt a payload using ChaCha20-Poly1305.
///
/// Returns `salt(4) || ciphertext || tag` (plaintext.len() + 4 + 16 bytes).
/// The 4-byte random salt is prepended so the receiver can reconstruct the
/// nonce; the ciphertext layout is unchanged from previous versions.
///
/// # Arguments
/// * `key` — The 256-bit encryption key.
/// * `packet_id` — Fresh 16-byte packet identifier for EVERY encryption under
///   this key (including retries); must match [`decrypt`]. The random four-byte
///   salt does not make reuse safe. Legacy callers should use [`encrypt_legacy`].
/// * `plaintext` — The data to encrypt.
/// * `aad` — Optional additional authenticated data (authenticated but not encrypted).
pub fn encrypt(
    key: &EncryptionKey,
    packet_id: &[u8; 16],
    plaintext: &[u8],
    aad: Option<&[u8]>,
) -> anyhow::Result<Vec<u8>> {
    encrypt_prefixed(key, packet_id, plaintext, aad, &[])
}

fn encrypt_prefixed(
    key: &EncryptionKey,
    packet_id: &[u8; 16],
    plaintext: &[u8],
    aad: Option<&[u8]>,
    prefix: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(key.as_bytes().into());
    let mut salt = [0u8; SALT_SIZE];
    OsRng.fill_bytes(&mut salt);
    let nonce_bytes = derive_nonce(&salt, packet_id);
    let capacity = prefix
        .len()
        .checked_add(SALT_SIZE)
        .and_then(|len| len.checked_add(plaintext.len()))
        .and_then(|len| len.checked_add(TAG_SIZE))
        .ok_or_else(|| anyhow::anyhow!("Encrypted payload length overflow"))?;
    let mut result = Zeroizing::new(Vec::with_capacity(capacity));
    result.extend_from_slice(prefix);
    result.extend_from_slice(&salt);
    result.extend_from_slice(plaintext);
    let tag = cipher
        .encrypt_inout_detached(
            Nonce::cast_from_core(&nonce_bytes),
            aad.unwrap_or_default(),
            (&mut result[prefix.len() + SALT_SIZE..]).into(),
        )
        .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;
    result.extend_from_slice(&tag);
    Ok(std::mem::take(&mut *result))
}

/// Decrypt a payload encrypted with [`encrypt`].
///
/// Returns the plaintext if the authentication tag is valid, or an error
/// if the data has been tampered with or the key is wrong.
///
/// # Arguments
/// * `key` — The 256-bit encryption key.
/// * `packet_id` — Must match the packet identifier used during encryption.
/// * `ciphertext` — The encrypted data (salt || ciphertext || tag).
/// * `aad` — Optional additional authenticated data (must match encryption).
pub fn decrypt(
    key: &EncryptionKey,
    packet_id: &[u8; 16],
    ciphertext: &[u8],
    aad: Option<&[u8]>,
) -> anyhow::Result<Vec<u8>> {
    if ciphertext.len() < SALT_SIZE + TAG_SIZE {
        anyhow::bail!(
            "Ciphertext too short: need at least {} bytes, got {}",
            SALT_SIZE + TAG_SIZE,
            ciphertext.len()
        );
    }

    let cipher = ChaCha20Poly1305::new(key.as_bytes().into());

    // Extract the salt from the first 4 bytes
    let mut salt = [0u8; SALT_SIZE];
    salt.copy_from_slice(&ciphertext[..SALT_SIZE]);
    let actual_ciphertext = &ciphertext[SALT_SIZE..];

    let nonce_bytes = derive_nonce(&salt, packet_id);
    let nonce = Nonce::cast_from_core(&nonce_bytes);

    let payload = match aad {
        Some(a) => Payload {
            msg: actual_ciphertext,
            aad: a,
        },
        None => Payload {
            msg: actual_ciphertext,
            aad: &[],
        },
    };

    cipher
        .decrypt(nonce, payload)
        .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))
}

/// Encrypt a legacy payload with a fresh random 128-bit identifier.
///
/// Output: `STGE || version(1) || packet_id(16) || salt(4) || ciphertext || tag(16)`.
/// The strict wrapper has no compatibility fallback to historical zero-ID data.
pub fn encrypt_legacy(
    key: &EncryptionKey,
    plaintext: &[u8],
    aad: Option<&[u8]>,
) -> anyhow::Result<Vec<u8>> {
    let mut packet_id = [0u8; 16];
    OsRng.fill_bytes(&mut packet_id);
    let mut header = [0u8; LEGACY_HEADER_SIZE];
    header[..4].copy_from_slice(&LEGACY_MAGIC);
    header[4] = LEGACY_VERSION;
    header[5..].copy_from_slice(&packet_id);
    encrypt_prefixed(key, &packet_id, plaintext, aad, &header)
}

/// Decrypt only the versioned legacy wrapper emitted by [`encrypt_legacy`].
pub fn decrypt_legacy(
    key: &EncryptionKey,
    ciphertext: &[u8],
    aad: Option<&[u8]>,
) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(
        ciphertext.len() >= LEGACY_ENCRYPTION_OVERHEAD,
        "Legacy ciphertext too short"
    );
    anyhow::ensure!(
        ciphertext[..4] == LEGACY_MAGIC,
        "Invalid legacy encryption magic"
    );
    anyhow::ensure!(
        ciphertext[4] == LEGACY_VERSION,
        "Unsupported legacy encryption version"
    );
    let packet_id: &[u8; 16] = ciphertext[5..LEGACY_HEADER_SIZE].try_into()?;
    decrypt(key, packet_id, &ciphertext[LEGACY_HEADER_SIZE..], aad)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PACKET_ID: [u8; 16] = *b"0123456789abcdef";
    const OTHER_PACKET_ID: [u8; 16] = *b"fdecba9876543210";

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = EncryptionKey::generate();
        let plaintext = b"top secret steganographic payload";
        let enc = encrypt(&key, &PACKET_ID, plaintext, None).unwrap();
        assert_ne!(&enc[SALT_SIZE..], plaintext);
        let dec = decrypt(&key, &PACKET_ID, &enc, None).unwrap();
        assert_eq!(dec, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_with_aad() {
        let key = EncryptionKey::generate();
        let plaintext = b"secret with AAD";
        let aad = b"associated data";
        let enc = encrypt(&key, &PACKET_ID, plaintext, Some(aad)).unwrap();
        let dec = decrypt(&key, &PACKET_ID, &enc, Some(aad)).unwrap();
        assert_eq!(dec, plaintext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = EncryptionKey::generate();
        let key2 = EncryptionKey::generate();
        let enc = encrypt(&key1, &PACKET_ID, b"secret", None).unwrap();
        assert!(decrypt(&key2, &PACKET_ID, &enc, None).is_err());
    }

    #[test]
    fn test_wrong_packet_id_fails() {
        // The packet identifier anchors the nonce: decrypting under a
        // different identifier must fail closed.
        let key = EncryptionKey::generate();
        let enc = encrypt(&key, &PACKET_ID, b"secret", None).unwrap();
        assert!(decrypt(&key, &OTHER_PACKET_ID, &enc, None).is_err());
    }

    #[test]
    fn test_tamper_detection() {
        let key = EncryptionKey::generate();
        let mut enc = encrypt(&key, &PACKET_ID, b"secret", None).unwrap();
        // Flip a bit in the ciphertext (after the salt)
        enc[SALT_SIZE] ^= 1;
        assert!(decrypt(&key, &PACKET_ID, &enc, None).is_err());
    }

    #[test]
    fn test_wrong_aad_fails() {
        let key = EncryptionKey::generate();
        let enc = encrypt(&key, &PACKET_ID, b"secret", Some(b"aad1")).unwrap();
        assert!(decrypt(&key, &PACKET_ID, &enc, Some(b"aad2")).is_err());
    }

    #[test]
    fn test_key_hex_roundtrip() {
        let key = EncryptionKey::generate();
        let hex = key.expose_hex();
        let restored = EncryptionKey::from_hex(&hex).unwrap();
        assert_eq!(key.as_bytes(), restored.as_bytes());
    }

    #[test]
    fn test_key_from_hex_invalid() {
        assert!(EncryptionKey::from_hex("not_hex").is_err());
        assert!(EncryptionKey::from_hex("00").is_err()); // too short
    }

    #[test]
    fn test_ciphertext_is_larger_than_plaintext() {
        let key = EncryptionKey::generate();
        let plaintext = b"payload data";
        let enc = encrypt(&key, &PACKET_ID, plaintext, None).unwrap();
        // ciphertext = salt(4) + plaintext.len() + tag(16)
        assert_eq!(enc.len(), plaintext.len() + SALT_SIZE + TAG_SIZE);
    }

    #[test]
    fn test_different_packet_ids_derive_different_nonces() {
        let salt = [1u8; SALT_SIZE];
        let n1 = derive_nonce(&salt, &PACKET_ID);
        let n2 = derive_nonce(&salt, &OTHER_PACKET_ID);
        assert_ne!(n1, n2, "distinct packets must not share an AEAD nonce");
        assert_ne!(n1, [0u8; NONCE_SIZE]);
    }

    #[test]
    fn test_debug_and_to_hex_do_not_leak_key() {
        let key = EncryptionKey::from_bytes(&[0xAA; KEY_SIZE]);
        let full = key.expose_hex();
        let debug_str = format!("{:?}", key);
        assert!(debug_str.contains("redacted"));
        assert!(!debug_str.contains(&full));
        assert_ne!(key.to_hex(), full, "to_hex must stay redacted");
        assert!(!full.starts_with(&key.to_hex()));
    }

    #[test]
    fn test_key_material_zeroizes() {
        // Exercises the exact call the Drop impl makes; Drop itself cannot be
        // observed after the fact without unsafe code.
        let mut key = EncryptionKey::from_bytes(&[0xAA; KEY_SIZE]);
        key.0.zeroize();
        assert!(key.0.iter().all(|&b| b == 0));
    }
}
