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
//! - **Nonce**: 12 bytes, derived deterministically from the frame index
//!   to avoid transmitting a per-payload nonce. The nonce is
//!   `counter_bytes[0..12]` where counter = frame_index. This is safe
//!   because each frame index is unique per key.
//! - **Output**: `ciphertext || tag` (16-byte Poly1305 tag appended).
//!
//! ## Security Notes
//!
//! - The same key must never be reused with different payloads under the
//!   same nonce. Since the nonce is derived from the frame index, each
//!   frame gets a unique nonce.
//! - The encryption key is separate from the signing key, though both
//!   can be derived from the same master secret via HKDF or similar.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use rand::rngs::OsRng;
use rand::RngCore;

/// Size of the encryption key in bytes (256-bit).
pub const KEY_SIZE: usize = 32;

/// Size of the Poly1305 authentication tag in bytes.
pub const TAG_SIZE: usize = 16;

/// Nonce size for ChaCha20-Poly1305 (96-bit).
pub const NONCE_SIZE: usize = 12;

/// An encryption key for payload encryption.
#[derive(Clone)]
pub struct EncryptionKey([u8; KEY_SIZE]);

impl EncryptionKey {
    /// Generate a fresh random encryption key.
    pub fn generate() -> Self {
        let mut key = [0u8; KEY_SIZE];
        OsRng.fill_bytes(&mut key);
        Self(key)
    }

    /// Create from raw 32 bytes.
    pub fn from_bytes(bytes: &[u8; KEY_SIZE]) -> Self {
        Self(*bytes)
    }

    /// Create from a hex-encoded string.
    pub fn from_hex(hex: &str) -> anyhow::Result<Self> {
        let bytes = hex_decode(hex)?;
        if bytes.len() != KEY_SIZE {
            anyhow::bail!(
                "Encryption key must be {} bytes ({} hex chars), got {} bytes",
                KEY_SIZE,
                KEY_SIZE * 2,
                bytes.len()
            );
        }
        let mut arr = [0u8; KEY_SIZE];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    /// Export as raw bytes.
    pub fn as_bytes(&self) -> &[u8; KEY_SIZE] {
        &self.0
    }

    /// Export as hex string.
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

impl std::fmt::Debug for EncryptionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EncryptionKey(redacted)")
    }
}

/// Derive a 12-byte nonce from a frame index.
///
/// The frame index is encoded as a 12-byte big-endian value to ensure
/// uniqueness per frame within a single key's lifetime.
fn derive_nonce(frame_index: u64) -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    // Use big-endian frame index in the last 8 bytes for clarity
    nonce[4..12].copy_from_slice(&frame_index.to_be_bytes());
    nonce
}

/// Encrypt a payload using ChaCha20-Poly1305.
///
/// Returns `ciphertext || tag` (plaintext.len() + 16 bytes).
///
/// # Arguments
/// * `key` — The 256-bit encryption key.
/// * `frame_index` — Used to derive a unique nonce per frame.
/// * `plaintext` — The data to encrypt.
/// * `aad` — Optional additional authenticated data (authenticated but not encrypted).
pub fn encrypt(
    key: &EncryptionKey,
    frame_index: u64,
    plaintext: &[u8],
    aad: Option<&[u8]>,
) -> anyhow::Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(key.as_bytes().into());
    let nonce_bytes = derive_nonce(frame_index);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let payload = match aad {
        Some(a) => Payload { msg: plaintext, aad: a },
        None => Payload { msg: plaintext, aad: &[] },
    };

    cipher
        .encrypt(nonce, payload)
        .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))
}

/// Decrypt a payload encrypted with [`encrypt`].
///
/// Returns the plaintext if the authentication tag is valid, or an error
/// if the data has been tampered with or the key is wrong.
///
/// # Arguments
/// * `key` — The 256-bit encryption key.
/// * `frame_index` — Must match the frame index used during encryption.
/// * `ciphertext` — The encrypted data (ciphertext || tag).
/// * `aad` — Optional additional authenticated data (must match encryption).
pub fn decrypt(
    key: &EncryptionKey,
    frame_index: u64,
    ciphertext: &[u8],
    aad: Option<&[u8]>,
) -> anyhow::Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(key.as_bytes().into());
    let nonce_bytes = derive_nonce(frame_index);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let payload = match aad {
        Some(a) => Payload { msg: ciphertext, aad: a },
        None => Payload { msg: ciphertext, aad: &[] },
    };

    cipher
        .decrypt(nonce, payload)
        .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))
}

/// Simple hex decoder.
fn hex_decode(s: &str) -> anyhow::Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        anyhow::bail!("Hex string must have even length");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|e| anyhow::anyhow!("Invalid hex at position {}: {}", i, e))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = EncryptionKey::generate();
        let plaintext = b"top secret steganographic payload";
        let enc = encrypt(&key, 42, plaintext, None).unwrap();
        assert_ne!(&enc[..], plaintext);
        let dec = decrypt(&key, 42, &enc, None).unwrap();
        assert_eq!(dec, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_with_aad() {
        let key = EncryptionKey::generate();
        let plaintext = b"secret with AAD";
        let aad = b"associated data";
        let enc = encrypt(&key, 1, plaintext, Some(aad)).unwrap();
        let dec = decrypt(&key, 1, &enc, Some(aad)).unwrap();
        assert_eq!(dec, plaintext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = EncryptionKey::generate();
        let key2 = EncryptionKey::generate();
        let enc = encrypt(&key1, 0, b"secret", None).unwrap();
        assert!(decrypt(&key2, 0, &enc, None).is_err());
    }

    #[test]
    fn test_wrong_frame_index_fails() {
        let key = EncryptionKey::generate();
        let enc = encrypt(&key, 100, b"secret", None).unwrap();
        assert!(decrypt(&key, 101, &enc, None).is_err());
    }

    #[test]
    fn test_tamper_detection() {
        let key = EncryptionKey::generate();
        let mut enc = encrypt(&key, 0, b"secret", None).unwrap();
        // Flip a bit in the ciphertext
        enc[0] ^= 1;
        assert!(decrypt(&key, 0, &enc, None).is_err());
    }

    #[test]
    fn test_wrong_aad_fails() {
        let key = EncryptionKey::generate();
        let enc = encrypt(&key, 0, b"secret", Some(b"aad1")).unwrap();
        assert!(decrypt(&key, 0, &enc, Some(b"aad2")).is_err());
    }

    #[test]
    fn test_key_hex_roundtrip() {
        let key = EncryptionKey::generate();
        let hex = key.to_hex();
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
        let enc = encrypt(&key, 0, plaintext, None).unwrap();
        // ciphertext = plaintext.len() + 16 (tag)
        assert_eq!(enc.len(), plaintext.len() + TAG_SIZE);
    }

    #[test]
    fn test_different_frame_indices_different_ciphertext() {
        let key = EncryptionKey::generate();
        let enc0 = encrypt(&key, 0, b"same data", None).unwrap();
        let enc1 = encrypt(&key, 1, b"same data", None).unwrap();
        assert_ne!(enc0, enc1);
    }

    #[test]
    fn test_debug_does_not_leak_key() {
        let key = EncryptionKey::generate();
        let debug_str = format!("{:?}", key);
        assert!(debug_str.contains("redacted"));
        assert!(!debug_str.contains(&key.to_hex()));
    }
}
