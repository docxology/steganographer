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
//! - **Nonce**: 12 bytes, derived as `BLAKE3(fresh 4-byte random salt ‖
//!   16-byte packet identifier)[..12]`. The salt is prepended to the
//!   ciphertext so the receiver can reconstruct the nonce. The nonce is never
//!   derived from caller-controlled transport data (the public locator
//!   nonce), and distinct packets derive distinct nonces under a shared key.
//! - **Output**: `salt(4) || ciphertext || tag` (4 + plaintext.len() + 16 bytes).
//!
//! ## Security Notes
//!
//! - The same key must never be reused with different payloads under the
//!   same nonce. The random salt ensures each invocation gets a unique nonce
//!   even when the frame index is identical (e.g. batch processing).
//! - The encryption key is separate from the signing key, though both
//!   can be derived from the same master secret via HKDF or similar.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroize;

/// Size of the encryption key in bytes (256-bit).
pub const KEY_SIZE: usize = 32;

/// Size of the Poly1305 authentication tag in bytes.
pub const TAG_SIZE: usize = 16;

/// Nonce size for ChaCha20-Poly1305 (96-bit).
pub const NONCE_SIZE: usize = 12;

/// Size of the random salt prepended to ciphertext (32-bit).
pub const SALT_SIZE: usize = 4;

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
        let mut bytes = hex_decode(hex)?;
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
        bytes.zeroize();
        Ok(Self(arr))
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
        self.0.iter().map(|b| format!("{:02x}", b)).collect()
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
/// The caller never supplies transport-controlled bytes, so the nonce cannot
/// be steered by public packet metadata. Distinct packets derive distinct
/// nonces even under a shared key, and the fresh salt keeps re-encryptions of
/// the same packet unique.
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
/// * `packet_id` — The 16-byte packet identifier the nonce is derived from;
///   it must match between [`encrypt`] and [`decrypt`]. Never derived from
///   public transport data such as the locator nonce.
/// * `plaintext` — The data to encrypt.
/// * `aad` — Optional additional authenticated data (authenticated but not encrypted).
pub fn encrypt(
    key: &EncryptionKey,
    packet_id: &[u8; 16],
    plaintext: &[u8],
    aad: Option<&[u8]>,
) -> anyhow::Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(key.as_bytes().into());

    // Generate a random salt for this invocation to prevent nonce reuse
    let mut salt = [0u8; SALT_SIZE];
    OsRng.fill_bytes(&mut salt);
    let nonce_bytes = derive_nonce(&salt, packet_id);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let payload = match aad {
        Some(a) => Payload {
            msg: plaintext,
            aad: a,
        },
        None => Payload {
            msg: plaintext,
            aad: &[],
        },
    };

    let ciphertext = cipher
        .encrypt(nonce, payload)
        .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

    // Prepend salt to ciphertext: salt || ciphertext || tag
    let mut result = Vec::with_capacity(SALT_SIZE + ciphertext.len());
    result.extend_from_slice(&salt);
    result.extend_from_slice(&ciphertext);
    Ok(result)
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
    let nonce = Nonce::from_slice(&nonce_bytes);

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
    fn test_same_packet_id_different_salt() {
        // Critical: encrypting the same data with the same packet_id must
        // produce different ciphertexts due to the fresh random salt.
        let key = EncryptionKey::generate();
        let enc0 = encrypt(&key, &PACKET_ID, b"same data", None).unwrap();
        let enc1 = encrypt(&key, &PACKET_ID, b"same data", None).unwrap();
        assert_ne!(
            enc0, enc1,
            "Same packet_id must produce different ciphertexts due to random salt"
        );
        // Both must still decrypt correctly
        assert_eq!(
            decrypt(&key, &PACKET_ID, &enc0, None).unwrap(),
            b"same data"
        );
        assert_eq!(
            decrypt(&key, &PACKET_ID, &enc1, None).unwrap(),
            b"same data"
        );
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
