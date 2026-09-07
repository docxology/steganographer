//! Key Derivation Functions (KDF) for Steganographer.
//!
//! Derives signing, encryption, and embedding keys from a single master
//! secret using BLAKE3's `derive_key` (context-based key derivation).
//!
//! This allows users to carry a single master secret and derive all
//! needed keys deterministically, rather than managing separate key files.
//!
//! ## Usage
//!
//! ```ignore
//! use steganographer_core::kdf;
//!
//! let master = b"my secret master key phrase";
//! let keys = kdf::derive_all(master);
//! // keys.signing_key  → 32 bytes for Ed25519
//! // keys.encryption_key → 32 bytes for ChaCha20-Poly1305
//! // keys.embedding_key → 32 bytes for LSB PRNG
//! ```

/// Context strings for BLAKE3 derive_key.
/// These are fixed and must not change between encode and verify.
const SIGNING_CONTEXT: &str = "steganographer-signing-v1";
const ENCRYPTION_CONTEXT: &str = "steganographer-encryption-v1";
const EMBEDDING_CONTEXT: &str = "steganographer-embedding-v1";
const LOCATOR_CONTEXT: &str = "steganographer-locator-v1";
const PLACEMENT_CONTEXT: &str = "steganographer-placement-v1";

/// All keys derived from a master secret.
#[derive(Debug, Clone)]
pub struct DerivedKeys {
    /// Ed25519 signing key (32 bytes).
    pub signing_key: [u8; 32],
    /// ChaCha20-Poly1305 encryption key (32 bytes).
    pub encryption_key: [u8; 32],
    /// LSB embedding key (32 bytes).
    pub embedding_key: [u8; 32],
}

/// Derive the Ed25519 signing key from a master secret.
pub fn derive_signing_key(master: &[u8]) -> [u8; 32] {
    blake3::derive_key(SIGNING_CONTEXT, master)
}

/// Derive the ChaCha20-Poly1305 encryption key from a master secret.
pub fn derive_encryption_key(master: &[u8]) -> [u8; 32] {
    blake3::derive_key(ENCRYPTION_CONTEXT, master)
}

/// Derive the LSB embedding key from a master secret.
pub fn derive_embedding_key(master: &[u8]) -> [u8; 32] {
    blake3::derive_key(EMBEDDING_CONTEXT, master)
}

/// Derive the keyed-locator subkey from an embedding key.
///
/// Keyed-locator placement uses a separate domain label so the locator
/// schedule never shares key material with body placement or encryption.
pub fn derive_locator_key(embedding_key: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key(LOCATOR_CONTEXT, embedding_key)
}

/// Derive the keyed body-placement subkey from an embedding key.
pub fn derive_placement_key(embedding_key: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key(PLACEMENT_CONTEXT, embedding_key)
}

/// Derive a frame-scoped embedding key for keyed carriers whose placement is
/// computed per frame (native GStreamer elements).
///
/// Frame 0 intentionally returns the embedding key unchanged, so a
/// single-frame (or first-frame) capture decodes with the raw key through
/// `KeyedSpatialLsb::new(key)` / the CLI `decode --embedding-key` path.
/// Frames at index N > 0 mix the index into the derivation, which is what
/// makes equal carrier buffers embed at different slots per frame while
/// staying decodable by the same derivation with the frame index.
pub fn derive_frame_embedding_key(embedding_key: &[u8; 32], frame_index: u64) -> [u8; 32] {
    if frame_index == 0 {
        return *embedding_key;
    }
    blake3::derive_key(
        "steganographer-frame-placement-v1",
        [embedding_key.as_slice(), &frame_index.to_le_bytes()]
            .concat()
            .as_slice(),
    )
}

/// Derive all three keys from a master secret.
pub fn derive_all(master: &[u8]) -> DerivedKeys {
    DerivedKeys {
        signing_key: derive_signing_key(master),
        encryption_key: derive_encryption_key(master),
        embedding_key: derive_embedding_key(master),
    }
}

/// Derive a per-session signing key from a master secret and a session counter.
///
/// This enables forward secrecy: each session uses a different signing key.
/// `session_counter` should be unique per session (e.g., a timestamp or
/// sequential counter).
pub fn derive_session_signing_key(master: &[u8], session_counter: u64) -> [u8; 32] {
    let mut input = master.to_vec();
    input.extend_from_slice(&session_counter.to_le_bytes());
    blake3::derive_key("steganographer-session-signing-v1", &input)
}

/// Derive a per-session encryption key from a master secret and a session counter.
pub fn derive_session_encryption_key(master: &[u8], session_counter: u64) -> [u8; 32] {
    let mut input = master.to_vec();
    input.extend_from_slice(&session_counter.to_le_bytes());
    blake3::derive_key("steganographer-session-encryption-v1", &input)
}

#[cfg(test)]
mod frame_key_tests {
    use super::derive_frame_embedding_key;

    #[test]
    fn frame_zero_preserves_embedding_key() {
        let key = [9u8; 32];
        assert_eq!(derive_frame_embedding_key(&key, 0), key);
    }

    #[test]
    fn frame_indices_produce_distinct_keys() {
        let key = [9u8; 32];
        let k0 = derive_frame_embedding_key(&key, 0);
        let k1 = derive_frame_embedding_key(&key, 1);
        let k2 = derive_frame_embedding_key(&key, 2);
        assert_ne!(k0, k1);
        assert_ne!(k1, k2);
        assert_ne!(k0, k2);
        // Deterministic.
        assert_eq!(derive_frame_embedding_key(&key, 1), k1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_all() {
        let master = b"my secret master key";
        let keys = derive_all(master);
        assert_ne!(keys.signing_key, keys.encryption_key);
        assert_ne!(keys.signing_key, keys.embedding_key);
        assert_ne!(keys.encryption_key, keys.embedding_key);
    }

    #[test]
    fn test_deterministic_derivation() {
        let master = b"deterministic test";
        let keys1 = derive_all(master);
        let keys2 = derive_all(master);
        assert_eq!(keys1.signing_key, keys2.signing_key);
        assert_eq!(keys1.encryption_key, keys2.encryption_key);
        assert_eq!(keys1.embedding_key, keys2.embedding_key);
    }

    #[test]
    fn test_different_masters_different_keys() {
        let keys1 = derive_all(b"master one");
        let keys2 = derive_all(b"master two");
        assert_ne!(keys1.signing_key, keys2.signing_key);
        assert_ne!(keys1.encryption_key, keys2.encryption_key);
        assert_ne!(keys1.embedding_key, keys2.embedding_key);
    }

    #[test]
    fn test_empty_master() {
        let keys = derive_all(b"");
        // Should still produce valid keys (BLAKE3 handles empty input)
        assert!(keys.signing_key.iter().any(|&b| b != 0));
        assert!(keys.encryption_key.iter().any(|&b| b != 0));
        assert!(keys.embedding_key.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_session_keys_differ_from_master() {
        let master = b"session test master";
        let base = derive_signing_key(master);
        let session = derive_session_signing_key(master, 1);
        assert_ne!(base, session, "Session key should differ from base key");
    }

    #[test]
    fn test_different_sessions_different_keys() {
        let master = b"multi-session test";
        let s1 = derive_session_signing_key(master, 1);
        let s2 = derive_session_signing_key(master, 2);
        assert_ne!(s1, s2, "Different sessions should produce different keys");
    }

    #[test]
    fn test_session_encryption_key() {
        let master = b"session encryption test";
        let base = derive_encryption_key(master);
        let session = derive_session_encryption_key(master, 42);
        assert_ne!(base, session);
        let s2 = derive_session_encryption_key(master, 43);
        assert_ne!(session, s2);
    }

    #[test]
    fn test_individual_derive_functions() {
        let master = b"individual test";
        let signing = derive_signing_key(master);
        let encryption = derive_encryption_key(master);
        let embedding = derive_embedding_key(master);
        assert_ne!(signing, encryption);
        assert_ne!(signing, embedding);
        assert_ne!(encryption, embedding);
    }

    #[test]
    fn test_large_master() {
        let master = vec![0xAB; 1024];
        let keys = derive_all(&master);
        assert!(keys.signing_key.iter().any(|&b| b != 0));
    }
}
