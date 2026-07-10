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
