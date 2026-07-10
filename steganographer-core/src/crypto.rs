//! Cryptographic binding: hashing + Ed25519 signing/verification.
//!
//! Provides [`Signer`] and [`Verifier`] for producing and checking
//! [`SignaturePayload`]s over video/audio frame data.
//!
//! ## Hash Algorithms
//!
//! The hash algorithm is configurable via [`HashAlgorithm`]:
//! - `Blake3` (default) — BLAKE3, fast and secure
//! - `Sha256` — SHA-256 (FIPS 180-4)
//! - `Sha3_256` — SHA-3 256 (FIPS 202)
//!
//! ## Format Identification
//!
//! Every payload begins with a 4-byte magic header (`STEG`) and a 1-byte
//! version number, allowing future format evolution and preventing
//! misinterpretation of non-steganographic data as a payload.

use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use ed25519_dalek::{Signer as DalekSigner, Verifier as DalekVerifier};
use rand::rngs::OsRng;
use sha2::Digest;
use subtle::ConstantTimeEq;

/// Magic header for Steganographer payloads (ASCII "STEG").
pub const MAGIC: [u8; 4] = *b"STEG";

/// Current payload format version.
pub const FORMAT_VERSION: u8 = 2;

/// Configurable hash algorithm for frame data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    /// BLAKE3 — fast, parallel, secure (default).
    Blake3,
    /// SHA-256 (FIPS 180-4).
    Sha256,
    /// SHA-3 256 (FIPS 202, Keccak).
    Sha3_256,
}

impl HashAlgorithm {
    /// Compute a 32-byte hash over the given data.
    pub fn hash(&self, frame_index: u64, video_bytes: &[u8], audio_bytes: Option<&[u8]>) -> [u8; 32] {
        match self {
            HashAlgorithm::Blake3 => {
                let mut hasher = blake3::Hasher::new();
                hasher.update(&frame_index.to_le_bytes());
                hasher.update(video_bytes);
                if let Some(a) = audio_bytes {
                    hasher.update(a);
                }
                *hasher.finalize().as_bytes()
            }
            HashAlgorithm::Sha256 => {
                let mut hasher = sha2::Sha256::new();
                hasher.update(&frame_index.to_le_bytes());
                hasher.update(video_bytes);
                if let Some(a) = audio_bytes {
                    hasher.update(a);
                }
                let result = hasher.finalize();
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&result);
                hash
            }
            HashAlgorithm::Sha3_256 => {
                let mut hasher = sha3::Sha3_256::new();
                hasher.update(&frame_index.to_le_bytes());
                hasher.update(video_bytes);
                if let Some(a) = audio_bytes {
                    hasher.update(a);
                }
                let result = hasher.finalize();
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&result);
                hash
            }
        }
    }

    /// Parse from a config string.
    pub fn parse(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "sha256" | "sha-256" => Self::Sha256,
            "sha3" | "sha-3" | "sha3-256" => Self::Sha3_256,
            _ => Self::Blake3,
        }
    }

    /// String identifier for display.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Blake3 => "blake3",
            Self::Sha256 => "sha256",
            Self::Sha3_256 => "sha3-256",
        }
    }
}

impl Default for HashAlgorithm {
    fn default() -> Self {
        Self::Blake3
    }
}

/// A signed payload embedded into or extracted from media frames.
///
/// Contains the frame index, BLAKE3 hash of frame data, and an Ed25519 signature.
/// The serialized format includes a magic header and version for format
/// identification:
///
/// ```text
/// [magic: 4B][version: 1B][frame_index: 8B][hash: 32B][signature: 64B] = 109 bytes
/// ```
#[derive(Debug, Clone)]
pub struct SignaturePayload {
    pub frame_index: u64,
    pub hash: [u8; 32],
    pub signature: Signature,
}

impl SignaturePayload {
    /// Total serialized size:
    /// 4 (magic) + 1 (version) + 8 (frame_index) + 32 (hash) + 64 (signature) = 109 bytes.
    pub const SERIALIZED_SIZE: usize = 4 + 1 + 8 + 32 + 64;

    /// Serialize the payload to bytes (little-endian).
    ///
    /// Format: `[magic][version][frame_index][hash][signature]`
    pub fn to_bytes(&self) -> [u8; Self::SERIALIZED_SIZE] {
        let mut buf = [0u8; Self::SERIALIZED_SIZE];
        buf[0..4].copy_from_slice(&MAGIC);
        buf[4] = FORMAT_VERSION;
        buf[5..13].copy_from_slice(&self.frame_index.to_le_bytes());
        buf[13..45].copy_from_slice(&self.hash);
        buf[45..109].copy_from_slice(&self.signature.to_bytes());
        buf
    }

    /// Deserialize from bytes.
    ///
    /// Validates the magic header and version before parsing.
    pub fn from_bytes(buf: &[u8; Self::SERIALIZED_SIZE]) -> anyhow::Result<Self> {
        // Validate magic header
        if buf[0..4] != MAGIC {
            anyhow::bail!("Invalid magic header: expected {:?}, got {:?}", &MAGIC, &buf[0..4]);
        }
        // Validate version
        let version = buf[4];
        if version != FORMAT_VERSION {
            anyhow::bail!(
                "Unsupported payload version: expected {}, got {}",
                FORMAT_VERSION,
                version
            );
        }
        let frame_index = u64::from_le_bytes(buf[5..13].try_into()?);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&buf[13..45]);
        let sig_bytes: [u8; 64] = buf[45..109].try_into()?;
        let signature = Signature::from_bytes(&sig_bytes);
        Ok(Self {
            frame_index,
            hash,
            signature,
        })
    }

    /// Check if a byte slice could be a valid payload by checking the magic header.
    pub fn has_valid_magic(buf: &[u8]) -> bool {
        buf.len() >= 5 && buf[0..4] == MAGIC && buf[4] == FORMAT_VERSION
    }
}

/// Signs frame data using BLAKE3 + Ed25519.
pub struct Signer {
    signing_key: SigningKey,
    hash_algorithm: HashAlgorithm,
}

impl Signer {
    /// Create a new signer with the given private key.
    pub fn new(signing_key: SigningKey) -> Self {
        Self {
            signing_key,
            hash_algorithm: HashAlgorithm::default(),
        }
    }

    /// Create a new signer with a specific hash algorithm.
    pub fn with_hash_algorithm(signing_key: SigningKey, algo: HashAlgorithm) -> Self {
        Self {
            signing_key,
            hash_algorithm: algo,
        }
    }

    /// Generate a fresh random signing key.
    pub fn generate() -> Self {
        Self {
            signing_key: SigningKey::generate(&mut OsRng),
            hash_algorithm: HashAlgorithm::default(),
        }
    }

    /// Set the hash algorithm.
    pub fn set_hash_algorithm(&mut self, algo: HashAlgorithm) {
        self.hash_algorithm = algo;
    }

    /// Get the current hash algorithm.
    pub fn hash_algorithm(&self) -> HashAlgorithm {
        self.hash_algorithm
    }

    /// Get the corresponding verifying (public) key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Export the signing key bytes (32 bytes).
    pub fn signing_key_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Import a signing key from raw bytes.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(bytes),
            hash_algorithm: HashAlgorithm::default(),
        }
    }

    /// Import a signing key with a specific hash algorithm.
    pub fn from_bytes_with_algo(bytes: &[u8; 32], algo: HashAlgorithm) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(bytes),
            hash_algorithm: algo,
        }
    }

    /// Hash frame data with the configured algorithm and sign the hash with Ed25519.
    ///
    /// The hash covers: `frame_index || video_bytes || audio_bytes (optional)`.
    pub fn sign_frame(
        &self,
        frame_index: u64,
        video_bytes: &[u8],
        audio_bytes: Option<&[u8]>,
    ) -> SignaturePayload {
        let hash = self
            .hash_algorithm
            .hash(frame_index, video_bytes, audio_bytes);
        let signature = self.signing_key.sign(&hash);
        SignaturePayload {
            frame_index,
            hash,
            signature,
        }
    }
}

/// Verifies signed frame payloads.
pub struct Verifier {
    verifying_key: VerifyingKey,
    hash_algorithm: HashAlgorithm,
}

impl Verifier {
    /// Create a verifier from a public key.
    pub fn new(verifying_key: VerifyingKey) -> Self {
        Self {
            verifying_key,
            hash_algorithm: HashAlgorithm::default(),
        }
    }

    /// Create a verifier with a specific hash algorithm.
    pub fn with_hash_algorithm(verifying_key: VerifyingKey, algo: HashAlgorithm) -> Self {
        Self {
            verifying_key,
            hash_algorithm: algo,
        }
    }

    /// Import a verifying key from raw bytes.
    pub fn from_bytes(bytes: &[u8; 32]) -> anyhow::Result<Self> {
        let verifying_key = VerifyingKey::from_bytes(bytes)?;
        Ok(Self {
            verifying_key,
            hash_algorithm: HashAlgorithm::default(),
        })
    }

    /// Import a verifying key with a specific hash algorithm.
    pub fn from_bytes_with_algo(bytes: &[u8; 32], algo: HashAlgorithm) -> anyhow::Result<Self> {
        let verifying_key = VerifyingKey::from_bytes(bytes)?;
        Ok(Self {
            verifying_key,
            hash_algorithm: algo,
        })
    }

    /// Set the hash algorithm.
    pub fn set_hash_algorithm(&mut self, algo: HashAlgorithm) {
        self.hash_algorithm = algo;
    }

    /// Verify a [`SignaturePayload`] against the original frame data.
    ///
    /// Re-computes the hash and checks the Ed25519 signature.
    /// Returns `true` if valid, `false` otherwise.
    ///
    /// Uses constant-time comparison for the hash check to prevent
    /// timing-based oracle attacks.
    pub fn verify(
        &self,
        payload: &SignaturePayload,
        video_bytes: &[u8],
        audio_bytes: Option<&[u8]>,
    ) -> bool {
        // Recompute hash
        let computed_hash = self
            .hash_algorithm
            .hash(payload.frame_index, video_bytes, audio_bytes);

        // Constant-time hash comparison to prevent timing attacks
        if !bool::from(computed_hash.ct_eq(&payload.hash)) {
            log::warn!(
                "Hash mismatch for frame {}: expected {:?}, got {:?}",
                payload.frame_index,
                payload.hash,
                computed_hash
            );
            return false;
        }

        // Verify Ed25519 signature over the hash
        self.verifying_key
            .verify(&computed_hash, &payload.signature)
            .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_verify() {
        let signer = Signer::generate();
        let verifier = Verifier::new(signer.verifying_key());

        let video_data = b"fake frame data for testing";
        let audio_data = b"fake audio samples";

        let payload = signer.sign_frame(42, video_data, Some(audio_data));

        assert_eq!(payload.frame_index, 42);
        assert!(verifier.verify(&payload, video_data, Some(audio_data)));
    }

    #[test]
    fn test_verify_without_audio() {
        let signer = Signer::generate();
        let verifier = Verifier::new(signer.verifying_key());

        let video_data = b"video only frame";
        let payload = signer.sign_frame(0, video_data, None);

        assert!(verifier.verify(&payload, video_data, None));
    }

    #[test]
    fn test_tamper_detection_data() {
        let signer = Signer::generate();
        let verifier = Verifier::new(signer.verifying_key());

        let video_data = b"original frame data";
        let payload = signer.sign_frame(1, video_data, None);

        // Tampered data should fail verification
        let tampered = b"TAMPERED frame data";
        assert!(!verifier.verify(&payload, tampered, None));
    }

    #[test]
    fn test_tamper_detection_index() {
        let signer = Signer::generate();
        let verifier = Verifier::new(signer.verifying_key());

        let video_data = b"frame data";
        let payload = signer.sign_frame(10, video_data, None);

        // Modify the frame index in the payload
        let tampered_payload = SignaturePayload {
            frame_index: 11,
            hash: payload.hash,
            signature: payload.signature,
        };
        assert!(!verifier.verify(&tampered_payload, video_data, None));
    }

    #[test]
    fn test_wrong_key_fails() {
        let signer = Signer::generate();
        let other_signer = Signer::generate();
        let wrong_verifier = Verifier::new(other_signer.verifying_key());

        let video_data = b"secret frame";
        let payload = signer.sign_frame(0, video_data, None);

        assert!(!wrong_verifier.verify(&payload, video_data, None));
    }

    #[test]
    fn test_payload_serialization_roundtrip() {
        let signer = Signer::generate();
        let payload = signer.sign_frame(12345, b"test", None);

        let bytes = payload.to_bytes();
        assert_eq!(bytes.len(), SignaturePayload::SERIALIZED_SIZE);

        let restored = SignaturePayload::from_bytes(&bytes).unwrap();
        assert_eq!(restored.frame_index, payload.frame_index);
        assert_eq!(restored.hash, payload.hash);
        assert_eq!(restored.signature, payload.signature);
    }

    #[test]
    fn test_signer_key_roundtrip() {
        let signer = Signer::generate();
        let key_bytes = signer.signing_key_bytes();
        let restored = Signer::from_bytes(&key_bytes);
        assert_eq!(
            signer.verifying_key().to_bytes(),
            restored.verifying_key().to_bytes()
        );
    }

    // ── Magic header and version tests ──

    #[test]
    fn test_magic_header_present() {
        let signer = Signer::generate();
        let payload = signer.sign_frame(0, b"test", None);
        let bytes = payload.to_bytes();
        assert_eq!(&bytes[0..4], &MAGIC);
        assert_eq!(bytes[4], FORMAT_VERSION);
    }

    #[test]
    fn test_invalid_magic_rejected() {
        let signer = Signer::generate();
        let payload = signer.sign_frame(0, b"test", None);
        let mut bytes = payload.to_bytes();
        // Corrupt the magic
        bytes[0] = b'X';
        assert!(SignaturePayload::from_bytes(&bytes).is_err());
    }

    #[test]
    fn test_invalid_version_rejected() {
        let signer = Signer::generate();
        let payload = signer.sign_frame(0, b"test", None);
        let mut bytes = payload.to_bytes();
        // Set a future version
        bytes[4] = 99;
        assert!(SignaturePayload::from_bytes(&bytes).is_err());
    }

    #[test]
    fn test_has_valid_magic() {
        let signer = Signer::generate();
        let payload = signer.sign_frame(0, b"test", None);
        let bytes = payload.to_bytes();
        assert!(SignaturePayload::has_valid_magic(&bytes));
        assert!(!SignaturePayload::has_valid_magic(b"not a payload"));
    }

    // ── Hash algorithm tests ──

    #[test]
    fn test_sha256_sign_verify() {
        let signer = Signer::with_hash_algorithm(SigningKey::generate(&mut OsRng), HashAlgorithm::Sha256);
        let verifier = Verifier::with_hash_algorithm(signer.verifying_key(), HashAlgorithm::Sha256);
        let data = b"sha256 test data";
        let payload = signer.sign_frame(0, data, None);
        assert!(verifier.verify(&payload, data, None));
    }

    #[test]
    fn test_sha3_sign_verify() {
        let signer = Signer::with_hash_algorithm(SigningKey::generate(&mut OsRng), HashAlgorithm::Sha3_256);
        let verifier = Verifier::with_hash_algorithm(signer.verifying_key(), HashAlgorithm::Sha3_256);
        let data = b"sha3 test data";
        let payload = signer.sign_frame(0, data, None);
        assert!(verifier.verify(&payload, data, None));
    }

    #[test]
    fn test_wrong_hash_algo_fails() {
        let signer = Signer::with_hash_algorithm(SigningKey::generate(&mut OsRng), HashAlgorithm::Blake3);
        let verifier = Verifier::with_hash_algorithm(signer.verifying_key(), HashAlgorithm::Sha256);
        let data = b"cross-algo test";
        let payload = signer.sign_frame(0, data, None);
        // Verifier using SHA-256 should not accept a BLAKE3-signed payload
        assert!(!verifier.verify(&payload, data, None));
    }

    #[test]
    fn test_hash_algorithm_parse() {
        assert_eq!(HashAlgorithm::parse("blake3"), HashAlgorithm::Blake3);
        assert_eq!(HashAlgorithm::parse("sha256"), HashAlgorithm::Sha256);
        assert_eq!(HashAlgorithm::parse("sha-256"), HashAlgorithm::Sha256);
        assert_eq!(HashAlgorithm::parse("sha3"), HashAlgorithm::Sha3_256);
        assert_eq!(HashAlgorithm::parse("SHA3-256"), HashAlgorithm::Sha3_256);
        assert_eq!(HashAlgorithm::parse("unknown"), HashAlgorithm::Blake3);
    }

    #[test]
    fn test_hash_algorithm_name() {
        assert_eq!(HashAlgorithm::Blake3.name(), "blake3");
        assert_eq!(HashAlgorithm::Sha256.name(), "sha256");
        assert_eq!(HashAlgorithm::Sha3_256.name(), "sha3-256");
    }

    #[test]
    fn test_different_hash_algos_produce_different_hashes() {
        let h1 = HashAlgorithm::Blake3.hash(0, b"data", None);
        let h2 = HashAlgorithm::Sha256.hash(0, b"data", None);
        let h3 = HashAlgorithm::Sha3_256.hash(0, b"data", None);
        assert_ne!(h1, h2);
        assert_ne!(h1, h3);
        assert_ne!(h2, h3);
    }
}
