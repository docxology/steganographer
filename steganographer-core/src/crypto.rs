//! Cryptographic binding: BLAKE3 hashing + Ed25519 signing/verification.
//!
//! Provides [`Signer`] and [`Verifier`] for producing and checking
//! [`SignaturePayload`]s over video/audio frame data.

use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use ed25519_dalek::{Signer as DalekSigner, Verifier as DalekVerifier};
use rand::rngs::OsRng;

/// A signed payload embedded into or extracted from media frames.
///
/// Contains the frame index, BLAKE3 hash of frame data, and an Ed25519 signature.
#[derive(Debug, Clone)]
pub struct SignaturePayload {
    pub frame_index: u64,
    pub hash: [u8; 32],
    pub signature: Signature,
}

impl SignaturePayload {
    /// Total serialized size: 8 (frame_index) + 32 (hash) + 64 (signature) = 104 bytes.
    pub const SERIALIZED_SIZE: usize = 8 + 32 + 64;

    /// Serialize the payload to bytes (little-endian).
    pub fn to_bytes(&self) -> [u8; Self::SERIALIZED_SIZE] {
        let mut buf = [0u8; Self::SERIALIZED_SIZE];
        buf[0..8].copy_from_slice(&self.frame_index.to_le_bytes());
        buf[8..40].copy_from_slice(&self.hash);
        buf[40..104].copy_from_slice(&self.signature.to_bytes());
        buf
    }

    /// Deserialize from bytes.
    pub fn from_bytes(buf: &[u8; Self::SERIALIZED_SIZE]) -> anyhow::Result<Self> {
        let frame_index = u64::from_le_bytes(buf[0..8].try_into()?);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&buf[8..40]);
        let sig_bytes: [u8; 64] = buf[40..104].try_into()?;
        let signature = Signature::from_bytes(&sig_bytes);
        Ok(Self {
            frame_index,
            hash,
            signature,
        })
    }
}

/// Signs frame data using BLAKE3 + Ed25519.
pub struct Signer {
    signing_key: SigningKey,
}

impl Signer {
    /// Create a new signer with the given private key.
    pub fn new(signing_key: SigningKey) -> Self {
        Self { signing_key }
    }

    /// Generate a fresh random signing key.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self { signing_key }
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
        let signing_key = SigningKey::from_bytes(bytes);
        Self { signing_key }
    }

    /// Hash frame data with BLAKE3 and sign the hash with Ed25519.
    ///
    /// The hash covers: `frame_index || video_bytes || audio_bytes (optional)`.
    pub fn sign_frame(
        &self,
        frame_index: u64,
        video_bytes: &[u8],
        audio_bytes: Option<&[u8]>,
    ) -> SignaturePayload {
        let hash = Self::compute_hash(frame_index, video_bytes, audio_bytes);
        let signature = self.signing_key.sign(&hash);
        SignaturePayload {
            frame_index,
            hash,
            signature,
        }
    }

    /// Compute the BLAKE3 hash for a frame.
    fn compute_hash(frame_index: u64, video_bytes: &[u8], audio_bytes: Option<&[u8]>) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&frame_index.to_le_bytes());
        hasher.update(video_bytes);
        if let Some(a) = audio_bytes {
            hasher.update(a);
        }
        *hasher.finalize().as_bytes()
    }
}

/// Verifies signed frame payloads.
pub struct Verifier {
    verifying_key: VerifyingKey,
}

impl Verifier {
    /// Create a verifier from a public key.
    pub fn new(verifying_key: VerifyingKey) -> Self {
        Self { verifying_key }
    }

    /// Import a verifying key from raw bytes.
    pub fn from_bytes(bytes: &[u8; 32]) -> anyhow::Result<Self> {
        let verifying_key = VerifyingKey::from_bytes(bytes)?;
        Ok(Self { verifying_key })
    }

    /// Verify a [`SignaturePayload`] against the original frame data.
    ///
    /// Re-computes the BLAKE3 hash and checks the Ed25519 signature.
    /// Returns `true` if valid, `false` otherwise.
    pub fn verify(
        &self,
        payload: &SignaturePayload,
        video_bytes: &[u8],
        audio_bytes: Option<&[u8]>,
    ) -> bool {
        // Recompute hash
        let mut hasher = blake3::Hasher::new();
        hasher.update(&payload.frame_index.to_le_bytes());
        hasher.update(video_bytes);
        if let Some(a) = audio_bytes {
            hasher.update(a);
        }
        let computed_hash = *hasher.finalize().as_bytes();

        // Check hash matches
        if computed_hash != payload.hash {
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
}
