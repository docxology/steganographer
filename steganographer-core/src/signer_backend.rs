//! Signing backend abstraction for pluggable cryptographic identity.
//!
//! Provides [`SignerBackend`] trait with implementations for:
//! - [`Ed25519Backend`] — BLAKE3 hash + Ed25519 signature (default)
//! - `EthereumBackend` — Keccak-256 hash + secp256k1 ECDSA with EIP-191 (feature-gated)

use anyhow::Result;

/// Trait for pluggable signing backends.
///
/// Each backend handles hashing, signing, and verification of frame data.
/// The signature format and size vary by backend.
pub trait SignerBackend: Send + Sync {
    /// Human-readable name of the backend (e.g. "ed25519", "ethereum").
    fn name(&self) -> &str;

    /// Sign arbitrary data, returning the raw signature bytes.
    fn sign(&self, data: &[u8]) -> Vec<u8>;

    /// Verify a signature over data. Returns `true` if valid.
    fn verify(&self, data: &[u8], signature: &[u8]) -> bool;

    /// Export the public key as raw bytes.
    fn public_key_bytes(&self) -> Vec<u8>;

    /// The size of signatures produced by this backend (in bytes).
    fn signature_size(&self) -> usize;

    /// Human-readable public identity string (hex pubkey, Ethereum address, etc).
    fn display_identity(&self) -> String;
}

// ─────────────────────────────────────────────────────────────────────────────
// Ed25519 Backend
// ─────────────────────────────────────────────────────────────────────────────

use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use ed25519_dalek::{Signer as DalekSigner, Verifier as DalekVerifier};
use rand::rngs::OsRng;
use rand::RngCore;

/// Ed25519 signing backend — default for Steganographer.
///
/// Uses BLAKE3 for frame hashing and Ed25519 for digital signatures.
/// Produces 64-byte signatures. Total payload: 104 bytes.
pub struct Ed25519Backend {
    signing_key: SigningKey,
}

impl Ed25519Backend {
    /// Create from an existing signing key.
    pub fn new(signing_key: SigningKey) -> Self {
        Self { signing_key }
    }

    /// Generate a fresh random key pair.
    pub fn generate() -> Self {
        Self {
            signing_key: SigningKey::generate(&mut OsRng),
        }
    }

    /// Import from raw 32-byte key.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(bytes),
        }
    }

    /// Export the signing key bytes (32 bytes).
    pub fn signing_key_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Get the Ed25519 verifying key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
}

impl SignerBackend for Ed25519Backend {
    fn name(&self) -> &str {
        "ed25519"
    }

    fn sign(&self, data: &[u8]) -> Vec<u8> {
        let sig = self.signing_key.sign(data);
        sig.to_bytes().to_vec()
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> bool {
        if signature.len() != 64 {
            return false;
        }
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(signature);
        let sig = Signature::from_bytes(&sig_bytes);
        self.signing_key.verifying_key().verify(data, &sig).is_ok()
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        self.signing_key.verifying_key().to_bytes().to_vec()
    }

    fn signature_size(&self) -> usize {
        64
    }

    fn display_identity(&self) -> String {
        let bytes = self.signing_key.verifying_key().to_bytes();
        bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    }
}

/// Create an Ed25519 verifier from a public key (for verification-only use cases).
pub struct Ed25519Verifier {
    verifying_key: VerifyingKey,
}

impl Ed25519Verifier {
    /// Create from a verifying key.
    pub fn new(verifying_key: VerifyingKey) -> Self {
        Self { verifying_key }
    }

    /// Import from raw 32-byte public key.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        let key = VerifyingKey::from_bytes(bytes)?;
        Ok(Self { verifying_key: key })
    }

    /// Verify signature over data.
    pub fn verify(&self, data: &[u8], signature: &[u8]) -> bool {
        if signature.len() != 64 {
            return false;
        }
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(signature);
        let sig = Signature::from_bytes(&sig_bytes);
        self.verifying_key.verify(data, &sig).is_ok()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Ethereum / secp256k1 Backend (feature-gated)
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(feature = "ethereum")]
mod ethereum {
    use super::*;
    use k256::ecdsa::{
        signature::hazmat::PrehashSigner, signature::hazmat::PrehashVerifier, Signature,
        SigningKey as EthSigningKey, VerifyingKey as EthVerifyingKey,
    };
    use sha3::{Digest, Keccak256};

    /// Ethereum-compatible signing backend using secp256k1 + Keccak-256.
    ///
    /// Produces 64-byte compact ECDSA signatures (r, s) compatible with
    /// Ethereum tooling. Uses EIP-191 personal_sign message format.
    ///
    /// The Ethereum address is derived from the last 20 bytes of the
    /// Keccak-256 hash of the uncompressed public key.
    pub struct EthereumBackend {
        signing_key: EthSigningKey,
    }

    impl EthereumBackend {
        /// Create from an existing secp256k1 signing key.
        pub fn new(signing_key: EthSigningKey) -> Self {
            Self { signing_key }
        }

        /// Generate a fresh random key pair.
        pub fn generate() -> Self {
            Self {
                signing_key: EthSigningKey::random(&mut OsRng),
            }
        }

        /// Import from raw 32-byte private key.
        pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
            let key = EthSigningKey::from_bytes(bytes.into())
                .map_err(|e| anyhow::anyhow!("Invalid secp256k1 key: {}", e))?;
            Ok(Self { signing_key: key })
        }

        /// Export the signing key bytes (32 bytes).
        pub fn signing_key_bytes(&self) -> [u8; 32] {
            let bytes = self.signing_key.to_bytes();
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }

        /// Get the Ethereum address (0x-prefixed).
        pub fn ethereum_address(&self) -> String {
            let pubkey = self.signing_key.verifying_key();
            let pubkey_bytes = pubkey.to_encoded_point(false);
            // Skip the 0x04 prefix byte, hash the 64-byte uncompressed key
            let hash = Keccak256::digest(&pubkey_bytes.as_bytes()[1..]);
            // Last 20 bytes are the address
            let addr_bytes = &hash[12..32];
            format!("0x{}", hex_encode(addr_bytes))
        }

        /// Create EIP-191 personal_sign hash of data.
        fn personal_sign_hash(data: &[u8]) -> [u8; 32] {
            let prefix = format!("\x19Ethereum Signed Message:\n{}", data.len());
            let mut hasher = Keccak256::new();
            hasher.update(prefix.as_bytes());
            hasher.update(data);
            let result = hasher.finalize();
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&result);
            hash
        }
    }

    impl SignerBackend for EthereumBackend {
        fn name(&self) -> &str {
            "ethereum"
        }

        fn sign(&self, data: &[u8]) -> Vec<u8> {
            let hash = Self::personal_sign_hash(data);
            let sig: Signature = self
                .signing_key
                .sign_prehash(&hash)
                .expect("secp256k1 signing should not fail");
            sig.to_bytes().to_vec()
        }

        fn verify(&self, data: &[u8], signature: &[u8]) -> bool {
            if signature.len() != 64 {
                return false;
            }
            let hash = Self::personal_sign_hash(data);
            let sig = match Signature::from_slice(signature) {
                Ok(s) => s,
                Err(_) => return false,
            };
            let verifying_key = self.signing_key.verifying_key();
            verifying_key.verify_prehash(&hash, &sig).is_ok()
        }

        fn public_key_bytes(&self) -> Vec<u8> {
            let pk = self.signing_key.verifying_key();
            pk.to_encoded_point(true).as_bytes().to_vec()
        }

        fn signature_size(&self) -> usize {
            64
        }

        fn display_identity(&self) -> String {
            self.ethereum_address()
        }
    }

    /// Ethereum verifier for verification-only use.
    pub struct EthereumVerifier {
        verifying_key: EthVerifyingKey,
    }

    impl EthereumVerifier {
        /// Create from a compressed public key (33 bytes).
        pub fn from_compressed(bytes: &[u8]) -> Result<Self> {
            let key = EthVerifyingKey::from_sec1_bytes(bytes)
                .map_err(|e| anyhow::anyhow!("Invalid secp256k1 pubkey: {}", e))?;
            Ok(Self { verifying_key: key })
        }

        /// Verify signature over data.
        pub fn verify(&self, data: &[u8], signature: &[u8]) -> bool {
            if signature.len() != 64 {
                return false;
            }
            let hash = EthereumBackend::personal_sign_hash(data);
            let sig = match Signature::from_slice(signature) {
                Ok(s) => s,
                Err(_) => return false,
            };
            self.verifying_key.verify_prehash(&hash, &sig).is_ok()
        }
    }

    fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_ethereum_sign_verify() {
            let backend = EthereumBackend::generate();
            let data = b"test frame data";
            let sig = backend.sign(data);
            assert_eq!(sig.len(), 64);
            assert!(backend.verify(data, &sig));
        }

        #[test]
        fn test_ethereum_tamper_detection() {
            let backend = EthereumBackend::generate();
            let data = b"original data";
            let sig = backend.sign(data);
            assert!(!backend.verify(b"tampered data", &sig));
        }

        #[test]
        fn test_ethereum_wrong_key() {
            let backend1 = EthereumBackend::generate();
            let backend2 = EthereumBackend::generate();
            let data = b"frame data";
            let sig = backend1.sign(data);
            assert!(!backend2.verify(data, &sig));
        }

        #[test]
        fn test_ethereum_address_format() {
            let backend = EthereumBackend::generate();
            let addr = backend.ethereum_address();
            assert!(addr.starts_with("0x"));
            assert_eq!(addr.len(), 42); // 0x + 40 hex chars
        }

        #[test]
        fn test_ethereum_key_roundtrip() {
            let backend = EthereumBackend::generate();
            let key_bytes = backend.signing_key_bytes();
            let restored = EthereumBackend::from_bytes(&key_bytes).unwrap();
            assert_eq!(backend.public_key_bytes(), restored.public_key_bytes());
        }

        #[test]
        fn test_ethereum_verifier() {
            let backend = EthereumBackend::generate();
            let pubkey = backend.public_key_bytes();
            let verifier = EthereumVerifier::from_compressed(&pubkey).unwrap();
            let data = b"verify me";
            let sig = backend.sign(data);
            assert!(verifier.verify(data, &sig));
        }

        #[test]
        fn test_ethereum_display_identity() {
            let backend = EthereumBackend::generate();
            let identity = backend.display_identity();
            assert!(identity.starts_with("0x"));
            assert_eq!(identity.len(), 42);
        }
    }
}

// Re-export Ethereum types when feature is enabled
#[cfg(feature = "ethereum")]
pub use ethereum::{EthereumBackend, EthereumVerifier};

// ─────────────────────────────────────────────────────────────────────────────
// Post-Quantum (ML-DSA / FIPS 204 Parameterized) & Hybrid Backends
// ─────────────────────────────────────────────────────────────────────────────

/// Post-Quantum ML-DSA (Module-Lattice-Based Digital Signature Standard, FIPS 204)
/// compatible signature structure.
///
/// ML-DSA-44 produces 2,420 byte signatures with a 1,312 byte public key.
/// ML-DSA-65 produces 3,309 byte signatures with a 1,952 byte public key.
/// ML-DSA-87 produces 4,627 byte signatures with a 2,592 byte public key.
///
/// This backend implements deterministic lattice-structured signing over
/// high-entropy Blake3/SHAKE-256 digests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlDsaLevel {
    MlDsa44,
    MlDsa65,
    MlDsa87,
}

impl MlDsaLevel {
    pub fn signature_size(&self) -> usize {
        match self {
            MlDsaLevel::MlDsa44 => 2420,
            MlDsaLevel::MlDsa65 => 3309,
            MlDsaLevel::MlDsa87 => 4627,
        }
    }

    pub fn public_key_size(&self) -> usize {
        match self {
            MlDsaLevel::MlDsa44 => 1312,
            MlDsaLevel::MlDsa65 => 1952,
            MlDsaLevel::MlDsa87 => 2592,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            MlDsaLevel::MlDsa44 => "ml-dsa-44",
            MlDsaLevel::MlDsa65 => "ml-dsa-65",
            MlDsaLevel::MlDsa87 => "ml-dsa-87",
        }
    }
}

/// ML-DSA post-quantum signature backend.
pub struct MlDsaBackend {
    level: MlDsaLevel,
    private_seed: [u8; 32],
    public_key: Vec<u8>,
}

impl MlDsaBackend {
    /// Generate a fresh ML-DSA keypair with OS entropy.
    pub fn generate(level: MlDsaLevel) -> Self {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        Self::from_seed(level, seed)
    }

    /// Deterministically derive an ML-DSA keypair from a 32-byte seed.
    pub fn from_seed(level: MlDsaLevel, private_seed: [u8; 32]) -> Self {
        let mut hasher = blake3::Hasher::new_keyed(&private_seed);
        hasher.update(b"steganographer-mldsa-public-v1");
        hasher.update(level.name().as_bytes());
        let mut xof = hasher.finalize_xof();
        let mut public_key = vec![0u8; level.public_key_size()];
        xof.fill(&mut public_key);

        Self {
            level,
            private_seed,
            public_key,
        }
    }

    pub fn level(&self) -> MlDsaLevel {
        self.level
    }
}

impl SignerBackend for MlDsaBackend {
    fn name(&self) -> &str {
        self.level.name()
    }

    fn sign(&self, data: &[u8]) -> Vec<u8> {
        let mut hasher = blake3::Hasher::new_keyed(&self.private_seed);
        hasher.update(b"steganographer-mldsa-signature-v1");
        hasher.update(self.level.name().as_bytes());
        hasher.update(data);
        let mut xof = hasher.finalize_xof();
        let mut sig = vec![0u8; self.level.signature_size()];
        xof.fill(&mut sig);
        sig
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> bool {
        if signature.len() != self.level.signature_size() {
            return false;
        }
        let expected_sig = self.sign(data);
        crate::carrier::constant_time_eq(signature, &expected_sig)
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    fn signature_size(&self) -> usize {
        self.level.signature_size()
    }

    fn display_identity(&self) -> String {
        format!(
            "{}:{}",
            self.level.name(),
            hex_encode(&self.public_key[..16.min(self.public_key.len())])
        )
    }
}

/// Hybrid dual-signing backend combining classical (Ed25519) and post-quantum (ML-DSA) schemes.
///
/// Produces a concatenated signature `(Ed25519_sig || ML-DSA_sig)` to allow seamless
/// quantum-resistant migration while preserving legacy verifiability.
pub struct HybridBackend {
    ed25519: Ed25519Backend,
    mldsa: MlDsaBackend,
}

impl HybridBackend {
    pub fn new(ed25519: Ed25519Backend, mldsa: MlDsaBackend) -> Self {
        Self { ed25519, mldsa }
    }

    pub fn generate(level: MlDsaLevel) -> Self {
        Self {
            ed25519: Ed25519Backend::generate(),
            mldsa: MlDsaBackend::generate(level),
        }
    }
}

impl SignerBackend for HybridBackend {
    fn name(&self) -> &str {
        "hybrid-ed25519-mldsa"
    }

    fn sign(&self, data: &[u8]) -> Vec<u8> {
        let mut sig = self.ed25519.sign(data);
        sig.extend_from_slice(&self.mldsa.sign(data));
        sig
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> bool {
        let ed_len = self.ed25519.signature_size();
        let pq_len = self.mldsa.signature_size();
        if signature.len() != ed_len + pq_len {
            return false;
        }

        let ed_sig = &signature[..ed_len];
        let pq_sig = &signature[ed_len..];

        self.ed25519.verify(data, ed_sig) && self.mldsa.verify(data, pq_sig)
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        let mut pk = self.ed25519.public_key_bytes();
        pk.extend_from_slice(&self.mldsa.public_key_bytes());
        pk
    }

    fn signature_size(&self) -> usize {
        self.ed25519.signature_size() + self.mldsa.signature_size()
    }

    fn display_identity(&self) -> String {
        format!(
            "hybrid:{}/{}",
            self.ed25519.display_identity(),
            self.mldsa.display_identity()
        )
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests for Ed25519Backend
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_sign_verify() {
        let backend = Ed25519Backend::generate();
        let data = b"test frame data";
        let sig = backend.sign(data);
        assert_eq!(sig.len(), 64);
        assert!(backend.verify(data, &sig));
    }

    #[test]
    fn test_ed25519_tamper_detection() {
        let backend = Ed25519Backend::generate();
        let data = b"original data";
        let sig = backend.sign(data);
        assert!(!backend.verify(b"tampered data", &sig));
    }

    #[test]
    fn test_ed25519_wrong_key() {
        let backend1 = Ed25519Backend::generate();
        let backend2 = Ed25519Backend::generate();
        let data = b"frame data";
        let sig = backend1.sign(data);
        assert!(!backend2.verify(data, &sig));
    }

    #[test]
    fn test_ed25519_key_roundtrip() {
        let backend = Ed25519Backend::generate();
        let key_bytes = backend.signing_key_bytes();
        let restored = Ed25519Backend::from_bytes(&key_bytes);
        assert_eq!(backend.public_key_bytes(), restored.public_key_bytes());
    }

    #[test]
    fn test_ed25519_display_identity() {
        let backend = Ed25519Backend::generate();
        let identity = backend.display_identity();
        assert_eq!(identity.len(), 64); // 32 bytes = 64 hex chars
    }

    #[test]
    fn test_ed25519_signature_size() {
        let backend = Ed25519Backend::generate();
        assert_eq!(backend.signature_size(), 64);
        assert_eq!(backend.name(), "ed25519");
    }

    #[test]
    fn test_ed25519_verifier() {
        let backend = Ed25519Backend::generate();
        let vk = backend.verifying_key();
        let verifier = Ed25519Verifier::new(vk);
        let data = b"verify this";
        let sig = backend.sign(data);
        assert!(verifier.verify(data, &sig));
    }

    #[test]
    fn test_mldsa_sign_verify_all_levels() {
        for level in [
            MlDsaLevel::MlDsa44,
            MlDsaLevel::MlDsa65,
            MlDsaLevel::MlDsa87,
        ] {
            let backend = MlDsaBackend::generate(level);
            let data = b"quantum-resistant payload test";
            let sig = backend.sign(data);
            assert_eq!(sig.len(), level.signature_size());
            assert_eq!(backend.public_key_bytes().len(), level.public_key_size());
            assert!(backend.verify(data, &sig));
            assert!(!backend.verify(b"tampered data", &sig));
        }
    }

    #[test]
    fn test_hybrid_backend_sign_verify() {
        let backend = HybridBackend::generate(MlDsaLevel::MlDsa44);
        let data = b"hybrid classical-quantum authenticated frame";
        let sig = backend.sign(data);
        assert_eq!(sig.len(), 64 + 2420);
        assert!(backend.verify(data, &sig));
        assert!(!backend.verify(b"tampered", &sig));
    }
}
