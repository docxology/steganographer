//! Signing backend abstraction for pluggable cryptographic identity.
//!
//! Provides [`SignerBackend`] trait with implementations for:
//! - [`Ed25519Backend`] — BLAKE3 hash + Ed25519 signature (default)
//! - [`MlDsaBackend`] — ML-DSA (FIPS 204) post-quantum signatures (RustCrypto `ml-dsa` crate)
//! - [`HybridBackend`] — dual Ed25519 + ML-DSA signatures
//! - `EthereumBackend` — Keccak-256 hash + secp256k1 ECDSA with EIP-191 (feature-gated)
//!
//! Verification-only counterparts: [`Ed25519Verifier`], [`MlDsaVerifier`], [`HybridVerifier`].

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
// Post-Quantum ML-DSA (FIPS 204) & Hybrid Backends
// ─────────────────────────────────────────────────────────────────────────────

/// FIPS 204 ML-DSA security levels, mapping 1:1 to the parameter sets of the
/// RustCrypto [`ml-dsa`](https://crates.io/crates/ml-dsa) crate: `MlDsa44`,
/// `MlDsa65`, `MlDsa87` (i.e. CRYSTALS-Dilithium, standardized as ML-DSA in
/// FIPS 204).
///
/// Encoded sizes are exactly the FIPS 204 values:
/// ML-DSA-44: 2,420-byte signature / 1,312-byte public key;
/// ML-DSA-65: 3,309 / 1,952; ML-DSA-87: 4,627 / 2,592.
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

use ml_dsa::{
    EncodedVerifyingKey, Keypair as MlDsaKeypair, MlDsa44, MlDsa65, MlDsa87, MlDsaParams, Seed,
    Signature as MlDsaSignature, Signer as MlDsaSigner, SigningKey as MlDsaSigningKey,
    VerifyingKey as MlDsaVerifyingKey,
};

/// Runtime dispatch over the three FIPS 204 parameter sets for an ML-DSA
/// signing key (in the `ml-dsa` crate, parameter sets are compile-time
/// generics, so a level-erased backend needs an enum over the instantiations).
enum MlDsaSigningKeyInner {
    MlDsa44(MlDsaSigningKey<MlDsa44>),
    MlDsa65(MlDsaSigningKey<MlDsa65>),
    MlDsa87(MlDsaSigningKey<MlDsa87>),
}

/// Deterministic ML-DSA signing: FIPS 204 Algorithm 2 (`ML-DSA.Sign`),
/// deterministic variant, empty context string — this is the mode the
/// `ml-dsa` crate's `Signer` implementation uses in 0.1.1.
fn mldsa_sign<P: MlDsaParams>(signing_key: &MlDsaSigningKey<P>, data: &[u8]) -> Vec<u8> {
    MlDsaSigner::sign(signing_key, data).encode().to_vec()
}

/// ML-DSA verification: FIPS 204 Algorithm 3 (`ML-DSA.Verify`), empty
/// context string, matching the signing context. `Signature::try_from`
/// rejects wrong-length and structurally invalid encodings outright.
fn mldsa_verify<P: MlDsaParams>(
    verifying_key: &MlDsaVerifyingKey<P>,
    data: &[u8],
    signature: &[u8],
) -> bool {
    match MlDsaSignature::<P>::try_from(signature) {
        Ok(sig) => verifying_key.verify_with_context(data, &[], &sig),
        Err(_) => false,
    }
}

/// ML-DSA post-quantum signature backend (FIPS 204), implemented with the
/// RustCrypto [`ml-dsa`](https://crates.io/crates/ml-dsa) crate (v0.1.1,
/// pure Rust; note that the crate has not been independently audited).
///
/// - Parameter sets: [`MlDsaLevel`] maps 1:1 to the crate's `MlDsa44` /
///   `MlDsa65` / `MlDsa87`; signature and public-key sizes are the exact
///   FIPS 204 encoded sizes (see [`MlDsaLevel`]).
/// - Key generation: `from_seed` uses the caller's 32 bytes directly as the
///   ml-dsa [`Seed`] — FIPS 204 Algorithm 6 (`ML-DSA.KeyGen_internal`), where
///   SHAKE-256 expands the seed into ρ, ρ′ and K. The same seed always
///   yields the same key pair.
/// - Signing: deterministic ML-DSA (FIPS 204 Algorithm 2, deterministic
///   variant, empty context string). Same seed + same message ⇒
///   byte-identical signature.
/// - Verification: real public-key verification (FIPS 204 Algorithm 3,
///   `ML-DSA.Verify`, empty context string), also available without any
///   private key material via [`MlDsaVerifier`].
///
/// # Migration note
/// Signatures produced by the pre-0.8 placeholder implementation (keyed
/// BLAKE3-XOF MACs over the private seed; its "public key" could not verify
/// anything) are NOT verifiable by this backend or by [`MlDsaVerifier`].
/// Payloads signed with that scheme must be re-signed.
pub struct MlDsaBackend {
    level: MlDsaLevel,
    signing_key: MlDsaSigningKeyInner,
}

impl MlDsaBackend {
    /// Generate a fresh ML-DSA keypair with OS entropy.
    pub fn generate(level: MlDsaLevel) -> Self {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        Self::from_seed(level, seed)
    }

    /// Deterministically derive an ML-DSA keypair from a 32-byte seed.
    ///
    /// The seed is passed unchanged to `SigningKey::<P>::from_seed`
    /// (FIPS 204 Algorithm 6). There is no extra domain separation between
    /// levels beyond the level-dependent expansion inside ML-DSA itself.
    pub fn from_seed(level: MlDsaLevel, private_seed: [u8; 32]) -> Self {
        let seed = Seed::from(private_seed);
        Self {
            level,
            signing_key: match level {
                MlDsaLevel::MlDsa44 => {
                    MlDsaSigningKeyInner::MlDsa44(MlDsaSigningKey::<MlDsa44>::from_seed(&seed))
                }
                MlDsaLevel::MlDsa65 => {
                    MlDsaSigningKeyInner::MlDsa65(MlDsaSigningKey::<MlDsa65>::from_seed(&seed))
                }
                MlDsaLevel::MlDsa87 => {
                    MlDsaSigningKeyInner::MlDsa87(MlDsaSigningKey::<MlDsa87>::from_seed(&seed))
                }
            },
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
        match &self.signing_key {
            MlDsaSigningKeyInner::MlDsa44(sk) => mldsa_sign(sk, data),
            MlDsaSigningKeyInner::MlDsa65(sk) => mldsa_sign(sk, data),
            MlDsaSigningKeyInner::MlDsa87(sk) => mldsa_sign(sk, data),
        }
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> bool {
        match &self.signing_key {
            MlDsaSigningKeyInner::MlDsa44(sk) => mldsa_verify(&sk.verifying_key(), data, signature),
            MlDsaSigningKeyInner::MlDsa65(sk) => mldsa_verify(&sk.verifying_key(), data, signature),
            MlDsaSigningKeyInner::MlDsa87(sk) => mldsa_verify(&sk.verifying_key(), data, signature),
        }
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        match &self.signing_key {
            MlDsaSigningKeyInner::MlDsa44(sk) => sk.verifying_key().encode().to_vec(),
            MlDsaSigningKeyInner::MlDsa65(sk) => sk.verifying_key().encode().to_vec(),
            MlDsaSigningKeyInner::MlDsa87(sk) => sk.verifying_key().encode().to_vec(),
        }
    }

    fn signature_size(&self) -> usize {
        self.level.signature_size()
    }

    fn display_identity(&self) -> String {
        let public_key = self.public_key_bytes();
        format!(
            "{}:{}",
            self.level.name(),
            hex_encode(&public_key[..16.min(public_key.len())])
        )
    }
}

/// Verification-only ML-DSA verifier built from a public key.
///
/// Mirrors [`Ed25519Verifier`]: construct from raw FIPS 204 public-key bytes
/// (exactly [`MlDsaLevel::public_key_size`] bytes for the given level) or
/// from a typed `ml_dsa::VerifyingKey`, then verify signatures without any
/// private key material.
pub struct MlDsaVerifier {
    level: MlDsaLevel,
    /// Encoded FIPS 204 public key (Algorithm 22, `pkEncode`).
    verifying_key: Vec<u8>,
}

impl MlDsaVerifier {
    /// Create from a typed `ml_dsa::VerifyingKey`. `level` must match the
    /// parameter set of `verifying_key` (checked in debug builds).
    pub fn new<P: MlDsaParams>(level: MlDsaLevel, verifying_key: MlDsaVerifyingKey<P>) -> Self {
        let encoded = verifying_key.encode();
        debug_assert_eq!(encoded.len(), level.public_key_size());
        Self {
            level,
            verifying_key: encoded.to_vec(),
        }
    }

    /// Import from raw FIPS 204 public-key bytes
    /// (`level.public_key_size()` bytes).
    pub fn from_public_key_bytes(level: MlDsaLevel, bytes: &[u8]) -> Result<Self> {
        anyhow::ensure!(
            bytes.len() == level.public_key_size(),
            "ML-DSA {} public key must be exactly {} bytes (got {})",
            level.name(),
            level.public_key_size(),
            bytes.len()
        );
        Ok(Self {
            level,
            verifying_key: bytes.to_vec(),
        })
    }

    /// The security level of this verifier's public key.
    pub fn level(&self) -> MlDsaLevel {
        self.level
    }

    /// Size (in bytes) of signatures verifiable by this verifier.
    pub fn signature_size(&self) -> usize {
        self.level.signature_size()
    }

    /// Verify a signature over `data` (FIPS 204 Algorithm 3, empty context
    /// string). Returns `true` only for a signature produced by the matching
    /// signing key.
    pub fn verify(&self, data: &[u8], signature: &[u8]) -> bool {
        match self.level {
            MlDsaLevel::MlDsa44 => self.verify_with::<MlDsa44>(data, signature),
            MlDsaLevel::MlDsa65 => self.verify_with::<MlDsa65>(data, signature),
            MlDsaLevel::MlDsa87 => self.verify_with::<MlDsa87>(data, signature),
        }
    }

    fn verify_with<P: MlDsaParams>(&self, data: &[u8], signature: &[u8]) -> bool {
        match EncodedVerifyingKey::<P>::try_from(&self.verifying_key[..]) {
            Ok(encoded) => mldsa_verify(&MlDsaVerifyingKey::<P>::decode(&encoded), data, signature),
            Err(_) => false,
        }
    }
}

/// Hybrid dual-signing backend combining classical (Ed25519) and post-quantum
/// (ML-DSA / FIPS 204) schemes.
///
/// Produces a concatenated signature `(Ed25519_sig || ML-DSA_sig)` and a
/// concatenated public key `(Ed25519_pk(32) || ML-DSA_pk)` to allow seamless
/// quantum-resistant migration while preserving legacy verifiability. Both
/// halves are real signatures; verification (via [`SignerBackend::verify`] or
/// [`HybridVerifier`]) requires BOTH to be valid.
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

/// Verification-only hybrid verifier built from public keys.
///
/// Mirrors [`HybridBackend`]'s concatenated layouts: `from_public_key_bytes`
/// parses `(Ed25519_pk(32) || ML-DSA_pk)` and `verify` splits
/// `(Ed25519_sig || ML-DSA_sig)`, requiring BOTH halves to be valid.
pub struct HybridVerifier {
    ed25519: Ed25519Verifier,
    mldsa: MlDsaVerifier,
}

impl HybridVerifier {
    /// Create from separately built verifiers. The ML-DSA verifier fixes the
    /// security level of the PQ half.
    pub fn new(ed25519: Ed25519Verifier, mldsa: MlDsaVerifier) -> Self {
        Self { ed25519, mldsa }
    }

    /// Import from concatenated public-key bytes `(Ed25519_pk(32) || ML-DSA_pk)`.
    pub fn from_public_key_bytes(level: MlDsaLevel, bytes: &[u8]) -> Result<Self> {
        anyhow::ensure!(
            bytes.len() == 32 + level.public_key_size(),
            "hybrid public key must be 32 + {} bytes (got {})",
            level.public_key_size(),
            bytes.len()
        );
        let (ed_pk, mldsa_pk) = bytes.split_at(32);
        let ed_bytes: [u8; 32] = ed_pk
            .try_into()
            .map_err(|_| anyhow::anyhow!("hybrid public key Ed25519 half must be 32 bytes"))?;
        Ok(Self {
            ed25519: Ed25519Verifier::from_bytes(&ed_bytes)?,
            mldsa: MlDsaVerifier::from_public_key_bytes(level, mldsa_pk)?,
        })
    }

    /// Verify a hybrid signature over `data`. Both the Ed25519 and the
    /// ML-DSA half must be valid.
    pub fn verify(&self, data: &[u8], signature: &[u8]) -> bool {
        let ed_len = 64;
        let pq_len = self.mldsa.signature_size();
        if signature.len() != ed_len + pq_len {
            return false;
        }
        self.ed25519.verify(data, &signature[..ed_len])
            && self.mldsa.verify(data, &signature[ed_len..])
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests for the signing backends and verifiers
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
    fn test_mldsa_sizes_exact_fips204() {
        for (level, sig_size, pk_size) in [
            (MlDsaLevel::MlDsa44, 2420, 1312),
            (MlDsaLevel::MlDsa65, 3309, 1952),
            (MlDsaLevel::MlDsa87, 4627, 2592),
        ] {
            let backend = MlDsaBackend::generate(level);
            assert_eq!(level.signature_size(), sig_size);
            assert_eq!(level.public_key_size(), pk_size);
            assert_eq!(backend.signature_size(), sig_size);
            assert_eq!(backend.sign(b"size check").len(), sig_size);
            assert_eq!(backend.public_key_bytes().len(), pk_size);
        }
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
            // Real lattice signature, not an input-appended MAC: the
            // signature must not be a deterministic function of the message
            // alone that a third party without the key could re-derive.
            assert_ne!(&sig[..32], &data[..32.min(data.len())]);
        }
    }

    #[test]
    fn test_mldsa_keygen_and_signing_deterministic() {
        for level in [
            MlDsaLevel::MlDsa44,
            MlDsaLevel::MlDsa65,
            MlDsaLevel::MlDsa87,
        ] {
            let seed = [0x42u8; 32];
            let a = MlDsaBackend::from_seed(level, seed);
            let b = MlDsaBackend::from_seed(level, seed);
            let data = b"deterministic keygen and signing";
            assert_eq!(a.public_key_bytes(), b.public_key_bytes());
            assert_eq!(a.sign(data), b.sign(data));
            // And the independent backend verifies the shared signature.
            assert!(b.verify(data, &a.sign(data)));
        }
    }

    #[test]
    fn test_mldsa_wrong_key_fails() {
        for level in [
            MlDsaLevel::MlDsa44,
            MlDsaLevel::MlDsa65,
            MlDsaLevel::MlDsa87,
        ] {
            let a = MlDsaBackend::from_seed(level, [1u8; 32]);
            let b = MlDsaBackend::from_seed(level, [2u8; 32]);
            assert_ne!(a.public_key_bytes(), b.public_key_bytes());
            let data = b"frame data";
            let sig = a.sign(data);
            assert!(a.verify(data, &sig));
            assert!(!b.verify(data, &sig));
        }
    }

    #[test]
    fn test_mldsa_tampered_signature_fails() {
        for level in [
            MlDsaLevel::MlDsa44,
            MlDsaLevel::MlDsa65,
            MlDsaLevel::MlDsa87,
        ] {
            let backend = MlDsaBackend::from_seed(level, [3u8; 32]);
            let data = b"frame data";
            let sig = backend.sign(data);
            assert!(backend.verify(data, &sig));
            // Flip a byte in the c̃ region (start)…
            let mut sig_start = sig.clone();
            sig_start[0] ^= 0x01;
            assert!(!backend.verify(data, &sig_start));
            // …and in the hint region (end).
            let mut sig_end = sig.clone();
            let n = sig_end.len();
            sig_end[n - 1] ^= 0x80;
            assert!(!backend.verify(data, &sig_end));
        }
    }

    #[test]
    fn test_mldsa_wrong_message_fails() {
        for level in [
            MlDsaLevel::MlDsa44,
            MlDsaLevel::MlDsa65,
            MlDsaLevel::MlDsa87,
        ] {
            let backend = MlDsaBackend::from_seed(level, [4u8; 32]);
            let sig = backend.sign(b"original message");
            assert!(!backend.verify(b"original message!", &sig));
        }
    }

    #[test]
    fn test_mldsa_verifier_from_public_key_bytes() {
        for level in [
            MlDsaLevel::MlDsa44,
            MlDsaLevel::MlDsa65,
            MlDsaLevel::MlDsa87,
        ] {
            let backend = MlDsaBackend::from_seed(level, [5u8; 32]);
            let verifier =
                MlDsaVerifier::from_public_key_bytes(level, &backend.public_key_bytes()).unwrap();
            assert_eq!(verifier.level(), level);
            assert_eq!(verifier.signature_size(), level.signature_size());
            let data = b"public-key-only verification";
            let sig = backend.sign(data);
            assert!(verifier.verify(data, &sig));
            assert!(!verifier.verify(b"wrong message", &sig));
            // Wrong key.
            let other = MlDsaBackend::from_seed(level, [6u8; 32]);
            assert!(!verifier.verify(data, &other.sign(data)));
            // Tampered signature.
            let mut tampered = sig.clone();
            tampered[16] ^= 0xff;
            assert!(!verifier.verify(data, &tampered));
            // Wrong-length public keys are rejected at import.
            assert!(MlDsaVerifier::from_public_key_bytes(
                level,
                &vec![0u8; level.public_key_size() - 1]
            )
            .is_err());
        }
    }

    #[test]
    fn test_mldsa_verifier_from_typed_verifying_key() {
        let sk = ml_dsa::SigningKey::<ml_dsa::MlDsa44>::from_seed(&ml_dsa::Seed::from([11u8; 32]));
        let verifier = MlDsaVerifier::new(MlDsaLevel::MlDsa44, sk.verifying_key());
        let backend = MlDsaBackend::from_seed(MlDsaLevel::MlDsa44, [11u8; 32]);
        let data = b"typed verifying key";
        let sig = backend.sign(data);
        assert!(verifier.verify(data, &sig));
        assert!(!verifier.verify(b"wrong message", &sig));
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

    #[test]
    fn test_hybrid_tamper_each_half_fails() {
        let backend = HybridBackend::generate(MlDsaLevel::MlDsa44);
        let data = b"hybrid tamper test";
        let sig = backend.sign(data);
        assert!(backend.verify(data, &sig));
        // Ed25519 half (first 64 bytes).
        let mut sig_ed = sig.clone();
        sig_ed[0] ^= 0x01;
        assert!(!backend.verify(data, &sig_ed));
        // ML-DSA half.
        let mut sig_pq = sig.clone();
        let n = sig_pq.len();
        sig_pq[n - 1] ^= 0x01;
        assert!(!backend.verify(data, &sig_pq));
    }

    #[test]
    fn test_hybrid_verifier_from_public_key_bytes() {
        let backend = HybridBackend::generate(MlDsaLevel::MlDsa44);
        let pk = backend.public_key_bytes();
        assert_eq!(pk.len(), 32 + 1312);
        let verifier = HybridVerifier::from_public_key_bytes(MlDsaLevel::MlDsa44, &pk).unwrap();
        let data = b"hybrid public-key-only verification";
        let sig = backend.sign(data);
        assert_eq!(sig.len(), 64 + 2420);
        assert!(verifier.verify(data, &sig));
        assert!(!verifier.verify(b"other message", &sig));
        // Wrong key.
        let other = HybridBackend::generate(MlDsaLevel::MlDsa44);
        assert!(!verifier.verify(data, &other.sign(data)));
        // Tampered Ed25519 half.
        let mut sig_ed = sig.clone();
        sig_ed[10] ^= 0x01;
        assert!(!verifier.verify(data, &sig_ed));
        // Tampered ML-DSA half.
        let mut sig_pq = sig.clone();
        let n = sig_pq.len();
        sig_pq[n - 1] ^= 0x01;
        assert!(!verifier.verify(data, &sig_pq));
        // Malformed public-key length is rejected at import.
        assert!(
            HybridVerifier::from_public_key_bytes(MlDsaLevel::MlDsa44, &pk[..pk.len() - 1])
                .is_err()
        );
    }
}
