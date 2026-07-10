//! # steganographer-core
//!
//! Media-agnostic steganography algorithms, cryptographic binding, and configuration.
//!
//! This crate provides:
//! - **Config** — TOML-based configuration model for pipelines
//! - **Crypto** — BLAKE3/SHA-256/SHA-3 hashing + Ed25519 signing/verification of frame payloads
//! - **Encryption** — ChaCha20-Poly1305 AEAD encryption for payload confidentiality
//! - **SignerBackend** — Pluggable signing backends (Ed25519, Ethereum/secp256k1)
//! - **Metrics** — Lightweight, lock-free pipeline performance counters
//! - **Video** — `VideoFrame` types and `VideoStegoModule` trait
//! - **Audio** — `AudioBuffer` types and `AudioStegoModule` trait
//! - **LSB Video** — Least-significant-bit embedding/extraction in video frames
//! - **LSB Audio** — Pseudo-random LSB embedding/extraction in audio samples
//! - **Spread Spectrum** — PN-sequence modulation for noise-resistant embedding
//! - **DCT Video** — DCT-domain embedding for compression-resistant steganography
//! - **Error Correction** — Reed-Solomon codes over GF(2^8) for payload resilience
//! - **Multi-Frame** — Spread one signature across N frames for partial loss resilience
//! - **Overlay** — Text burn-in watermark for video frames
//! - **Hash Chain** — Merkle tree / hash chain for streaming authentication
//! - **Adaptive** — Content-adaptive steganography (high-variance region embedding)
//! - **Info Bar** — Exoteric info overlay with timestamp, barcode, QR code

pub mod adaptive;
pub mod audio;
pub mod config;
pub mod crypto;
pub mod dct_video;
pub mod encryption;
pub mod error_correction;
pub mod hash_chain;
pub mod info_bar;
pub mod kdf;
pub mod lsb_audio;
pub mod lsb_video;
pub mod mdct_audio;
pub mod metrics;
pub mod multi_frame;
pub mod overlay;
pub mod signer_backend;
pub mod spread_spectrum;
pub mod steganalysis;
pub mod video;

pub use audio::{AudioBuffer, AudioStegoModule};
pub use config::{AudioStegoConfig, Config, VideoStegoConfig};
pub use crypto::{HashAlgorithm, SignaturePayload, Signer, Verifier};
pub use encryption::EncryptionKey;
pub use kdf::{
    derive_all, derive_embedding_key, derive_encryption_key, derive_signing_key, DerivedKeys,
};
pub use metrics::StegoMetrics;
pub use signer_backend::{Ed25519Backend, Ed25519Verifier, SignerBackend};
pub use spread_spectrum::{SpreadSpectrumAudio, SpreadSpectrumVideo};
pub use steganalysis::{
    analyze_combined, chi_squared_detect, rs_analyze, sample_pair_detect, CombinedResult,
    DetectionResult,
};
pub use video::{VideoFormat, VideoFrame, VideoStegoModule};

#[cfg(feature = "ethereum")]
pub use signer_backend::{EthereumBackend, EthereumVerifier};
