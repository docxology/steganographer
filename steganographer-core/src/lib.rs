//! # steganographer-core
//!
//! Media-agnostic steganography algorithms, cryptographic binding, and configuration.
//!
//! This crate provides:
//! - **Config** — TOML-based configuration model for pipelines
//! - **Crypto** — BLAKE3 hashing + Ed25519 signing/verification of frame payloads
//! - **SignerBackend** — Pluggable signing backends (Ed25519, Ethereum/secp256k1)
//! - **Metrics** — Lightweight, lock-free pipeline performance counters
//! - **Video** — `VideoFrame` types and `VideoStegoModule` trait
//! - **Audio** — `AudioBuffer` types and `AudioStegoModule` trait
//! - **LSB Video** — Least-significant-bit embedding/extraction in video frames
//! - **LSB Audio** — Pseudo-random LSB embedding/extraction in audio samples
//! - **Overlay** — Text burn-in watermark for video frames
//! - **Info Bar** — Exoteric info overlay with timestamp, barcode, QR code

pub mod audio;
pub mod config;
pub mod crypto;
pub mod info_bar;
pub mod lsb_audio;
pub mod lsb_video;
pub mod metrics;
pub mod overlay;
pub mod signer_backend;
pub mod video;

pub use audio::{AudioBuffer, AudioStegoModule};
pub use config::{AudioStegoConfig, Config, VideoStegoConfig};
pub use crypto::{SignaturePayload, Signer, Verifier};
pub use metrics::StegoMetrics;
pub use signer_backend::{Ed25519Backend, Ed25519Verifier, SignerBackend};
pub use video::{VideoFormat, VideoFrame, VideoStegoModule};

#[cfg(feature = "ethereum")]
pub use signer_backend::{EthereumBackend, EthereumVerifier};
