//! # steganographer-wasm
//!
//! Browser-facing facade over [`steganographer-core`] for local, in-browser
//! steganography. No network, no filesystem: every entry point operates on
//! raw byte buffers.
//!
//! Surfaces (plan spec 04 WASM-001 — packet, PNG/WAV, and supported scan
//! capabilities; vectors are alpha-provisional per QUA-003):
//!
//! - **Packet framing** — encode/decode of untransformed generic packets
//!   (`packet.rs` protocol v1)
//! - **Carriers** — capacity + LSB embed/extract over raw RGB8 byte carriers
//!   (the byte stream behind PNG pixel data) and interleaved little-endian
//!   16-bit PCM (the sample stream inside WAV files)
//! - **Forensics** — structural/statistical byte scan plus Unicode/text
//!   steganography analysis
//! - **Decode limits** — bounded-decode configuration surface
//!
//! # Layout
//!
//! - [`api`] — plain-Rust functions, always compiled; used directly by native
//!   callers and the native integration tests.
//! - `bindings` (`#[cfg(target_arch = "wasm32")]` only) — `#[wasm_bindgen]`
//!   exports over the same functions, with `Vec<u8>`/`String` signatures and
//!   JSON-string reports. Build with
//!   `cargo check --target wasm32-unknown-unknown -p steganographer-wasm`;
//!   `wasm-pack`/`wasm-bindgen` bundling is future packaging work.

mod api;
#[cfg(target_arch = "wasm32")]
mod bindings;

pub use api::{
    capacity_pcm_s16le, capacity_rgb, decode_limits_default, decode_limits_from_json,
    embed_pcm_s16le, embed_rgb, extract_pcm_s16le, extract_rgb, forensic_scan, packet_decode,
    packet_encode, text_analyze_bytes, text_analyze_text,
};
