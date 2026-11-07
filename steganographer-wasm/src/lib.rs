//! # steganographer-wasm
//!
//! Browser-facing facade over [`steganographer_core`] for local, in-browser
//! steganography. No network, no filesystem: every entry point operates on
//! raw byte buffers.
//!
//! Surfaces: protocol-v1 packets, raw RGB/PCM carriers and bounded scans.
//! Frozen generic wire vectors remain unchanged; packet reports use schema v2.
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
//! - Public plain-Rust functions re-exported from the internal `api` module
//!   are always compiled and exercised by native integration tests.
//! - `bindings` (`#[cfg(target_arch = "wasm32")]` only) — `#[wasm_bindgen]`
//!   exports over the same functions, with `Vec<u8>`/`String` signatures and
//!   checked JS-number controls. Reports are JSON strings, not JS objects.
//!   Packet/extraction reports identify [`PACKET_REPORT_SCHEMA`] and represent
//!   `original_len` and nullable `created_at_unix` as exact decimal strings;
//!   use `BigInt(value)` when arithmetic is needed, not `Number(value)`.
//!   Carrier counts remain numbers; embed outputs remain `{carrier, report}`.
//!   Decode-limit overrides are JSON strings on operations; the
//!   [`decode_limits_from_json`] Rust helper is not a JavaScript export.
//!   Generate JS with a `wasm-bindgen` CLI matching the resolved library version.

mod api;
#[cfg(target_arch = "wasm32")]
mod bindings;

pub use api::{
    capacity_pcm_s16le, capacity_rgb, decode_limits_default, decode_limits_from_json,
    embed_pcm_s16le, embed_rgb, extract_pcm_s16le, extract_rgb, forensic_scan, packet_decode,
    packet_encode, text_analyze_bytes, text_analyze_text, PACKET_REPORT_SCHEMA,
};
