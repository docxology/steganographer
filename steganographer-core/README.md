# steganographer-core

![CI](https://github.com/docxology/steganographer/actions/workflows/ci.yml/badge.svg)
![Tests](https://img.shields.io/badge/tests-114%20(56%20unit%20%2B%2058%20integration)-brightgreen)
Pure, media-agnostic algorithms for steganographic embedding, cryptographic signing, and configuration. This is the foundational crate with zero GStreamer or I/O dependencies.

## Modules

| Module | File | Description |
| -------- | ------ | ------------- |
| `video` | `src/video.rs` | `VideoFrame` struct, `VideoFormat` enum, `VideoStegoModule` trait |
| `audio` | `src/audio.rs` | `AudioBuffer` struct, `AudioStegoModule` trait |
| `crypto` | `src/crypto.rs` | `Signer`, `Verifier`, `SignaturePayload` — BLAKE3 + Ed25519 |
| `signer_backend` | `src/signer_backend.rs` | `SignerBackend` / `Ed25519Backend` / `EthereumBackend` trait + impls |
| `config` | `src/config.rs` | `Config` TOML parsing, hex key decoding, overlay/info_bar config |
| `lsb_video` | `src/lsb_video.rs` | `LsbVideo` — 1–4 bit LSB video embed/extract with length prefix |
| `lsb_audio` | `src/lsb_audio.rs` | `LsbAudio` — keyed PRNG index permutation LSB audio embed/extract |
| `overlay` | `src/overlay.rs` | `TextOverlay` — 8×8 bitmap font renderer, template expansion (`{timestamp}`, `{frame_index}`) |
| `info_bar` | `src/info_bar.rs` | `InfoBar` — exoteric visible watermark with toggleable timestamps, barcodes, QR |
| `metrics` | `src/metrics.rs` | `StegoMetrics` — thread-safe atomic counters for latency/frame tracking |

## Tests

- **Unit tests**: 56 inline tests across all modules
- **Integration tests**: 58 tests in `tests/integration_tests.rs`
- **Total**: 114 tests

```bash
cargo test -p steganographer-core
```

## Dependencies

```toml
blake3 = "1.5"
ed25519-dalek = { version = "2", features = ["rand_core"] }
rand = "0.8"
anyhow = "1"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
toml = "0.8"
log = "0.4"
chrono = "0.4"
```

## Architecture

```text
lib.rs
├── video.rs             → VideoFrame / VideoStegoModule trait
├── audio.rs             → AudioBuffer / AudioStegoModule trait
├── crypto.rs            → Signer + Verifier (BLAKE3 hash, Ed25519 sign)
├── signer_backend.rs    → SignerBackend trait + Ed25519/Ethereum impls
├── config.rs            → Config model + TOML parsing
├── lsb_video.rs         → LsbVideo implements VideoStegoModule
├── lsb_audio.rs         → LsbAudio implements AudioStegoModule
├── overlay.rs           → TextOverlay implements VideoStegoModule + template expansion
├── info_bar.rs          → InfoBar implements VideoStegoModule
└── metrics.rs           → StegoMetrics (atomic counters, JSON export)
```
