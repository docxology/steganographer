# AGENTS.md — Steganographer (Root)

## Project Overview

**Steganographer** is a Rust workspace providing real-time steganographic watermarking for video and audio streams. It uses BLAKE3 hashing + Ed25519/secp256k1 signing with LSB steganography, plus a live web dashboard for round-trip verification.

## Directory Structure

| Path | Type | Description |
| ---- | ---- | ----------- |
| `steganographer-core/` | Crate | Pure algorithms: generic packets/carriers (byte + PCM S16 LSB), keyed placement, LSB video/audio, crypto, overlays, signing, metrics, config, frequency-domain kernels, encryption, ECC, multi-frame, adaptive, hash-chain, KDF, password KDF, transforms, and steganalysis (28 modules, 277 unit tests, 113 integration tests) |
| `steganographer-gst/` | Crate | GStreamer integration: AppSink/AppSrc video/audio filter pipelines (4 modules) |
| `steganographer-cli/` | Crate | CLI binary: 13 Clap subcommands — video, audio, encode, decode, verify, keygen, info, analyze, derive, config, revoke, dashboard, ots (9 modules) |
| `steganographer-dashboard/` | Crate | Axum web dashboard: 3-tab GUI (Video/Audio/Docs) with WebSocket streaming, dynamic LSB, signature preview (2 modules + 6 static assets) |
| `config/` | Config | Example TOML configuration files |
| `docs/` | Docs | 18 user-facing guides + 7 steganography-platform planning specifications |
| `steganographer.toml` | Config | Master configuration (fully documented) |
| `run.sh` | Script | Interactive terminal menu (6 options: Dashboard, CLI Tools, Live Pipelines, Quick Demo, Run Tests, System Info) |

## File Counts

- **Root files**: 11 (`.gitattributes`, `.gitignore`, `AGENTS.md`, `CHANGELOG.md`, `Cargo.lock`, `Cargo.toml`, `FUNDING.md`, `README.md`, `TODO.md`, `run.sh`, `steganographer.toml`)
- **Source files**: 28 Rust source files + 6 static web assets across 4 crates
- **Tests**: 277 core unit + 113 core integration + 6 CLI unit + 28 CLI integration + 23 dashboard + 2 GStreamer/doc = **449 passing tests**
- **Doc files**: 25 markdown files under `docs/` (18 existing docs + 7 program planning specifications) + README.md / AGENTS.md per crate
- **Config files**: 2 TOML files (`steganographer.toml`, `config/example.toml`)

## Build & Test

```bash
cargo build --workspace
cargo test -p steganographer-core              # 390 tests (277 unit + 113 integration, Ed25519 default)
cargo test -p steganographer-core --features ethereum  # includes Ethereum tests
cargo test --workspace                         # 449 total tests
./run.sh                                       # Interactive menu
```

## Key Dependencies

| Dependency | Version | Purpose |
| ---------- | ------- | ------- |
| `blake3` | 1.5 | BLAKE3 hashing |
| `sha2` | 0.10 | SHA-256 hashing |
| `ed25519-dalek` | 2.x | Ed25519 signatures (default) |
| `k256` | 0.13 | secp256k1/Ethereum signing (feature-gated) |
| `sha3` | 0.10 | Keccak-256 for EIP-191 |
| `chacha20poly1305` | 0.10 | ChaCha20-Poly1305 AEAD payload encryption |
| `subtle` | 2 | Constant-time comparisons |
| `axum` | 0.8 | Dashboard web server |
| `tokio` | 1.x | Async runtime |
| `gstreamer` | 0.23.x | Media pipeline |
| `clap` | 4.x | CLI argument parsing |
| `serde` + `toml` | 1.x / 0.8 | Configuration |
| `serde_json` | 1.x | JSON output for verify command |
| `chrono` | 0.4 | Timestamp template expansion |
| `qrcode` | 0.14 | QR code generation for info bar |
| `image` | 0.25 | Image processing for dashboard |
| `tower-http` | 0.6 | HTTP static file serving + CORS |
| `anyhow` | 1.x | Error handling |
| `thiserror` | 1.x | Custom error types |
| `rand` | 0.8 | Random number generation |
