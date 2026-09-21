# AGENTS.md — Steganographer (Root)

## Project Overview

**Steganographer** is a Rust workspace providing real-time steganographic watermarking for video and audio streams. It uses BLAKE3 hashing + Ed25519/secp256k1 signing with LSB steganography, plus a live web dashboard for round-trip verification.

## Directory Structure

| Path | Type | Description |
| ---- | ---- | ----------- |
| `steganographer-core/` | Crate | Pure algorithms: generic packets/carriers (byte + PCM S16 LSB), keyed + interleaved placement, LSB video/audio, crypto, overlays, signing (Ed25519, Ethereum, real FIPS 204 ML-DSA via the RustCrypto `ml-dsa` crate with public-key-only `MlDsaVerifier`/`HybridVerifier`, Hybrid), metrics, config, frequency-domain kernels, encryption (packet-id-derived AEAD nonce), ECC, multi-frame, adaptive, hash-chain, KDF, password KDF, transforms, steganalysis, forensics + unicode-text detectors (FOR-005), and WASM inspection facade (32 modules + `lib.rs`) |
| `steganographer-gst/` | Crate | GStreamer integration: AppSink/AppSrc video/audio filter pipelines + native `stegovideo` (keyed/sequential LSB video element) and `stegoaudio` (S16 PCM audio element) with cdylib plugin packaging (6 modules + integration tests) |
| `steganographer-cli/` | Crate | CLI binary: 15 Clap subcommands — video, audio, encode, decode, extract, verify, keygen, info, analyze, scan, derive, config, revoke, dashboard, ots (10 modules) |
| `steganographer-dashboard/` | Crate | Axum web dashboard: 3-tab GUI (Video/Audio/Docs) with WebSocket streaming, dynamic LSB, signature preview (2 modules + 7 static assets) |
| `config/` | Config | Example TOML configuration files |
| `docs/` | Docs | 17 user-facing guides + 7 steganography-platform planning specifications (+ `README.md` / `AGENTS.md`) |
| `steganographer.toml` | Config | Master configuration (fully documented) |
| `run.sh` | Script | Interactive terminal menu (6 options: Dashboard, CLI Tools, Live Pipelines, Quick Demo, Run Tests, System Info) |

## File Counts

- **Root files**: 18 (`.dockerignore`, `.gitattributes`, `.gitignore`, `.gitleaks.toml`, `AGENTS.md`, `CHANGELOG.md`, `Cargo.lock`, `Cargo.toml`, `deny.toml`, `Dockerfile`, `FUNDING.md`, `LICENSE`, `README.md`, `release.toml`, `run.sh`, `rust-toolchain.toml`, `steganographer.toml`, `TODO.md`)
- **Source files**: 60 Rust files (49 `src/` modules + 5 test files + 4 fuzz targets + 1 benchmark file + `build.rs`) + 7 static web assets across 4 crates
- **Tests**: 343 core unit + 123 core integration (80 in `integration_tests.rs` + 37 in `ots_integration_tests.rs` + 6 in `golden_vectors.rs`) + 14 CLI unit + 46 CLI integration (39 in `cli_integration_tests.rs` + 7 in `cli_packet_tests.rs`) + 44 dashboard tests + 8 dashboard doc-tests + 14 GStreamer unit + 9 GStreamer integration + 1 GStreamer doc-test = **602 passing tests** — **canonical count home is this line** (as of 2026-09-20; verify with `cargo test --workspace` or `./scripts/status.sh --check` and update here first, then defer from other docs).
- **Doc files**: 27 markdown files under `docs/` (17 guides + `README.md` + `AGENTS.md` + 7 program planning specifications + `manuscript/MANUSCRIPT_STATUS.md`) + README.md / AGENTS.md per crate
- **Config files**: 2 TOML files (`steganographer.toml`, `config/example.toml`)

## Build & Test

```bash
cargo build --workspace
cargo test -p steganographer-core              # core crate only (count: canonical Tests line above)
cargo test -p steganographer-core --features ethereum  # includes Ethereum tests
cargo test --workspace                         # 602 total tests
./run.sh                                       # Interactive menu
./scripts/status.sh                            # executable status: version, subcommand count, docs, git, test count
./scripts/status.sh --check                    # exit 1 if the canonical test count in AGENTS.md drifts from cargo
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
