# AGENTS.md — Steganographer (Root)

## Project Overview

**Steganographer** is a Rust workspace providing real-time steganographic watermarking for video and audio streams. It uses BLAKE3 hashing + Ed25519/secp256k1 signing with LSB steganography, plus a live web dashboard for round-trip verification.

## Directory Structure

| Path | Type | Description |
| ---- | ---- | ----------- |
| `steganographer-core/` | Crate | Pure algorithms: LSB video/audio, crypto, overlay, info_bar, signer_backend, metrics, config, DCT video, encryption, error_correction, multi_frame, spread_spectrum (16 modules, 115 unit tests, 59 integration tests) |
| `steganographer-gst/` | Crate | GStreamer integration: AppSink/AppSrc video/audio filter pipelines (4 modules) |
| `steganographer-cli/` | Crate | CLI binary: 8 Clap subcommands — video, audio, encode, verify, keygen, info, config, dashboard (5 modules) |
| `steganographer-dashboard/` | Crate | Axum web dashboard: 3-tab GUI (Video/Audio/Docs) with WebSocket streaming, dynamic LSB, signature preview (2 modules + 6 static assets) |
| `config/` | Config | Example TOML configuration files |
| `docs/` | Docs | 17 comprehensive documentation files |
| `steganographer.toml` | Config | Master configuration (fully documented) |
| `run.sh` | Script | Interactive terminal menu (6 options: Dashboard, CLI Tools, Live Pipelines, Quick Demo, Run Tests, System Info) |

## File Counts

- **Root files**: 10 (`.gitattributes`, `.gitignore`, `AGENTS.md`, `CHANGELOG.md`, `Cargo.lock`, `Cargo.toml`, `FUNDING.md`, `README.md`, `TODO.md`, `run.sh`, `steganographer.toml`)
- **Source files**: 22 Rust source files + 6 static web assets across 4 crates
- **Test files**: 2 integration test files (58 tests) + inline unit tests (56 tests) + dashboard tests (12) = **132 total tests**
- **Doc files**: 17 markdown documentation files + README.md / AGENTS.md per crate
- **Config files**: 2 TOML files (`steganographer.toml`, `config/example.toml`)

## Build & Test

```bash
cargo build --workspace
cargo test -p steganographer-core              # 114 tests (Ed25519 default)
cargo test -p steganographer-core --features ethereum  # includes Ethereum tests
cargo test --workspace                         # 132 total tests
./run.sh                                       # Interactive menu (press 'a' for run-all)
```

## Key Dependencies

| Dependency | Version | Purpose |
| ---------- | ------- | ------- |
| `blake3` | 1.5 | BLAKE3 hashing |
| `ed25519-dalek` | 2.x | Ed25519 signatures (default) |
| `k256` | 0.13 | secp256k1/Ethereum signing (feature-gated) |
| `sha3` | 0.10 | Keccak-256 for EIP-191 |
| `axum` | 0.8 | Dashboard web server |
| `tokio` | 1.x | Async runtime |
| `gstreamer` | 0.23.x | Media pipeline |
| `clap` | 4.x | CLI argument parsing |
| `serde` + `toml` | 1.x / 0.8 | Configuration |
| `serde_json` | 1.x | JSON output for verify command |
| `chrono` | 0.4 | Timestamp template expansion |
