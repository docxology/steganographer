# AGENTS.md — Steganographer (Root)

## Project Overview

**Steganographer 0.8.0** provides bounded generic packets/forensics, domain-separated signed media, native GStreamer integration and a sampled signed-artifact web dashboard. Surface capabilities are explicit: live Ed25519/LSB is not the full set of optional core signing/kernel APIs.

## Directory Structure

| Path | Type | Description |
| ---- | ---- | ----------- |
| `steganographer-core/` | Crate | Pure algorithms: generic packets/carriers (byte + PCM S16 LSB), keyed + interleaved placement, LSB video/audio, crypto, overlays, signing (Ed25519, Ethereum, real FIPS 204 ML-DSA via the RustCrypto `ml-dsa` crate with public-key-only `MlDsaVerifier`/`HybridVerifier`, Hybrid), metrics, config, frequency-domain kernels, encryption (packet-id-derived AEAD nonce), ECC, multi-frame, adaptive, hash-chain, KDF, password KDF, transforms (incl. the `TRANSFORM_KDF_ARGON2ID` password-KDF transform, PKT-007), steganalysis, forensics with the stable detector registry + calibration corpus (FOR-001) and OOXML/ZIP container analysis (DOC-001/DOC-002), bounded nested decode (`decode_nested`, PKT-009), unicode-text detectors (FOR-005), and WASM inspection facade (31 modules + `forensics/ooxml` + `lib.rs`) |
| `steganographer-gst/` | Crate | AppSink/AppSrc bridges, exact RGB Matroska/whole-selection PCM WAV, `stegovideo`/`stegoaudio` elements and cdylib packaging |
| `steganographer-cli/` | Crate | Shared `src/cli.rs` Clap schema: 15 top-level commands with GStreamer, generated shell completions/manuals, atomic file I/O |
| `steganographer-dashboard/` | Crate | Video/Audio/Docs GUI, authenticated HTTP/WebSocket and optional WebRTC, bounded work and actual signed PNG/WAV archives |
| `steganographer-wasm/` | Crate | Native facade plus generated node/web bindings, numeric-safe controls and exact `steganographer.packet-report.v2` metadata |
| `config/` | Config | Example TOML configuration files |
| `docs/` | Docs | 18 user guides, documentation/planning indexes, seven platform-planning specifications and supporting metadata |
| `steganographer.toml` | Config | Master configuration (fully documented) |
| `run.sh` | Script | Interactive terminal menu (6 options: Dashboard, CLI Tools, Live Pipelines, Quick Demo, Run Tests, System Info) |

## File Counts

- **Sources**: five workspace crates, eight fuzz targets, native integration tests and generated-binding regression scenarios. Use Cargo metadata/file listings instead of pinning a source-file count.
- **Tests**: `cargo test --workspace --locked` = **767 passing tests** (default features); all-feature run: 821 passed across 28 suites. Both intentionally ignore only the immutable-fixture materializer. Canonical count home is this line; observed on macOS arm64, 2026-11-07. Update here first, then defer from other docs.
- **Documentation**: `scripts/status.sh` derives top-level and platform-plan inventories; recursive documentation also includes image/manuscript metadata.
- **Config files**: 2 TOML files (`steganographer.toml`, `config/example.toml`)

## Build & Test

```bash
cargo build --workspace --all-features --locked
cargo test -p steganographer-core --locked      # core only
cargo test --workspace --locked                # default features; canonical count above
./run.sh                                       # Interactive menu
./scripts/status.sh                            # executable status: version, subcommand count, docs, git, test count
./scripts/status.sh --check                    # exit 1 if the canonical test count in AGENTS.md drifts from cargo
```

Minimum supported Rust: **1.91**. Check the locked workspace with all features
and all targets; current stable builds alone do not establish the MSRV.
Public Rust documentation must pass `RUSTDOCFLAGS="-D warnings" cargo doc
--workspace --all-features --no-deps --locked`.

## Key Dependencies

| Dependency | Version | Purpose |
| ---------- | ------- | ------- |
| `blake3` | 1.x | Domain-separated media and packet hashing |
| `sha2` | 0.10 | SHA-256 hashing |
| `ed25519-dalek` | 2.x | Ed25519 signatures (default) |
| `k256` | 0.14 | secp256k1/Ethereum core signing (feature-gated) |
| `sha3` | 0.10 | Keccak-256 for EIP-191 |
| `chacha20poly1305` | 0.11 | ChaCha20-Poly1305 AEAD payload encryption |
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
