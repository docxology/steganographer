# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Payload Encryption** — ChaCha20-Poly1305 AEAD encryption for steganographic payloads (`encryption.rs`)
- **Spread-Spectrum Steganography** — PN-sequence modulation for noise-resistant embedding (`spread_spectrum.rs`)
- **DCT-Domain Embedding** — 8×8 DCT block embedding for JPEG compression resistance (`dct_video.rs`)
- **Reed-Solomon Error Correction** — GF(2^8) error correction for payload recovery (`error_correction.rs`)
- **Multi-Frame Signature Spreading** — XOR-based n-of-n secret sharing across N frames (`multi_frame.rs`)
- **Configurable Hash Algorithms** — BLAKE3 (default), SHA-256, SHA-3 via `hash_algorithm` config
- **Magic Header + Version** — `STEG` magic (4B) + version (1B) in payload for format identification
- **Constant-Time Hash Comparison** — Uses `subtle` crate to prevent timing attacks
- **Key File Loading** — `key_file = "path"` in TOML config for both global and LSB configs
- **Capacity Reporting** — new `steganographer info` CLI command
- **New CLI flags** — `--embedding-key` for verify command, `info` subcommand
- **New stego types for encode/verify** — `spread_spectrum_video`, `dct_video`
- **Info bar config** — `[video.stego.info_bar]` with label, show_barcode, show_qr, show_timestamp
- **Payload config** — encrypt, encryption_key, encryption_key_file, error_correction, multi_frame_spread
- **Secure keygen** — private key files now have 0600 permissions on Unix
- Release acceptance criteria in `TODO.md` — gates every release on tests, docs, code quality, security, and build compatibility
- `FUNDING.md` with sponsorship information
- `TODO.md` with scoped upcoming and backlog items
- `CHANGELOG.md` (this file)
- Dashboard favicon
- Toast notification system for config saves, session exports, and copy-to-clipboard
- `--quiet` CLI flag for scripting (suppresses all output except final result)
- Colorized verify output — green ✓ for pass, red ✗ for fail
- `--format json` for encode — structured JSON output with hash, signature, byte count
- `steganographer config check` subcommand — validates TOML configuration without running
- Keyboard shortcut cheat sheet — `?` key overlay showing all shortcuts
- Config preset buttons — Low / Medium / High one-click LSB presets in dashboard
- GitHub Actions CI — matrix build (Linux + macOS) with test and release verification
- CI and test count badges in all sub-crate READMEs

### Changed

- **Payload size** — 104 → 109 bytes (added 4B magic header + 1B version)
- **SHA-3** — now non-optional in steganographer-core (was feature-gated behind `ethereum`)
- **`ethereum` feature** — no longer includes sha3 (just k256)
- **Audio key security** — CLI and dashboard now use random keys instead of hardcoded zero key
- **Dashboard audio key** — EncodedAudioChunk now carries the audio_key for decode handler
- Redesigned `README.md` — hero screenshot, demo video, shield badges, deep links into all 17 docs
- Test count updated from 132 → 190 across all documentation files
- Dashboard screenshots refreshed (Video, Audio, Docs tabs)

### Fixed

- **Security: hardcoded zero key** — Audio CLI and dashboard no longer use `[0u8; 32]` as embedding key
- **Security: timing attacks** — Hash comparison now uses constant-time comparison via `subtle` crate
- Metrics API test assertion (used correct field name `frames_processed`)

## [0.1.0] — 2026-03-06

### Added

- **LSB Video Steganography** — sequential embedding with 1–4 bits, length prefix, round-trip extraction
- **LSB Audio Steganography** — keyed PRNG permutation (ChaCha8), 1–4 bits, length prefix extraction
- **Text Overlay** — built-in 8×8 bitmap font, configurable position/color/scale
- **Info Bar** — QR code, Code-128 barcode, and metadata overlay that survives compression
- **BLAKE3 + Ed25519 Signing** — per-frame hashing and signing with 104-byte payload
- **Pluggable Signing Backends** — Ed25519 and Ethereum/secp256k1 via `SignerBackend` trait
- **GStreamer Integration** — real-time processing via AppSink/AppSrc (V4L2, AVFoundation, PulseAudio, PipeWire)
- **CLI** — 6 subcommands: `video`, `audio`, `encode`, `verify`, `keygen`, `dashboard`
- **Configuration** — full TOML config with modular pipeline chains
- **Web Dashboard** — three-tab GUI (Video | Audio | Docs) with real-time encode/decode verification
- **Audio Dashboard** — microphone capture with waveform/spectrum visualization, WAV recording
- **Documentation Viewer** — browse all project docs in-dashboard with syntax highlighting
- **MetaMask / Ethereum** — browser-based `personal_sign` via EIP-1193
- **Dynamic LSB Configuration** — live config changes via `POST /api/config`
- **QR Data Matrix Overlay** — 13×13 binary grid encoding metadata with timestamp
- **Keyboard Shortcuts** — Space=camera, R=record, 1/2/3=tabs, +/−=LSB, E=export
- **Session Export** — download session report as JSON
- **Copy-to-Clipboard** — buttons on hash and signature fields
- **Help Tooltips** — custom JavaScript tooltips
- **Session Stats API** — `GET /api/session` endpoint
- **Auto-Start Camera** — `?autostart=1` URL parameter
- **Footer Verified Counter** — live ✅ X / ❌ Y ratio
- **132 Tests** — 56 core unit + 58 core integration + 12 dashboard + 1 GStreamer + 5 Ethereum (feature-gated)
- **17 Documentation Files** — architecture, cryptography, algorithms, CLI, config, GStreamer, platforms, API, security, threat model, theory, contributing, roadmap, FAQ

[Unreleased]: https://github.com/docxology/steganographer/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/docxology/steganographer/releases/tag/v0.1.0
