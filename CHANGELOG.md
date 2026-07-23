# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] — 2026-07-22

### Security (Critical)

- **Key purge + history scrub** — Removed a real Ed25519 private key (`keys/daf.key`) that was committed to this public repository since v0.1.0. Scrubbed from git history via `git filter-repo`. Key rotated; old key revoked. See [`docs/key-rotation.md`](docs/key-rotation.md).
- **.gitignore hardened** — Added `keys/`, `output/`, `*.key`, `*.pub` to `.gitignore`, mirroring the existing `.dockerignore` exclusions that were missing from `.gitignore`.
- **Secret-scanning CI gate** — Added `gitleaks` to CI (`.github/workflows/ci.yml`) with custom `.gitleaks.toml` config. Any future key/credential leak fails CI.
- **Dashboard authentication** — Default bind changed from `0.0.0.0` to `127.0.0.1`. Added `--host` flag for explicit `0.0.0.0` opt-in. Added `--auth-token` flag with Bearer token auth on POST routes (`/api/config`, `/api/metrics/reset`) using constant-time comparison via `subtle` crate. Replaced `CorsLayer::permissive()` with restrictive CORS.
- **Cargo.lock committed** — For reproducible builds and dependency auditability (was gitignored).
- **Dockerfile non-root** — Container now runs as `stego` user instead of root. Dashboard CMD uses `--host 127.0.0.1`.

### Security (Major crypto fixes)

- **AEAD nonce reuse fixed** — `encryption.rs` now prepends a 4-byte random salt to the ChaCha20-Poly1305 nonce derivation. Each invocation gets a unique nonce even with identical `frame_index` (prevents key+nonce reuse in batch encodes). Ciphertext format: `salt(4) || ciphertext || tag`.
- **CLI spread-spectrum key wiring fixed** — `embed_ss_bit` now uses the secret key from `SpreadSpectrumVideo` to seed the PN-sequence RNG (was ignored, breaking round-trip verification and confidentiality).
- **RS decode DoS bound** — `error_correction::decode()` now caps `parity_count` (≤16) and `data_len` (≤65536) symmetric with `encode()`, preventing CPU-exhaustion via crafted media.
- **`unreachable!()` removed** — `gf_inv` now returns 0 with an error log instead of panicking (defense-in-depth).
- **`dct_video` CLI stub fixed** — Now returns a clear error instead of silently falling back to LSB embedding (core library `DctVideo` is correct; CLI raw-byte path was a stub).
- **Config bits validation** — Added `LsbVideo::try_new()` / `LsbAudio::try_new()` returning `Result`. CLI callers now validate bits from config/CLI args instead of panicking.
- **lsb_audio verify** — Now `bail!`s on missing `--embedding-key` instead of silently using a zero key.
- **KDF context dedup** — `cmd_encode.rs` now calls `kdf::derive_all()` instead of hand-copying context strings.

### Added

- **CLI integration tests** — 10 integration tests in `steganographer-cli/tests/cli_integration_tests.rs` covering keygen, lsb_video/audio round-trips, encryption, ECC, spread-spectrum, dct_video error, config check, unsigned media verify, and info capacity. First test coverage for the CLI crate.
- **`--master-secret-file` / `--master-secret-stdin`** — Safer alternatives to `--master-secret` for the `derive` command (secrets no longer visible in shell history / `ps`).
- **Entropy warning** — `derive` command warns if master secret is < 32 bytes (BLAKE3 derive_key is not a slow KDF).
- **Public key visibility** — Live video/audio pipelines now print the signing public key via `eprintln!` (unconditional stderr) so `--quiet` doesn't hide it.
- **Fuzz harness** — Proper `cargo-fuzz` targets with `Cargo.toml` and `fuzz_target!` macros: `fuzz_lsb_video_extract`, `fuzz_payload_from_bytes`, `fuzz_rs_decode` (regression test for the DoS finding).
- **`rust-toolchain.toml`** — Pins stable Rust + clippy + rustfmt for deterministic builds.
- **`SpreadSpectrumVideo::key()`** — Public accessor for the secret key (used by CLI embed/verify).
- **`LsbVideo::try_new()` / `LsbAudio::try_new()`** — Fallible constructors for untrusted input.
- **Nonce-reuse regression test** — `test_same_frame_index_different_salt` verifies the fix.
- **Key rotation documentation** — `docs/key-rotation.md` with incident report, new public key, and revocation notice.
- **CLI reference for `analyze` and `derive`** — Full documentation in `docs/cli-reference.md` including Mermaid diagram, options, examples, and security notes.

### Changed

- **CLI subcommands** — 10 (was 6): added `info`, `analyze`, `derive`, `config`.
- **Core modules** — 21 (was 16): added `adaptive`, `hash_chain`, `kdf`, `mdct_audio`, `steganalysis`.
- **Test count** — 282 (was 132 at v0.1.0): 171 core unit + 76 core integration + 10 CLI integration + 23 dashboard + 1 GStreamer + 1 doc-test.
- **`deny.toml`** — Advisory policy now matches its comment: `deny = ["medium", "high", "critical"]`.
- **`docs/threat-model.md`** — T2 "Residual Risk: None" replaced with scoped statement acknowledging T4 (signature stripping).
- **`docs/platforms.md`** — Windows section relabeled "Community-Supported — No CI Coverage".
- **`docs/roadmap.md`** — Real Gantt dates (2026-2027), correct test count, correct subcommand count.
- **Dockerfile example** — `docs/platforms.md` Docker example synced with real Dockerfile (rust:1.97, pkg-config, /build workdir).

### Fixed

- **`--quiet` hiding public key** — Live pipelines now print the public key to stderr unconditionally.
- **`deny.toml` policy mismatch** — Advisory severity policy now enforces what the comment claims.
- **Threat model contradiction** — T2/T4 residual risk statements reconciled.
- **Fuzz harness** — Was not a runnable cargo-fuzz target; now properly structured with `Cargo.toml` and `fuzz_target!` macros.
- **Stale documentation** — All test counts, module counts, and subcommand counts updated across README.md, AGENTS.md, per-crate AGENTS.md files, roadmap.md, and cli-reference.md.

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

[Unreleased]: https://github.com/docxology/steganographer/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/docxology/steganographer/releases/tag/v0.2.0
[0.1.0]: https://github.com/docxology/steganographer/releases/tag/v0.1.0
