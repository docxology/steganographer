# TODO

Scoped improvements and future plans.
See [docs/roadmap.md](docs/roadmap.md) for the full release timeline.

---

## ✅ Release Acceptance Criteria

**Every release** — including patch and minor releases — must satisfy all of the following before merge:

### Tests

- [ ] `cargo test --workspace` — **all tests pass**, 0 failures, 0 ignored (currently 271)
- [ ] `cargo build --workspace` — **clean build**, no warnings
- [ ] `cargo clippy --workspace` — no new warnings introduced
- [ ] Any new feature has at least one corresponding test
- [ ] Test count in documentation matches actual count across all files

### Documentation

- [ ] All changed or new public APIs are documented (doc comments or `docs/*.md`)
- [ ] `README.md` accurately reflects current feature set
- [ ] `AGENTS.md` (root + per-crate) file/module counts are up to date
- [ ] `docs/roadmap.md` "Implemented" list includes any new features
- [ ] `docs/api-reference.md` covers any new HTTP/WebSocket endpoints
- [ ] `docs/cli-reference.md` covers any new CLI flags or subcommands
- [ ] `docs/configuration.md` covers any new TOML fields
- [ ] `docs/faq.md` is reviewed for stale answers
- [ ] `docs/threat-model.md` is updated if new attack surfaces are introduced

### Code Quality

- [ ] No `TODO`, `FIXME`, or `HACK` comments left unresolved
- [ ] No `unwrap()` or `expect()` in production code paths (tests excepted)
- [ ] All `log::` calls use appropriate levels (`info`, `warn`, `error`, `debug`)
- [ ] No hardcoded secrets, keys, or credentials in source

### Security

- [ ] Dependencies audited: `cargo audit` reports no known vulnerabilities
- [ ] New dependencies reviewed for license compatibility (MIT/Apache-2.0)
- [ ] Cryptographic code uses audited libraries only (no custom primitives)

### Build & Compatibility

- [ ] `cargo build --workspace --release` compiles without error
- [ ] Core crate builds without GStreamer (`cargo build -p steganographer-core`)
- [ ] `./run.sh` interactive menu launches successfully

---

## ✅ Implemented (v0.2.0 — unreleased)

### Security

- [x] **Payload encryption** — ChaCha20-Poly1305 AEAD (`encryption.rs`)
- [x] **Magic header + version** — `STEG` magic (4B) + version (1B) in payload
- [x] **Constant-time hash comparison** — `subtle` crate prevents timing attacks
- [x] **Key file loading** — `key_file = "path"` in TOML config for LSB keys
- [x] **Fixed hardcoded zero-key** — Audio CLI and dashboard now use random keys
- [x] **Secure keygen** — private key files have 0600 permissions
- [x] **Key derivation** — BLAKE3 `derive_key` from master secret (`kdf.rs`)
- [x] **Session key rotation** — per-session keys from master + counter
- [x] **Hash chain streaming auth** — Merkle tree for segment-level tamper detection (`hash_chain.rs`)

### Power

- [x] **Spread-spectrum steganography** — PN-sequence modulation (`spread_spectrum.rs`)
- [x] **DCT-domain embedding** — compression-resistant 8×8 DCT blocks (`dct_video.rs`)
- [x] **Reed-Solomon error correction** — GF(2^8) for payload recovery (`error_correction.rs`)
- [x] **Multi-frame signature spreading** — XOR n-of-n secret sharing (`multi_frame.rs`)
- [x] **Capacity reporting** — `steganographer info` CLI command
- [x] **Steganalysis** — chi-squared, sample-pair, RS analysis (`steganalysis.rs`)
- [x] **Combined analysis** — multi-detector summary with confidence
- [x] **Adaptive embedding** — content-aware pixel selection (`adaptive.rs`)
- [x] **Multi-frame video file support** — encode/verify multi-frame raw RGB files

### Flexibility

- [x] **Configurable hash algorithm** — BLAKE3, SHA-256, SHA-3 via config
- [x] **New CLI stego types** — `spread_spectrum_video`, `dct_video`
- [x] **New CLI flags** — `--encrypt`, `--decrypt`, `--ecc`, `--spread`, `--hash-algorithm`, `--signing-key`, `--embedding-key`, `--input-format`, `--dir`
- [x] **Info bar config** — `[video.stego.info_bar]` with toggleable features
- [x] **GStreamer pipeline integration** — spread_spectrum and dct as pipeline steps
- [x] **Hash algorithm in live pipelines** — cmd_video.rs and cmd_audio.rs
- [x] **Dashboard LiveConfig** — stego_type, hash_algorithm, encrypt, ecc fields
- [x] **New CLI commands** — `analyze` (chi-squared), `derive` (key derivation)
- [x] **Batch processing** — `--dir` flag for directory encoding
- [x] **PNG/WAV format I/O** — image + hound crates for file format support
- [x] **Container format I/O** — GStreamer decodebin/encodebin for MP4/MKV/WAV (`process_video_file`, `process_audio_file`)

### Platform & Distribution

- [x] **Docker image** — multi-stage build with GStreamer runtime
- [x] **cargo audit** — security advisory check in CI
- [x] **cargo deny** — license and vulnerability audit
- [x] **CI clippy** — lint check in CI workflow
- [x] **Shell completions** — bash/zsh/fish via clap_complete (build.rs)
- [x] **Man pages** — `steganographer.1` via clap_mangen (build.rs)
- [x] **Criterion benchmarks** — sign, LSB, spread-spectrum, DCT, audio
- [x] **Fuzz targets** — extraction robustness and payload parsing (`fuzz/fuzz_targets.rs`)

### Dashboard

- [x] **Mutex lock recovery** — `expect()` replaced with `.unwrap_or_else(|e| e.into_inner())`
- [x] **Dark/light theme toggle** — persisted in localStorage
- [x] **Mobile-responsive layout** — media queries for ≤768px viewport

---

## 🔜 Upcoming (Minor Improvements)

- [ ] **Frame diff viewer** — side-by-side original vs. watermarked with pixel diff (subagent in progress)
- [ ] **Historical metrics charts** — FPS, latency, verify rate over time (subagent in progress)
- [ ] **Multi-camera support** — device selector dropdown (subagent in progress)
- [ ] **MDCT audio embedding** — frequency-domain audio steganography for MP3/AAC resistance (subagent in progress)
- [ ] **Berlekamp-Massey decoder** — full multi-error RS correction (subagent in progress)

---

## 📋 Backlog (Future Features)

Larger items requiring design work or architecture changes.

### Core Improvements

- [ ] **Post-quantum signatures** — ML-DSA (FIPS 204) as Ed25519 alternative
- [ ] **Hybrid signing** — Ed25519 + ML-DSA via multi-frame spreading
- [ ] **Certificate chain support** — X.509 or WebPKI for identity binding

### Platform & Distribution

- [ ] **WASM build** — browser-based encode/verify via WebAssembly
- [ ] **`cargo install` support** — publish to crates.io (make GStreamer optional)
- [ ] **Homebrew formula** — `brew install steganographer`
- [ ] **Windows support** — Media Foundation sources/sinks
- [ ] **Native GStreamer plugin** — full `BaseTransform` for zero-copy pipelines

### Dashboard Enhancements

- [ ] **WebRTC streaming** — replace WebSocket frame-by-frame with WebRTC

### Documentation & Tooling

- [ ] **`cargo-release` workflow** — automated version bumps and CHANGELOG updates

---

Contributions welcome — see [docs/contributing.md](docs/contributing.md) for the workflow.
