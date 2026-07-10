# TODO

Scoped improvements and future plans.
See [docs/roadmap.md](docs/roadmap.md) for the full release timeline.

---

## ✅ Release Acceptance Criteria

**Every release** — including patch and minor releases — must satisfy all of the following before merge:

### Tests

- [ ] `cargo test --workspace` — **all tests pass**, 0 failures, 0 ignored (currently 187)
- [ ] `cargo build --workspace` — **clean build**, no warnings
- [ ] `cargo clippy --workspace` — no new warnings introduced
- [ ] Any new feature has at least one corresponding test
- [ ] Test count in documentation matches actual count across all files

### Documentation

- [ ] All changed or new public APIs are documented (doc comments or `docs/*.md`)
- [ ] `README.md` accurately reflects current feature set
- [ ] `AGENTS.md` (root + dashboard) file/module counts are up to date
- [ ] `docs/roadmap.md` "Implemented" list includes any new features
- [ ] `docs/api-reference.md` covers any new HTTP/WebSocket endpoints
- [ ] `docs/cli-reference.md` covers any new CLI flags or subcommands
- [ ] `docs/configuration.md` covers any new TOML fields
- [ ] `docs/faq.md` is reviewed for stale answers
- [ ] `docs/threat-model.md` is updated if new attack surfaces are introduced

### Code Quality

- [ ] No `TODO`, `FIXME`, or `HACK` comments left unresolved
- [ ] No `unwrap()` in production code paths (use `anyhow` or proper error handling)
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

## ✅ Implemented (Unreleased)

### Security

- [x] **Payload encryption** — ChaCha20-Poly1305 AEAD (`encryption.rs`)
- [x] **Magic header + version** — `STEG` magic (4B) + version (1B) in payload
- [x] **Constant-time hash comparison** — `subtle` crate prevents timing attacks
- [x] **Key file loading** — `key_file = "path"` in TOML config
- [x] **Fixed hardcoded zero-key** — Audio CLI and dashboard now use random keys
- [x] **Secure keygen** — private key files have 0600 permissions

### Power

- [x] **Spread-spectrum steganography** — PN-sequence modulation (`spread_spectrum.rs`)
- [x] **DCT-domain embedding** — compression-resistant 8×8 DCT blocks (`dct_video.rs`)
- [x] **Reed-Solomon error correction** — GF(2^8) for payload recovery (`error_correction.rs`)
- [x] **Multi-frame signature spreading** — XOR n-of-n secret sharing (`multi_frame.rs`)
- [x] **Capacity reporting** — `steganographer info` CLI command

### Flexibility

- [x] **Configurable hash algorithm** — BLAKE3, SHA-256, SHA-3 via config
- [x] **New CLI stego types** — `spread_spectrum_video`, `dct_video`
- [x] **New CLI flags** — `--embedding-key`, `info` subcommand

---

## 🔜 Upcoming (Minor Improvements)

- [ ] **Key file references in TOML** — `key_file = "path/to/key.pub"` for signing keys (LSB key_file already done)
- [ ] **YUV420 text overlay** — overlay support in YUV color space
- [ ] **Integrate encryption into encode/verify CLI** — `--encrypt` flag and key management
- [ ] **Integrate error correction into encode/verify CLI** — `--ecc` flag
- [ ] **Integrate multi-frame spreading into CLI** — `--spread N` flag

---

## 📋 Backlog (Future Features)

Larger items requiring design work or architecture changes.

### Core Improvements

- [ ] **DCT-domain audio** — MDCT embedding for audio compression resistance
- [ ] **Berlekamp-Massey decoder** — full multi-error RS correction (currently single-error)

### Robustness & Formats

- [ ] **Container format I/O** — read/write MP4, MKV, WAV via GStreamer decodebin/encodebin
- [ ] **Batch processing** — `steganographer encode --dir ./frames/ --output ./signed/`

### Cryptography

- [ ] **Post-quantum signatures** — ML-DSA (FIPS 204) as Ed25519 alternative
- [ ] **Merkle tree streaming auth** — hash chains for segment-level tamper detection
- [ ] **Certificate chain support** — X.509 or WebPKI for identity binding

### Platform & Distribution

- [ ] **WASM build** — browser-based encode/verify via WebAssembly
- [ ] **Docker image** — `docker run steganographer dashboard` for zero-install demo
- [ ] **Windows support** — Media Foundation sources/sinks
- [ ] **Native GStreamer plugin** — full `BaseTransform` for zero-copy pipelines

### Dashboard Enhancements

- [ ] **Dark/light theme toggle** — persist preference in `localStorage`
- [ ] **Mobile-responsive layout** — media queries for ≤768px viewport
- [ ] **Frame diff viewer** — side-by-side original vs. watermarked with pixel diff
- [ ] **Metrics dashboard** — historical charts of latency, frame rate, capacity
- [ ] **Multi-camera support** — select from available video devices
- [ ] **WebRTC streaming** — replace WebSocket frame-by-frame with WebRTC

### Documentation & Tooling

- [ ] **Man pages** — generate `steganographer.1` from Clap metadata
- [ ] **`cargo deny`** — license and vulnerability audit in CI
- [ ] **Release automation** — `cargo-release` workflow for version bumps

---

Contributions welcome — see [docs/contributing.md](docs/contributing.md) for the workflow.
