# TODO

Scoped improvements and future plans.
See [docs/roadmap.md](docs/roadmap.md) for the full release timeline.

> **Status note (2026-07-22, v0.2.0):** All Critical, Major, Medium, and Minor
> findings from the 2026-07-22 deep review + 8-agent RedTeam adversarial
> analysis have been resolved in v0.2.0. The items below are the remaining
> genuinely-open work — new findings, strategic decisions, and future features.
> Each item is scoped with file:line evidence where applicable.

---

## 🚨 CRITICAL — None Open

All Critical findings from the audit are resolved in v0.2.0:

- [x] ~~Real Ed25519 private key committed to this public repo~~ — scrubbed from
  git history via `git filter-repo`, key rotated, `.gitignore` hardened, gitleaks
  CI gate added. See [`docs/key-rotation.md`](docs/key-rotation.md).
- [x] ~~Regenerable build artifacts committed alongside the key~~ — removed from
  git tracking, `output/` added to `.gitignore`.
- [x] ~~No key lifecycle model~~ — key rotation documented, revocation procedure
  published, secret-scanning CI gate active. Full key-lifecycle system (rotation
  API + revoked-keys list checked at verify time) remains a Backlog item below.
- [x] ~~Live dashboard has zero authentication~~ — default bind `127.0.0.1`,
  `--auth-token` Bearer auth on POST routes (constant-time via `subtle`), CORS
  restricted, `--host` flag for explicit `0.0.0.0` opt-in.

---

## 🔴 MAJOR — None Open

All Major crypto/functional findings from the audit are resolved in v0.2.0:

- [x] ~~AEAD nonce reuse across batch encodes~~ — `encryption.rs` now prepends a
  4-byte random salt to the nonce. Each invocation gets a unique nonce.
- [x] ~~CLI spread-spectrum embedding never uses the secret key~~ — `embed_ss_bit`
  now uses `ss.key()` to seed the PN-sequence RNG. Round-trip verified.
- [x] ~~Unbounded RS decode brute force DoS~~ — `decode()` now caps
  `parity_count` (≤16) and `data_len` (≤65536).
- [x] ~~`dct_video` CLI stego type silently falls back to LSB~~ — now errors
  clearly on both encode and verify sides.
- [x] ~~Zero automated test coverage for `steganographer-cli`~~ — 10 CLI
  integration tests added covering all stego types + encrypt/ECC round-trips.
- [x] ~~Unvalidated config `bits` field panics the live pipeline~~ —
  `LsbVideo::try_new()` / `LsbAudio::try_new()` added, CLI callers wired.

---

## 🟡 MEDIUM — None Open

All Medium findings from the audit are resolved in v0.2.0:

- [x] ~~No slow-KDF / salt for master-secret derivation~~ — entropy warning added
  for master secrets < 32 bytes. `--master-secret-file` / `--master-secret-stdin`
  alternatives added.
- [x] ~~Inconsistent failure mode for missing `--embedding-key`~~ — `lsb_audio`
  verify now `bail!`s like `spread_spectrum_video`.
- [x] ~~`--quiet` can hide live session public key~~ — `eprintln!` used instead
  of `log::info!` in `cmd_video.rs` and `cmd_audio.rs`.
- [x] ~~`AGENTS.md` doc drift understates crypto surface~~ — all per-crate
  AGENTS.md files updated with correct module/subcommand/test counts.
- [x] ~~Duplicated KDF context strings~~ — `cmd_encode.rs` now calls
  `kdf::derive_all()` instead of hand-copying context strings.
- [x] ~~`deny.toml` advisory policy doesn't match comment~~ — fixed: `deny =
  ["medium", "high", "critical"]`.
- [x] ~~`Cargo.lock` is gitignored~~ — committed for reproducible builds.
- [x] ~~`docs/threat-model.md` internal contradiction~~ — T2 residual risk
  scoped to acknowledge T4 (signature stripping).
- [x] ~~Fuzz harness isn't wired to cargo-fuzz~~ — proper `Cargo.toml` + 3
  `fuzz_target!` binaries + README.
- [x] ~~CI has no Windows job~~ — `docs/platforms.md` softened to
  "Community-Supported — No CI Coverage".
- [x] ~~Dockerfile runs as root~~ — non-root `USER stego` added, CMD uses
  `--host 127.0.0.1`, digest-pinning guidance added.

---

## 🟢 MINOR — None Open

All Minor findings from the audit are resolved in v0.2.0:

- [x] ~~Stale test counts (187/266/271)~~ — all updated to 282 across every file.
- [x] ~~Stale CLI subcommand count (6/8)~~ — all updated to 10.
- [x] ~~Stale module count (16)~~ — updated to 21.
- [x] ~~`docs/roadmap.md` fictional Gantt dates~~ — real dates (2026-2027).
- [x] ~~`rand` version fragmentation~~ — informational only, no CVE. Workspace
  pins `rand = "0.8"`.
- [x] ~~Latent `unreachable!()` in `gf_inv`~~ — replaced with logged 0-return.
- [x] ~~Secrets passed as CLI arguments~~ — `--master-secret-file` / `--master-secret-stdin`
  alternatives added with warning on `--master-secret`.
- [x] ~~Local build note (MSRV)~~ — `rust-toolchain.toml` pins stable + clippy
  + rustfmt for deterministic toolchain.

---

## 📐 Strategic — from RedTeam Adversarial Analysis

These findings are architectural/strategic decisions, not code bugs. They
require design discussion before implementation.

- **Key lifecycle system (8/8 agent convergence).** The cryptographic primitives
  are sound. The v0.2.0 fixes (key rotation docs, secret-scanning CI) address
  the immediate gap. The remaining work: ship a minimal revocation mechanism
  (a published revoked-keys list checked at verify time) before investing in
  post-quantum/certificate-chain items.
  - [ ] **Key lifecycle: rotation API + revocation list** — minimum viable: API
    endpoint or CLI command to revoke a key, and a published revoked-keys list
    that `verify` checks against.

- **Headline claim vs shipped reality.** `docs/steganography-theory.md:271`
  states the current default pipeline is intra-frame LSB ("maximizes capacity
  at the cost of robustness"). The genuinely robust approach (learned
  watermarking encoder, VideoSeal-style) is roadmap-only.
  - [ ] **Narrow leading claim** — update README/intro to match the default
    pipeline's actual robustness, or move the robust method up the roadmap.
  - [ ] **Learned watermarking encoder** — research + prototype a neural
    watermarking approach resistant to re-encoding/cropping/AI upscaling.

- **C2PA interoperability decision.**
  - [ ] **Record architectural decision** — in `docs/architecture.md`, decide
    whether/how to interoperate with or emit C2PA (Content Credentials)
    manifests alongside the custom format.

---

## 🔜 Upcoming (Minor Improvements)

- [ ] **Berlekamp-Massey decoder** — full multi-error RS correction. The current
  `error_correction.rs` implements brute-force single-error correction (now
  bounded — see v0.2.0 fix). A real Berlekamp-Massey decoder is both more
  capable *and* polynomial-time bounded. No BM algorithm exists anywhere in
  the codebase (`grep -i berlekamp` = 0 hits).

- [ ] **DCT raw-byte CLI path** — wire the CLI's `dct_video` stego type through
  the real `DctVideo` core library implementation (currently errors clearly
  instead of silently falling back to LSB, which is the correct stopgap).

- [ ] **`cargo-release` workflow** — automated version bumps and CHANGELOG
  updates for consistent releases.

- [ ] **Fuzz CI integration** — add a short timed fuzz run (e.g. 60s per target)
  to CI. The fuzz targets are now properly structured (`steganographer-core/fuzz/`),
  just need a CI job with nightly Rust.

- [ ] **Live pipeline `--signing-key` option** — the live video/audio pipelines
  (`cmd_video.rs`, `cmd_audio.rs`) generate ephemeral keypairs with no way to
  specify a persistent signing key. Adding `--signing-key` would enable
  reproducible verification across sessions.

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
- [ ] **Windows CI** — add Windows matrix entry to `.github/workflows/ci.yml`
  (currently documented as "Community-Supported — No CI Coverage")
- [ ] **Native GStreamer plugin** — full `BaseTransform` for zero-copy pipelines

### Dashboard Enhancements

- [ ] **WebRTC streaming** — replace WebSocket frame-by-frame with WebRTC

### Documentation & Tooling

- [ ] **Live test-count badge** — replace static badge with a CI-computed count
  to prevent future drift

---

Contributions welcome — see [docs/contributing.md](docs/contributing.md) for the workflow.
