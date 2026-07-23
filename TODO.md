# TODO

Scoped improvements and future plans.
See [docs/roadmap.md](docs/roadmap.md) for the full release timeline.

> **Status note (2026-07-23, v0.3.0):** All Critical, Major, Medium, and Minor
> findings from the 2026-07-22 deep review + 8-agent RedTeam adversarial analysis
> have been resolved. The v0.3.0 release added Berlekamp-Massey decoder
> infrastructure, live pipeline `--signing-key`, nightly fuzz CI, and recorded the
> C2PA interoperability decision. The items below are genuinely-open work.

---

## 🚨 CRITICAL — None Open

All resolved in v0.2.0 (see [CHANGELOG.md](CHANGELOG.md) for details).

---

## 🔴 MAJOR — None Open

All resolved in v0.2.0 (see [CHANGELOG.md](CHANGELOG.md) for details).

---

## 🟡 MEDIUM — None Open

All resolved in v0.2.0 (see [CHANGELOG.md](CHANGELOG.md) for details).

---

## 🟢 MINOR — None Open

All resolved in v0.2.0–v0.3.0 (see [CHANGELOG.md](CHANGELOG.md) for details).

---

## 📐 Strategic — from RedTeam Adversarial Analysis

These are architectural/strategic decisions, not code bugs.

- [ ] **Key lifecycle: rotation API + revocation list** — minimum viable: CLI
  command to revoke a key, and a published revoked-keys list that `verify` checks
  against. The v0.2.0 fixes (key rotation docs, secret-scanning CI) address the
  immediate gap; this is the full system.
  - **Scope**: Add `steganographer revoke --key <hex>` command that appends to a
    `revoked-keys.json` file. Modify `verify` to check the signer's public key
    against this list and warn/fail if revoked. Publish the list alongside signed
    media for third-party verification.
  - **Files**: `steganographer-cli/src/cmd_encode.rs` (new `revoke` subcommand),
    `steganographer-core/src/crypto.rs` (revocation check in `Verifier`),
    `steganographer-cli/src/main.rs` (new `Commands::Revoke` variant).

- [ ] **Learned watermarking encoder** — research + prototype a neural watermarking
  approach resistant to re-encoding/cropping/AI upscaling (VideoSeal-style).
  This is a major research effort, not a code fix.
  - **Scope**: Literature review of HiDDeN, StegaStamp, RivaGAN, VideoSeal.
    Prototype with PyTorch, evaluate against JPEG/PNG compression, H.264/265
    transcoding, and resize/crop attacks. If viable, implement as a new
    `steganographer-core/src/neural_stego.rs` module.
  - **Dependency**: Requires ML model training infrastructure (GPU, dataset).

---

## 🔜 Upcoming (Scoped Improvements)

- [ ] **Berlekamp-Massey multi-error correction** — the BM/Chien/Forney
  infrastructure is built (`error_correction.rs` lines 275–410). Single-error
  correction works via brute-force fallback. Multi-error correction via BM
  needs a convention fix: the error locator polynomial's roots must correctly
  map to codeword positions for this non-systematic evaluation-based RS code.
  Two tests are `#[ignore]`d with explanation.
  - **Scope**: Debug the BM syndrome/Chien/Forney convention mismatch. The
    syndrome computation uses high-frequency DFT coefficients
    (`S_p = sum_i r[i] * alpha^((k+p)*i)` for `p = 0..parity_count-1`). The
    error locator should have roots at `alpha^(-i)` for error at position `i`,
    but the exact mapping between BM output and Chien search evaluation points
    needs verification against a known-error test case.
  - **Files**: `steganographer-core/src/error_correction.rs` (fix convention in
    `chien_search()` and `forney()`, un-ignore 2 tests).

- [ ] **DCT raw-byte CLI path** — wire the CLI's `dct_video` stego type through
  the real `DctVideo` core library implementation. Currently errors clearly
  instead of silently falling back to LSB (correct stopgap in v0.2.0).
  - **Scope**: The core `DctVideo` works with `SignaturePayload` (structured),
    but the CLI raw-byte path uses a length-prefixed format. Need to either:
    (a) adapt the CLI path to use `SignaturePayload` directly, or
    (b) add a raw-byte embed/extract API to `DctVideo`.
  - **Files**: `steganographer-cli/src/cmd_encode.rs` (`embed_raw_dct_video`),
    `steganographer-cli/src/cmd_verify.rs` (`extract_payload` dct_video branch),
    `steganographer-core/src/dct_video.rs` (possibly add raw-byte API).

- [ ] **`cargo-release` workflow** — automated version bumps and CHANGELOG updates.
  - **Scope**: Add `release.toml` config, `cargo-release` as dev-dependency,
    automate: version bump, CHANGELOG section move, tag, push.
  - **Files**: New `release.toml`, `Cargo.toml` (dev-dependency).

- [ ] **Live test-count badge** — replace static shields.io badge with a
  CI-computed count to prevent future drift.
  - **Scope**: Add a CI step that counts `#[test]` functions and updates the
    README badge, or use a dynamic badge endpoint.
  - **Files**: `.github/workflows/ci.yml`, `README.md`.

---

## 📋 Backlog (Future Features)

Larger items requiring design work or architecture changes.

### Core Improvements

- [ ] **Post-quantum signatures** — ML-DSA (FIPS 204) as Ed25519 alternative.
  - **Scope**: Add `pq` feature, implement `MlDsaBackend` alongside
    `Ed25519Backend`. Research `pqcrypto-dilithium` crate or bind to liboqs.
  - **Dependency**: FIPS 204 finalization, Rust PQ crate maturity.

- [ ] **Hybrid signing** — Ed25519 + ML-DSA via multi-frame spreading.
  - **Scope**: Use `multi_frame.rs` to split a hybrid signature across frames.
  - **Dependency**: Post-quantum signatures above.

- [ ] **Certificate chain support** — X.509 or WebPKI for identity binding.
  - **Scope**: Add `--cert <path>` flag, verify chain during `steganographer
    verify`. Use `x509-parser` crate.
  - **Dependency**: Key lifecycle system (revocation list) above.

### Platform & Distribution

- [ ] **WASM build** — browser-based encode/verify via WebAssembly.
  - **Scope**: Make GStreamer optional, build `steganographer-core` to wasm32,
    expose encode/verify via JS bindings.
  - **Dependency**: GStreamer feature-gating.

- [ ] **`cargo install` support** — publish to crates.io (make GStreamer optional).
  - **Scope**: Feature-gate GStreamer behind `gst` feature. Publish
    `steganographer-core` and `steganographer-cli` to crates.io.

- [ ] **Homebrew formula** — `brew install steganographer`.
  - **Scope**: Homebrew tap, formula that builds from source with GStreamer.

- [ ] **Windows CI** — add Windows matrix entry to CI.
  - **Scope**: Add `windows-latest` to CI matrix, install GStreamer MSVC,
    handle any Windows-specific build issues.

- [ ] **Native GStreamer plugin** — full `BaseTransform` for zero-copy pipelines.
  - **Scope**: Implement `gst::BaseTransform` in `steganographer-gst`,
    register as a real GStreamer element (not just AppSink/AppSrc wrapper).

### Dashboard Enhancements

- [ ] **WebRTC streaming** — replace WebSocket frame-by-frame with WebRTC.
  - **Scope**: Use `wgpu` or `webrtc-rs` for browser-to-server streaming,
    reducing latency from ~100ms (WebSocket) to ~20ms (WebRTC).

---

Contributions welcome — see [docs/contributing.md](docs/contributing.md) for the workflow.
