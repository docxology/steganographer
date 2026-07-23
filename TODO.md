# TODO

Scoped improvements and future plans.
See [docs/roadmap.md](docs/roadmap.md) for the full release timeline.

> **Status (2026-07-23, v0.5.0):** All Critical/Major/Medium/Minor audit
> findings resolved. Key lifecycle (revoke + verify-time check), cargo-release,
> live test-count badge, BM decoder infrastructure, live `--signing-key`, fuzz
> CI, C2PA decision — all shipped. Below is the remaining open work.

---

## 🔜 Upcoming

### BM Multi-Error Correction Convention Fix

**Status:** Infrastructure built, convention mismatch identified, 2 tests `#[ignore]`d.

The Berlekamp-Massey / Chien search / Forney pipeline is implemented in
`error_correction.rs` (lines 275–410). Single-error correction works reliably
via bounded brute-force. Multi-error correction via BM fails because the error
locator polynomial's roots don't map to the correct codeword positions for this
non-systematic evaluation-based RS code.

**Root cause:** The syndrome computation uses high-frequency DFT coefficients
(`S_p = sum_i r[i] * alpha^((k+p)*i)` for `p = 0..parity_count-1`). The BM
algorithm produces a Lambda polynomial, but Chien search evaluates it at either
`alpha^i` or `alpha^(-i)` — neither convention yields roots at the actual error
positions. The fundamental issue is that standard BM expects syndromes from a
systematic/cyclic code, not a non-systematic evaluation code. The correct
syndrome for this code structure may require computing residuals from Lagrange
interpolation rather than DFT coefficients.

**Scope:**
- Determine correct syndrome definition for evaluation-based RS codes
  (likely: interpolate from first k received values, compute residuals at
  positions k..n-1, use those as syndromes for BM)
- Fix `compute_syndromes()` to use the correct formula
- Verify Chien search convention matches the corrected syndromes
- Un-ignore `test_two_error_correction` and `test_two_errors_with_higher_parity`

**Files:** `steganographer-core/src/error_correction.rs`

**Impact:** Enables multi-error RS correction (currently only single-error works).
Low practical urgency — steganographic payloads are ~104 bytes, single-error
correction covers the realistic noise scenario.

---

### DCT Raw-Byte CLI Path

**Status:** Currently errors clearly (correct stopgap since v0.2.0).

The core `DctVideo` module (`dct_video.rs`) works with `SignaturePayload`
(structured 109-byte payload). The CLI's `dct_video` stego type uses a
length-prefixed raw-byte format that doesn't match. When a user runs
`steganographer encode --stego-type dct_video`, it returns an error instead
of silently falling back to LSB.

**Scope:**
- Option A (preferred): Adapt the CLI path to construct a `SignaturePayload`,
  pass it to `DctVideo::embed()`, and use `DctVideo::extract()` on verify.
  This requires the CLI to create a `Signer` + `SignaturePayload` before
  calling the DctVideo module, rather than passing raw bytes.
- Option B: Add a `embed_raw()` / `extract_raw()` API to `DctVideo` that
  handles length-prefixed bytes directly. More work but keeps CLI structure
  unchanged.

**Files:**
- `steganographer-cli/src/cmd_encode.rs` — `embed_raw_dct_video()` (currently errors)
- `steganographer-cli/src/cmd_verify.rs` — `extract_payload()` dct_video branch (currently errors)
- `steganographer-core/src/dct_video.rs` — possibly add raw-byte API (Option B)

**Impact:** Enables DCT-domain embedding (JPEG/compression-resistant) via CLI.
The core library already works and is tested — this is a CLI wiring task.

---

## 📋 Backlog

### Core Improvements

- [ ] **Post-quantum signatures** — ML-DSA (FIPS 204) as Ed25519 alternative.
  - **Scope:** Add `pq` feature to `steganographer-core`. Implement
    `MlDsaBackend` alongside `Ed25519Backend` implementing `SignerBackend`
    trait. Wire into CLI as `--backend mldsa`. Evaluate `pqcrypto-dilithium`
    crate or FFI to liboqs.
  - **Files:** `steganographer-core/src/signer_backend.rs`,
    `steganographer-core/Cargo.toml`, `steganographer-cli/src/main.rs`
  - **Dependency:** FIPS 204 finalization, Rust PQ crate maturity.
  - **Signature size:** ML-DSA-44 → 2420 bytes (vs Ed25519's 64 bytes) —
    requires multi-frame spreading or increased embedding capacity.

- [ ] **Hybrid signing** — Ed25519 + ML-DSA via multi-frame spreading.
  - **Scope:** Use `multi_frame.rs` XOR secret sharing to split a hybrid
    signature (Ed25519 || ML-DSA) across N frames. The verifier recovers
    both signatures, checks both. If either is valid, the content is
    authenticated (backward-compatible PQ migration).
  - **Files:** `steganographer-core/src/multi_frame.rs`,
    `steganographer-core/src/signer_backend.rs`
  - **Dependency:** Post-quantum signatures above.

- [ ] **Certificate chain support** — X.509 or WebPKI for identity binding.
  - **Scope:** Add `--cert <path>` flag to `encode` and `verify`. During
    verify, parse the X.509 certificate chain with `x509-parser` crate,
    validate the chain, extract the public key, and check it against the
    embedded signature. Store the certificate fingerprint in the payload.
  - **Files:** `steganographer-cli/src/cmd_verify.rs`,
    `steganographer-cli/src/main.rs`, `steganographer-core/Cargo.toml`
  - **Dependency:** Key lifecycle system (shipped in v0.4.0–v0.5.0).

### Platform & Distribution

- [ ] **WASM build** — browser-based encode/verify via WebAssembly.
  - **Scope:** Feature-gate GStreamer behind `gst` feature in
    `steganographer-core` and `steganographer-cli`. Build
    `steganographer-core` to `wasm32-unknown-unknown`. Expose encode/verify
    via `wasm-bindgen` JS bindings. The dashboard could then use in-browser
    steganography instead of WebSocket round-trips.
  - **Files:** `steganographer-core/Cargo.toml` (feature gating),
    `steganographer-core/src/lib.rs` (conditional exports),
    new `steganographer-wasm/` crate with bindings.
  - **Dependency:** GStreamer feature-gating (also needed for crates.io).

- [ ] **`cargo install` support** — publish to crates.io.
  - **Scope:** Feature-gate GStreamer behind `gst` feature (default off for
    `cargo install`, on for the dashboard/full CLI). Publish
    `steganographer-core` and `steganographer-cli` to crates.io. Users can
    `cargo install steganographer` for core encode/verify without GStreamer;
    `cargo install steganographer --features gst` for live pipelines.
  - **Files:** All `Cargo.toml` files, `steganographer-gst/Cargo.toml`
    (make optional).
  - **Dependency:** WASM build's feature-gating work (shared).

- [ ] **Homebrew formula** — `brew install steganographer`.
  - **Scope:** Create a Homebrew tap (`docxology/homebrew-steganographer`).
    Formula builds from source with GStreamer dependency. Support both
    `brew install steganographer` (core) and
    `brew install steganographer --with-gstreamer` (full).
  - **Dependency:** crates.io publish or tagged GitHub releases.

- [ ] **Windows CI** — add Windows matrix entry to CI.
  - **Scope:** Add `windows-latest` to the CI matrix in
    `.github/workflows/ci.yml`. Install GStreamer MSVC runtime and
    development headers. Handle any Windows-specific build issues (path
    separators, DLL loading, GStreamer plugin paths). Update
    `docs/platforms.md` to remove "No CI Coverage" caveat.
  - **Files:** `.github/workflows/ci.yml`, `docs/platforms.md`
  - **Risk:** GStreamer on Windows can be finicky; may need `PKG_CONFIG`
    workarounds or vcpkg.

- [ ] **Native GStreamer plugin** — full `BaseTransform` for zero-copy pipelines.
  - **Scope:** Implement `gst::BaseTransform` subclass in
    `steganographer-gst` that does in-place LSB embedding during the
    transform pass. Register as a real GStreamer element via
    `gst::Element.register()`. This eliminates the AppSink/AppSrc
    round-trip (copy buffer → embed → copy back) for a ~2x throughput
    improvement in live pipelines.
  - **Files:** `steganographer-gst/src/plugin.rs` (currently a skeleton),
    new `steganographer-gst/src/transform.rs`
  - **Dependency:** GStreamer Rust bindings `BaseTransform` support.

### Dashboard Enhancements

- [ ] **WebRTC streaming** — replace WebSocket frame-by-frame with WebRTC.
  - **Scope:** Use `webrtc-rs` crate on the server side and browser
    `RTCPeerConnection` on the client. Encode frames as VP8/Opus in RTP
    packets. Reduces latency from ~100ms (WebSocket + JPEG encode/decode)
    to ~20ms (WebRTC direct). Requires adding a WHIP/WHEP signaling
    endpoint to the Axum server.
  - **Files:** `steganographer-dashboard/src/lib.rs` (new `/whip` and
    `/whep` endpoints), `steganographer-dashboard/src/static/app.js`
    (WebRTC client), `steganographer-dashboard/Cargo.toml` (`webrtc-rs`)
  - **Dependency:** Significant refactor of dashboard streaming architecture.

### Research

- [ ] **Learned watermarking encoder** — neural network-based watermarking
  resistant to re-encoding/cropping/AI upscaling (VideoSeal-style).
  - **Scope:** Literature review of HiDDeN, StegaStamp, RivaGAN, VideoSeal.
    Prototype with PyTorch, evaluate against JPEG/PNG compression, H.264/265
    transcoding, and resize/crop attacks. If viable, implement as a new
    `steganographer-core/src/neural_stego.rs` module or as an ONNX runtime
    inference path.
  - **Dependency:** Requires ML model training infrastructure (GPU, dataset).
  - **Impact:** Would close the gap between the current LSB default
    ("maximizes capacity at the cost of robustness") and the marketing claim
    of surviving transcoding/AI upscaling.

---

Contributions welcome — see [docs/contributing.md](docs/contributing.md) for the workflow.
