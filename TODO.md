# TODO

Scoped improvements and future plans.
See [docs/roadmap.md](docs/roadmap.md) for the full release timeline.

> **Status (2026-07-28, v0.6.0):** All Critical/Major/Medium/Minor audit
> findings resolved. Key lifecycle (revoke + verify-time check), cargo-release,
> live test-count badge, bounded Berlekamp-Welch ECC, live `--signing-key`, fuzz
> CI, C2PA decision, the v0.6.1 correctness baseline, and the first opt-in
> generic packet/LSB vertical slice are implemented. Below is the remaining
> open work.

---

## 🧭 Steganography Platform Expansion

The generic-payload, carrier/placement, safe-format, forensic, OOXML/PDF,
CLI/JSON, WASM, validation, and migration program is scoped in the composable
[Steganography Platform Expansion Plan](docs/plans/steganography-platform/README.md).

Execution continues from the completed correctness baseline (`COR-001` through
`COR-008`) and packet foundation (`PKT-001`, `PKT-002`, `PKT-003`, `PKT-006`,
and the first sequential spatial-LSB slice), following the issue-sized order in
the
[Delivery and Migration Plan](docs/plans/steganography-platform/06-delivery-and-migration.md).
Detailed work-package checklists live in those plans and are intentionally not
duplicated here.

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
