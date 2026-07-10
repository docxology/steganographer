# TODO

Scoped improvements and future plans.
See [docs/roadmap.md](docs/roadmap.md) for the full release timeline.

---

## ✅ Release Acceptance Criteria

**Every release** — including patch and minor releases — must satisfy all of the following before merge:

### Tests

- [ ] `cargo test --workspace` — **all tests pass**, 0 failures, 0 ignored (currently 190)
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
- [x] **Info bar config** — `[video.stego.info_bar]` with toggleable features

---

## 🔜 Phase 1: Wire New Modules Into CLI + GStreamer + Dashboard (High Priority)

The encryption, error correction, multi-frame, spread-spectrum, DCT, and
hash algorithm modules exist in core but are NOT yet wired into the
encode/verify CLI paths, GStreamer live pipelines, or the dashboard.
They are implemented + tested but dormant. This phase makes them
end-to-end usable.

### 1A. CLI Integration

- [ ] **`--encrypt` flag on encode** — When set, encrypt the `SignaturePayload`
      with ChaCha20-Poly1305 before embedding. Requires `--encryption-key <hex>`
      or `--encryption-key-file <path>`. The encrypted payload is larger
      (payload + 16-byte tag), so the `info` capacity command and LSB
      minimum-size checks must account for this.
      - Files: `steganographer-cli/src/cmd_encode.rs`, `main.rs`
      - New struct: `EncodeOptions { encrypt: bool, encryption_key: Option<String>, ecc: bool, spread: u32 }`
      - Tests: round-trip encode → encrypt → embed → extract → decrypt → verify

- [ ] **`--decrypt` flag on verify** — Decrypt the extracted payload before
      signature verification. Requires the same `--encryption-key`.
      - Files: `steganographer-cli/src/cmd_verify.rs`

- [ ] **`--ecc` flag on encode** — Apply Reed-Solomon error correction to the
      payload (or encrypted payload) before embedding. Adds parity symbols,
      increasing embedded size. `--ecc-parity N` controls parity count (default: 4).
      - Files: `steganographer-cli/src/cmd_encode.rs`

- [ ] **`--ecc` flag on verify** — Run RS decode on extracted data before
      decryption/verification. Tolerates up to `N/2` corrupted symbols.
      - Files: `steganographer-cli/src/cmd_verify.rs`

- [ ] **`--spread N` flag on encode** — Use multi-frame spreading. Embeds
      N shards into N separate output files (or N consecutive frames in a
      raw video). Output naming: `output_001.rgb`, `output_002.rgb`, ...
      - Files: `steganographer-cli/src/cmd_encode.rs`

- [ ] **`--spread N` flag on verify** — Read N files, reconstruct the
      payload from shards, then verify.
      - Files: `steganographer-cli/src/cmd_verify.rs`

- [ ] **`--hash-algorithm` flag** — Override the config's hash algorithm
      for encode and verify. `--hash-algorithm sha256` or `sha3-256`.
      - Files: `cmd_encode.rs`, `cmd_verify.rs`, `main.rs`
      - Note: `Signer::with_hash_algorithm()` and
        `Verifier::with_hash_algorithm()` already exist in `crypto.rs`

- [ ] **`--signing-key` flag on encode** — Load a signing key from file
      instead of always generating a random one. `--signing-key keys/daf.key`.
      Enables deterministic, reproducible encoding for audit trails.
      - Files: `cmd_encode.rs`, `main.rs`

- [ ] **`--input-format` / `--output-format` flags** — Currently the encode
      command assumes raw RGB. Add format hints: `raw_rgb`, `raw_s16le`,
      `png`, `wav`. Uses the `image` crate (already a dep in dashboard)
      for PNG/JPEG decode, and raw byte parsing for WAV.
      - Files: `cmd_encode.rs`

### 1B. GStreamer Pipeline Integration

- [ ] **Spread-spectrum in live video pipeline** — `cmd_video.rs` currently
      only builds `LsbVideo` modules. Add `"spread_spectrum"` as a pipeline
      step in `build_video_stego_chain()`. Requires the LSB key from config
      for PN-seed derivation.
      - Files: `steganographer-cli/src/cmd_video.rs`
      - Config: `[video.stego] pipeline = ["spread_spectrum", "overlay"]`

- [ ] **DCT in live video pipeline** — Add `"dct"` as a pipeline step.
      - Files: `steganographer-cli/src/cmd_video.rs`

- [ ] **Hash algorithm in live pipelines** — `cmd_video.rs` and
      `cmd_audio.rs` use `Signer::generate()` which defaults to BLAKE3.
      Read `cfg.global.hash_algorithm` and pass it to
      `Signer::with_hash_algorithm()`.
      - Files: `cmd_video.rs`, `cmd_audio.rs`

- [ ] **Encryption in live pipelines** — When `payload.encrypt` is set in
      config, encrypt each `SignaturePayload` before embedding and decrypt
      on extraction. The GStreamer filter functions need an optional
      `EncryptionKey` parameter.
      - Files: `steganographer-gst/src/video_filter.rs`,
        `steganographer-gst/src/audio_filter.rs`,
        `steganographer-cli/src/cmd_video.rs`, `cmd_audio.rs`

- [ ] **Multi-frame spreading in live pipelines** — Buffer N frames, split
      the payload into shards, embed each shard into a different frame.
      Requires a frame buffer in the filter loop.
      - Files: `steganographer-gst/src/video_filter.rs`
      - Complexity: Medium — the pull-based loop already has `frame_index`,
        just need a shard buffer and deferred embedding

### 1C. Dashboard Integration

- [ ] **Spread-spectrum in dashboard encode/decode** — The WebSocket
      handlers use `LsbVideo::new(bits)`. Add a config option to switch
      between `lsb`, `spread_spectrum`, and `dct` stego types.
      - Files: `steganographer-dashboard/src/ws_handler.rs`
      - LiveConfig: add `stego_type: String` field

- [ ] **Hash algorithm selector in dashboard** — Dropdown to choose
      BLAKE3 / SHA-256 / SHA-3. Passed to the `Signer` on encode and
      `Verifier` on decode.
      - Files: `ws_handler.rs`, `lib.rs` (LiveConfig), `app.js`

- [ ] **Encryption toggle in dashboard** — Checkbox to enable payload
      encryption. Shows an encryption key input field.
      - Files: `ws_handler.rs`, `lib.rs`, `index.html`, `app.js`

- [ ] **Error correction toggle in dashboard** — Checkbox + parity count
      slider. Applies RS encode/decode to payloads.
      - Files: `ws_handler.rs`, `index.html`, `app.js`

---

## 🔜 Phase 2: Robustness & Real-World Format Support (Medium Priority)

### 2A. Container Format I/O

- [ ] **PNG encode/decode** — Use the `image` crate (already in
      `steganographer-dashboard` deps) to read/write PNG files instead of
      raw RGB. This makes `steganographer encode --input photo.png` work
      directly. PNG is lossless, so LSB survives perfectly.
      - Files: `steganographer-cli/Cargo.toml` (add `image` dep),
        `cmd_encode.rs`, `cmd_verify.rs`
      - Complexity: Low — `image::open()` → `to_rgb8()` → embed → `save()`

- [ ] **WAV encode/decode** — Read/write WAV headers for audio stego
      instead of raw S16LE. Use the `hound` crate.
      - Files: `steganographer-cli/Cargo.toml` (add `hound` dep),
        `cmd_encode.rs`, `cmd_verify.rs`
      - Complexity: Low — `hound::WavReader` / `WavWriter`

- [ ] **JPEG round-trip with DCT** — Encode with DCT stego, save as JPEG,
      re-read, extract. This is the killer test for DCT robustness. The
      `image` crate can write JPEG. Test at Q=75, Q=85, Q=95.
      - Files: `cmd_encode.rs`, `cmd_verify.rs`, integration tests
      - Complexity: Medium — need to verify DCT extraction survives
        JPEG quantization

- [ ] **GStreamer decodebin/encodebin** — For live pipeline I/O with
      container formats (MP4, MKV), use `decodebin` as the source and
      `encodebin` as the sink in the GStreamer pipeline strings.
      - Files: `cmd_video.rs`, `cmd_audio.rs`
      - Complexity: Medium — caps negotiation with AppSink/AppSrc

- [ ] **Multi-frame video file support** — Read a multi-frame raw video
      file (sequence of frames), embed a signature in each, write back.
      Currently `encode` handles a single frame.
      - Files: `cmd_encode.rs`
      - Complexity: Low — loop over frame-sized chunks

### 2B. Batch Processing

- [ ] **`--dir` flag for encode** — `steganographer encode --dir ./frames/
      --output ./signed/ --stego-type lsb_video`. Processes every file in
      the directory.
      - Files: `cmd_encode.rs`, `main.rs`

- [ ] **`--dir` flag for verify** — Verify all files in a directory, report
      pass/fail summary.
      - Files: `cmd_verify.rs`, `main.rs`

- [ ] **`--recursive` flag** — Recurse into subdirectories.

### 2C. Fuzzing & Hardening

- [ ] **`cargo fuzz` targets** — Fuzz the LSB extraction with random byte
      inputs to verify it never panics. Fuzz the crypto `from_bytes` with
      random 109-byte inputs.
      - Files: `steganographer-core/fuzz/` (new directory)
      - Complexity: Low — `cargo fuzz init` + 2 fuzz targets

- [ ] **Replace `expect()` with graceful error handling** — The dashboard
      has 12 `expect("lock poisoned")` calls. Replace with
      `lock().unwrap_or_else(|e| e.into_inner())` to recover from panics
      in other threads.
      - Files: `steganographer-dashboard/src/lib.rs`, `ws_handler.rs`

- [ ] **Capacity check before embed** — In the GStreamer filter loops,
      check `frame.data.len() >= payload_size * 8 / bits` before embedding.
      Currently it bails with an error; should skip the frame and log
      a warning instead, keeping the pipeline alive.
      - Files: `steganographer-gst/src/video_filter.rs`, `audio_filter.rs`

---

## 🔜 Phase 3: Advanced Cryptography (Medium-High Priority)

### 3A. Berlekamp-Massey Decoder

- [ ] **Full multi-error RS correction** — The current `error_correction.rs`
      uses brute-force single-error correction (iterate all 255 positions
      × 255 values). Implement the Berlekamp-Massey algorithm to find the
      error locator polynomial, then Chien search for positions, then
      Forney algorithm for values. This enables correction of up to
      `parity_count / 2` errors.
      - Files: `steganographer-core/src/error_correction.rs`
      - Complexity: High — GF(2^8) polynomial arithmetic, Euclidean
        algorithm for the key equation
      - Test: inject 2, 3, 4 errors and verify correction with 4, 6, 8
        parity symbols respectively

### 3B. Post-Quantum Signatures

- [ ] **ML-DSA (FIPS 204)** — Add a post-quantum signing backend using
      `dilithium` or `pqcrypto-dilithium`. Feature-gated behind `postquantum`.
      Payload size grows to ~2,440 bytes for ML-DSA-44, requiring much
      larger frames or multi-frame spreading.
      - Files: `steganographer-core/src/signer_backend.rs` (new backend),
        `Cargo.toml` (new optional dep)
      - Complexity: Medium — the `SignerBackend` trait already exists
      - Trade-off: Much larger signatures. DCT or spread-spectrum embedding
        is preferred since they have more capacity. Or use multi-frame
        spreading with `--spread 23` (2440/109 ≈ 23 frames).

- [ ] **Hybrid signing** — Sign with both Ed25519 (small, fast) and
      ML-DSA (post-quantum). Embed both signatures using multi-frame
      spreading: Ed25519 in frame 0, ML-DSA shards across frames 1–23.
      Provides classical + quantum resistance in one stream.
      - Files: `signer_backend.rs`, `multi_frame.rs`

### 3C. Streaming Authentication

- [ ] **Hash chain for segment-level auth** — Instead of per-frame
      signatures, create a Merkle tree over N-frame segments. Embed the
      Merkle root + a chain proof. Reduces per-frame overhead from 109
      bytes to ~32 bytes (root hash) + amortized proof.
      - Files: new `steganographer-core/src/hash_chain.rs`
      - Complexity: Medium — BLAKE3 is already available; need Merkle
        tree construction and inclusion proof generation/verification

- [ ] **Forward-secure MAC chain** — Each frame's signature covers the
      previous frame's hash, creating a tamper-evident chain. If any frame
      is modified, all subsequent frames fail verification.
      - Files: `crypto.rs` (add `sign_frame_chain()`)

### 3D. Key Derivation

- [ ] **HKDF from master secret** — Derive signing key, encryption key,
      and LSB embedding key from a single master secret using HKDF-SHA256.
      `steganographer derive --master-secret <hex> --output keys/`.
      Produces `signing.key`, `encryption.key`, `embedding.key`.
      - Files: new `steganographer-core/src/kdf.rs`
      - Complexity: Low — `hkdf` crate or manual HMAC-SHA256

- [ ] **Key rotation** — Derive per-session keys from a master key +
      session counter. Enables forward secrecy: compromising one session
      doesn't compromise others.
      - Files: `kdf.rs`

---

## 🔜 Phase 4: Detection Resistance & Steganalysis (Research)

### 4A. Statistical Steganalysis Defense

- [ ] **LSB histogram analysis** — Implement the chi-squared attack
      detector (Westfeld & Pfitzmann). If our LSB embedding creates a
      detectable histogram signature, we need to know. Add a
      `steganographer analyze --input file.rgb --type chi_squared` command.
      - Files: new `steganographer-core/src/steganalysis.rs`
      - Complexity: Medium — chi-squared test over color-pair histograms

- [ ] **Sample-pair analysis** — Implement the sample-pair attack
      (Fridrich et al.) that detects LSB embedding by analyzing pairs
      of pixel values.
      - Files: `steganalysis.rs`

- [ ] **RS steganalysis** — Implement the RS analysis (regular/singular
      groups) to estimate the embedding rate.
      - Files: `steganalysis.rs`

- [ ] **Adaptive embedding** — Use a content-adaptive embedding strategy
      (e.g., HUGO, WOW, S-UNIWARD) that embeds in regions with high
      texture/noise to minimize statistical detectability.
      - Files: new `steganographer-core/src/adaptive.rs`
      - Complexity: High — distortion metric + embedding simulation
      - Trait: implements `VideoStegoModule` with adaptive pixel selection

### 4B. Audio Steganalysis

- [ ] **Audio LSB detectability analysis** — Check if the keyed PRNG
      permutation in `lsb_audio.rs` is detectable via spectral analysis.
      - Files: `steganalysis.rs`

- [ ] **MDCT audio embedding** — Modified Discrete Cosine Transform for
      audio, analogous to DCT for video. Embeds in the frequency domain
      of audio, surviving MP3/AAC compression.
      - Files: new `steganographer-core/src/mdct_audio.rs`
      - Complexity: High — MDCT windowing, overlap-add reconstruction

---

## 🔜 Phase 5: Platform & Distribution (Lower Priority)

### 5A. Cross-Platform

- [ ] **Windows support** — Media Foundation video sources/sinks for
      GStreamer on Windows. Test `mfvideosrc` and `d3dvideosink`.
      - Files: `cmd_video.rs` (pipeline strings), `platforms.md`
      - Complexity: Medium — mostly config + CI matrix

- [ ] **WASM build** — `cargo build --target wasm32-unknown-unknown` for
      `steganographer-core`. Enables browser-based encode/verify without
      a server. The `image` crate already supports WASM.
      - Files: `Cargo.toml` (crate-type cdylib), new `steganographer-wasm/` crate
      - Complexity: Medium — need to handle `rand::rngs::OsRng` on WASM
        (use `getrandom` feature)

### 5B. Distribution

- [ ] **Docker image** — `Dockerfile` with GStreamer pre-installed.
      `docker run -p 8080:8080 steganographer dashboard` for zero-install.
      - Files: `Dockerfile`, `.dockerignore`
      - Complexity: Low — base on `gstreamer` official image

- [ ] **`cargo install` support** — Publish to crates.io so
      `cargo install steganographer-cli` works. Requires splitting the
      GStreamer dependency into an optional feature.
      - Files: `Cargo.toml` (make gstreamer optional), `steganographer-cli/Cargo.toml`
      - Complexity: Low but breaking — users who want live pipelines need
        `cargo install steganographer-cli --features gstreamer`

- [ ] **Homebrew formula** — `brew install steganographer` for macOS.
      Requires a pre-built binary release.
      - Files: `Formula/steganographer.rb`
      - Complexity: Low — template from any Rust Homebrew formula

### 5C. Native GStreamer Plugin

- [ ] **`BaseTransform` implementation** — Convert the AppSink/AppSrc
      pattern to a native GStreamer `BaseTransform` element for zero-copy
      processing. This eliminates the buffer-copy overhead and allows
      the steganographer to be used as a drop-in GStreamer element:
      `gst-launch-1.0 videotestsrc ! stegostamp ! autovideosink`.
      - Files: `steganographer-gst/src/plugin.rs` (currently a skeleton)
      - Complexity: High — GStreamer `BaseTransform` trait, caps
        negotiation, allocation, registration via `gst_plugin_define!`

---

## 🔜 Phase 6: Dashboard UX Enhancements (Lower Priority)

- [ ] **Stego type selector** — Dropdown to switch between LSB,
      spread-spectrum, and DCT embedding in the live dashboard.
      - Files: `ws_handler.rs`, `index.html`, `app.js`

- [ ] **Frame diff viewer** — Side-by-side original vs. watermarked
      with pixel-diff heatmap overlay. Toggle to see exactly which pixels
      were modified.
      - Files: `app.js` (canvas diff rendering)
      - Complexity: Medium — need to store original + watermarked frames

- [ ] **Historical metrics charts** — Latency, FPS, capacity, verify-rate
      over time. Use Chart.js or a lightweight SVG charting library.
      - Files: `app.js`, `index.html`
      - Complexity: Medium — need a time-series buffer in `StegoMetrics`

- [ ] **Dark/light theme toggle** — Persist in `localStorage`.
      - Files: `style.css`, `app.js`

- [ ] **Mobile-responsive layout** — Media queries for ≤768px.
      - Files: `style.css`

- [ ] **Multi-camera support** — `enumerateDevices()` dropdown to select
      from available video devices.
      - Files: `app.js`

- [ ] **WebRTC streaming** — Replace WebSocket frame-by-frame with WebRTC
      for lower latency. The current approach serializes JPEG frames over
      WebSocket; WebRTC would use H.264/VP8 with real-time encoding.
      - Files: `app.js`, `ws_handler.rs` (replace WS with WebRTC signaling)
      - Complexity: High — WebRTC signaling server, STUN/TURN

---

## 🔜 Phase 7: Documentation & Tooling (Ongoing)

- [ ] **`cargo audit` in CI** — Add a `cargo audit` step to the CI workflow.
      - Files: `.github/workflows/ci.yml`

- [ ] **`cargo deny`** — License and vulnerability audit. `deny.toml` config.
      - Files: `deny.toml`, `.github/workflows/ci.yml`

- [ ] **Man pages** — Generate `steganographer.1` from Clap metadata using
      `clap_mangen`.
      - Files: `steganographer-cli/build.rs`

- [ ] **Shell completions** — Generate bash/zsh/fish completions using
      `clap_complete`.
      - Files: `steganographer-cli/build.rs`

- [ ] **`cargo-release` workflow** — Automated version bumps and CHANGELOG
      updates.
      - Files: `release.toml`

- [ ] **Benchmark suite** — `cargo bench` with Criterion for measuring
      embedding/extracting throughput (MB/s), signing latency (µs), and
      DCT transform time. Track regressions in CI.
      - Files: `steganographer-core/benches/` (new directory)
      - Complexity: Low — Criterion is straightforward to set up

---

## 📋 Backlog (Future Research)

### LLM Text Steganography (inspired by ST3GG)

- [ ] **Text-channel steganography** — Embed data in LLM-generated text by
      manipulating token selection. This is a fundamentally different domain
      (text vs. media) but could be a future module. Approach: use a
      deterministic PRNG to select among top-K tokens at each generation step,
      encoding bits in the token choice. Requires an LLM inference backend.
      - Not part of the Rust workspace — would be a separate tool or
        Python module that interfaces with the core crypto primitives.
      - The `SignaturePayload` and `Signer` are media-agnostic and could
        be reused directly.

### Neural Watermarking

- [ ] **Video Seal integration** — Meta's neural-network-based robust
      watermarking. Embeds an imperceptible watermark that survives
      re-encoding, cropping, and compression. Would require PyTorch/ONNX
      inference, likely as a separate Python service that the Rust core
      calls via FFI or HTTP.
      - Complexity: Very High — model weights, training pipeline,
        inference optimization

### Hardware Acceleration

- [ ] **GPU-accelerated hashing** — CUDA BLAKE3 for 10×+ throughput on
      high-resolution video. The `blake3` crate has a `rayon` feature but
      not GPU.
- [ ] **GPU-accelerated DCT** — CUDA DCT for real-time 4K processing.

---

Contributions welcome — see [docs/contributing.md](docs/contributing.md) for the workflow.
