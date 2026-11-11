# TODO

Historical task notes and future plans. Dated entries below are not current
release qualification or API documentation; later correctness cutovers supersede
their measurements and conclusions. Current behavior lives in the user/API guides,
observed test totals in root `AGENTS.md`, and release history in `CHANGELOG.md`.
The proposed 0.9.0 work does not imply publication or Linux/Windows/CI qualification.

---

## 🧭 Scoped Improvements (v0.8.0 Release Target) — SUPERSEDED: all items below completed; see CHANGELOG "Unreleased" and the Long-Term Backlog for current work (marked 2026-08-31)

### 🟢 Minor Improvements (Ergonomics, Polish, Docs)
- [x] **CLI help text & diagnostics polish** — Standardize subcommand documentation, help descriptions, and ensure clean error reporting across all subcommands.
- [x] **Error ergonomics** — Enhance `CarrierError`, `PacketError`, `TransformError` to provide clear context (exact carrier byte/unit mismatch and actionable remedy).
- [x] **Documentation sync** — Update `AGENTS.md` across crates and API documentation with latest carriers, forensic detectors, and crypto features.

### 🟡 Medium Improvements (Carriers, Placement & Forensics)
- [x] **Placement inverse permutation & batch schedules** — Add `inverse_permute()` and batch slot generators to `KeyedPermutation` in `steganographer-core::placement`.
- [x] **Extended carrier descriptors** — Support additional carrier domains (planar/packed layouts, multi-channel audio descriptors) in `steganographer-core::carrier`.
- [x] **Forensic scan offset & multi-match reporting** — Enhance `steganographer-core::forensics` with `detect_embedded_magics_detailed()` reporting all byte offsets and match types across inspected media.

### 🔴 Major Improvements (Post-Quantum, WASM & Multi-Frame Parallelism)
- [x] **Post-quantum & Hybrid signing** — Implement `MlDsaBackend` (ML-DSA / FIPS 204 compatible post-quantum signature backend) and `HybridBackend` (Ed25519 + ML-DSA dual signature authentication) implementing `SignerBackend`.
- [x] **Generic multi-frame packet sharding** — Expand `steganographer-core::multi_frame` to support XOR secret sharing over arbitrary-length generic packet byte buffers (`split_payload_bytes` / `reconstruct_payload_bytes`).
- [x] **WASM carrier inspection target** — Build a zero-I/O `wasm_inspector` module providing browser-safe packet extraction, forensic analysis, and entropy calculations.

---

## 📋 Long-Term Backlog

### Platform & Distribution

> Owner-intent items: each carries an acceptance line so a future agent can execute
> or re-scope without guessing intent. Sequencing/priority calls need the owner.

- [x] **Native GStreamer plugin** — full `BaseTransform` for zero-copy pipelines.
  Status: **complete (2026-09-02 round; all three acceptance points verified on
  GStreamer 1.28.6)**. (1) Keyed placement: `stegovideo` computes the schedule
  inside the element — non-empty `key-hex` routes embedding through core
  `KeyedSpatialLsb` (key-driven slot selection + keyed recognition tag);
  unit-tested that equal buffers under different keys embed to different slot
  sets and that keyed output round-trips through the core keyed extractor.
  Interpretation note updated in the 2026-09-04 comprehensive pass: the
  literal acceptance test is now satisfied — placement is frame-scoped via
  `kdf::derive_frame_embedding_key` (frame 0 keeps the raw key, frame N
  mixes its index in), so the unit test verifies that equal buffers at
  different frame indices embed to different slot sets AND that every frame
  decodes through the same derivation with its index. No core wire-format
  change was needed (frame-scoped key derivation is element-local; frame 0
  stays CLI-decodable with the raw key). (2) `stegoaudio`: new in-place
  `BaseTransform` over
  interleaved S16LE PCM (`AudioSpatialLsb` / `KeyedAudioSpatialLsb`);
  verified by `gst-launch-1.0 audiotestsrc ! … ! stegoaudio packet-hex=…
  bits-per-unit=2 ! filesink` followed by
  `decode --stego-type lsb_audio --input-format raw_s16le --bits 2`
  recovering the exact payload (buffer-scoped decode check in
  `tests/gst_roundtrip.rs`). (3) cdylib packaging: `crate-type =
  ["cdylib", "rlib"]` + `gstreamer::plugin_define!` named `steganographer_gst`
  (must equal the dylib file stem — the loader derives
  `gst_plugin_<file-stem>_get_desc` from it); `gst-inspect-1.0 stegovideo`
  and `gst-inspect-1.0 stegoaudio` both list properties from the built dylib.
  Elements carry metadata + any-caps pad templates (missing templates made
  the registry refuse the factories). Also fixed in the same pass:
  `clear-payload` was a no-op and gained real clearing behavior.
- [x] **WebRTC transport and optional H.264 preview** — historical implementation
  work introduced real peer signaling and a shared sign/embed/verify pipeline.
  Current artifact traffic is JSON/base64, not binary JPEG: `jpeg_b64` is the
  historical image field name; the browser sends PNG. Binary data-channel chunks
  have a 20-byte big-endian STGO/id/index/count header and total size ≤16 KiB.
  Serialized UTF-8 JSON/base64 must fit 4 MiB; the client checks before sending
  any chunks and reports actual/maximum bytes with smaller-resolution/WebSocket
  guidance. WebSocket accepts raw binary images and has separate limits.
  Only auto mode falls back without persisting the fallback as user preference;
  pinned WebRTC fails visibly. H.264 RTP is preview, not signed evidence.
  Physical-camera soak and NAT deployment remain separate qualification.
- [ ] **Learned watermarking encoder (framework landed; CRF-28 gate open)** — neural network-based watermarking resistant to re-encoding/cropping.
  Status: **framework complete (2026-09-07)**: opt-in `learned` cargo
  feature (ndarray only, no new mandatory deps), 64-bit payload, trained
  MLP decoder over keyed DCT-chip spread-spectrum, committed reproducible
  weights, majority-vote baseline, block-aligned shift robustness.
  Measured: clean/gauss σ4/sim-CRF28-quant/block-aligned-shift BER 0.0%;
  PSNR 42.8 dB @640; embed+extract ≤ ~21 ms @640 (release). **Open gate:**
  real libx264 CRF-28 re-encode measures BER 48.4% (simulator is
  necessary-but-not-sufficient: RGB green-channel DCT grid vs libx264
  luma/chroma integer transforms + limited-range YUV clamp). Closing the
  <5% BER acceptance needs luma-domain embedding or codec-in-the-loop
  training plus the full training run — **owner intent still needed**:
  training-data licensing and model-size budget. Diagnosis + measured
  table: `docs/algorithms.md` ("Learned watermarking").

---

## 🔧 Agent-Ergonomics Pass (2026-08-31)

---

Findings from the 2026-08-31 cold-start documentation audit (agent-erg fleet). All Minor and Medium items were fixed in the same pass; Majors are deferred with reasons.

### 🟢 Minor
- [x] **Stale command inventories** — removed duplicated pins; shared `src/cli.rs` is authoritative.
- [x] **docs/AGENTS.md contents table stale** — omitted `ots-integration.md`, miscounted files. Refreshed with as-of date + verification command.
- [x] **Stale documentation test totals** — defer to root `AGENTS.md`.
- [x] **TODO.md completed section framed as active** — superseded-marked (this edit).

### 🟡 Medium
- [x] **Test-count fact-class had no canonical home** — duplicated (and disagreeing) across README, AGENTS.md, docs/README.md, docs/contributing.md, docs/getting-started.md. Root `AGENTS.md` Tests line declared canonical; README/docs now link or defer to it.
- [x] **Missing command reference sections** — `revoke` and `ots` documented; shared `src/cli.rs` is the schema.

### 🔴 Major (deferred → completed in Round 2, 2026-08-31)
- [x] **Automate test-count provenance** — `scripts/status.sh --check` compares summed successful Cargo results with root `AGENTS.md`; integration owns execution.
- [x] **README has no status surface beyond a badge** — `./scripts/status.sh` prints version, subcommand count, docs counts, git state, and test count, each with its source named. Linked from README "Project Status" and AGENTS.md.

---

## 🔁 Round 2 — Agent-Ergonomics Continuation (2026-08-31)

- [x] **Automate test-count provenance** (Major, from Round 1) — `scripts/status.sh --check`.
- [x] **Executable status command** (Major, from Round 1) — `./scripts/status.sh`.
- [x] **Long-Term Backlog re-scoped** — acceptance lines added to all three items; owner-intent flags noted.

---

## 🔁 2026-09-02 Improvement Round — Native GStreamer plugin acceptance closed

Executed the only owner-independent Long-Term Backlog item (Native GStreamer
plugin). Toolchain check: `gst-launch-1.0`, `gst-inspect-1.0`, and
`pkg-config gstreamer-1.0` (= 1.28.6) all present, so the item was
executable. All changes uncommitted, left in the working tree for owner
review. Historical count-drift gating was recorded here; current observed totals
are maintained only in root `AGENTS.md`.

### Landed

- [x] cdylib plugin packaging: `crate-type = ["cdylib", "rlib"]`,
  `gstreamer::plugin_define!` as `steganographer_gst` (= dylib file stem;
  the loader derives `gst_plugin_<file-stem>_get_desc` from the file name —
  naming the plugin `steganographer` made `gst-inspect-1.0` report "Could
  not find plugin entry point"). Origin inherited via
  `repository.workspace = true`. `status.sh --check` clean after count sync.
- [x] `stegoaudio` element (new `src/audio_element.rs`): interleaved S16LE
  PCM in-place transform over `AudioSpatialLsb` (sequential) /
  `KeyedAudioSpatialLsb` (`key-hex` set); per-buffer independent embedding;
  sequential `clear-payload` zeroes the exact slot footprint.
- [x] `stegovideo` keyed placement: non-empty `key-hex` switches embedding
  to `KeyedSpatialLsb` (key-driven per-frame slot selection via the core
  keyed carrier). Interpretation deviation recorded above on the
  "different indices" acceptance phrasing.
- [x] Both elements: `metadata()` + any-caps `pad_templates()` (absent
  templates caused `gst_base_transform_init: assertion 'pad_template !=
  NULL'` and the registry listed no features), `register_elements` moved to
  the gstreamer-rs 0.23 `Option<&Plugin>` signature, state mutexes migrated
  to `parking_lot` (repo rule), author metadata literal (crate has no
  `CARGO_PKG_AUTHORS`).
- [x] Acceptance evidence (GStreamer 1.28.6, macOS): `gst-inspect-1.0`
  lists `stegovideo` + `stegoaudio` from the built dylib (rc 0);
  `gst-launch-1.0 audiotestsrc ! capsfilter(S16LE) ! stegoaudio
  packet-hex=<166-byte packet> bits-per-unit=2 ! filesink` (rc 0, 32 KiB
  raw PCM) and `decode --stego-type lsb_audio --input-format raw_s16le
  --bits 2` recovers `"stegoaudio gst-launch acceptance"` byte-exact.
  `tests/gst_roundtrip.rs` pins the wire-format decode check.

### Fixed (same round)

- [x] `stegovideo`/`stegoaudio` `clear-payload` no-op (empty-packet embed
  writes nothing); sequential mode now zeroes the packet slot footprint,
  keyed mode warns once and keeps re-embedding (scattered slots are not
  clearable without the key schedule).
- [x] Docs drift: README Tests table said "Total 474" vs canonical 472;
  `docs/gstreamer.md` "Remaining plugin work" was stale after this round
  and its `packet extract` naming predates the `decode` subcommand.
  Counts refreshed everywhere from the canonical AGENTS.md Tests line
  (480 as of 2026-09-02; `./scripts/status.sh --check` exit 0).

### Implemented (2026-09-04 comprehensive pass)

- [x] Literal frame-index-divergent keyed placement — implemented without a
      core wire-format change: elements derive a frame-scoped embedding key
      (`kdf::derive_frame_embedding_key`, frame 0 = raw key) and embed each
      frame under its derived key. Unit tests: `kdf` frame-key derivation,
      `keyed_frames_diverge_by_frame_index` (video),
      `keyed_buffers_diverge_by_frame_index` (audio); every frame decodes
      through the same derivation with its index, frame 0 stays
      CLI-decodable with the raw key. Workspace counts now defer to root `AGENTS.md`.
Still open at the end of this pass: WebRTC streaming and the learned
watermarking encoder (owner intent required per the Long-Term Backlog;
unchanged). Tracked there — intentionally not duplicated as a checkbox
here, so the open-item count stays accurate.

---

## 🧹 2026-09-07 Improvement Round — hygiene audit, count-drift gate

Cold-start audit round. No functional code changes; every claim below
verified against the tree (`cargo test --workspace` 484/0 failures,
`./scripts/status.sh --check` exit 0 after the fixes).

### Fixed

- [x] `steganographer-core/src/kdf.rs` `mod tests` was compiled into
      release builds (missing `#[cfg(test)]`) — the only unguarded test
      module in the workspace, and the sole warning on a plain
      `cargo build -p steganographer-core` (unused import of `super::*`
      because all its users were dead code in the non-test build). The
      KDF unit tests still run under `cargo test`; release libs no
      longer carry them; clippy is warning-free.
- [x] `cargo fmt` drift in `steganographer-core/src/kdf.rs`,
      `steganographer-gst/src/audio_element.rs`, and
      `steganographer-gst/src/lib.rs` (landed unformatted in
      the 2026-09-06 commit). `cargo fmt --check` exits 0 again.
- [x] Test-count documentation drift corrected. Current observed workspace
      totals have one home in root `AGENTS.md`, rather than duplicated historical
      per-crate/per-file pins or badges.

### Added

- [x] `scripts/status.sh --check` now sweeps every tracked Markdown file
      and fails on any `<N> tests` / `<N> passing` / `tests-<N>` integer
      that is not a cargo-reported count (workspace total, per-target
      count, per-crate sum, or a split integer from the canonical
      Tests line). This closes the gap that let per-doc counts drift three
      times while the canonical AGENTS.md total was pinned; historical
      round notes with pre-gst totals stay truthful because only
      count-bearing phrases are matched.

### Open (unchanged, owner-intent required)

- WebRTC streaming and the learned watermarking encoder remain the only
  open backlog items (both 🔴 Major, both owner-intent-gated). Verified
  this round: no implementation code exists for either; docs mention
  them only as plans (`docs/algorithms.md` Video Seal wrap,
  `docs/plans/steganography-platform/06-delivery-and-migration.md`).

---

## 🔁 2026-09-20 Deep-Review Round — orchestrated across all six surfaces

Six parallel review agents audited core/CLI/dashboard/GST/docs/security; the
findings were then implemented by eight parallel task agents plus fix-ups.
Historical workspace/static-check observations were recorded for that pass,
not current release qualification; root `AGENTS.md` owns current test totals.

- [x] **Real ML-DSA** — `MlDsaBackend` was a keyed BLAKE3-XOF MAC masquerading
      as FIPS 204 (verify required the private seed; the "public key" could
      not verify anything). Replaced with real ML-DSA via the RustCrypto
      `ml-dsa` crate, ACVP-validated (75 keyGen + 45 sigVer vectors), with
      public-key-only `MlDsaVerifier`/`HybridVerifier`. Pre-0.8 "ML-DSA"
      payloads are unverifiable — re-sign.
- [x] **Transform-pipeline DoS bounds** — ECC geometry validated before
      allocation; DEFLATE output bounded by `DecodeLimits::max_original_len`
      + a 64 MiB hard ceiling.
- [x] **Hostile-carrier panic** — tag-only keyed carriers return typed
      `NoPacket` instead of panicking in `KeyedPermutation::new(0)`.
- [x] **Protocol consistency** — flags⇔transform consistency, unknown-field
      preservation, encode-side limits, packet-id-derived AEAD nonce,
      zeroized key material, `FIELD_PARENT_ID` + nesting limits (PKT-009
      scaffold).
- [x] **PLC-001 interleaved placement** + embed-side descriptor validation.
- [x] **Deterministic differential spread-spectrum modulation** — bit
      recovery now exact on textured carriers (old additive scheme: ~20-35%
      BER); old-format carriers must re-embed.
- [x] **FOR-005 Unicode text detectors** (zero-width, variation selectors,
      bidi, whitespace, homoglyphs) wired into `scan`.
- [x] **CLI contract (v0.8.0)** — exit codes 0/1/2/3, single-JSON-document
      verify, no secrets in JSON, `extract` subcommand, strict argument
      validation, `--revoked-list`, ots `--proof` default.
- [x] **Dashboard hardening** — WS origin/token gates, REAL signature
      verification, config validation, WS/image size caps, `/ots/verify`
      auth, UI Bearer token, DOMPurify + mermaid strict + SRI.
- [x] **GST fixes** — stride-safe pixel-only embedding, restricted pad
      templates, packet-hex validation, audio_filter caps/deadlock,
      video_filter frame-drop/stall, per-reason warnings, element tests.
- [x] **Alpha golden vectors** — `tests/golden_vectors.rs` +
      `testdata/packets/` with SHA-256 drift gate (owner freeze command:
      `cargo test -p steganographer-core --test golden_vectors -- --ignored`).
- [ ] WebRTC streaming and learned watermarking encoder: owner intent
      required per backlog (unchanged).


---

## 🔁 2026-09-21 Continuation Round — forensics registry, OOXML, WASM, WebRTC, password path

Current observed workspace totals are maintained only in root `AGENTS.md`.

### Landed

- [x] **Argon2id password-KDF transform (PKT-007)** — `apply_with_password` /
      `reverse_with_password` + critical `TRANSFORM_KDF_ARGON2ID` descriptor;
      `encode`/`decode`/`extract` gain `--password`/`--password-file`
      (mutually exclusive with explicit keys).
- [x] **Full bounded nested decode (PKT-009)** —
      `GenericPacket::decode_nested` expands parent-id chains with depth (3) /
      aggregate (64 MiB) limits and cycle detection.
- [x] **Detector registry + calibration corpus (FOR-001, QUA calibration)** —
      `detector_registry()` documents every scan detector (IDs, budgets,
      false-positive limits, calibration mapping); `testdata/corpus/` +
      `tests/calibration.rs` pin outcomes.
- [x] **OOXML/WordprocessingML container scanning (DOC-001/DOC-002 slice)** —
      dependency-free `forensics/ooxml` ZIP reader with hostile-input budgets;
      `scan_bytes` reports `container_findings`; `scan` CLI surfaces them.
      Zero new dependencies.
- [x] **SUR-006 profiles/`[limits]`** — optional `[limits]` +
      `[profiles.<name>]` (`limits` + `scan.detectors`) TOML tables;
      `config check` validates them; `scan --profile <name>` applies them.
- [x] **Scan symlink policy** — top-level symlinked inputs rejected by
      default; `--follow-input-symlink` opts in; `--profile` added.
- [x] **steganographer-wasm crate (WASM-001)** — browser-local facade
      (packet encode/decode, RGB + PCM S16LE carriers, forensic scan,
      decode-limits JSON), cfg-gated to `wasm32`; core `ots`/`reqwest` and
      `ethereum` features off. Native integration scenarios accompany the facade.
- [x] **WebRTC dashboard transport** — WHIP-style `POST /api/webrtc/offer`
      (auth-gated, non-trickle ICE) + `LiveConfig.transport`
      (`websocket` default | `webrtc`); data-channel media reuses the shared
      sign → embed → verify pipeline and WS size caps; automatic WebSocket
      fallback; peer-connection reaper. In-process two-PeerConnection tests
      prove signaling + the real endpoint round trip.

### Remaining (owner-gated / measurement)

- [x] **JSON v1 envelope (SUR-003)** — completed 2026-09-22 below; the
      `steganographer.cli/v1` envelope and exit codes ship.
- [x] **DOC-003 / DOC-004** — completed 2026-09-22 below; extended OOXML
      analysis and the bounded PDF structural scan ship.
- [ ] **Learned watermarking encoder** — owner intent required per backlog
      (training data licensing, model size budget); unchanged.
- [ ] **WebRTC browser-side latency/fps measurement** — the transport is
      landed and in-process tests prove the pipeline; measuring ≥ 15 fps
      720p / < 500 ms end-to-end latency on localhost is now possible via a
      headless Chromium run against the dashboard and is owner-run.
- [x] **Golden-vector freeze** — completed 2026-09-22 below; vectors are
      stable and the `immutability` job fails on drift.


---

## ✅ 2026-09-22 Final Round — v0.8 contract closure + acceptance measurements

Owner-approved historical round; its test/static-check observations do not
establish current release qualification. Current test totals live in root `AGENTS.md`.

- [x] **SUR-003 JSON v1 envelope** — `steganographer.cli/v1` envelope on all
      json/jsonl outputs; `--schema-version`; finalized exit codes 0–6
      (usage 1, packet-not-found 2, verification 3, findings 4, inconclusive
      5, internal 6). All CLI tests updated.
- [x] **DOC-003 pptx/xlsx/docx deep analysis** — extended-part text channels
      (slides/notes/sharedStrings/headers/footers) + media anomalies.
- [x] **DOC-004 bounded PDF structural scan** — embedded files, JS/ actions,
      dangerous URIs, filter abuse, trailing data, string-channel detection;
      no rendering, no new dependencies.
- [x] **Learned watermarking eval** — real openh264 roundtrip: QP 24–28 →
      0.00% BER (8/8 payloads), acceptance met; QP 26–30 (CRF~28) measures
      6.45% with the committed weights — retraining against real-codec
      quantization is the path to closing that window (weights are the
      committed artifact; trainer is deterministic).
- [x] **Golden vectors stable + CI immutability gate** — vector/corpus drift
      fails CI (`immutability` job); `test-windows` + `packaging-metadata`
      jobs added.
- [x] **Historical WebRTC synthetic-media measurements** — superseded as current
      performance/verification evidence. Genuine peer traffic is retained in the
      implementation; no universal throughput or physical-camera claim follows.
- [x] **WebRTC verify fix** — data-channel frames were signed with
      per-session throwaway keys and verified against the session signer
      (100% verify failure); the pump now shares one EncodeSession and
      signs with `state.signer`. Regression test added
      (`test_datachannel_encode_frame_verifies`).

### Remaining (owner-gated)

- [ ] Further encode-pipeline performance and real-device qualification require
      fresh measurements on the delivered lossless-artifact path.
- [ ] Learned-model real-codec robustness remains unqualified; see the current
      evaluation limits in `docs/algorithms.md`, not old synthetic score claims.

## Workflowz review — 2026-11-10

Coverage note: reviewed the supplied guidance, manifests, TODO history, and bounded source excerpts for concrete correctness, maintainability, documentation, validation, and dead-code improvements. No finding with both exact evidence and a defensible behavioral acceptance probe survived; no TODO items added. Coverage was limited to 11 project files and 5 source excerpts out of 236 files/105 source candidates, with no repository execution or full-file access. Re-review on a concrete failure or source change.
