# TODO

Scoped improvements and future plans.
See [docs/roadmap.md](docs/roadmap.md) for the full release timeline.

> **Status (2026-08-19, v0.7.0):** Correctness baseline, OpenTimestamps attestation integration, exact info capacity, bounded scan command, post-write verification, and generic packet slices for RGB/WAV carriers are completed. All legacy audit findings are resolved.

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
  `clear-payload` was a no-op (empty-packet embed writes zero bits); gst
  suite 7 → 15, workspace 472 → 480.
- [ ] **WebRTC streaming** — replace WebSocket frame-by-frame with WebRTC.
  Acceptance: dashboard Video tab streams at ≥ 15 fps 720p over `whep`/whip-style signaling with end-to-end latency < 500 ms on localhost; verification round-trip still passes on the rendered frames; fallback to WebSocket retained behind a config flag. Owner intent needed: target browsers and signaling stack.
- [ ] **Learned watermarking encoder** — neural network-based watermarking resistant to re-encoding/cropping.
  Acceptance: trained model embeds a 64-bit payload surviving H.264 re-encode at CRF 28 with bit error rate < 5 percent on a fixed eval set; embed/extract runs ≤ 50 ms/frame on CPU; ships as an opt-in cargo feature with no new mandatory deps. Owner intent needed: training data licensing and model size budget.

---

## 🔧 Agent-Ergonomics Pass (2026-08-31)

---

Findings from the 2026-08-31 cold-start documentation audit (agent-erg fleet). All Minor and Medium items were fixed in the same pass; Majors are deferred with reasons.

### 🟢 Minor
- [x] **"All 13 commands" stale count** — actual subcommand count is 14. Fixed in `README.md`, `docs/AGENTS.md`; `docs/cli-reference.md` gained `revoke` + `ots` sections.
- [x] **docs/AGENTS.md contents table stale** — omitted `ots-integration.md`, miscounted files. Refreshed with as-of date + verification command.
- [x] **docs/README.md test count stale (457)** — now points to the canonical Tests line in root `AGENTS.md`.
- [x] **TODO.md completed section framed as active** — superseded-marked (this edit).

### 🟡 Medium
- [x] **Test-count fact-class had no canonical home** — duplicated (and disagreeing) across README, AGENTS.md, docs/README.md, docs/contributing.md, docs/getting-started.md. Root `AGENTS.md` Tests line declared canonical; README/docs now link or defer to it.
- [x] **cli-reference.md missing 2 of 14 subcommands** — `revoke` and `ots` sections added from `steganographer-cli/src/main.rs` (source of truth: `enum Commands`).

### 🔴 Major (deferred → completed in Round 2, 2026-08-31)
- [x] **Automate test-count provenance** — `scripts/status.sh --check` compares `cargo test --workspace -- --list` against the canonical Tests line in AGENTS.md; exit 1 on drift. Run before any docs change that touches counts.
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
review. Docs-count changes were gated by `./scripts/status.sh --check`
(ran first at canonical 472 → confirmed MISMATCH exit 1 → counts updated →
re-run clean).

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
      CLI-decodable with the raw key. Workspace 480 → 484 tests; `./scripts/status.sh --check` verified clean at 484 == 484.
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
      9 kdf unit tests still run under `cargo test`; release libs no
      longer carry them; clippy is warning-free.
- [x] `cargo fmt` drift in `steganographer-core/src/kdf.rs`,
      `steganographer-gst/src/audio_element.rs`, and
      `steganographer-gst/src/lib.rs` (landed unformatted in
      the 2026-09-06 commit). `cargo fmt --check` exits 0 again.
- [x] Test-count drift corrected from cargo-verified counts
      (484 total = 290 core unit + 117 core integration (80 + 37) +
      37 CLI (6 + 31) + 23 dashboard + 17 gst (14 + 2 + 1 doctest)):
      `README.md` (288→290, 405→407), `docs/README.md` (288→290,
      gst 2→17, total 467→484), `docs/contributing.md` (457→484 twice,
      395/282+113→407/290+117), `docs/getting-started.md` (457→484,
      395→407), `steganographer-core/AGENTS.md` (288→290, 405→407), and
      `steganographer-core/README.md` (405→407 badge and totals). The
      earlier "counts refreshed everywhere" claims had not
      reached these files — the numbers predated the gst element work.

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

