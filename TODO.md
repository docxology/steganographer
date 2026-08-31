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

- [ ] **Native GStreamer plugin** — full `BaseTransform` for zero-copy pipelines.
  Status: `stegovideo` in-place transform with packet embedding landed (2026-08-27).
  Acceptance: (1) keyed placement schedule computed inside `stegovideo` (property `key-hex` drives per-frame slot selection, verified by a unit test that two frames with equal buffers but different indices embed to different slots); (2) `stegoaudio` element round-trips a PCM S16 packet through `gst-launch` (verified by `GST_PLUGIN_PATH=. gst-launch-1.0 ... ! fakesink` + decode check); (3) cdylib packaging produces a loadable plugin and `gst-inspect-1.0 stegovideo` lists its properties.
- [ ] **WebRTC streaming** — replace WebSocket frame-by-frame with WebRTC.
  Acceptance: dashboard Video tab streams at ≥ 15 fps 720p over `whep`/whip-style signaling with end-to-end latency < 500 ms on localhost; verification round-trip still passes on the rendered frames; fallback to WebSocket retained behind a config flag. Owner intent needed: target browsers and signaling stack.
- [ ] **Learned watermarking encoder** — neural network-based watermarking resistant to re-encoding/cropping.
  Acceptance: trained model embeds a 64-bit payload surviving H.264 re-encode at CRF 28 with bit error rate < 5 percent on a fixed eval set; embed/extract runs ≤ 50 ms/frame on CPU; ships as an opt-in cargo feature with no new mandatory deps. Owner intent needed: training data licensing and model size budget.

---

## 🔧 Agent-Ergonomics Pass (2026-08-31)

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
