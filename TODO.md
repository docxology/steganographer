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
- [ ] **Native GStreamer plugin** — full `BaseTransform` for zero-copy pipelines. Status: `stegovideo` in-place transform with packet embedding landed (2026-08-27); remaining: keyed placement schedule in-element, audio sibling element (`stegoaudio`), cdylib packaging + `GST_PLUGIN_PATH` smoke pipeline.
- [ ] **WebRTC streaming** — replace WebSocket frame-by-frame with WebRTC.
- [ ] **Learned watermarking encoder** — neural network-based watermarking resistant to re-encoding/cropping.

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

### 🔴 Major (deferred)
- [ ] **Automate test-count provenance** — a small generator (or CI step) that writes the test count into a checked-in file would remove the manual-sync class of staleness entirely. Deferred: introduces a build step to a docs-only pass; current canonical-line convention is workable.
- [ ] **README has no status surface beyond a badge** — a `make status`-style executable status command would beat prose. Deferred: repo has no Makefile convention; adding one is an infra decision out of scope for this pass.
