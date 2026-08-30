# TODO

Scoped improvements and future plans.
See [docs/roadmap.md](docs/roadmap.md) for the full release timeline.

> **Status (2026-08-19, v0.7.0):** Correctness baseline, OpenTimestamps attestation integration, exact info capacity, bounded scan command, post-write verification, and generic packet slices for RGB/WAV carriers are completed. All legacy audit findings are resolved.

---

## 🧭 Scoped Improvements (v0.8.0 Release Target)

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
