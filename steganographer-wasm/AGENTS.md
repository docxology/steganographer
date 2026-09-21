# AGENTS.md — steganographer-wasm

## Purpose

Browser-facing facade over `steganographer-core`: packet framing, spatial-LSB
capacity/embed/extract over RGB and S16LE PCM carriers, and forensics scans,
all over raw byte buffers (WASM-001). Vectors are alpha-provisional (QUA-003).

## Module Map

| File | Key Symbols |
| ---- | ----------- |
| `src/lib.rs` | crate docs, `mod api`, cfg-gated `mod bindings`, native re-exports |
| `src/api.rs` | plain-Rust surface: `packet_encode`/`packet_decode`, `capacity_rgb`/`capacity_pcm_s16le`, `embed_rgb`/`embed_pcm_s16le`, `extract_rgb`/`extract_pcm_s16le`, `forensic_scan`, `text_analyze_bytes`/`text_analyze_text`, `decode_limits_default`/`decode_limits_from_json`; helpers `packet_report`, `extract_value`, `capacity_value` |
| `src/bindings.rs` | `#[wasm_bindgen]` exports (wasm32 only) over `api`, JSON-string reports, `Option<String>` limits override |
| `tests/wasm_facade.rs` | native tests: RGB/PCM round trips, capacity parity with core, clean-vs-laced scan, text findings, limits enforcement |

## Contract

- `src/api.rs` compiles on **both** native and wasm32; it must not depend on
  anything wasm-bindgen. The `#[wasm_bindgen]` code lives only in
  `src/bindings.rs`, which `src/lib.rs` includes under
  `#[cfg(target_arch = "wasm32")]`.
- The core dependency is `default-features = false` (no `ots`/reqwest, no
  `ethereum`/k256). Do not re-enable network-carrying features.
- `getrandom` with the `js` feature is declared under
  `[target.'cfg(target_arch = "wasm32")'.dependencies]` because `rand` 0.8 in
  core needs it on wasm32. Keep that target block.
- Signatures: `Vec<u8>` byte arrays, `Option<DecodeLimits>` natively /
  `Option<String>` JSON on the bindings; reports are `serde_json::Value`
  (bindings serialize to strings). `embed_*` returns the modified carrier
  plus the embed report.
- Packet encoding records the intended embedding strength in the kernel
  descriptor (`KERNEL_SPATIAL_LSB`, parameters `[bits_per_unit]`); the same
  `bits_per_unit` must be used for the subsequent `embed_*` call or the
  carrier kernel rejects the packet as `DescriptorMismatch`.

## Commands

- Native tests: `cargo test -p steganographer-wasm`
- wasm32 target verification:
  `cargo check --target wasm32-unknown-unknown -p steganographer-wasm`
- `wasm-pack`/`wasm-bindgen` bundling (`--target web`) is future packaging.
