# AGENTS.md — steganographer-wasm

## Purpose

Browser-facing facade over `steganographer-core`: packet framing, spatial-LSB
capacity/embed/extract over RGB and S16LE PCM carriers, and forensics scans,
all over raw byte buffers. Protocol-v1 golden wire bytes remain unchanged;
the packet-report JSON schema changes independently of the wire format.

## Module Map

| File | Key Symbols |
| ---- | ----------- |
| `src/lib.rs` | crate docs, `mod api`, cfg-gated `mod bindings`, native re-exports |
| `src/api.rs` | plain-Rust surface: `packet_encode`/`packet_decode`, `capacity_rgb`/`capacity_pcm_s16le`, `embed_rgb`/`embed_pcm_s16le`, `extract_rgb`/`extract_pcm_s16le`, `forensic_scan`, `text_analyze_bytes`/`text_analyze_text`, `decode_limits_default`/`decode_limits_from_json`; helpers `packet_report`, `extract_value`, `capacity_value` |
| `src/bindings.rs` | `#[wasm_bindgen]` exports (wasm32 only) over `api`, JSON-string reports, `Option<String>` limits override |
| `tests/wasm_facade.rs`, `tests/bindings.cjs` | native facade regressions and real generated wasm-bindgen Node boundary regressions |

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
- Packet/extraction reports use
  `schema: "steganographer.packet-report.v2"`. `original_len` is a decimal string;
  `created_at_unix` is a decimal string or null. Consumers needing arithmetic
  must use `BigInt`, not `Number`; this preserves values above 2^53 through
  `u64::MAX`. Body arrays and wasm32 carrier counts remain numeric.
- JS strength/kind controls cross as `f64`; validate the original value as
  finite, integral, and in range **before** narrowing. Strength is 1–4; payload
  kind is 1–5. Never restore wrapping u8/u16 exports.
- Limits overrides reject unknown keys, malformed/noninteger/negative values,
  and values outside wasm32 `usize`. Explicit raised encode/extract limits
  remain effective through embedding; no hidden default body-size ceiling.
- Forensic reports expose actual findings, `detected`, incompleteness/reasons,
  and statistical availability. Unavailable/partial negatives are not clean;
  scores are not calibrated natural-image steganography probabilities.

## Commands

Run these only as integration gates, not concurrently with implementation:

```sh
cargo test -p steganographer-wasm
# Isolate WASM feature resolution from native workspace network features:
cargo build --release --target wasm32-unknown-unknown -p steganographer-wasm --no-default-features
# wasm-bindgen CLI version must match the resolved Cargo.lock crate exactly:
wasm-bindgen --target nodejs --out-dir /tmp/steganographer-wasm-bindings \
  target/wasm32-unknown-unknown/release/steganographer_wasm.wasm
node steganographer-wasm/tests/bindings.cjs \
  /tmp/steganographer-wasm-bindings/steganographer_wasm.js
```

Build only this package for wasm32, not `--workspace`/`--all-features`.
Use a dedicated `CARGO_TARGET_DIR` if sharing a checkout with native jobs
(adjust the input WASM path accordingly). For browser packaging,
`wasm-bindgen --target web` produces browser modules; that is distinct from
the Node acceptance module.

Parent exercised real generated release bindings, including original JS-number
rejection and exact timestamp strings, plus a real Node >16 MiB body path with
explicit limits. Native tests or a wasm32 check alone do not establish that
generated JavaScript exports work. Do not claim a browser smoke from Node.
