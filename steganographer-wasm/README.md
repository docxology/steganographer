# steganographer-wasm

Browser-facing facade over [`steganographer-core`](../steganographer-core) for
local, in-browser steganography. Every entry point operates on raw byte
buffers — no network, no filesystem. (Plan spec 04, WASM-001.)

## What it exposes

| Surface | Functions | Core kernels |
| ------- | --------- | ------------ |
| Packet framing | `packet_encode`, `packet_decode` | `packet` protocol-v1 untransformed generic packets |
| RGB carrier | `capacity_rgb`, `embed_rgb`, `extract_rgb` | `carrier::SpatialLsb` (byte units, stride 1) |
| WAV/PCM carrier | `capacity_pcm_s16le`, `embed_pcm_s16le`, `extract_pcm_s16le` | `carrier::AudioSpatialLsb` (S16LE sample units, stride 2) |
| Forensics | `forensic_scan`, `text_analyze_bytes`, `text_analyze_text` | `forensics` + `wasm_inspector` + `unicode_text` |
| Decode limits | `decode_limits_default`; Rust-only `decode_limits_from_json` | `packet::DecodeLimits` |

Report-returning functions produce JSON strings. Byte arrays map to JavaScript
`Uint8Array`; `embed_*` returns the modified carrier plus an embed report.
`extract_*` / `packet_decode` return public metadata and body bytes.

Packet reports use **`steganographer.packet-report.v2`**. All `u64` fields,
including `original_len` and optional timestamps, are exact decimal strings.
Handle them with `BigInt` when needed, not lossy JavaScript `Number` conversion.
Original JS numbers are validated before narrowing; invalid strengths, payload
kinds, fractions, NaN/infinities and wraparound values are rejected.

Decode limits accept partial JSON overrides of `decode_limits_default()`.
Unknown fields, invalid types and out-of-range values fail. Raised body limits
are supported through the actual generated bindings, not only native Rust calls.
Generic STG3 v1 [frozen vectors](../steganographer-core/testdata/packets/) remain
stable; stricter validation intentionally rejects malformed/inconsistent packets.

## Building and checking

Rust 1.91+; the package compiles natively for boundary/integration tests:
Run these commands from the workspace root.

```sh
cargo test -p steganographer-wasm --locked
rustup target add wasm32-unknown-unknown
cargo build -p steganographer-wasm --release --target wasm32-unknown-unknown --locked
```

Install the `wasm-bindgen-cli` version matching `wasm-bindgen` in Cargo.lock
(0.2.126 for this release), then generate the actual JavaScript interfaces:

```sh
wasm-bindgen --target nodejs --out-dir target/wasm-node --out-name steganographer_wasm \
  target/wasm32-unknown-unknown/release/steganographer_wasm.wasm
node steganographer-wasm/tests/bindings.cjs \"$PWD/target/wasm-node/steganographer_wasm.js\"
wasm-bindgen --target web --out-dir target/wasm-web --out-name steganographer_wasm \
  target/wasm32-unknown-unknown/release/steganographer_wasm.wasm
```

Serve web output over HTTP(S), import the ES module, and await its default
initializer before calling exports. Node and web glue are separate targets;
native tests do not prove JavaScript coercion or module-loading behavior.

## Dependency boundaries

- Core uses `default-features = false`: no GStreamer, network OTS client,
  Ethereum signing or filesystem surface is exposed.
- wasm32-only `getrandom` feature dependencies provide browser/Node entropy
  for the rand 0.8 and newer crypto stacks; they are not unused direct calls.
- This facade does not turn dashboard previews into authenticated recordings.
  Dashboard archives have a separate signed-media/manifest contract.
