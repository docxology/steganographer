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
| Decode limits | `decode_limits_default`, `decode_limits_from_json` | `packet::DecodeLimits` |

Report-returning functions produce JSON strings. Byte arrays map to JS
`Uint8Array` on the wasm side; `embed_*` returns
`{"carrier": [...], "report": {...}}` (the modified carrier plus the embed
report), `extract_*`/`packet_decode` return the packet's public metadata plus
its body, and `forensic_scan` returns the structural/statistical verdict with
appended Unicode/text findings.

Decode limits may be passed as a partial JSON override of
`decode_limits_default()` (e.g. `{"max_envelope_len": 1024}`); unknown fields
and negative values are rejected so typos fail loudly.

> Vectors are **alpha-provisional** (QUA-003): the wire formats may change
> before the first stable release, so persisted artifacts must be re-verified
> against each build.

## Building

The crate always compiles natively (the wasm-bindgen exports are cfg-gated to
`wasm32`), which is what the native integration tests use:

```sh
cargo test -p steganographer-wasm
```

Target verification for the browser build:

```sh
cargo check --target wasm32-unknown-unknown -p steganographer-wasm
```

`wasm-pack`/`wasm-bindgen` bundling (`--target web`) is future packaging work;
the `cdylib` target is what those tools consume.

## Dependency notes

- `steganographer-core` is used with `default-features = false`: no `ots`
  (HTTP client), no `ethereum` — the wasm surface is pure computation.
- `getrandom` with the `js` feature is declared for `wasm32` because `rand`
  0.8 inside core needs a browser/Node entropy source there.
