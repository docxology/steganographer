# steganographer-core/src/

Source modules for the core steganographer algorithms.

## Files

| File | Lines | Purpose |
| ------ | ------- | --------- |
| `lib.rs` | 26 | Crate root — module declarations and public re-exports |
| `video.rs` | 65 | `VideoFrame` struct, `VideoFormat` enum (Rgb8/Bgra8/Yuv420), `VideoStegoModule` trait |
| `audio.rs` | 46 | `AudioBuffer` struct (i16 samples), `AudioStegoModule` trait |
| `crypto.rs` | 261 | `Signer` (BLAKE3 hash → Ed25519 sign), `Verifier`, `SignaturePayload` serialization |
| `signer_backend.rs` | ~350 | `SignerBackend` trait, `Ed25519Backend`, `EthereumBackend`, `display_identity()` |
| `config.rs` | 239 | TOML config model with `serde`, hex key decode, overlay + info_bar config |
| `metrics.rs` | 216 | `StegoMetrics` — atomic counters for frames/latency/verify, `to_json()`, `average_fps()` |
| `lsb_video.rs` | 290 | `LsbVideo` — multi-bit embed/extract with 32-bit length prefix protocol |
| `lsb_audio.rs` | 343 | `LsbAudio` — keyed PRNG (ChaCha8) Fisher-Yates permutation for sample indices |
| `overlay.rs` | ~402 | `TextOverlay` — 8×8 bitmap font, RGB/BGRA rendering, 5 positions, `expand_template()` |
| `info_bar.rs` | ~290 | `InfoBar` — exoteric visible watermark with toggleable timestamps, barcodes, QR |

## Trait Hierarchy

```text
VideoStegoModule      AudioStegoModule      SignerBackend
├── LsbVideo          └── LsbAudio          ├── Ed25519Backend
├── TextOverlay                             └── EthereumBackend
└── InfoBar
```

## Conventions

- All modules include `#[cfg(test)] mod tests` with inline unit tests (56 total)
- Error handling via `anyhow::Result`
- Logging via `log::debug!()` / `log::warn!()`
- No I/O operations — all methods operate on in-memory buffers
- Thread-safe metrics via atomic operations (no locks for GStreamer callback compatibility)
