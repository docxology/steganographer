# steganographer-core/src/

Source modules for the core steganographer algorithms.

## Files

| File | Lines | Purpose |
| ------ | ------- | --------- |
| `lib.rs` | 95 | Crate root — module declarations and public re-exports |
| `packet.rs` | 1278 | `GenericPacket`, `Locator`, `PacketEnvelope`, `PacketCodec` — generic packet v1 alpha |
| `carrier.rs` | 1086 | `CarrierDescriptor`, `SpatialLsb`, `AudioSpatialLsb`, keyed kernels — carrier embed/extract |
| `placement.rs` | 243 | `KeyedPermutation` — Feistel-network keyed slot placement |
| `video.rs` | 64 | `VideoFrame` struct, `VideoFormat` enum (Rgb8/Bgra8/Yuv420), `VideoStegoModule` trait |
| `audio.rs` | 45 | `AudioBuffer` struct (i16 samples), `AudioStegoModule` trait |
| `crypto.rs` | 600 | `Signer` (BLAKE3 hash → Ed25519 sign), `Verifier`, `SignaturePayload` serialization |
| `signer_backend.rs` | 649 | `SignerBackend` trait, `Ed25519Backend`, `MlDsaBackend`, `HybridBackend`, `EthereumBackend` (feature-gated) |
| `config.rs` | 529 | TOML config model with `serde`, hex key decode, overlay + info_bar config |
| `metrics.rs` | 332 | `StegoMetrics` — atomic counters for frames/latency/verify, `to_json()`, `average_fps()` |
| `lsb_video.rs` | 298 | `LsbVideo` — multi-bit embed/extract with 32-bit length prefix protocol |
| `lsb_audio.rs` | 360 | `LsbAudio` — keyed PRNG (ChaCha8) Fisher-Yates permutation for sample indices |
| `overlay.rs` | 417 | `TextOverlay` — 8×8 bitmap font, RGB/BGRA rendering, 5 positions, `expand_template()` |
| `info_bar.rs` | 568 | `InfoBar` — exoteric visible watermark with toggleable timestamps, barcodes, QR |

## Trait Hierarchy

```text
VideoStegoModule      AudioStegoModule      SignerBackend
├── LsbVideo          └── LsbAudio          ├── Ed25519Backend
├── TextOverlay                             ├── MlDsaBackend
└── InfoBar                                 ├── HybridBackend
                                            └── EthereumBackend (feature-gated)
```

## Conventions

- All modules include `#[cfg(test)] mod tests` with inline unit tests (288 total)
- Error handling via `anyhow::Result`
- Logging via `log::debug!()` / `log::warn!()`
- No I/O operations — all methods operate on in-memory buffers
- Thread-safe metrics via atomic operations (no locks for GStreamer callback compatibility)
