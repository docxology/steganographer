# steganographer-core/src/

Source modules for the core steganographer algorithms.

## Files

| File | Lines | Purpose |
| ------ | ------- | --------- |
| `lib.rs` | 100 | Crate root — module declarations and public re-exports |
| `packet.rs` | 2069 | `GenericPacket`, `Locator`, `PacketEnvelope`, `PacketCodec`, `FIELD_PARENT_ID` nesting, bounded `GenericPacket::decode_nested` — generic packet v1 alpha |
| `carrier.rs` | 1625 | `CarrierDescriptor`, `SpatialLsb`, `AudioSpatialLsb`, `KeyedSpatialLsb`/`KeyedAudioSpatialLsb` keyed kernels — carrier embed/extract |
| `placement.rs` | 441 | `KeyedPermutation` — Feistel-network keyed slot placement; `InterleavedSchedule` (`PLACEMENT_INTERLEAVED`, PLC-001) |
| `video.rs` | 64 | `VideoFrame` struct, `VideoFormat` enum (Rgb8/Bgra8/Yuv420), `VideoStegoModule` trait |
| `audio.rs` | 45 | `AudioBuffer` struct (i16 samples), `AudioStegoModule` trait |
| `crypto.rs` | 600 | `Signer` (BLAKE3 hash → Ed25519 sign), `Verifier`, `SignaturePayload` serialization |
| `signer_backend.rs` | 1020 | `SignerBackend` trait, `Ed25519Backend`, `MlDsaBackend` (real FIPS 204 via RustCrypto `ml-dsa`), `HybridBackend`, `EthereumBackend` (feature-gated), plus public-key-only `Ed25519Verifier`, `MlDsaVerifier`, `HybridVerifier` |
| `config.rs` | 856 | TOML config model with `serde`, hex key decode, overlay + info_bar config, `[limits]`/`[profiles]` tables + validation |
| `metrics.rs` | 332 | `StegoMetrics` — atomic counters for frames/latency/verify, `to_json()`, `average_fps()`, `reset()` |
| `lsb_video.rs` | 298 | `LsbVideo` — multi-bit embed/extract with 32-bit length prefix protocol |
| `lsb_audio.rs` | 360 | `LsbAudio` — keyed PRNG (ChaCha8) Fisher-Yates permutation for sample indices |
| `overlay.rs` | 417 | `TextOverlay` — 8×8 bitmap font, RGB/BGRA rendering, 5 positions, `expand_template()` |
| `info_bar.rs` | 568 | `InfoBar` — exoteric visible watermark with toggleable timestamps, barcodes, QR |
| `transforms.rs` | 1434 | AEAD/ECC/DEFLATE transform chain incl. `TRANSFORM_KDF_ARGON2ID` password-KDF transform (PKT-007: `apply_with_password` / `reverse_with_password`) |
| `forensics.rs` | 728 | `ForensicScan` (incl. `text_findings`, `container_findings`), `detector_registry()` (FOR-001), `detect_text_stego()` — bounded forensic byte scanning |
| `forensics/ooxml.rs` | 1187 | Dependency-free in-memory ZIP reader + OOXML/WordprocessingML analysis (`ZIP_TOPOLOGY`, DOC-001 package anomalies, DOC-002 concealment; `CONTAINER_*` budgets) |
| `unicode_text.rs` | 702 | Unicode/text steganography detectors (FOR-005 detector IDs) |

## Trait Hierarchy

```text
VideoStegoModule      AudioStegoModule      SignerBackend
├── LsbVideo          └── LsbAudio          ├── Ed25519Backend
├── TextOverlay                             ├── MlDsaBackend  (FIPS 204, ml-dsa crate)
└── InfoBar                                 ├── HybridBackend (Ed25519 + ML-DSA)
                                            └── EthereumBackend (feature-gated)

Verification-only (no private key): Ed25519Verifier · MlDsaVerifier · HybridVerifier
```

## Conventions
- All modules include `#[cfg(test)] mod tests` with inline unit tests (381 total)
- Error handling via `anyhow::Result`
- Logging via `log::debug!()` / `log::warn!()`
- No I/O operations — all methods operate on in-memory buffers
- Thread-safe metrics via atomic operations (no locks for GStreamer callback compatibility)
