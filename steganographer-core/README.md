# steganographer-core

![CI](https://github.com/docxology/steganographer/actions/workflows/ci.yml/badge.svg)
Media algorithms, generic packets, cryptographic signing and bounded forensic analysis without GStreamer dependencies. Most kernels are in-memory; optional OpenTimestamps support performs bounded network/proof I/O.

## Modules

| Module | File | Description |
| -------- | ------ | ------------- |
| `packet` | `src/packet.rs` | `GenericPacket`, `Locator`, `PacketEnvelope`, `PacketCodec`, bounded `decode_nested` (PKT-009) — generic packet v1 alpha |
| `carrier` | `src/carrier.rs` | `CarrierDescriptor`, `SpatialLsb`, `AudioSpatialLsb`, keyed kernels — carrier embed/extract |
| `carrier_binding` | `src/carrier_binding.rs` | Shared canonical carrier representation for offline and native signing/verification; never hashes row padding |
| `placement` | `src/placement.rs` | `KeyedPermutation` — Feistel-network keyed slot placement; `InterleavedSchedule` — coprime-stride interleaved schedule (`PLACEMENT_INTERLEAVED`, PLC-001) |
| `video` | `src/video.rs` | `VideoFrame` struct, `VideoFormat` enum, `VideoStegoModule` trait |
| `audio` | `src/audio.rs` | `AudioBuffer` struct, `AudioStegoModule` trait |
| `crypto` | `src/crypto.rs` | `Signer`, `Verifier`, `SignaturePayload` — BLAKE3 + Ed25519 |
| `revocation` | `src/revocation.rs` | Known-compromise checks and normalized additional public-key registries; authorization is separate from raw signature mathematics |
| `signer_backend` | `src/signer_backend.rs` | `SignerBackend` / `Ed25519Backend` / `EthereumBackend` / `MlDsaBackend` / `HybridBackend` + public-key-only `MlDsaVerifier` / `HybridVerifier` (real FIPS 204 ML-DSA via the RustCrypto `ml-dsa` crate) |
| `config` | `src/config.rs` | `Config` TOML parsing, hex key decoding, overlay/info_bar config |
| `lsb_video` | `src/lsb_video.rs` | `LsbVideo` — 1–4 bit LSB video embed/extract with length prefix |
| `lsb_audio` | `src/lsb_audio.rs` | `LsbAudio` — keyed PRNG index permutation LSB audio embed/extract |
| `overlay` | `src/overlay.rs` | `TextOverlay` — 8×8 bitmap font renderer, template expansion (`{timestamp}`, `{frame_index}`) |
| `info_bar` | `src/info_bar.rs` | `InfoBar` — exoteric visible watermark with toggleable timestamps, barcodes, QR |
| `metrics` | `src/metrics.rs` | `StegoMetrics` — thread-safe atomic counters for latency/frame tracking |
| `transforms` | `src/transforms.rs` | ChaCha20-Poly1305 AEAD + chunked Reed-Solomon + DEFLATE transform chain, incl. `TRANSFORM_KDF_ARGON2ID` password-KDF transform (PKT-007) |
| `password` | `src/password.rs` | `Argon2Params` (RFC 9106), `derive_all_from_password` — Argon2id password stretching |
| `forensics` | `src/forensics.rs` | `ForensicScan`, `scan_bytes`, stable `detector_registry()` (FOR-001) — structural + statistical + container findings + calibration corpus mapping |
| `forensics/ooxml` | `src/forensics/ooxml.rs` | Dependency-free in-memory ZIP reader + OOXML/WordprocessingML container analysis (DOC-001 package anomalies, DOC-002 concealment; `ZIP_TOPOLOGY` inventory) |
| `unicode_text` | `src/unicode_text.rs` | Unicode/text steganography detectors (FOR-005: zero-width, variation selectors, bidi controls, whitespace anomalies, homoglyph suspects) |
| `adaptive` | `src/adaptive.rs` | Masked local variance with framing-sized heap selection; stable tie order, no full candidate sort |
| `ots_client` | `src/ots_client.rs` | Standard detached proof lifecycle; `verify_with_upgrade` returns verdict and optional changed bytes |

## Bounded contracts

Sequential/keyed locator flags must agree with placement. Compression admits
at most 64 MiB logical input and records only shrinkage; readers preflight
transforms and enforce decode limits. CLI limits can be lower.
Nested decode is opt-in through an identifiable parent-id field, not a mere
STG3 prefix; linked children must occupy the complete logical payload and obey
parent/depth/aggregate/cycle checks. Parentless packet-shaped bytes stay opaque.

Forensics reports coverage/incomplete reasons separately from positive evidence;
detector byte/finding/decode budgets apply even when all input was supplied.
Statistical `available` is not a detection verdict or calibrated probability.
See [Algorithms](../docs/algorithms.md) and [API Reference](../docs/api-reference.md).

## Tests

- Inline tests and real integration suites exercise cryptographic, parser,
  carrier, signal, forensics and OpenTimestamps boundaries.
- Frozen packet vectors and the detector calibration corpus remain immutable.
- Canonical observed workspace totals live in [`../AGENTS.md`](../AGENTS.md).

```bash
cargo test -p steganographer-core
```

## Dependencies

```toml
blake3 = "1.5"
ed25519-dalek = { version = "2", features = ["rand_core"] }
rand = "0.8"
anyhow = "1"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
toml = "0.8"
log = "0.4"
chrono = "0.4"
```

## Architecture

```text
lib.rs
├── packet.rs            → GenericPacket / Locator / PacketEnvelope codec (+ bounded decode_nested)
├── carrier.rs           → CarrierDescriptor / SpatialLsb / keyed kernels
├── carrier_binding.rs   → shared kernel-canonical carrier representation
├── video.rs             → VideoFrame / VideoStegoModule trait
├── audio.rs             → AudioBuffer / AudioStegoModule trait
├── crypto.rs            → Signer + Verifier (BLAKE3 hash, Ed25519 sign)
├── revocation.rs        → immutable compromise policy + normalized additional registries
├── signer_backend.rs    → SignerBackend trait + Ed25519/Ethereum/ML-DSA/Hybrid impls (+ public-key-only verifiers)
├── config.rs            → Config model + TOML parsing
├── lsb_video.rs         → LsbVideo implements VideoStegoModule
├── lsb_audio.rs         → LsbAudio implements AudioStegoModule
├── overlay.rs           → TextOverlay implements VideoStegoModule + template expansion
├── info_bar.rs          → InfoBar implements VideoStegoModule
├── metrics.rs           → StegoMetrics (atomic counters, JSON export)
├── forensics.rs         → ForensicScan / detector_registry() (FOR-001) / scan_bytes
├── forensics/ooxml.rs   → ZIP reader + DOC-001/DOC-002 container analysis
└── unicode_text.rs      → Unicode/text steganography detectors (FOR-005)
```
