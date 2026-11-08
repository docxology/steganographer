# AGENTS.md — steganographer-core

## Purpose

In-memory steganography/crypto/packet/forensic algorithms and config parsing, plus optional bounded OpenTimestamps network/proof I/O. No GStreamer dependency.

## Module Map

| File | Public Types | Trait | Lines |
| ------ | ------------- | ------- | ------- |
| `src/lib.rs` | re-exports | — | 100 |
| `src/video.rs` | `VideoFrame`, `VideoFormat` | `VideoStegoModule` | 64 |
| `src/audio.rs` | `AudioBuffer` | `AudioStegoModule` | 45 |
| `src/packet.rs` | `GenericPacket`, `Locator`, `PacketEnvelope`, codecs, limits/errors, `FIELD_PARENT_ID` nesting, `GenericPacket::decode_nested` (bounded chain decode) | `PacketCodec` | 2069 |
| `src/carrier.rs` | `CarrierDescriptor`, `EmbeddingConfig`, reports, `SpatialLsb`, `AudioSpatialLsb`, keyed kernels | `CarrierEmbedder`, `CarrierExtractor` | 1625 |
| `src/carrier_binding.rs` | `canonicalize` — shared offline/native kernel binding over packed logical carrier bytes | — | — |
| `src/crypto.rs` | `Signer`, `Verifier`, `SignaturePayload`, `HashAlgorithm` | — | 600 |
| `src/revocation.rs` | `RevocationList`, `RevokedKey`, `is_known_compromised_key`, `check_known_revocations` | — | 167 |
| `src/signer_backend.rs` | `SignerBackend`, `Ed25519Backend`, `Ed25519Verifier`, `MlDsaBackend`, `MlDsaVerifier`, `HybridBackend`, `HybridVerifier`, `EthereumBackend`*, `EthereumVerifier`* | `SignerBackend` | 1020 |
| `src/metrics.rs` | `StegoMetrics` | — | 332 |
| `src/config.rs` | `Config`, `GlobalConfig`, `VideoConfig`, `AudioConfig`, `PayloadConfig`, `LsbSignatureConfig`, `OverlayConfig`, `InfoBarConfig`, `LimitsConfig` (`[limits]`), `ProfileConfig` (`[profiles.<name>]`), etc. | — | 856 |
| `src/lsb_video.rs` | `LsbVideo` | `VideoStegoModule` | 298 |
| `src/lsb_audio.rs` | `LsbAudio` | `AudioStegoModule` | 360 |
| `src/overlay.rs` | `TextOverlay`, `OverlayPosition`, `expand_template` | `VideoStegoModule` | 417 |
| `src/info_bar.rs` | `InfoBar` | `VideoStegoModule` | 568 |
| `src/dct_video.rs` | `DctVideo` | `VideoStegoModule` | 468 |
| `src/spread_spectrum.rs` | `SpreadSpectrumVideo`, `SpreadSpectrumAudio`, `capacity()` — host-canceling differential-pair modulation | — | 780 |
| `src/encryption.rs` | `EncryptionKey`, `encrypt()` (nonce = `BLAKE3(salt ∥ packet_id)[..12]`), `decrypt()` | — | 370 |
| `src/error_correction.rs` | `encode()`, `decode()`, `correction_capability()` | — | 546 |
| `src/multi_frame.rs` | `SignatureShard`, `GenericPayloadShard`, `split()`, `reconstruct()`, `split_payload_bytes()`, `reconstruct_payload_bytes()` | — | 461 |
| `src/wasm_inspector.rs` | `inspect_bytes()`, `extract_packet_rgb8()`, `capacity_rgb8()`, `WasmInspectionReport` | — | 119 |
| `src/placement.rs` | `KeyedPermutation` (PLC-002), `InterleavedSchedule` (`PLACEMENT_INTERLEAVED`, PLC-001) | — | 441 |
| `src/kdf.rs` | `derive_signing_key()`, `derive_encryption_key()`, `derive_embedding_key()`, `derive_locator_key()`, `derive_placement_key()`, `derive_frame_embedding_key()` | — | 266 |
| `src/transforms.rs` | `apply`, `reverse`, `apply_with_password` / `reverse_with_password` (PKT-007), `TRANSFORM_KDF_ARGON2ID` descriptor | — | 1434 |
| `src/forensics.rs` | `ForensicScan` (incl. `text_findings`, `container_findings`), `detector_registry()` (FOR-001), `detect_text_stego()`, `scan_bytes()` | — | 728 |
| `src/forensics/ooxml.rs` | `analyze_package()`, `ZipArchive`/`ZipEntry`, `ContainerFinding` families (`ZIP_TOPOLOGY`, `DOC-001`, `DOC-002`), `CONTAINER_*` budgets | — | 1187 |
| `src/unicode_text.rs` | `TextFinding` (FOR-005 detector IDs) — zero-width, variation-selector, bidi-control, whitespace, homoglyph detectors | — | 702 |
| `src/ots_config.rs` | `OtsConfig` (`enabled`, `server_url`, `method`, `interval_secs`, `proof_dir`, `timeout_secs`), `OtsSettings` | — | — |
| `tests/integration_tests.rs` | — | — | ~1900 |

\* Feature-gated behind `ethereum`

## Key Constants
- `SignaturePayload::SERIALIZED_SIZE` = 109 bytes (4 + 1 + 8 + 32 + 64)
- LSB range: 1–4 bits per byte/sample
- Legacy payload capacity at 1-bit: 872 carrier units (CLI length-prefixed path: 904)
- Generic public locator: 32 bytes (`STG3`, protocol 1.0 alpha)
- Encryption: ChaCha20-Poly1305 AEAD (256-bit key, 96-bit nonce derived from a fresh random salt + the 16-byte `packet_id` — never the public locator nonce)
- Error correction: evaluation-form Reed-Solomon over GF(2⁸), bounded Berlekamp-Welch correction
- Multi-frame: XOR n-of-n secret sharing
- Flags and transform descriptors, plus keyed-locator/placement policy, must agree.
  Nested decode expands only identifiable parent-id-linked children; bare STG3
  payloads remain opaque. Enforce complete child span, matching parent, cycle,
  depth and aggregate encoded-byte limits (root included).
- Compression writers/readers share the 64 MiB logical ceiling; configured
  CLI limits may be lower. Record compression only when it shrinks the body.
- Adaptive selection retains only the framing-sized best prefix, preserving
  descending variance and stable original-order ties with O(k) retained memory.
- Forensics latches detection separately from evidence caps and propagates
  detector input/decode/finding limits as incompleteness. Unavailable statistical
  methods are not clean negatives.
- OTS `verify_with_upgrade` returns verdict plus optional changed bytes;
  completed Bitcoin proofs skip calendars, not explorer/header verification.
  Consumers publish upgrades append-only without replacing original receipts.
- Spread-spectrum: host-canceling differential-pair modulation (pre-0.8 absolute-correlation embeds are no longer extractable — re-embed)

## Features

| Feature | Dependencies | Purpose |
| --------- | ------------- | --------- |
| `ethereum` | `k256`, `sha3` | secp256k1 + EIP-191 signing backend |

## Test Coverage

Inline unit tests and real integration suites cover packet/carrier boundaries,
crypto, revocation, signal processing, forensics, OpenTimestamps and immutable
golden vectors. The canonical observed workspace totals live in
[`../AGENTS.md`](../AGENTS.md); run `cargo test -p steganographer-core --locked`
for this crate's current breakdown.

