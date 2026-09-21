# AGENTS.md — steganographer-core

## Purpose

Pure, zero-I/O steganography algorithms, cryptographic signing (Ed25519, Ethereum, FIPS 204 ML-DSA, hybrid), payload encryption, error correction, metrics, forensic scanning, and config parsing.

## Module Map

| File | Public Types | Trait | Lines |
| ------ | ------------- | ------- | ------- |
| `src/lib.rs` | re-exports | — | 100 |
| `src/video.rs` | `VideoFrame`, `VideoFormat` | `VideoStegoModule` | 64 |
| `src/audio.rs` | `AudioBuffer` | `AudioStegoModule` | 45 |
| `src/packet.rs` | `GenericPacket`, `Locator`, `PacketEnvelope`, codecs, limits/errors, `FIELD_PARENT_ID` nesting, `GenericPacket::decode_nested` (bounded chain decode) | `PacketCodec` | 2069 |
| `src/carrier.rs` | `CarrierDescriptor`, `EmbeddingConfig`, reports, `SpatialLsb`, `AudioSpatialLsb`, keyed kernels | `CarrierEmbedder`, `CarrierExtractor` | 1625 |
| `src/crypto.rs` | `Signer`, `Verifier`, `SignaturePayload`, `HashAlgorithm` | — | 600 |
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
- Packet flags ⇔ transform descriptors are checked for mutual consistency at decode (no silent downgrades); unknown non-critical envelope fields are preserved; PKT-009 full bounded nested decode: `GenericPacket::decode_nested` expands parent-id chains with `max_nesting_depth` (3) and `max_aggregate_nested_bytes` (64 MiB), cycle detection included
- Spread-spectrum: host-canceling differential-pair modulation (pre-0.8 absolute-correlation embeds are no longer extractable — re-embed)

## Features

| Feature | Dependencies | Purpose |
| --------- | ------------- | --------- |
| `ethereum` | `k256`, `sha3` | secp256k1 + EIP-191 signing backend |

## Test Coverage

381 unit tests (inline) + 125 integration tests (80 in `integration_tests.rs` + 37 in `ots_integration_tests.rs` + 6 in `golden_vectors.rs` + 2 in `calibration.rs`) = **506 total**

