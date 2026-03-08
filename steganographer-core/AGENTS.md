# AGENTS.md — steganographer-core

## Purpose

Pure, zero-I/O steganography algorithms, cryptographic signing (Ed25519 + Ethereum), metrics, and config parsing.

## Module Map

| File | Public Types | Trait | Lines |
| ------ | ------------- | ------- | ------- |
| `src/lib.rs` | re-exports | — | 37 |
| `src/video.rs` | `VideoFrame`, `VideoFormat` | `VideoStegoModule` | 65 |
| `src/audio.rs` | `AudioBuffer` | `AudioStegoModule` | 46 |
| `src/crypto.rs` | `Signer`, `Verifier`, `SignaturePayload` | — | 261 |
| `src/signer_backend.rs` | `SignerBackend`, `Ed25519Backend`, `Ed25519Verifier`, `EthereumBackend`*, `EthereumVerifier`* | `SignerBackend` | 438 |
| `src/metrics.rs` | `StegoMetrics` | — | 180 |
| `src/config.rs` | `Config`, `GlobalConfig`, `VideoConfig`, `AudioConfig`, `PayloadConfig` | — | 290 |
| `src/lsb_video.rs` | `LsbVideo` | `VideoStegoModule` | 290 |
| `src/lsb_audio.rs` | `LsbAudio` | `AudioStegoModule` | 343 |
| `src/overlay.rs` | `TextOverlay`, `OverlayPosition`, `expand_template` | `VideoStegoModule` | 402 |
| `src/info_bar.rs` | `InfoBar` | `VideoStegoModule` | 496 |
| `tests/integration_tests.rs` | — | — | ~1100 |

\* Feature-gated behind `ethereum`

## Key Constants

- `SignaturePayload::SERIALIZED_SIZE` = 104 bytes (8 + 32 + 64)
- LSB range: 1–4 bits per byte/sample
- Minimum capacity at 1-bit: 864 bytes/samples

## Features

| Feature | Dependencies | Purpose |
| --------- | ------------- | --------- |
| `ethereum` | `k256`, `sha3` | secp256k1 + EIP-191 signing backend |

## Test Coverage

56 unit tests (inline) + 58 integration tests = **114 total**
