# AGENTS.md — steganographer-core

## Purpose

Pure, zero-I/O steganography algorithms, cryptographic signing (Ed25519 + Ethereum), payload encryption, error correction, metrics, and config parsing.

## Module Map

| File | Public Types | Trait | Lines |
| ------ | ------------- | ------- | ------- |
| `src/lib.rs` | re-exports | — | 48 |
| `src/video.rs` | `VideoFrame`, `VideoFormat` | `VideoStegoModule` | 64 |
| `src/audio.rs` | `AudioBuffer` | `AudioStegoModule` | 45 |
| `src/crypto.rs` | `Signer`, `Verifier`, `SignaturePayload`, `HashAlgorithm` | — | 538 |
| `src/signer_backend.rs` | `SignerBackend`, `Ed25519Backend`, `Ed25519Verifier`, `EthereumBackend`*, `EthereumVerifier`* | `SignerBackend` | 442 |
| `src/metrics.rs` | `StegoMetrics` | — | 215 |
| `src/config.rs` | `Config`, `GlobalConfig`, `VideoConfig`, `AudioConfig`, `PayloadConfig`, `LsbSignatureConfig`, `OverlayConfig`, `InfoBarConfig`, etc. | — | 478 |
| `src/lsb_video.rs` | `LsbVideo` | `VideoStegoModule` | 289 |
| `src/lsb_audio.rs` | `LsbAudio` | `AudioStegoModule` | 347 |
| `src/overlay.rs` | `TextOverlay`, `OverlayPosition`, `expand_template` | `VideoStegoModule` | 401 |
| `src/info_bar.rs` | `InfoBar` | `VideoStegoModule` | 490 |
| `src/dct_video.rs` | `DctVideo` | `VideoStegoModule` | 463 |
| `src/spread_spectrum.rs` | `SpreadSpectrumVideo`, `SpreadSpectrumAudio`, `capacity()` | — | 592 |
| `src/encryption.rs` | `EncryptionKey`, `encrypt()`, `decrypt()` | — | 270 |
| `src/error_correction.rs` | `encode()`, `decode()`, `correction_capability()` | — | 404 |
| `src/multi_frame.rs` | `SignatureShard`, `split()`, `reconstruct()` | — | 263 |
| `tests/integration_tests.rs` | — | — | ~1100 |

\* Feature-gated behind `ethereum`

## Key Constants

- `SignaturePayload::SERIALIZED_SIZE` = 104 bytes (8 + 32 + 64)
- LSB range: 1–4 bits per byte/sample
- Minimum capacity at 1-bit: 864 bytes/samples
- Encryption: ChaCha20-Poly1305 AEAD (256-bit key, 96-bit nonce)
- Error correction: Reed-Solomon over GF(2⁸), single-error correction
- Multi-frame: XOR n-of-n secret sharing

## Features

| Feature | Dependencies | Purpose |
| --------- | ------------- | --------- |
| `ethereum` | `k256`, `sha3` | secp256k1 + EIP-191 signing backend |

## Test Coverage

115 unit tests (inline) + 59 integration tests = **174 total**
