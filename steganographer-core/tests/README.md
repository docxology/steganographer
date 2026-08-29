# steganographer-core/tests/

Integration tests for the steganographer-core crate.

## Files

| File | Tests | Lines | Description |
| ------ | ------- | ------- | ------------- |
| `integration_tests.rs` | 80 | ~1900 | Cross-module E2E, crypto, LSB, config, overlay, template, info_bar, metrics, signer_backend, encryption, ECC, DCT, spread-spectrum, adaptive, KDF, hash-chain, steganalysis, multi-frame, WASM, and stress tests |
| `ots_integration_tests.rs` | 37 | ~450 | OpenTimestamps client, config, and handler tests |

## Test Categories (`integration_tests.rs`)

| Category | Count | What They Verify |
| ---------- | ------- | ------------------ |
| End-to-end | 4 | Full sign→embed→extract→verify for video and audio, multi-bit audio, LSB+overlay pipeline |
| Crypto | 5 | Key roundtrip, verifier from bytes, audio hash sensitivity, payload field preservation, empty-data sign/verify |
| LSB Video | 7 | 2–4 bit roundtrip, minimum/too-small frames, high-bit preservation, BGRA format |
| LSB Audio | 7 | 2–4 bit roundtrip, wrong key/frame defense, high-bit preservation, negative samples |
| Config | 5 | example.toml parse, key length errors, video-only, audio-only |
| Overlay | 4 | Scale 1, full ASCII glyph set, tiny-frame no-panic, `extract()` returns `None` |
| Template Expansion | 3 | `{frame_index}` substitution, plain text stability, `expand_template()` |
| Info Bar Toggles | 2 | Barcode/QR disabled, all disabled |
| Config Overlay Parsing | 1 | TOML with template placeholders |
| Metrics | 2 | Frame counters, `to_json()` roundtrip validation |
| Signer Backend | 6 | Ed25519 E2E, public key bytes, wrong-key failure, display identity, signature size, deterministic `from_bytes` |
| Payload/Serialization | 3 | Size constant, invalid bytes, bad magic |
| Post-quantum & Hybrid | 2 | `MlDsaBackend`, `HybridBackend` E2E |
| Multi-frame | 2 | Signature and generic payload sharding |
| WASM inspector | 1 | In-memory capacity and forensic metadata extraction |
| Stress | 2 | Sequential embeds, multiple signers |
| Frequency-domain & adaptive kernels | 5 | DCT, spread-spectrum video/audio, adaptive LSB round-trips |
| Encryption & ECC | 5 | AEAD roundtrip/tamper/wrong-key, Reed-Solomon roundtrip/correction |
| KDF / hash chain / steganalysis | 4 | `derive_all`, hash chain, chi-squared and combined analysis |
| Hash-algorithm variants | 2 | SHA-256 and SHA-3 sign/verify |
| Video/audio buffer helpers | 8 | Pixel byte counts, formats, sample count, duration |
| **Total** | **80** | |

## Run

```bash
cargo test -p steganographer-core --test integration_tests
cargo test -p steganographer-core --test ots_integration_tests
```
