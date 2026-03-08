# steganographer-core/tests/

Integration tests for the steganographer-core crate.

## Files

| File | Tests | Lines | Description |
| ------ | ------- | ------- | ------------- |
| `integration_tests.rs` | 58 | ~1100 | Cross-module E2E, crypto, LSB, config, overlay, template, info_bar, metrics, signer_backend, and stress tests |

## Test Categories

| Category | Count | What They Verify |
| ---------- | ------- | ------------------ |
| End-to-end | 2 | Full sign→embed→extract→verify for video and audio |
| Pipeline | 1 | LSB + overlay applied to same frame |
| Crypto | 7 | Key roundtrip, verifier from bytes, audio hash, u64::MAX, cross-verification |
| LSB Video | 5 | 1–4 bit roundtrip, BGRA format, capacity errors |
| LSB Audio | 7 | 1–4 bit roundtrip, wrong key/frame defense, negative samples |
| Config | 7 | example.toml parse, key lengths, video/audio only, defaults, errors |
| Overlay | 6 | Positions, colors, scale, empty text, overflow |
| Template Expansion | 3 | `{frame_index}` substitution, plain text stability, `expand_template()` |
| Info Bar Toggles | 2 | Barcode/QR disabled, all disabled |
| Config Overlay Parsing | 1 | TOML with template placeholders |
| Metrics JSON | 1 | `to_json()` roundtrip validation |
| Signer Backend E2E | 2 | `Ed25519Backend` sign/verify, public key export |
| Payload/Serialization | 3 | Size constants, invalid bytes, video format bytes |
| Stress | 2 | Sequential embeds, multiple signers |

## Run

```bash
cargo test -p steganographer-core --test integration_tests
```
