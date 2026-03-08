# AGENTS.md — steganographer-core/tests/

## Purpose

Integration tests that exercise cross-module interactions and end-to-end workflows.

## Coverage

58 tests in `integration_tests.rs` (~1100 lines) covering:

| Category | Count | Tests |
| ---------- | ------- | ------- |
| E2E video sign → embed → extract → verify | 1 | `test_e2e_video_sign_embed_extract_verify` |
| E2E audio sign → embed → extract → verify | 1 | `test_e2e_audio_sign_embed_extract_verify` |
| E2E video pipeline with overlay | 1 | `test_pipeline_lsb_then_overlay` |
| Crypto key round-trip | 7 | Key export/import, tamper detection, cross-verification |
| LSB video variations | 5 | Bits 1–4, BGRA format, capacity errors |
| LSB audio variations | 7 | Bits 1–4, key/frame index compat, negative samples |
| Overlay text rendering | 6 | Positions, colors, scale, empty text, overflow |
| Template expansion | 3 | `{frame_index}` substitution, plain text stability, `expand_template()` |
| Info bar toggles | 2 | Barcode/QR disabled, all disabled |
| Config overlay parsing | 1 | TOML with template placeholders |
| Metrics JSON | 1 | `to_json()` roundtrip |
| Signer backend E2E | 2 | `Ed25519Backend` sign/verify, public key export |
| Payload/serialization | 3 | Size constants, invalid bytes, video format bytes |
| Stress tests | 2 | Sequential embeds, multiple signers |
| Config parsing | 7 | Defaults, overrides, audio, full, errors |

## Test Dependencies

Uses only `steganographer_core` public API — no test-only utilities or mocks.
