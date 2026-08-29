# AGENTS.md — steganographer-core/tests/

## Purpose

Integration tests that exercise cross-module interactions and end-to-end workflows.

## Coverage

80 tests in `integration_tests.rs` (~1900 lines) covering:

| Category | Count | Tests |
| ---------- | ------- | ------- |
| E2E video sign → embed → extract → verify | 1 | `test_e2e_video_sign_embed_extract_verify` |
| E2E audio sign → embed → extract → verify | 1 | `test_e2e_audio_sign_embed_extract_verify` |
| E2E audio multi-bit levels all verify | 1 | `test_e2e_audio_multi_bit_levels_all_verify` |
| E2E video pipeline with overlay | 1 | `test_pipeline_lsb_then_overlay` |
| Crypto round-trip | 5 | Key export/import, verifier from bytes, hash sensitivity, field preservation, empty-data sign/verify |
| LSB video variations | 7 | 2–4 bit round-trips, minimum frame size, one-byte-too-small, high-bit preservation, BGRA |
| LSB audio variations | 7 | 2–4 bit round-trips, wrong key/frame index, high-bit preservation, negative samples |
| Overlay text rendering | 4 | Scale 1, full ASCII glyph set, tiny-frame no-panic, `extract()` returns `None` |
| Template expansion | 3 | `{frame_index}` substitution, plain text stability, `expand_template()` |
| Info bar toggles | 2 | Barcode/QR disabled, all disabled |
| Config overlay parsing | 1 | TOML with template placeholders |
| Metrics | 2 | Frame counter accuracy, comprehensive JSON |
| Signer backend | 6 | Ed25519 E2E, public key bytes, wrong-key failure, display identity, signature size, deterministic `from_bytes` |
| Payload/serialization | 3 | Size constant, invalid bytes, bad magic |
| Post-quantum (ML-DSA) & Hybrid | 2 | `MlDsaBackend` E2E sign/verify, `HybridBackend` E2E sign/verify |
| Multi-frame sharding | 2 | Signature `split()`/`reconstruct()` and generic payload sharding E2E |
| WASM inspector | 1 | Zero-I/O in-memory capacity and forensic metadata extraction |
| Stress tests | 2 | Sequential embeds, multiple signers |
| Config parsing | 5 | `example.toml` parse, key-length errors, video-only, audio-only |
| DCT / spread-spectrum / adaptive kernels | 5 | Round-trips for `DctVideo`, `SpreadSpectrumVideo/Audio`, `AdaptiveLsb` |
| Encryption & error correction | 5 | ChaCha20-Poly1305 roundtrip/tamper/wrong-key, Reed-Solomon roundtrip/correction |
| KDF / hash chain / steganalysis | 4 | `derive_all`, hash chain, chi-squared and combined analysis |
| Hash-algorithm variants | 2 | SHA-256 and SHA-3 sign/verify |
| Video/audio buffer helpers | 8 | Pixel byte counts, formats, sample count, duration |

## Test Dependencies

Uses only `steganographer_core` public API — no test-only utilities or mocks.
