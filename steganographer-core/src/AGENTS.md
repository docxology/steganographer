# AGENTS.md — steganographer-core/src/

## Module Details

### lib.rs

Entry point. Declares and re-exports: `packet`, `carrier`, `placement`, `video`,
`audio`, `crypto`, `config`, `lsb_video`, `lsb_audio`, `overlay`, `info_bar`,
`signer_backend`, `metrics`, `dct_video`, `spread_spectrum`, `encryption`,
`error_correction`, `multi_frame`, `kdf`, `password`, `transforms`, `adaptive`,
`hash_chain`, `steganalysis`, `forensics`, `mdct_audio`, `ots_client`,
`ots_config`, `ots_handler`, `wasm_inspector`.

### packet.rs

- `Locator` — fixed 32-byte `STG3` protocol 1.0-alpha bootstrap
- `PacketEnvelope` — canonical bounded TLV metadata and digest
- `GenericPacket` — arbitrary byte body plus locator/envelope
- `DecodeLimits`, `PacketError` — hostile-input ceilings and typed failures
  (including PKT-009 `max_nesting_depth` = 3 and `max_aggregate_nested_bytes`
  = 64 MiB; unknown non-critical fields are preserved, unknown critical
  fields reject)
- `PacketCodec` — byte codec contract implemented by `GenericPacketCodec` and
  legacy `SignaturePayloadCodec`

### carrier.rs

- `CarrierDescriptor`, `EmbeddingConfig` — shared decoded-unit descriptor
  (`Rgb8`/`ByteStream`/`PcmS16Le`), unit stride, and checked 1–4 bit strength
- `CarrierEmbedder`, `CarrierExtractor` — capacity/embed/extract contracts
- `SpatialLsb` — sequential generic packet kernel over byte units with
  locator-first bounded extraction and descriptor validation
- `AudioSpatialLsb` — sequential generic packet kernel over interleaved S16LE
  PCM samples (one unit per sample; only the low byte's LSBs change)
- `KeyedSpatialLsb` / `KeyedAudioSpatialLsb` — keyed byte/sample packet
  kernels: a short recognition tag at the canonical bootstrap slots (key-less
  scanners see no `STG3` magic) and the packet spread over keyed-permuted
  positions; wrong/missing keys report `NoPacket`

### placement.rs

- `KeyedPermutation` — O(1)-memory keyed permutation over `0..len` built from a
  balanced Feistel network over the next power-of-two domain with cycle walking
  (`PLC-002` bounded-memory schedule); every slot is hit exactly once and a
  different key/label yields an unrelated order
- `InterleavedSchedule` — coprime-stride even-spread slot mapping
  (`PLACEMENT_INTERLEAVED` = 3, `PLC-001`); keyed by `derive_placement_key`
  over a domain/label pair, deterministic and length-independent

### password.rs

- `Argon2Params`, `PasswordKdfError` — Argon2id (RFC 9106) password-stretching
  parameters and typed failures
- `derive_master_from_password`, `derive_all_from_password` — stretch a
  human-chosen password into a high-entropy master, then reuse `kdf::derive_all`
- `generate_salt`, `RECOMMENDED_MEMORY_KIB` / `RECOMMENDED_ITERATIONS` — 128-bit
  salt generation and the OWASP parameter floor

### transforms.rs

- `TransformContext` — packet identity (id, nonce, kind, length) bound into AEAD
- `apply` / `reverse` — ChaCha20-Poly1305 encryption and chunked Reed-Solomon
  error correction over a generic packet body, with envelope descriptor + flag
  bookkeeping
- `is_encrypted`, `TransformError`, `DEFAULT_ECC_CHUNK_LEN`, `MAX_ECC_PARITY`

### video.rs

- `VideoFormat` — `Rgb8` (3 bpp), `Bgra8` (4 bpp), `Yuv420` (1.5 bpp)
- `VideoFrame` — mutable view: `width`, `height`, `stride`, `format`, `data: &mut [u8]`, `frame_index`
- `VideoStegoModule` — trait with `embed(&mut frame, sig)` and `extract(&frame)` methods

### audio.rs

- `AudioBuffer` — `channels: u16`, `sample_rate: u32`, `samples: &mut [i16]`, `frame_index: u64`
- `AudioStegoModule` — trait with `embed(&mut buf, sig)` and `extract(&buf)` methods
- Helper: `sample_count()`, `duration_secs()`

### crypto.rs

- `SignaturePayload` — 109 bytes: `magic(4) + version(1) + frame_index(8) + hash(32) + signature(64)`, with `from_bytes()` / `to_bytes()`, magic header validation
- `Signer` — `generate()`, `from_bytes()`, `sign_frame()`, `signing_key_bytes()`, `verifying_key()`
- `Verifier` — `new()`, `from_bytes()`, `verify()` — recomputes BLAKE3 hash, checks Ed25519 signature

### signer_backend.rs

- `SignerBackend` trait — `name()`, `sign()`, `verify()`, `public_key_bytes()`, `signature_size()`, `display_identity()`
- `Ed25519Backend` — `generate()`, `new()`, `from_bytes()`, `signing_key_bytes()`, `verifying_key()`
- `Ed25519Verifier` — `new()`, `from_bytes()`, `verify()` (verification-only, no signing key)
- `MlDsaBackend` — `generate()`, `from_seed()`, ML-DSA-44/65/87 post-quantum
  signing backend — **real FIPS 204** via the RustCrypto `ml-dsa` crate:
  seed-based keygen (FIPS 204 Algorithm 6), deterministic signing
  (Algorithm 2), real public-key verification (Algorithm 3). Note: pre-0.8
  "ML-DSA" payloads were keyed MACs over the private seed and are NOT
  verifiable — re-sign.
- `MlDsaVerifier` — `new()`, `from_public_key_bytes()`, `verify()`
  (verification-only, from raw FIPS 204 public-key bytes)
- `HybridBackend` — `generate()`, `new()`, dual Ed25519 + ML-DSA signing
  (concatenated signature `(Ed25519_sig ∥ ML-DSA_sig)`, concatenated public key)
- `HybridVerifier` — `new()`, `from_public_key_bytes()`, `verify()`; both
  halves must be valid
- `EthereumBackend`\* — `generate()`, `from_signing_key()`, `address()`, `personal_sign_hash()`
- `EthereumVerifier`\* — address-based verification

\* Feature-gated behind `ethereum`

### metrics.rs

- `StegoMetrics` — thread-safe atomic counters (lock-free for GStreamer callback threads)
- Methods: `record_frame()`, `record_verify_ok/fail()`, `record_sign/verify/embed_duration()`
- `to_json()` — JSON serialization for dashboard consumption
- `avg_sign_latency_us()`, `avg_verify_latency_us()`, `average_fps()`, `reset()`

### config.rs

- `Config` — `from_toml()` top-level parser
- `LsbSignatureConfig` — `bits: u8`, `key: Option<String>`, `key_file: Option<String>`, `key_bytes()` → `Result<[u8;32]>`
- `OverlayConfig` — `text`, `position`, `font_size` (all `Option<String>` / `Option<u32>`)
- `InfoBarConfig` — `label`, `show_barcode`, `show_qr`, `show_timestamp`
- `hex_decode()` private helper

### lsb_video.rs

- `LsbVideo::new(bits)` — bits 1–4
- `embed()` — length-prefix (32 bits) + payload bits → LSB of frame bytes
- `extract()` — read length prefix → read payload → `SignaturePayload::from_bytes()`

### lsb_audio.rs

- `LsbAudio::new(bits, key)` — 32-byte key for PRNG, `bits()` accessor
- `gen_indices()` — Fisher-Yates shuffle using `StdRng::from_seed(key XOR frame_index)` (private)
- `embed()` / `extract()` — write/read bits at permuted sample indices

### overlay.rs

- `TextOverlay` — `new(text, position)`, `.with_color()`, `.with_scale()`
- `expand_template(text, frame_index)` — substitutes `{timestamp}`, `{frame_index}`, `{date}`, `{time}` placeholders
- `render_text()` (private) — 8×8 bitmap font lookup, scaled pixel rendering with bounds checks
- `get_glyph(char)` → `[u8; 8]` — full A-Z, 0-9, punctuation, fallback box
- Template expansion happens in `embed()` before rendering, original text restored after

### info_bar.rs

- `InfoBar` — `new(label)`, with builder methods: `.with_barcode()`, `.with_qr()`, `.with_timestamp()`
- Renders exoteric watermark strip: label text, timestamp, barcode pattern from the signature hash, QR code
- Each feature is independently toggleable

### forensics.rs

- `ForensicScan` — scan result struct with structural + statistical findings
  and `text_findings: Vec<unicode_text::TextFinding>` (FOR-005 detector IDs)
- `detect_text_stego(data)` — decode text and collect Unicode steganography findings
- `scan_bytes(data)` — bounded byte-level forensic scan

### unicode_text.rs

- Unicode/text steganography detectors (FOR-005) with stable detector IDs:
  zero-width characters, variation selectors, bidi controls, whitespace
  anomalies, homoglyph suspects
- `TextFinding` — `detector_id`, code-point locations, severity, and preview;
  normalization handled so equivalent sequences do not double-report

### ots_config.rs

- `OtsConfig` — `[ots]` TOML block: `enabled`, `server_url`, `method`
  (`bitcoin`/`ethereum`), `interval_secs`, `proof_dir`, `timeout_secs`;
  entirely opt-in (disabled by default)
- `OtsSettings` — resolved `Copy` view for hot paths
