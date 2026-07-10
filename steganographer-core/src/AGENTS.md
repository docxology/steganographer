# AGENTS.md — steganographer-core/src/

## Module Details

### lib.rs

Entry point. Declares and re-exports: `video`, `audio`, `crypto`, `config`, `lsb_video`, `lsb_audio`, `overlay`, `info_bar`, `signer_backend`, `metrics`.

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
- `LsbSignatureConfig` — `bits: u8, key: String`, `key_bytes()` → `Result<[u8;32]>`
- `OverlayConfig` — `text`, `position`, `font_size` (all `Option<String>` / `Option<u32>`)
- `InfoBarConfig` — `label`, `show_barcode`, `show_qr`, `show_timestamp`
- `hex_decode()` private helper

### lsb_video.rs

- `LsbVideo::new(bits)` — bits 1–4
- `embed()` — length-prefix (32 bits) + payload bits → LSB of frame bytes
- `extract()` — read length prefix → read payload → `SignaturePayload::from_bytes()`

### lsb_audio.rs

- `LsbAudio::new(bits, key)` — 32-byte key for PRNG, `bits()` accessor
- `generate_indices()` — Fisher-Yates shuffle using `StdRng::from_seed(key XOR frame_index)`
- `embed()` / `extract()` — write/read bits at permuted sample indices

### overlay.rs

- `TextOverlay` — `new(text, position)`, `.with_color()`, `.with_scale()`
- `expand_template(text, frame_index)` — substitutes `{timestamp}`, `{frame_index}`, `{date}`, `{time}` placeholders
- `render_text()` — 8×8 bitmap font lookup, scaled pixel rendering with bounds checks
- `get_glyph(char)` → `[u8; 8]` — full A-Z, 0-9, punctuation, fallback box
- Template expansion happens in `embed()` before rendering, original text restored after

### info_bar.rs

- `InfoBar` — `new(label)`, with builder methods: `.with_barcode()`, `.with_qr()`, `.with_timestamp()`
- Renders exoteric watermark strip: label text, timestamp, DataMatrix/QR code, 1D Code-128 barcode
- Each feature is independently toggleable
