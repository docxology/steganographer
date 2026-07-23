# API Reference

> **Note**: This reference covers the public Rust API of the `steganographer-core` and `steganographer-gst` crates, including the new pipeline configuration structs introduced for config-driven pipeline construction.

## Crate: `steganographer-core`

### Module: `config`

#### `Config`

Top-level configuration struct, deserialized from TOML.

```rust
pub struct Config {
    pub global: GlobalConfig,
    pub video: Option<VideoConfig>,
    pub audio: Option<AudioConfig>,
}
```

| Method | Signature | Description |
| -------- | ----------- | ------------- |
| `from_file` | `fn from_file(path: &str) -> Result<Self>` | Parse a TOML file into `Config` |
| `from_str` | `fn from_str(toml: &str) -> Result<Self>` | Parse a TOML string into `Config` |

#### `GlobalConfig`

```rust
pub struct GlobalConfig {
    pub log_level: Option<String>,
    pub hash_algorithm: Option<String>,  // "blake3" (default), "sha256", "sha3-256"
    pub key_file: Option<String>,        // Path to file with hex key (overrides inline)
}
```

| Method | Signature | Description |
| -------- | ----------- | ------------- |
| `hash_algorithm_name` | `fn hash_algorithm_name(&self) -> &str` | Returns algorithm name or `"blake3"` default |

#### `VideoConfig`

```rust
pub struct VideoConfig {
    pub pipeline: Option<VideoPipelineConfig>,
    pub input: EndpointConfig,
    pub output: EndpointConfig,
    pub stego: VideoStegoConfig,
}
```

#### `VideoPipelineConfig`

```rust
pub struct VideoPipelineConfig {
    pub width: Option<u32>,       // default: 640
    pub height: Option<u32>,      // default: 480
    pub framerate: Option<u32>,   // default: 30
    pub opacity: Option<f64>,     // default: 1.0
    pub payload: Option<PayloadConfig>,
}
```

| Method | Signature | Description |
| -------- | ----------- | ------------- |
| `width_or_default` | `fn width_or_default(&self) -> u32` | Width or 640 |
| `height_or_default` | `fn height_or_default(&self) -> u32` | Height or 480 |
| `framerate_or_default` | `fn framerate_or_default(&self) -> u32` | Framerate or 30 |
| `opacity_or_default` | `fn opacity_or_default(&self) -> f64` | Opacity or 1.0 |

#### `PayloadConfig`

Cryptographic payload configuration including encryption and error correction.

```rust
pub struct PayloadConfig {
    pub r#type: Option<String>,               // "signature" (default) or "custom"
    pub size: Option<u32>,                    // default: 109 for v2 format
    pub signing_backend: Option<String>,      // "ed25519" (default) or "ethereum"
    pub encrypt: Option<bool>,                // Enable ChaCha20-Poly1305 encryption
    pub encryption_key: Option<String>,       // Hex-encoded 32-byte key
    pub encryption_key_file: Option<String>,  // Path to key file
    pub error_correction: Option<String>,     // "none" (default) or "reed_solomon"
    pub multi_frame_spread: Option<u32>,      // Frames to spread signature across (default: 1)
}
```

| Method | Signature | Description |
| -------- | ----------- | ------------- |
| `encrypt_enabled` | `fn encrypt_enabled(&self) -> bool` | Whether encryption is enabled |
| `spread_count` | `fn spread_count(&self) -> u32` | Multi-frame spread count (min 1) |

#### `AudioConfig`

```rust
pub struct AudioConfig {
    pub input: EndpointConfig,
    pub output: EndpointConfig,
    pub stego: AudioStegoConfig,
}
```

#### `EndpointConfig`

```rust
pub struct EndpointConfig {
    pub r#type: String,            // "device", "file", "network"
    pub backend: Option<String>,    // "v4l2", "avfoundation", etc
    pub device: Option<String>,     // "/dev/video0"
    pub path: Option<String>,       // File path
}
```

#### `VideoStegoConfig`

```rust
pub struct VideoStegoConfig {
    pub pipeline: Vec<String>,
    pub lsb_signature: Option<LsbSignatureConfig>,
    pub overlay: Option<OverlayConfig>,
    pub info_bar: Option<InfoBarConfig>,
}
```

#### `AudioStegoConfig`

```rust
pub struct AudioStegoConfig {
    pub pipeline: Vec<String>,
    pub lsb_signature: Option<LsbSignatureConfig>,
}
```

#### `LsbSignatureConfig`

```rust
pub struct LsbSignatureConfig {
    pub bits: u8,
    pub key: Option<String>,      // 64 hex chars
    pub key_file: Option<String>, // Path to key file (overrides `key`)
}
```

| Method | Signature | Description |
| -------- | ----------- | ------------- |
| `key_bytes` | `fn key_bytes(&self) -> Result<[u8; 32]>` | Decode hex key from `key_file` or inline `key` to 32-byte array |

#### `InfoBarConfig`

```rust
pub struct InfoBarConfig {
    pub label: Option<String>,          // default: "STEGANOGRAPHER"
    pub show_barcode: Option<bool>,     // default: true
    pub show_qr: Option<bool>,          // default: true
    pub show_timestamp: Option<bool>,   // default: true
}
```

| Method | Signature | Description |
| -------- | ----------- | ------------- |
| `show_barcode` | `fn show_barcode(&self) -> bool` | Whether to show barcode |
| `show_qr` | `fn show_qr(&self) -> bool` | Whether to show QR code |
| `show_timestamp` | `fn show_timestamp(&self) -> bool` | Whether to show timestamp |
| `label_or_default` | `fn label_or_default(&self) -> &str` | Label or `"STEGANOGRAPHER"` |

#### `resolve_key` (module-level function)

```rust
pub fn resolve_key(inline_hex: Option<&str>, key_file: Option<&str>) -> Result<[u8; 32]>
```

Resolve a 32-byte key from either an inline hex string or a file path. Priority: file > inline hex.

#### `OverlayConfig`

```rust
pub struct OverlayConfig {
    pub text: Option<String>,
    pub position: Option<String>,
    pub font_size: Option<u32>,
}
```

---

### Module: `crypto`

#### `SignaturePayload`

A signed payload embedded into or extracted from media frames.

```rust
pub struct SignaturePayload {
    pub frame_index: u64,
    pub hash: [u8; 32],
    pub signature: Signature,
}
```

| Constant | Value | Description |
| -------- | ----------- | ------------- |
| `SERIALIZED_SIZE` | 104 | Total bytes: 8 + 32 + 64 |

| Method | Signature | Description |
| -------- | ----------- | ------------- |
| `to_bytes` | `fn to_bytes(&self) -> [u8; 104]` | Serialize to little-endian bytes |
| `from_bytes` | `fn from_bytes(buf: &[u8; 104]) -> Result<Self>` | Deserialize from bytes |

#### `Signer`

Signs frame data using BLAKE3/SHA-256/SHA-3 + Ed25519.

| Method | Signature | Description |
| -------- | ----------- | ------------- |
| `new` | `fn new(signing_key: SigningKey) -> Self` | Create with existing key (BLAKE3 default) |
| `with_hash_algorithm` | `fn with_hash_algorithm(signing_key: SigningKey, algo: HashAlgorithm) -> Self` | Create with specific hash algorithm |
| `generate` | `fn generate() -> Self` | Generate random keypair |
| `verifying_key` | `fn verifying_key(&self) -> VerifyingKey` | Get public key |
| `signing_key_bytes` | `fn signing_key_bytes(&self) -> [u8; 32]` | Export private key bytes |
| `from_bytes` | `fn from_bytes(bytes: &[u8; 32]) -> Self` | Import from raw bytes |
| `set_hash_algorithm` | `fn set_hash_algorithm(&mut self, algo: HashAlgorithm)` | Change hash algorithm |
| `hash_algorithm` | `fn hash_algorithm(&self) -> HashAlgorithm` | Get current hash algorithm |
| `sign_frame` | `fn sign_frame(&self, frame_index: u64, video: &[u8], audio: Option<&[u8]>) -> SignaturePayload` | Hash and sign frame data |

#### `HashAlgorithm`

```rust
pub enum HashAlgorithm {
    Blake3,
    Sha256,
    Sha3_256,
}
```

Defaults to `Blake3`. Configurable via `[global] hash_algorithm` in TOML.

#### `Verifier`

Verifies signed frame payloads.

| Method | Signature | Description |
| -------- | ----------- | ------------- |
| `new` | `fn new(verifying_key: VerifyingKey) -> Self` | Create from public key |
| `from_bytes` | `fn from_bytes(bytes: &[u8; 32]) -> Result<Self>` | Import from raw bytes |
| `verify` | `fn verify(&self, payload: &SignaturePayload, video: &[u8], audio: Option<&[u8]>) -> bool` | Verify payload against data |

---

### Module: `video`

#### `VideoFormat`

```rust
pub enum VideoFormat {
    Rgb8,
    Bgra8,
    Yuv420,
}
```

#### `VideoFrame`

```rust
pub struct VideoFrame<'a> {
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub format: VideoFormat,
    pub data: &'a mut [u8],
    pub frame_index: u64,
}
```

#### `VideoStegoModule` (Trait)

```rust
pub trait VideoStegoModule: Send {
    fn embed(&mut self, frame: &mut VideoFrame, sig: Option<&SignaturePayload>) -> Result<()>;
    fn extract(&self, frame: &VideoFrame) -> Result<Option<SignaturePayload>>;
}
```

**Implementors**: `LsbVideo`, `TextOverlay`

---

### Module: `audio`

#### `AudioBuffer`

```rust
pub struct AudioBuffer<'a> {
    pub channels: u32,
    pub sample_rate: u32,
    pub samples: &'a mut [i16],
    pub frame_index: u64,
}
```

#### `AudioStegoModule` (Trait)

```rust
pub trait AudioStegoModule: Send {
    fn embed(&mut self, buf: &mut AudioBuffer, sig: Option<&SignaturePayload>) -> Result<()>;
    fn extract(&self, buf: &AudioBuffer) -> Result<Option<SignaturePayload>>;
}
```

**Implementors**: `LsbAudio`

---

### Module: `lsb_video`

#### `LsbVideo`

Sequential LSB video steganography module.

| Method | Signature | Description |
| -------- | ----------- | ------------- |
| `new` | `fn new(bits: u8) -> Self` | Create with 1–4 bits per byte |

Implements `VideoStegoModule`.

---

### Module: `lsb_audio`

#### `LsbAudio`

Keyed PRNG LSB audio steganography module.

| Method | Signature | Description |
| -------- | ----------- | ------------- |
| `new` | `fn new(bits: u8, key: [u8; 32]) -> Self` | Create with bits per sample and PRNG key |

Implements `AudioStegoModule`.

---

### Module: `overlay`

#### `OverlayPosition`

```rust
pub enum OverlayPosition {
    TopLeft, TopRight, BottomLeft, BottomRight, Center,
}
```

| Method | Signature | Description |
| -------- | ----------- | ------------- |
| `from_str` | `fn from_str(s: &str) -> Self` | Parse from config string (e.g., `"top-left"`) |

#### `TextOverlay`

| Method | Signature | Description |
| -------- | ----------- | ------------- |
| `new` | `fn new(text: String, position: OverlayPosition) -> Self` | Create overlay |
| `with_color` | `fn with_color(self, r: u8, g: u8, b: u8) -> Self` | Set RGB color |
| `with_scale` | `fn with_scale(self, scale: u8) -> Self` | Set character scale (1–8) |

Implements `VideoStegoModule`.

---

### Module: `info_bar`

#### `InfoBar`

Exoteric visual watermark rendering timestamp, Code-128 barcode, and QR code.

| Method | Signature | Description |
| -------- | ----------- | ------------- |
| `new` | `fn new() -> Self` | Create default InfoBar overlay |

Implements `VideoStegoModule`.

---

### Module: `signer_backend`

#### `SignerBackend` (Trait)

Pluggable signing backend abstraction. Each backend handles hashing, signing, and verification.

```rust
pub trait SignerBackend: Send + Sync {
    fn name(&self) -> &str;
    fn sign(&self, data: &[u8]) -> Vec<u8>;
    fn verify(&self, data: &[u8], signature: &[u8]) -> bool;
    fn public_key_bytes(&self) -> Vec<u8>;
    fn signature_size(&self) -> usize;
    fn display_identity(&self) -> String;
}
```

#### `Ed25519Backend`

Default signing backend. Uses BLAKE3 for frame hashing and Ed25519 for digital signatures. Produces 64-byte signatures.

| Method | Signature | Description |
| -------- | ----------- | ------------- |
| `new` | `fn new(signing_key: SigningKey) -> Self` | Create from existing key |
| `generate` | `fn generate() -> Self` | Generate random keypair |
| `from_bytes` | `fn from_bytes(bytes: &[u8; 32]) -> Self` | Import from raw 32 bytes |
| `signing_key_bytes` | `fn signing_key_bytes(&self) -> [u8; 32]` | Export private key bytes |
| `verifying_key` | `fn verifying_key(&self) -> VerifyingKey` | Get Ed25519 public key |

#### `EthereumBackend` (feature-gated: `ethereum`)

Ethereum-compatible signing using secp256k1 + Keccak-256 with EIP-191 `personal_sign` format. Produces 64-byte compact ECDSA signatures (r, s).

| Method | Signature | Description |
| -------- | ----------- | ------------- |
| `new` | `fn new(signing_key: k256::ecdsa::SigningKey) -> Self` | Create from existing key |
| `generate` | `fn generate() -> Self` | Generate random keypair |
| `from_bytes` | `fn from_bytes(bytes: &[u8; 32]) -> Self` | Import from raw 32 bytes |
| `ethereum_address` | `fn ethereum_address(&self) -> String` | Get `0x`-prefixed Ethereum address |
| `personal_sign_hash` | `fn personal_sign_hash(data: &[u8]) -> [u8; 32]` | Compute EIP-191 hash |

#### `Ed25519Verifier`

Verification-only wrapper for Ed25519 (no private key required).

| Method | Signature | Description |
| -------- | ----------- | ------------- |
| `new` | `fn new(verifying_key: VerifyingKey) -> Self` | Create from public key |
| `from_bytes` | `fn from_bytes(bytes: &[u8; 32]) -> Result<Self>` | Import from raw bytes |
| `verify` | `fn verify(&self, data: &[u8], signature: &[u8]) -> bool` | Verify signature |

---

### Module: `metrics`

#### `StegoMetrics`

Lock-free pipeline performance counters using atomic operations. Thread-safe for concurrent access across encode/decode handlers.

```rust
pub struct StegoMetrics {
    pub frames_signed: AtomicU64,
    pub frames_verified: AtomicU64,
    pub frames_failed: AtomicU64,
    pub last_sign_us: AtomicU64,
    pub last_verify_us: AtomicU64,
}
```

| Method | Signature | Description |
| -------- | ----------- | ------------- |
| `new` | `fn new() -> Self` | Create zeroed counters |
| `reset` | `fn reset(&self)` | Reset all counters to zero |

---

### Module: `encryption`

#### `EncryptionKey`

ChaCha20-Poly1305 AEAD encryption for payload confidentiality.

```rust
pub struct EncryptionKey { /* 32-byte key */ }
```

| Method | Signature | Description |
| -------- | ----------- | ------------- |
| `generate` | `fn generate() -> Self` | Generate random encryption key |
| `from_bytes` | `fn from_bytes(bytes: &[u8; 32]) -> Self` | Import from raw 32 bytes |
| `encrypt` | `fn encrypt(&self, plaintext: &[u8]) -> Vec<u8>` | Encrypt with AEAD (returns nonce + ciphertext) |
| `decrypt` | `fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>>` | Decrypt AEAD ciphertext |

---

### Module: `spread_spectrum`

#### `SpreadSpectrumVideo`

PN-sequence modulation for noise-resistant video embedding.

| Method | Signature | Description |
| -------- | ----------- | ------------- |
| `new` | `fn new(key: [u8; 32], spread_factor: u32) -> Self` | Create with PRNG key and spread factor |

Implements `VideoStegoModule`.

#### `SpreadSpectrumAudio`

PN-sequence modulation for noise-resistant audio embedding.

| Method | Signature | Description |
| -------- | ----------- | ------------- |
| `new` | `fn new(key: [u8; 32], spread_factor: u32) -> Self` | Create with PRNG key and spread factor |

Implements `AudioStegoModule`.

---

### Module: `dct_video`

#### `DctVideo`

DCT-domain embedding for compression-resistant video steganography.

| Method | Signature | Description |
| -------- | ----------- | ------------- |
| `new` | `fn new(bits: u8, key: [u8; 32]) -> Self` | Create with bits and PRNG key |

Implements `VideoStegoModule`.

---

### Module: `error_correction`

Reed-Solomon codes over GF(2⁸) for payload resilience against partial LSB corruption.

---

### Module: `multi_frame`

Spread a single signature across N frames for partial loss resilience. Uses `PayloadConfig.multi_frame_spread` to determine spread count.

---

## Crate: `steganographer-gst`

### Top-Level Functions

| Function | Signature | Description |
| -------- | ----------- | ------------- |
| `init` | `fn init() -> Result<()>` | Initialize GStreamer runtime (calls `NSApplicationLoad` via FFI on macOS) |
| `launch` | `fn launch(pipeline_str: &str) -> Result<Pipeline>` | Launch a GStreamer pipeline |

### Module: `video_filter`

```rust
pub struct VideoFilterConfig {
    pub source_pipeline: String,
    pub sink_pipeline: String,
}
```

| Function | Signature | Description |
| -------- | ----------- | ------------- |
| `run_video_filter` | `fn run_video_filter(config, stego, signer, max_frames) -> Result<()>` | Run video processing pipeline |

### Module: `audio_filter`

```rust
pub struct AudioFilterConfig {
    pub source_pipeline: String,
    pub sink_pipeline: String,
}
```

| Function | Signature | Description |
| -------- | ----------- | ------------- |
| `run_audio_filter` | `fn run_audio_filter(config, stego, signer, max_buffers) -> Result<()>` | Run audio processing pipeline |

---

## Crate: `steganographer-dashboard`

### `LiveConfig`

Live-updatable configuration from the dashboard UI, serialized with camelCase for JavaScript interop.

```rust
pub struct LiveConfig {
    pub opacity: f64,           // 0.0–1.0 overlay opacity
    pub lsb_bits: u8,           // 1–4 LSB bits for embedding
    pub signing_backend: String, // "ed25519" or "ethereum"
    pub overlay_text: String,    // Text rendered on QR overlay
    pub sign_rate_ms: u32,       // Signing interval in milliseconds
    pub qr_scale: u32,           // QR overlay scale (5–100%)
    pub resolution: String,      // Video resolution (e.g., "640x480")
}
```

| Method | Signature | Description |
| -------- | ----------- | ------------- |
| `default` | `fn default() -> Self` | Default: opacity=1.0, lsb_bits=1, ed25519, "CONFIDENTIAL", 1000ms |

### `DashboardState`

```rust
pub struct DashboardState {
    pub metrics: Arc<StegoMetrics>,
    pub signing_backend: String,
    pub identity: String,
    pub width: u32,
    pub height: u32,
    pub last_encoded_frame: Mutex<Option<EncodedFrame>>,
    pub last_encoded_audio: Mutex<Option<EncodedAudioChunk>>,
    pub live_config: Mutex<LiveConfig>,
    pub session_start: std::time::Instant,
    pub auth_token: Option<String>,
}
```

### Top-Level Functions

| Function | Signature | Description |
| -------- | ----------- | ------------- |
| `create_router` | `fn create_router(state: Arc<DashboardState>) -> Router` | Create Axum router with all routes |
| `start_server` | `async fn start_server(state, port, host) -> Result<()>` | Start HTTP server bound to `host:port` |

### HTTP Routes

> **Security:** POST routes (`/api/config`, `/api/metrics/reset`) require a
> `Authorization: Bearer <token>` header if `auth_token` is set in
> `DashboardState`. If `auth_token` is `None` (local-only mode), auth is
> disabled. The dashboard defaults to binding `127.0.0.1`; use `--host 0.0.0.0`
> for network access (requires `--auth-token` for safety).

| Method | Path | Handler | Description |
| ------ | ---- | ------- | ----------- |
| GET | `/` | `serve_index` | Dashboard HTML page (tabbed: Video + Audio) |
| GET | `/style.css` | `serve_css` | CSS stylesheet |
| GET | `/app.js` | `serve_js` | JavaScript application (video tab + recording + keyboard shortcuts) |
| GET | `/audio_tab.js` | `serve_audio_js` | Audio tab JavaScript (microphone, waveform, recording) |
| GET | `/docs_tab.js` | `serve_docs_js` | Documentation tab JavaScript |
| GET | `/ws/encode` | `ws_encode_handler` | Video encode WebSocket (binary JPEG → signed frame) |
| GET | `/ws/decode` | `ws_decode_handler` | Video decode WebSocket (poll for verification data) |
| GET | `/ws/audio/encode` | `ws_audio_encode_handler` | Audio encode WebSocket (PCM → LSB signed chunk) |
| GET | `/ws/audio/decode` | `ws_audio_decode_handler` | Audio decode WebSocket (extract + verify audio payload) |
| GET | `/api/version` | `api_version` | Crate version and name as JSON |
| GET | `/api/metrics` | `api_metrics` | Live pipeline metrics as JSON |
| GET | `/api/config` | `api_config_get` | Current config + identity as JSON |
| POST | `/api/config` | `api_config_post` | Update live config from dashboard UI |
| POST | `/api/metrics/reset` | `api_metrics_reset` | Reset all metrics counters to zero |
| GET | `/api/session` | `api_session` | Session stats: uptime, config, metrics, backend, identity |
| GET | `/api/docs` | `api_docs_list` | List available documentation files |
| GET | `/api/docs/{name}` | `api_docs_content` | Return raw markdown content of a doc file |

#### Audio WebSocket Protocol

**`/ws/audio/encode`** — Client sends JSON:

```json
{
  "type": "audio_frame",
  "chunk_index": 42,
  "sample_rate": 44100,
  "channels": 1,
  "buffer_size": 2048,
  "lsb_bits": 1,
  "pcm_base64": "<base64-encoded Int16 PCM>"
}
```

Server responds with:

```json
{
  "type": "audio_signed",
  "chunk_index": 42,
  "sign_us": 125.3
}
```

**`/ws/audio/decode`** — Client sends `{"type": "decode_request"}`, server responds with:

```json
{
  "type": "audio_verify",
  "verified": true,
  "payload": {
    "chunk_index": 42,
    "hash": "a1b2c3d4...",
    "signature_preview": "e5f6a7b8...",
    "signature_full": "e5f6a7b8...complete hex..."
  },
  "backend": "ed25519",
  "verify_us": 89.7,
  "timestamp": "12:34:56.789Z",
  "lsb_bits": 1
}
```

#### `GET /api/config` Response

```json
{
  "signing_backend": "ed25519",
  "identity": "abc123...",
  "width": 640,
  "height": 480,
  "opacity": 1.0,
  "lsb_bits": 1,
  "overlay_text": "CONFIDENTIAL",
  "sign_rate_ms": 1000
}
```

#### `POST /api/config` Request Body

```json
{
  "opacity": 0.75,
  "lsbBits": 2,
  "signingBackend": "ed25519",
  "overlayText": "SECRET",
  "signRateMs": 500
}
```

---

## Generating Full rustdoc

```bash
cargo doc --workspace --no-deps --open
```
