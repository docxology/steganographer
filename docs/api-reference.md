# API Reference

This reference summarizes public Rust APIs and the JavaScript facade. Fallible
boundaries below are part of the API cutover; propagate their errors instead of
using unchecked defaults. For exhaustive signatures, generate rustdoc.

## Migration and trust boundaries

- Legacy `SignaturePayload` uses format **4**, still 109 bytes. Versions 2/3
  reject; re-encode old media. The hash binds frame index, video length,
  audio presence and audio length, not an ambiguous concatenation. Keyed legacy
  audio placement also changed with this format.
- Generic STG3 protocol-v1 wire/golden bytes are unchanged. Generic signatures
  authenticate logical payload bytes, not every semantic envelope field.
  A mathematically valid signature alone is not authorship: pin the trusted
  signer public key. CLI `verify` without a public key is extraction-only
  (`not_verified`), not trusted verification.
- Canonical carrier verification excludes kernel-owned/low-bit regions.
  It does not authenticate every container byte, metadata field, or arbitrary
  post-embedding lossy conversion. Exact artifact commitment uses SHA-256 of
  the file (for example with OTS).
- Ed25519 verification is strict; byte imports reject weak public keys.
  Owned key/master buffers are zeroized; borrowed caller secrets remain the
  caller's memory-management responsibility.

## Crate: `steganographer-core`

### Module: `config`

#### `Config`

Top-level configuration struct, deserialized from TOML.

```rust
pub struct Config {
    pub global: GlobalConfig,
    pub video: Option<VideoConfig>,
    pub audio: Option<AudioConfig>,
    pub ots: Option<OtsConfig>,  // optional OpenTimestamps `[ots]` block
    pub limits: Option<LimitsConfig>,
    pub profiles: Option<BTreeMap<String, ProfileConfig>>,
}
```

| Method | Signature | Description |
| -------- | ----------- | ------------- |
| `from_file` | `fn from_file(path: &str) -> Result<Self>` | Parse a TOML file into `Config` |
| `from_toml` | `fn from_toml(s: &str) -> Result<Self>` | Parse TOML; call `validate()` before operational use |
| `validate` | `fn validate(&self) -> Result<()>` | Reject unsupported algorithms, strengths, and invalid resource ceilings |

`from_file` parses and validates. `LimitsConfig` and named `ProfileConfig`
overrides resolve effective `DecodeLimits`; callers must use those limits
throughout encode/decode rather than silently replacing them with defaults.

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
    pub size: Option<u32>,                    // 109-byte legacy signature
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
| `spread_count` | `fn spread_count(&self) -> u32` | Configured count or 1; this accessor does not clamp/validate |

Configuration fields do not imply every surface implements them. Signed live
native pipelines reject encryption/ECC/spreading options and visible/invisible
compositions they cannot honor. Generic offline spreading supports RGB LSB,
2–8 shards, not arbitrary audio/SS/DCT sharding.

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
| `SERIALIZED_SIZE` | 109 | Total bytes: 4 magic + 1 version + 8 frame index + 32 hash + 64 signature |

| Method | Signature | Description |
| -------- | ----------- | ------------- |
| `to_bytes` | `fn to_bytes(&self) -> [u8; 109]` | Serialize format 4 |
| `from_bytes` | `fn from_bytes(buf: &[u8; 109]) -> Result<Self>` | Validate magic and format 4; reject older legacy versions |

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

Verifies mathematical signatures against frame bytes; authorization is separate.

| Method | Signature | Description |
| -------- | ----------- | ------------- |
| `new` | `fn new(verifying_key: VerifyingKey) -> Self` | Create from public key |
| `from_bytes` | `fn from_bytes(bytes: &[u8; 32]) -> Result<Self>` | Import from raw bytes |
| `verify` | `fn verify(&self, payload: &SignaturePayload, video: &[u8], audio: Option<&[u8]>) -> bool` | Verify payload against data |

`Verifier::with_hash_algorithm(key, algo)` and
`Verifier::from_bytes_with_algo(bytes, algo)` select the same hash as the signer;
the byte-import form is fallible.

#### Shared hexadecimal helpers

```rust
pub fn decode_hex(hex: &str) -> anyhow::Result<Vec<u8>>;
pub fn decode_hex_array<const N: usize>(hex: &str) -> anyhow::Result<[u8; N]>;
pub fn encode_hex(bytes: &[u8]) -> String;
```

Decoding accepts ASCII hex in either case, requires even length, and rejects
whitespace/non-ASCII input without slicing at invalid Unicode boundaries.
`decode_hex_array` requires exactly `2 * N` characters and decodes into a fixed
array without a heap allocation.

---

### Module: `revocation`

Authorization policy is distinct from raw signing, verification and packet
transform mathematics:

| API | Contract |
| --- | --- |
| `is_known_compromised_key` | Recognize the documented compromised Ed25519 public identity |
| `check_known_revocations` | Return typed `RevokedKey` before managed signing or trust |
| `RevocationList` | Serde JSON array of 64-character hex public keys; normalize, sort and deduplicate on load |
| `RevocationList::is_revoked` | Check additional entries and immutable known-compromise policy without allocation |
| `insert`, `len`, `is_empty` | Manage/count explicit entries only; an empty list does not restore compromised trust |

Managed CLI, GStreamer and dashboard entry points reject the known compromised
identity. CLI verification/extraction also applies its selected additional
registry, loaded once per command. An explicitly selected missing file, malformed
registry or unreadable policy fails closed; only an omitted, genuinely absent
default registry is optional. See [Security](security.md).

---

### Module: `packet` (v1.0 alpha)

The generic packet API is byte-oriented. Protocol-v1 golden wire bytes remain
unchanged by the legacy format-4 migration. `SignaturePayloadCodec` adapts the
current 109-byte legacy representation; it does not revive rejected formats.

| Type | Purpose |
| --- | --- |
| `Locator` | Fixed 32-byte `STG3` bootstrap with version, flags, bounded lengths, CRC32C, and nonce |
| `PacketEnvelope` | Canonical, ordered TLV metadata with payload digest and numeric algorithm descriptors |
| `GenericPacket` | Locator, envelope, and arbitrary byte body |
| `DecodeLimits` | Allocation and complexity ceilings checked during decoding |
| `PacketCodec` | Shared byte-oriented encode/decode contract |
| `GenericPacketCodec` | Codec for protocol-v1 alpha packets |
| `SignaturePayloadCodec` | Adapter for the current 109-byte legacy representation |

`GenericPacket::new_untransformed()` constructs a digest-bound packet.
`encode()` validates that locator lengths/checksum match the canonical envelope
and body. `decode()` checks limits before allocation, CRC32C, TLV canonicality,
untransformed length, and content digest.

### Module: `carrier` (alpha)

| Type or trait | Purpose |
| --- | --- |
| `CarrierDescriptor` | Describes decoded carrier kind and usable unit count |
| `EmbeddingConfig` | Shared checked embedding strength (currently 1–4 bits per unit) |
| `CapacityReport`, `EmbedReport`, `ExtractReport` | Exact capacity and operation evidence |
| `CarrierEmbedder`, `CarrierExtractor` | Packet-to-carrier contracts |
| `SpatialLsb` | Sequential spatial-LSB kernel for the first generic vertical slice |

Extraction reads only the fixed locator first, validates declared packet size
against carrier capacity and `DecodeLimits`, then extracts and validates the
complete packet. It also rejects packet placement/kernel descriptors that do
not match the requested configuration.

### Module: `carrier_binding`

The shared binding moved from the CLI into `steganographer_core`; import it
from core rather than maintaining a CLI copy:

```rust
pub fn canonicalize(
    data: &[u8], stego_type: &str, bits: u8, width: u32, height: u32,
    embedded_payload_len: usize,
) -> anyhow::Result<Vec<u8>>;
```

Supply packed logical pixels or complete S16LE samples, never padding.
Use the actual embedded payload length for kernels that reserve a payload
region. The SS case describes the offline CLI scalar format, not the trait's
green-only video/first-channel audio mapping; native trait SS signing rejects.

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

| Method | Signature | Meaning |
| --- | --- | --- |
| `validate_packed_layout` | `fn validate_packed_layout(&self) -> Result<usize>` | Validate RGB/BGRA dimensions, stride, extent and final row; return bytes/pixel; reject planar input |
| `pixel_byte_count` | `fn pixel_byte_count(&self) -> Result<usize>` | Checked logical size excluding padding; does **not** validate the backing view |

Callers must propagate both errors. Do not substitute `data.len()` for pixel
count on a padded view.

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
    pub channels: u16,
    pub sample_rate: u32,
    pub samples: &'a mut [i16],
    pub frame_index: u64,
}
```

`AudioBuffer::validate(&self) -> Result<()>` checks positive channels/rate and
complete interleaved sample frames before processing.

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
| `try_new` | `fn try_new(bits: u8) -> Result<Self>` | Fallible construction for untrusted strength |

Implements `VideoStegoModule`.

---

### Module: `lsb_audio`

#### `LsbAudio`

Keyed PRNG LSB audio steganography module.

| Method | Signature | Description |
| -------- | ----------- | ------------- |
| `new` | `fn new(bits: u8, key: [u8; 32]) -> Self` | Create with bits per sample and PRNG key |
| `try_new` | `fn try_new(bits: u8, key: [u8; 32]) -> Result<Self>` | Fallible construction for untrusted strength |

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
| `with_scale` | `fn with_scale(self, scale: u8) -> Self` | Set character scale (minimum 1) |

Implements `VideoStegoModule`.

---

### Module: `info_bar`

#### `InfoBar`

Exoteric visual watermark rendering timestamp, Code-128 barcode, and QR code.

| Method | Signature | Description |
| -------- | ----------- | ------------- |
| `new` | `fn new(label: String) -> Self` | Create InfoBar with the supplied label |

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
| `from_bytes` | `fn from_bytes(bytes: &[u8; 32]) -> Result<Self>` | Import a valid secp256k1 private key |
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
    frames_processed: AtomicU64,
    frames_verified_ok: AtomicU64,
    frames_verified_fail: AtomicU64,
    total_sign_us: AtomicU64,
    total_verify_us: AtomicU64,
    total_embed_us: AtomicU64,
    // OpenTimestamps counters
    ots_proofs_generated: AtomicU64,
    ots_verifications_passed: AtomicU64,
    ots_verifications_failed: AtomicU64,
    ots_last_timestamp: AtomicI64,   // Unix seconds, 0 = none
    ots_last_verified: AtomicBool,
    start_time: Instant,
}
```

| Method | Signature | Description |
| -------- | ----------- | ------------- |
| `new` | `fn new() -> Self` | Create zeroed counters |
| `reset` | `fn reset(&self)` | Reset all counters to zero (start time preserved) |
| `record_frame` / `record_verify_ok` / `record_verify_fail` | `fn record_*(&self)` | Increment the respective counters |
| `record_sign_duration` / `record_verify_duration` / `record_embed_duration` | `fn record_*_duration(&self, d: Duration)` | Accumulate microsecond timings |
| `record_ots_proof` / `record_ots_verification` | `fn record_ots_*(&self, …)` | OTS counters (`record_ots_verification(verified, timestamp)`) |
| `frames_processed` / `frames_verified_ok` / `frames_verified_fail` | `fn …(&self) -> u64` | Counter accessors |
| `ots_proofs_generated` / `ots_verifications_passed` / `ots_verifications_failed` / `ots_last_timestamp` / `ots_last_verified` | `fn …(&self)` | OTS counter accessors |
| `average_fps` | `fn average_fps(&self) -> f64` | Frames per second since start |
| `avg_sign_latency_us` / `avg_verify_latency_us` | `fn …(&self) -> f64` | Average per-frame latencies |
| `to_json` | `fn to_json(&self) -> String` | JSON serialization for the dashboard (frames_processed, frames_verified_ok/fail, fps, latencies, uptime, OTS counters) |

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
| `from_hex` | `fn from_hex(hex: &str) -> Result<Self>` | Checked 32-byte key import |
| `to_hex` / `expose_hex` | `fn …(&self) -> String` | Redacted display / explicit full secret export |

Encryption operations are **module functions**, not key methods:

```rust
pub fn encrypt(key: &EncryptionKey, packet_id: &[u8; 16],
    plaintext: &[u8], aad: Option<&[u8]>) -> anyhow::Result<Vec<u8>>;
pub fn decrypt(key: &EncryptionKey, packet_id: &[u8; 16],
    ciphertext: &[u8], aad: Option<&[u8]>) -> anyhow::Result<Vec<u8>>;
pub fn encrypt_legacy(key: &EncryptionKey, plaintext: &[u8],
    aad: Option<&[u8]>) -> anyhow::Result<Vec<u8>>;
pub fn decrypt_legacy(key: &EncryptionKey, ciphertext: &[u8],
    aad: Option<&[u8]>) -> anyhow::Result<Vec<u8>>;
```

Raw STG3 AEAD callers must ensure packet-ID uniqueness per key. The legacy
wrapper emits `STGE` version 1 with a fresh 128-bit packet ID (41-byte total
overhead); decryption has no fallback to old zero-ID ciphertext.

---

### Module: `spread_spectrum`

#### `SpreadSpectrumVideo`

Keyed video watermarking; trait mapping uses the green channel. Compression
survival is not guaranteed by the type name or an in-memory round trip.

| Method | Signature | Description |
| -------- | ----------- | ------------- |
| `new` | `fn new(key: [u8; 32], amplitude: i32, spread_factor: usize) -> Self` | Panics on invalid parameters; use `try_new` for untrusted input |
| `try_new` | `fn try_new(key: [u8; 32], amplitude: i32, spread_factor: usize) -> Result<Self>` | Checked construction |

Implements `VideoStegoModule`.

#### `SpreadSpectrumAudio`

Keyed audio watermarking; trait mapping uses the first interleaved PCM channel.

| Method | Signature | Description |
| -------- | ----------- | ------------- |
| `new` | `fn new(key: [u8; 32], amplitude: i32, spread_factor: usize) -> Self` | Panics on invalid parameters |
| `try_new` | `fn try_new(key: [u8; 32], amplitude: i32, spread_factor: usize) -> Result<Self>` | Checked construction |

Implements `AudioStegoModule`.

Both types provide fallible scalar helpers:
`embed_bit(&self, data, start: usize, bit: u8, bit_pos: usize,
frame_index: u64) -> Result<()>` and
`extract_bit(&self, data, start: usize, bit_pos: usize,
frame_index: u64) -> Result<u8>`. Video data is `&mut [u8]` / `&[u8]`;
audio data is `&mut [i16]` / `&[i16]`. Invalid/short regions return errors;
failed embedding leaves the slice unchanged. These scalar helpers are not the
same carrier mapping as trait embedding. Native signed SS is unsupported.

---

### Module: `dct_video`

#### `DctVideo`

DCT-domain video embedding. Integer reconstruction is checked for recoverability;
unrecoverable/clipped output fails without committing a corrupt carrier.

| Method | Signature | Description |
| -------- | ----------- | ------------- |
| `new` | `fn new(coef_index: usize, quant_step: i32, channel: usize) -> Self` | Checked-by-assertion construction; coefficient 1–63, positive step, RGB channel 0–2 |
| `with_defaults` | `fn with_defaults() -> Self` | Coefficient 20, step 16, green channel |

Embedding requires `quant_step >= 8`; smaller positive values can be
constructed for extraction but embedding rejects them.

Implements `VideoStegoModule`.

---

### Module: `error_correction`

Reed-Solomon codes over GF(2⁸) for payload resilience against partial LSB corruption.

---

### Module: `multi_frame`

Legacy signature spreading uses `PayloadConfig.multi_frame_spread`. Generic
offline RGB-LSB sharding is a separate packet path; supported counts are 2–8.

### Module: `learned`

| Associated function | Signature |
| --- | --- |
| `LearnedModel::from_flat` | `fn from_flat(flat: &[f32]) -> Result<Self>` |
| `LearnedModel::from_bytes` | `fn from_bytes(bytes: &[u8]) -> Result<Self>` |
| `LearnedWatermarker::built_in` | `fn built_in() -> Result<Self>` |
| `LearnedWatermarker::with_config` | `fn with_config(config: LearnedConfig) -> Result<Self>` |
| `LearnedWatermarker::with_model` | `fn with_model(config: LearnedConfig, model: LearnedModel) -> Result<Self>` |

Model length/configuration/committed-weight validation can fail; callers must
handle errors. Configuration requires 64 bits, nonzero redundancy and finite positive
strength. Learned embed/extract also validate packed layout. A model's existence
or an identity/math test is not evidence of real-media robustness or accuracy.

### Module: `ots_client` (feature `ots`)

`OTSMethod` supports `Bitcoin` only; parsing unsupported methods fails.
`OTSClient::new(method)` and `OTSClient::from_config(&config)` return
`Result<Self, OTSError>`.

| Method | Signature |
| --- | --- |
| `compute_sha256_digest` | `fn compute_sha256_digest(data: &[u8]) -> [u8; 32]` |
| `stamp_digest` | `async fn stamp_digest(&self, digest: &[u8; 32]) -> Result<Vec<u8>, OTSError>` |
| `stamp_digest_force` | `async fn stamp_digest_force(&self, digest: &[u8; 32]) -> Result<Vec<u8>, OTSError>` |
| `stamp_data` | `async fn stamp_data(&self, data: &[u8]) -> Result<Vec<u8>, OTSError>` |
| `upgrade` | `async fn upgrade(&self, proof: &[u8], expected: &[u8; 32]) -> Result<Vec<u8>, OTSError>` |
| `verify` | `async fn verify(&self, proof: &[u8], expected_digest: &[u8; 32]) -> Result<OTSVResult, OTSError>` |
| `verify_attestations` | `async fn verify_attestations(&self, proof: &[u8], expected_digest: &[u8; 32]) -> Result<OTSVResult, OTSError>` |
| `validate_proof` | `fn validate_proof(proof: &[u8], expected: &[u8; 32]) -> Result<bool, OTSError>` |
| `proof_path_for` | `fn proof_path_for(&self, digest_hex: &str) -> Result<PathBuf, OTSError>` |
| `save_proof` | `async fn save_proof(&self, proof: &[u8], digest_hex: &str) -> Result<PathBuf, OTSError>` |
| `save_proof_to` | `async fn save_proof_to(&self, proof: &[u8], output_path: &Path) -> Result<PathBuf, OTSError>` |
| `load_proof` | `async fn load_proof(path: &Path) -> Result<Vec<u8>, OTSError>` |

Proofs are bounded standard detached `.ots`, submitted via the calendar protocol,
not bespoke JSON success responses. Compute the expected SHA-256 locally from
the intended artifact; never trust a digest merely because it is inside a proof.
`verify` upgrades pending proofs through the configured calendar when needed;
`verify_attestations` skips calendar upgrade but still contacts the explorer.
`validate_proof` validates format/digest locally and returns whether the proof
is pending; its boolean is **not** a verified Bitcoin timestamp.

`OTSVResult` contains `verified: bool`, `pending: bool`, `method: String`,
`timestamp: Option<u64>` and `details: String`. Pending is not verified.
Verification checks operations/Merkle commitment, raw Bitcoin header and PoW,
but trusts the configured Esplora provider's canonical height index (default
`https://blockstream.info/api`); this is not independent full-node validation.
The default calendar is `https://alice.btc.calendar.opentimestamps.org`.
No newly confirmed live Bitcoin attestation is claimed by release validation.

Proof I/O is capped, uses a pinned directory capability and rejects unsafe
links/nonregular files; atomic no-clobber publication requires a hard-link-capable
filesystem. Existing evidence is never silently overwritten.

### Module: `hash_chain`

`HashChain::verify_chain(root: &MerkleRoot, frames: &[(u64, &[u8])],
previous_hash: FrameHash) -> bool` requires the trusted predecessor hash for
later segments (zero for the first). Ordering/start-frame checks are included;
the exact segment ordinal remains trusted external metadata. Historical root
bytes are unchanged.

### Modules: `forensics`, `steganalysis`

`forensics::scan_bytes(data: &[u8]) -> ForensicScan` returns findings, not an
invented identity or recovered hidden message. In addition to entropy/family,
magic/text/container evidence and statistical observations, it exposes:

```rust
pub container_detected: bool,
pub incomplete: bool,
pub incomplete_reasons: Vec<String>,
pub detected: bool,
pub message: String,
```

`forensics::ooxml::analyze_package(data)` and
`forensics::pdf::analyze_pdf(data)` return `ContainerAnalysis {
findings: Vec<ContainerFinding>, detected: bool, incomplete_reasons: Vec<String>
}` rather than a finding vector. `ContainerFinding` has `path`, `family`, and
`detail` strings. Positive detection is latched independently of display caps.
ZIP topology, entropy, statistical scores and PDF structural observations alone
do not establish concealment. `detected` follows content-derived magic/text and
selected concealment detectors, not `!container_findings.is_empty()`.

ZIP scans bound local/central records, CRC/inflate/XML work and text encodings;
PDF analysis is bounded lexical analysis, not a full PDF renderer. Budget,
unsupported-parse and input cutoffs surface in `incomplete_reasons`. A negative
partial scan is not a clean bill of health.

`steganalysis::DetectionResult` exposes `available`, `detected`, `confidence`
and `message`. Unavailable methods (including insufficient/invalid inputs or
unidentifiable RS models) are not clean negatives. Method scores/RS replacement
estimates are not calibrated probabilities or natural-image detection accuracy.
`CombinedResult` keeps each method's availability alongside its aggregate.

---

## Crate: `steganographer-gst`

### Top-Level Functions

| Function | Signature | Description |
| -------- | ----------- | ------------- |
| `init` | `fn init() -> Result<()>` | Initialize GStreamer only; no NSApplication or platform loop |
| `launch` | `fn launch(pipeline_str: &str) -> Result<gstreamer::Element>` | Parse a launch string; caller controls pipeline state |

### Module: `video_filter`

```rust
pub struct VideoFilterConfig {
    pub source_pipeline: String,
    pub sink_pipeline: String,
    pub signing_kernel: Option<SigningKernel>,
}
```

Headless repeated/threaded calls run on their calling thread. For macOS
camera/GUI elements, the application owns Cocoa at entry; CLI live commands
enter `gstreamer::macos_main` once **before Tokio**, never per filter.

`SigningKernel` is `Lsb { bits: u8 }`, `Dct`, or `SpreadSpectrum`.
Signing requires a matching supported binding; trait SS signing rejects.

| Function | Signature | Description |
| -------- | ----------- | ------------- |
| `run_video_filter` | `fn run_video_filter(config: &VideoFilterConfig, stego: Box<dyn VideoStegoModule>, signer: Option<&Signer>, max_frames: Option<u64>) -> Result<()>` | RGB/BGRA processing; LSB/DCT canonical signatures |
| `extract_from_source` | `fn extract_from_source(source_pipeline_str: &str, stego: &dyn VideoStegoModule, max_frames: Option<u64>) -> Result<Vec<(u64, Option<SignaturePayload>)>>` | Extract selected video frames; source errors propagate |
| `process_video_file` | `fn process_video_file(input_path: &str, output_path: &str, stego: Box<dyn VideoStegoModule>, signer: Option<&Signer>, signing_kernel: Option<SigningKernel>, max_frames: Option<u64>) -> Result<()>` | Exact RGB Matroska `.mkv` |
| `process_audio_file` | `fn process_audio_file(input_path: &str, output_path: &str, stego: &mut dyn AudioStegoModule, signer: Option<&Signer>, signing_kernel: Option<SigningKernel>, max_buffers: Option<u64>) -> Result<()>` | Exact PCM `.wav`; one bounded logical file frame at index 0 |

### Module: `audio_filter`

```rust
pub struct AudioFilterConfig {
    pub source_pipeline: String,
    pub sink_pipeline: String,
    pub signing_kernel: Option<SigningKernel>,
}
```

| Function | Signature | Description |
| -------- | ----------- | ------------- |
| `run_audio_filter` | `fn run_audio_filter(config: &AudioFilterConfig, stego: &mut dyn AudioStegoModule, signer: Option<&Signer>, max_buffers: Option<u64>) -> Result<()>` | Interleaved S16LE, LSB signatures only; preserves each selected buffer boundary/index |
| `extract_from_source` | `fn extract_from_source(source_pipeline_str: &str, stego: &dyn AudioStegoModule, max_buffers: Option<u64>) -> Result<Vec<(u64, Option<SignaturePayload>)>>` | Extract selected audio buffers |

File audio gathers complete selected PCM, bounded to 64 MiB. No explicit
`max_buffers` means complete input; exceeding the bound, empty input or changing
caps fails rather than silently truncating. Extract from the whole delivered
WAV PCM at index 0. Both bridges propagate bus errors, forward current
caps/TIME segments/timestamps, drain downstream EOS and clean up on failure.
Post-embed verification occurs before AppSrc; only the exact file chains
preserve the carrier without a caller-supplied downstream conversion.

---

## Crate: `steganographer-wasm`

The native facade uses `Vec<u8>`/slices and `Option<DecodeLimits>`; wasm-bindgen
exports use `Uint8Array` and optional JSON-string limits. Reports are JSON
strings, and errors throw strings. The core dependency disables default
network/OTS and Ethereum features.

| Surface | Exports |
| --- | --- |
| Framing | `packet_encode(payload, payload_kind, packet_id, nonce, bits_per_unit, limits_json)`, `packet_decode(packet, limits_json)` |
| RGB / PCM | `capacity_rgb`, `capacity_pcm_s16le`, `embed_rgb`, `embed_pcm_s16le`, `extract_rgb`, `extract_pcm_s16le` |
| Inspection | `forensic_scan`, `text_analyze_bytes`, `text_analyze_text`, `decode_limits_default` |

RGB is a raw byte carrier; PCM is raw interleaved S16LE, not WAV-container bytes.
Packet ID is exactly 16 bytes and nonce 8. JS controls are checked in their
original numeric form: finite integer strength 1–4 and payload kind 1–5, before
u8/u16 narrowing. Fractional, wrapping, negative, NaN and infinite values reject.
Limits reject unknown fields and values outside nonnegative wasm32 `usize`.
Explicit raised limits remain effective through encode/embed/extract.

Packet decode/extraction reports use
`schema: "steganographer.packet-report.v2"`:
`original_len` is a decimal string; `created_at_unix` is a decimal string or
null. Use `BigInt(report.original_len)` and, when nonnull,
`BigInt(report.created_at_unix)`; converting to `Number` loses large u64 values.
Body bytes and wasm32 carrier counts remain numeric. `embed_*` returns JSON
`{"carrier": [...], "report": {...}}`; extraction adds `consumed_units` and
`bits_per_unit` to the packet report. Forensics preserves actual evidence,
completeness reasons and statistical availability.

Build only `-p steganographer-wasm --no-default-features` for
`wasm32-unknown-unknown`, isolated from native workspace feature-unification,
and generate bindings with a CLI matching the resolved wasm-bindgen version.
`steganographer-wasm/tests/bindings.cjs` runs against actual `--target nodejs`
generated output, not a mock/native substitute. Parent exercised generated
release bindings and a real Node >16 MiB body with explicit limits. Node
coverage is not a browser-execution claim; `--target web` packaging is separate.
See the crate's [agent guide](../steganographer-wasm/AGENTS.md) for gate commands.

---

## Crate: `steganographer-dashboard`

### `LiveConfig`

```rust
pub struct LiveConfig {
    pub opacity: f64,             // preview opacity, 0.0–1.0
    pub lsb_bits: u8,             // 1–4
    pub signing_backend: String,  // supported: "ed25519"
    pub overlay_text: String,     // retained setting; visual overlays unavailable
    pub sign_rate_ms: u32,        // minimum 50 ms
    pub qr_scale: u32,            // 5–100
    pub resolution: String,       // WIDTHxHEIGHT, each dimension 1–4096
    pub stego_type: String,       // supported: "lsb"
    pub hash_algorithm: String,   // supported: "blake3"
    pub encrypt: bool,            // must be false
    pub ecc: bool,                // must be false
    pub transport: Transport,     // Live video feed transport: "websocket" (default) or "webrtc"
}
```

`Transport` is a serde enum: `websocket` sends JPEG input and returns signed PNG over the
`/ws/encode` WebSocket (default); `webrtc` negotiates a WebRTC data channel
through `POST /api/webrtc/offer` (WHIP-style) and streams the same
`encoded_frame`/`decoded_frame` JSON messages over it, so the same UI handlers
render both transports. Unknown transport values are rejected at parse time.
The audio feed always uses WebSocket.

| Method | Signature | Description |
| -------- | ----------- | ------------- |
| `default` | `fn default() -> Self` | opacity=1.0, lsb_bits=1, ed25519, "CONFIDENTIAL", 1000ms, qr_scale=10%, "640x480", "lsb", "blake3", no encryption, no ECC, transport websocket |

`POST /api/config` uses **snake_case**, denies unknown fields, and validates
the limits above. Unsupported signer/hash/kernel/encryption/ECC values reject
instead of becoming decorative settings. WebRTC rejects when unavailable in
the build. The first violation returns HTTP 400; invalid bearer auth returns
HTTP 401. Preview opacity does not alter the authenticated carrier.

### `DashboardState`

Shared state holds the metrics, live config, delivered-frame/audio caches,
session signer and audio embedding key, auth/OTS settings and outcomes, and
transport policy/session state. The public identity equals the session signer's
Ed25519 public key. It is stable for that runtime, not independent proof of a
person or organization. See rustdoc for its full construction fields.

`EncodedFrame` stores delivered RGB/PNG; `EncodedAudioChunk` stores delivered
samples/PCM. Both retain indices, revision, bit depth and commitment, **not**
private pre-embed snapshots. Decode verifies extracted signatures from actual
post-embed media using canonical carrier binding and the session public key.
Recording exports signed PNG snapshots / PCM WAV chunks plus an extraction
manifest in stored ZIP, not a continuous lossy video recording.

### Top-Level Functions

| Function | Signature | Description |
| -------- | ----------- | ------------- |
| `create_router` | `fn create_router(state: Arc<DashboardState>) -> Result<Router>` | Create Axum router; reject known compromised signing identity |
| `start_server` | `async fn start_server(state, port, host) -> Result<()>` | Start HTTP server bound to `host:port` |

### HTTP Routes

> **Security:**
>
> - **POST routes** (`/api/config`, `/api/metrics/reset`, `/ots/stamp`,
>   `/ots/verify`, `/api/webrtc/offer`) require an `Authorization: Bearer
>   <token>` header when `auth_token` is set in `DashboardState`
>   (constant-time comparison). Tokenless local mode still rejects foreign
>   browser mutation Origins.
> - **WebSocket upgrades** pass a dedicated gate (CORS does not apply to WS):
>   cross-origin `Origin` headers are rejected with HTTP 403 unless the origin
>   host is loopback (`127.0.0.1`, `::1`, `localhost`) or matches the request's
>   `Host` header. When `auth_token` is set, the upgrade also needs
>   `?token=<token>` in the query string **or** a
>   `Sec-WebSocket-Protocol: bearer-<token>` subprotocol; otherwise HTTP 401.
> - **Size caps**: decoded WS messages are capped at 4 MiB and WS frames at
>   1 MiB; JPEG frames are additionally capped at 4096×4096 pixels and audio
>   chunks at 10 s duration / 384 kHz sample rate.
> - The dashboard defaults to binding `127.0.0.1`; use `--host 0.0.0.0` for
>   network access (requires `--auth-token` for safety).

| Method | Path | Handler | Description |
| ------ | ---- | ------- | ----------- |
| GET | `/` | `serve_index` | Dashboard HTML page (tabbed: Video + Audio) |
| GET | `/style.css` | `serve_css` | CSS stylesheet |
| GET | `/app.js` | `serve_js` | JavaScript application (video tab + recording + keyboard shortcuts) |
| GET | `/audio_tab.js` | `serve_audio_js` | Audio tab JavaScript (microphone, waveform, recording) |
| GET | `/docs_tab.js` | `serve_docs_js` | Documentation tab JavaScript |
| GET | `/ots.js` | `serve_ots_js` | OpenTimestamps panel JavaScript |
| GET | `/ws/encode` | `ws_encode_handler` | Video encode WebSocket (binary JPEG → signed frame) |
| GET | `/ws/decode` | `ws_decode_handler` | Video decode WebSocket (extract + real signature verification) |
| GET | `/ws/audio/encode` | `ws_audio_encode_handler` | Audio encode WebSocket (PCM → LSB signed chunk) |
| GET | `/ws/audio/decode` | `ws_audio_decode_handler` | Audio decode WebSocket (extract + real signature verification) |
| GET | `/api/version` | `api_version` | Version, crate name, and `signature_payload_size` as JSON |
| GET | `/api/metrics` | `api_metrics` | Live pipeline metrics as JSON |
| GET | `/api/session` | `api_session` | Session stats: uptime, config, metrics, backend, identity |
| GET | `/api/docs` | `api_docs_list` | List available documentation files |
| GET | `/api/docs/{name}` | `api_docs_content` | Return raw markdown content of a doc file |
| GET | `/ots/status` | `ots_status` | OTS configuration and readiness (HTTP 200 even when disabled; the JSON body carries the real status) |
| POST | `/ots/stamp` | `ots_stamp` | Stamp latest actual signed-media commitment or SHA-256 of an explicit body; reject no-media empty requests |
| POST | `/ots/verify` | `ots_verify` | Verify bounded `.ots` body with required `X-Expected-Digest` SHA-256 hex header |
| POST | `/api/webrtc/offer` | `api_webrtc_offer` | WHIP-style WebRTC signaling: browser SDP offer JSON in, server SDP answer JSON out (non-trickle ICE); data channel feeds the encode pipeline (Bearer auth) |

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

Server responds with (the server assigns `chunk_index` itself; the
client-sent `chunk_index` in the request is informational):

```json
{
  "type": "audio_signed",
  "chunk_index": 42,
  "sign_us": 125,
  "embed_us": 340,
  "sample_count": 2048,
  "backend": "ed25519"
}
```

Client sanity caps enforced before embedding: `channels` must be 1–2,
`sample_rate` 1–384 000 Hz, `lsb_bits` 1–4, and the chunk at most
10 seconds of audio. Violations return a `{"type": "error", …}` message on
the socket and skip the chunk without closing the connection.

**`/ws/audio/decode`** — Client sends a text trigger — the literal `"poll"`
or `{"type": "decode_request"}` (both video and audio decode handlers accept
the same two triggers; other messages are ignored and never run a decode
cycle). Queued triggers that arrive while a decode cycle is in flight are
collapsed into the cycle that just completed, so a burst of polls triggers
one decode. Server responds with:

```json
{
  "type": "audio_verify",
  "verified": true,
  "payload": {
    "payload_found": true,
    "chunk_index": 42,
    "hash": "a1b2c3d4...",
    "signature_preview": "e5f6a7b8...",
    "signature_full": "e5f6a7b8...complete hex..."
  },
  "backend": "ed25519",
  "verify_us": 89,
  "timestamp": "12:34:56.789Z",
  "lsb_bits": 1,
  "sample_count": 2048,
  "sample_rate": 44100
}
```

When no chunk has been encoded yet, the response is
`{"type": "audio_verify", "verified": false, "waiting": true, "backend": …}`.
`verified` is real Ed25519 verification of the actual delivered PCM after
canonicalization, using the session public key, not a payload-found echo or
private pre-embed snapshot. Video verification follows the same delivered-media
rule. Pending OTS state is separate from confirmed verification.

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
  "sign_rate_ms": 1000,
  "stego_type": "lsb",
  "hash_algorithm": "blake3",
  "encrypt": false,
  "ecc": false,
  "transport": "websocket"
}
```

#### `POST /api/webrtc/offer` Request/Response

WHIP-style single-request signaling for the WebRTC transport. The body is a
browser SDP offer; the response is the server SDP answer with **non-trickle
ICE** — all server candidates are gathered before the answer is returned, so
no trickle-ICE channel is required. Media flows over the negotiated **data
channel only** (no RTP audio/video tracks); data-channel messages reuse the
WebSocket encode/decode shapes (binary JPEG in, `encoded_frame`/`decoded_frame`
JSON out), and the same session signer, live config, size caps (4 MiB message
/ 1 MiB frame, 4096×4096 JPEG), and real-verification pipeline apply. Requires
Bearer auth when an auth token is configured; non-offer SDP types and
malformed SDP are rejected with HTTP 400. Answer-side peer connections are
reaped on disconnect, failure, data-channel close, or after a 60 s
never-connected deadline.

```json
// Request
{ "type": "offer", "sdp": "v=0 ..." }

// Response
{ "type": "answer", "sdp": "v=0 ..." }
```

#### `POST /api/config` Request Body

Snake_case, deserialized into `LiveConfig` (merge into a full current config
before sending; omitted fields deserialize to defaults):

```json
{
  "opacity": 0.75,
  "lsb_bits": 2,
  "signing_backend": "ed25519",
  "overlay_text": "SECRET",
  "sign_rate_ms": 500,
  "transport": "webrtc"
}
```

#### `GET /api/version` Response

```json
{
  "version": "<workspace-version>",
  "name": "steganographer-dashboard",
  "signature_payload_size": 109
}
```

`signature_payload_size` is `SignaturePayload::SERIALIZED_SIZE` (109 bytes).

---

## Generating Full rustdoc

```bash
cargo doc --workspace --no-deps --open
```
