# Configuration

The 0.8 TOML model is defined in `steganographer-core/src/config.rs` and
`ots_config.rs`. Configuration fields are not a promise that every execution
surface supports every combination. In particular, offline transforms, native
signed pipelines and dashboard live settings have distinct contracts.

## Loading and validation

The CLI defaults to `config/example.toml`. Override it explicitly:

```bash
steganographer --config steganographer.toml config check
steganographer --config config/example.toml config check --format json
```

Only absence of the implicit default can fall back to a minimal `[global]`
config. An explicitly selected missing file, malformed config, invalid limits,
unknown profile/detector or unsupported configured algorithm fails (exit 1).
Validation does not probe hardware, plugins, network reachability or whether a
particular live module combination is usable. Live commands additionally need
their video/audio section and enforce their own capabilities.

The shipped example and root configuration use **LSB-only signed pipelines**.
The populated overlay/info-bar tables do not activate those modules: `pipeline`
selects them. Example embedding keys are public examples, not secrets.

## Global fields

| `[global]` key | Meaning |
| --- | --- |
| `log_level` | Logging setting; CLI `--log-level` controls CLI logging |
| `hash_algorithm` | `blake3` (fallback), `sha256`, `sha3-256`; aliases `sha-256`, `sha3`, `sha-3` |
| `key_file` | Hex embedding-key file used by offline resolution and native audio |

Keys are 32 bytes, represented as 64 hex characters. Native audio resolves
the section's `key_file`, then global `key_file`, then section inline `key`.
Offline CLI options take precedence over those configured sources. Prefer
explicit `--embedding-key-file` for reproducible offline audio/SS workflows.

## Video and audio fields

When `[video]` is present it requires `input`, `output` and `stego`. `[audio]`
has the same required sections but no `pipeline` parameters table.

### Endpoints: `[video.input]`, `[video.output]`, audio equivalents

| Key | Type | Meaning |
| --- | --- | --- |
| `type` | string, required | `test`, `device`, `file` or `network` |
| `backend` | optional string | Required platform backend for device input |
| `device` | optional string | Device path/identifier; AVFoundation uses numeric index, CoreAudio numeric identifier |
| `path` | optional string | File path or input network URI |

`test` explicitly selects synthetic media without opening capture hardware.
Device input requires `v4l2`/`avfoundation` for video or
`pulseaudio`/`pipewire`/`coreaudio` for audio; unknown backends never fall back
to fake media. File and network input use GStreamer decoding. Headerless raw
input needs an explicit parsing `--source`. Network output requires an explicit
lossless `--sink`; the CLI does not guess codecs or transports.

Managed video output is exact RGB Matroska `.mkv`; managed audio output is
whole-selection PCM `.wav` (64 MiB limit, one signature at frame index 0).
Both publish atomically after EOS and never overwrite existing destinations.
Live/explicit sources require `--max-frames` or `--max-buffers` for managed
file capture. Explicit `--source` / `--sink` fragments override their endpoint;
arbitrary sinks do not inherit exact-byte or atomic-file guarantees.

### `[video.pipeline]`

| Key | Resolved fallback | Meaning |
| --- | --- | --- |
| `width`, `height` | 640, 480 | Requested frame geometry |
| `framerate` | 30 | Requested frames per second |
| `opacity` | 1.0 | Native video accepts only 1.0; dashboard preview opacity is separate |
| `payload` | absent | Payload settings below |

The native config-driven source negotiates width, height and framerate caps
before signing, scaling dimensions when needed. It does not insert `videorate`
or manufacture/drop frames to repair an incompatible source rate; negotiation
fails instead. An explicit `--source` owns its caps and any intentional rate
conversion. Invisible LSB depth is controlled by `bits`, not opacity.

### `[video.pipeline.payload]`

| Key | Supported interpretation |
| --- | --- |
| `type` | Payload description (`signature` in shipped config) |
| `size` | Legacy signature description, 109 bytes in format 4; not arbitrary packet sizing |
| `signing_backend` | `ed25519` only for native signed pipelines |
| `encrypt` | Offline legacy payload encryption |
| `encryption_key`, `encryption_key_file` | Offline encryption key; file takes precedence |
| `error_correction` | `none` or offline `reed_solomon` |
| `multi_frame_spread` | Offline RGB LSB only, 1 disabled or 2–8 shards |

Native video rejects enabled encryption, ECC, spreading, custom payload types
and non-109-byte signature sizes **before starting pipelines**. Use offline
encode for those transforms. The generic packet CLI is explicitly selected
with `--payload-file` / `--payload-text`, not this table. Recoverable JSON
workflows require explicit keys/password credentials; machine output contains
no secrets. Audio has no video payload table and does not apply those settings.

### `[video.stego]` and `[audio.stego]`

`pipeline` is an ordered array of module names. Signed native video requires
exactly one invisible kernel: `lsb_signature` or `dct`; native trait
`spread_spectrum` signing is rejected because its channel mapping differs from
the offline scalar binding. Signed native audio supports only
`["lsb_signature"]`. Multiple invisible kernels or mixing signing with
`overlay` / `info_bar` is unsupported, not a successfully authenticated chain.

Visible `overlay` and `info_bar` modules remain available as separate unsigned
rendering operations. Offline CLI kernel names differ: `lsb_video`,
`lsb_audio`, `dct_video`, `spread_spectrum_video`.

| Subtable | Fields |
| --- | --- |
| `lsb_signature` | Required `bits` (1–4), optional `key` / `key_file` |
| `overlay` (video) | Optional `text`, `position`, `font_size` |
| `info_bar` (video) | Optional `label`, `show_barcode`, `show_qr`, `show_timestamp` |

Native LSB video uses sequential placement; audio needs its keyed placement
config. Overlay positions are `top-left`, `top-right`, `bottom-left`,
`bottom-right`, `center`. Text supports `{timestamp}`, `{frame_index}`, `{date}`,
`{time}`. The font is a scaled bitmap font, not a system font selector.
The native info bar honors its own label/timestamp fields, not overlay text.
Visible-only native bars must explicitly disable `show_barcode` and `show_qr`:
cryptographic barcode/QR rendering requires a supplied signature payload.

### Minimal signed test pipelines

```toml
[global]
hash_algorithm = "blake3"

[video.input]
type = "test"
[video.output]
type = "device"
[video.stego]
pipeline = ["lsb_signature"]
[video.stego.lsb_signature]
bits = 1

[audio.input]
type = "test"
[audio.output]
type = "device"
[audio.stego]
pipeline = ["lsb_signature"]
[audio.stego.lsb_signature]
bits = 1
key_file = "keys/embedding.key"
```

Generate the embedding key independently (e.g. `openssl rand -hex 32`) or use
`derive --password-file ...` to create separate signing/encryption/embedding
keys. Do not repurpose a signing private key as a placement key.

## Effective packet limits: `[limits]`

The following optional fields override built-in `DecodeLimits`:

| Key | Built-in fallback |
| --- | --- |
| `max_packet_len` | 16 MiB + 16 KiB + locator |
| `max_body_len` | 16 MiB |
| `max_original_len` | 16 MiB |
| `max_field_len` | 8 KiB |
| `max_extensions` | 64 |
| `max_nesting_depth` | 3 |
| `max_aggregate_nested_bytes` | 64 MiB |

Present values must be positive; configured body/packet ceilings must be
consistent. Limits govern generic carrier extraction, packet parsing and
transform reversal, including declared logical size before decompression.
They are effective CLI bounds, not comments that extraction ignores. The full
Rust/WASM limits API has additional fields; they are not invented TOML keys.

```toml
[limits]
max_packet_len = 2097152
max_body_len = 1048576
max_original_len = 1048576
```

### `[profiles.<name>]`

Named profiles have optional `limits` (same override fields) and
`scan.detectors`. Apply one with `scan --profile <name>`; there is no
encode/decode `--profile` option. Supported detector IDs:
`statistical`, `magic`, `ZERO_WIDTH`, `VARIATION_SELECTORS`, `BIDI_CONTROLS`,
`WHITESPACE_ANOMALY`, `HOMOGLYPH_SUSPECT`. An empty or unknown detector set
fails; container findings always contribute independently.

```toml
[profiles.strict.limits]
max_packet_len = 8192
max_body_len = 4096
[profiles.strict.scan]
detectors = ["ZERO_WIDTH", "statistical"]
```

## OpenTimestamps: `[ots]`

Optional, disabled by default for automatic integration. Explicit `ots` commands
perform the requested operation. Bitcoin is the only supported method.

```toml
[ots]
enabled = true
server_url = "https://alice.btc.calendar.opentimestamps.org"
method = "bitcoin"
interval_secs = 300
proof_dir = "ots_proofs"
timeout_secs = 30
bitcoin_explorer_url = "https://blockstream.info/api"
```

`interval_secs` must be 1–86400; `timeout_secs` 1–300. Endpoints must be HTTP(S);
`proof_dir` must be nonempty without NUL bytes. CLI file commitments use
SHA-256(input). Proofs live at `proof_dir/<digest-hex>.ots`; omitted verify
`--proof` resolves the same path. Dashboard paths are `/ots/status`,
`/ots/stamp`, `/ots/verify`. Pending is not verified; canonical Bitcoin chain
verification trusts the configured Esplora provider, not an independent full
node. For the complete protocol and safe proof I/O requirements see
[OTS Integration](ots-integration.md).

## Dashboard live settings are a separate API

The dashboard uses snake_case `LiveConfig` over `GET /api/config` and
`POST /api/config`; it is not an arbitrary live TOML editor. Supported signed
operation is Ed25519 + BLAKE3 + LSB, without encryption/ECC. Unsupported
backend/kernel/hash/crypto selections fail rather than being ignored.

- `lsb_bits`: 1–4; `resolution`: `WIDTHxHEIGHT`, dimensions 1–4096.
- `sign_rate_ms`: at least 50 ms; requests are sampled artifacts, not a
  continuous signed-media timeline.
- `opacity`: 0–1, **preview only**, not modification of signed carrier bytes.
- `signing_backend = "ed25519"`, `stego_type = "lsb"`,
  `hash_algorithm = "blake3"`, `encrypt = false`, `ecc = false`.
- `overlay_text` (at most 4096 bytes) and `qr_scale` (5–100) remain settings
  fields, not evidence that an overlay is embedded. Unavailable visual
  controls are disabled in the UI.
- `transport`: `websocket` or feature-enabled `webrtc` (resolved transport,
  distinct from CLI policy `auto`). Audio uses WebSocket.

The browser hydrates supported settings before serialized full-config writes.
Frame metadata belongs to the returned frame, not the latest settings view.
The displayed public key is the actual runtime signer, stable for that runtime,
not an independent person/organization identity. There is no live Ethereum or
MetaMask signing backend.

### Transport and evidence

Transport choice is URL query (`?transport=`), then saved user choice, then
server-advertised default from `GET /api/webrtc/config`. Auto may fall back to
WebSocket; fallback is not persisted as the user's pinned preference. Pinned
WebRTC fails visibly if unavailable. `--ice-server` is repeatable and requires
a WebRTC-enabled build; unsupported schemes/TURN without credentials are
skipped with diagnostics. No configured STUN/TURN server does not imply a
loopback-only network topology: host candidates depend on the machine.

Optional H.264 RTP is a lossy preview, not the exact signed evidence. Record
exports are bounded stored-ZIP archives containing signed PNG snapshots or
PCM16 WAV chunks and extraction manifests (public key, indices, bit depth,
audio placement key). They are **sampled artifacts, not continuous video or
uninterrupted microphone recordings**. Preview overlays and opacity are not
part of the signed bytes. Extract/verify the archived artifacts using their
manifest; live server metrics alone are not archive-verification proof.

See [CLI Reference](cli-reference.md), [Getting Started](getting-started.md),
and [Compatibility](compatibility.md).
