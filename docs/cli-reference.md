# CLI Reference

## Synopsis

```text
steganographer [OPTIONS] <COMMAND>
```

```mermaid
flowchart LR
    CLI["steganographer"] --> VIDEO["video\n🎥 Live video pipeline"]
    CLI --> AUDIO["audio\n🎵 Live audio pipeline"]
    CLI --> ENCODE["encode\n🔒 Offline encoding"]
    CLI --> DECODE["decode\n📦 Generic packet decode"]
    CLI --> EXTRACT["extract\n📤 Packet payload extraction"]
    CLI --> SCAN["scan\n🧪 Bounded forensic scan"]
    CLI --> VERIFY["verify\n🔓 Signature verification"]
    CLI --> KEYGEN["keygen\n🔑 Key generation"]
    CLI --> INFO["info\n📊 Capacity reporting"]
    CLI --> ANALYZE["analyze\n🔬 Steganographic analysis"]
    CLI --> DERIVE["derive\n🔑 Key derivation"]
    CLI --> CONFIG["config\n⚙️ Config validation"]
    CLI --> DASH["dashboard\n🌐 Web GUI"]
    CLI --> REVOKE["revoke\n🚫 Key revocation"]
    CLI --> OTS["ots\n⏱ OpenTimestamps"]
    style CLI fill:#333,stroke:#e53935,color:#e0e0e0
    style DASH fill:#2d5016,stroke:#4a8c2a,color:#fff
```

## Global Options

| Option | Short | Default | Description |
| --- | --- | --- | --- |
| `--config <PATH>` | `-c` | `config/example.toml` | Path to TOML configuration file |
| `--log-level <LEVEL>` | `-l` | `info` | Log verbosity: `trace`, `debug`, `info`, `warn`, `error` |
| `--quiet` | `-q` | `false` | Suppress all output except final result (for scripting) |
| `--help` | `-h` | — | Print help information |
| `--version` | `-V` | — | Print version |

---

## Commands

### `video` — Live Video Pipeline

Run a real-time video pipeline: capture frames from a source, apply steganography, and push to a sink.

```bash
steganographer video [OPTIONS]
```

| Option | Default | Description |
| --- | --- | --- |
| `--source <PIPELINE>` | From config | GStreamer source element string |
| `--sink <PIPELINE>` | From config | GStreamer sink element string |
| `--max-frames <N>` | Unlimited | Stop after processing N frames |
| `--signing-key <PATH>` | Ephemeral | Hex-encoded 32-byte Ed25519 signing-key file; if omitted, an ephemeral keypair is generated per run |

**Examples**:

```bash
# Test source → display window (macOS)
steganographer video --source "videotestsrc" --sink "osxvideosink"

# Webcam → virtual camera (Linux with v4l2loopback)
steganographer video \
    --source "v4l2src device=/dev/video0" \
    --sink "v4l2sink device=/dev/video42"

# Using config file
steganographer video --config config/example.toml

# Process exactly 100 frames
steganographer video --source "videotestsrc" --sink "autovideosink" --max-frames 100
```

---

### `audio` — Live Audio Pipeline

Run a real-time audio pipeline with LSB steganography.

```bash
steganographer audio [OPTIONS]
```

| Option | Default | Description |
| --- | --- | --- |
| `--source <PIPELINE>` | From config | GStreamer audio source element |
| `--sink <PIPELINE>` | From config | GStreamer audio sink element |
| `--max-buffers <N>` | Unlimited | Stop after processing N audio buffers |
| `--signing-key <PATH>` | Ephemeral | Hex-encoded 32-byte Ed25519 signing-key file; if omitted, an ephemeral keypair is generated per run |

**Examples**:

```bash
# Test tone → speakers
steganographer audio \
    --source "audiotestsrc wave=sine freq=440" \
    --sink "autoaudiosink"

# Microphone → PulseAudio output
steganographer audio \
    --source "pulsesrc" \
    --sink "pulsesink"
```

---

### `encode` — Offline File Encoding

Embed legacy signed-carrier attestations, or explicitly embed an opt-in generic
packet payload.

```bash
steganographer encode [OPTIONS]
```

| Option | Short | Default | Description |
| --- | --- | --- | --- |
| `--input <PATH>` | `-i` | Required | Input file path |
| `--output <PATH>` | `-o` | Required | Output file path |
| `--stego-type <TYPE>` | — | `lsb_video` | Algorithm: `lsb_video`, `lsb_audio`, `spread_spectrum_video`, `dct_video` |
| `--bits <N>` | — | `1` | LSB bits per sample/pixel (1–4) |
| `--format <FORMAT>` | — | `plain` | Output format: `plain` (human-readable) or `json` (machine-readable) |
| `--input-format <FORMAT>` | — | Auto | `raw_rgb`, `raw_s16le`, `png`/`image`, or `wav` |
| `--width <N>` / `--height <N>` | — | None | Required pair for dimension-dependent headerless RGB kernels such as DCT |
| `--signing-key <PATH>` | — | Ephemeral | Hex-encoded 32-byte Ed25519 signing-key file (legacy signature or generic packet payload) |
| `--embedding-key <HEX>` | — | Config/random | Keyed audio/spread placement key |
| `--embedding-key-file <PATH>` | — | Config/random | File containing the embedding key |
| `--encrypt` | — | `false` | Encrypt the payload (legacy signature or generic packet) with ChaCha20-Poly1305 |
| `--encryption-key <HEX>` | — | Random | ChaCha20-Poly1305 key |
| `--encryption-key-file <PATH>` | — | None | File containing the encryption key |
| `--password <TEXT>` | — | None | Password for an Argon2id-derived encryption key (PKT-007); the KDF transform records its salt + parameters in the envelope. **Mutually exclusive with `--encryption-key`/`--encryption-key-file`; visible in shell history/`ps`** |
| `--password-file <PATH>` | — | None | File containing the password for password-derived encryption (mutually exclusive with `--encryption-key`/`--encryption-key-file`) |
| `--ecc` | — | `false` | Apply bounded Reed-Solomon error correction (legacy signature or generic packet) |
| `--ecc-parity <N>` | — | `4` | Reed-Solomon parity symbols (maximum 16) |
| `--payload-file <PATH>` | — | None | Opt into generic packet alpha with arbitrary file bytes |
| `--payload-text <TEXT>` | — | None | Opt into generic packet alpha with UTF-8 text |
| `--mime-type <TYPE>` | — | None | Public generic-packet MIME metadata |
| `--filename <NAME>` | — | Payload basename | Safe display filename; path components are rejected |
| `--no-verify-write` | — | `false` | Skip the post-write re-read verification of a generic packet carrier |
| `--spread <N>` | — | `1` | Multi-frame spreading: spread one signature across N frames (legacy signature path only; generic packets reject `> 1`) |
| `--hash-algorithm <ALGO>` | — | `blake3` | Hash algorithm: `blake3` (default), `sha256`, `sha3-256` |
| `--dir` | — | `false` | Batch mode: process all files in the input directory (legacy signature path only; rejected with generic packets) |

**Currently supported formats**:

- `lsb_video`: Raw RGB or lossless decoded PNG/image data
- `lsb_audio`: Raw S16LE PCM or 16-bit integer WAV, preserving WAV properties
- `spread_spectrum_video`: PN-sequence modulation for noise resistance
- `dct_video`: DCT-domain embedding for compression resistance

**Examples**:

```bash
# Encode video with 1-bit LSB
steganographer encode -i frame.rgb -o frame_signed.rgb --stego-type lsb_video --bits 1

# Encode audio with 2-bit LSB
steganographer encode -i audio.wav -o audio_signed.wav --stego-type lsb_audio \
  --bits 2 --embedding-key-file keys/audio.key

# Opt-in generic packet alpha
steganographer encode -i cover.png -o packed.png \
  --payload-file report.pdf --mime-type application/pdf --bits 2

# Password-protected packet (Argon2id KDF, PKT-007) — mutually exclusive
# with --encryption-key/--encryption-key-file
steganographer encode -i cover.png -o packed.png \
  --payload-file report.pdf --password-file secret.txt --bits 2
```

Without `--payload-file` or `--payload-text`, encode preserves the legacy signed
carrier behavior and prints the public key needed by `verify`. The generic
packet path supports `lsb_video` (RGB/PNG) and `lsb_audio` (PCM S16 WAV / raw
S16LE) carriers, sequential or keyed placement (`--embedding-key`), and the
Ed25519 signing (`--signing-key`), DEFLATE (`--compress`), AEAD encryption
(`--encrypt` or the password path), and chunked Reed-Solomon (`--ecc`)
transforms. The password path (PKT-007) derives the AEAD key with Argon2id
and records a critical `TRANSFORM_KDF_ARGON2ID` descriptor (salt + parameters)
so `decode --password*` can re-derive it; it is mutually exclusive with
explicit encryption keys. After writing, the carrier is re-read and
re-extracted to confirm byte-identical packet recovery
(post-write verification); `--no-verify-write` skips that check. Multi-frame
spreading remains unsupported for generic packets.

---

### `decode` — Generic Packet Decode

Decode and digest-check an opt-in generic packet. This does not imply carrier
provenance; use `verify` for legacy signed-carrier attestations.

```bash
steganographer decode --input packed.png --output recovered.pdf [OPTIONS]
```

| Option | Short | Default | Description |
| --- | --- | --- | --- |
| `--input <PATH>` | `-i` | Required | Encoded carrier |
| `--output <PATH>` | `-o` | Required | Decoded payload destination |
| `--stego-type <TYPE>` | — | `lsb_video` | Generic kernel: `lsb_video` or `lsb_audio` |
| `--bits <VALUE>` | — | `auto` | Probe 1–4, or require an exact strength |
| `--input-format <FORMAT>` | — | Auto | `raw_rgb`, `raw_s16le`, `png`/`image`, or `wav` |
| `--format <FORMAT>` | — | `plain` | `plain` or `json` report |
| `--force` | — | `false` | Replace an existing payload output |
| `--decrypt` | — | `false` | Decrypt an AEAD-encrypted generic packet payload |
| `--decryption-key <HEX>` | — | None | ChaCha20-Poly1305 decryption key (hex, 32 bytes) |
| `--decryption-key-file <PATH>` | — | None | File containing the decryption key |
| `--password <TEXT>` | — | None | Password to re-derive the Argon2id AEAD key recorded in the packet's `TRANSFORM_KDF_ARGON2ID` descriptor (PKT-007). **Mutually exclusive with `--decryption-key`/`--decryption-key-file`; visible in shell history/`ps`** |
| `--password-file <PATH>` | — | None | File containing the password for password-derived decryption (mutually exclusive with `--decryption-key`/`--decryption-key-file`) |
| `--embedding-key <HEX>` | — | None | Embedding key (hex, 32 bytes) for keyed placement |
| `--embedding-key-file <PATH>` | — | None | File containing the embedding key |

```bash
steganographer decode -i packed.png -o recovered.pdf --bits auto --format json

# Encrypted packet requires the key
steganographer decode -i packed.png -o recovered.pdf --decrypt --decryption-key <hex>

# Password-protected packet: re-derive the Argon2id AEAD key from the envelope
steganographer decode -i packed.png -o recovered.pdf --password-file secret.txt
```

Decode validates locator limits, envelope CRC32C, canonical metadata, declared
kernel parameters, payload length, and the content digest before writing. It
also reverses any recorded AEAD/ECC transforms (requiring `--decrypt` for
encrypted packets) and refuses to overwrite an existing output unless
`--force` is explicit.

---

### `verify` — Signature Verification

Extract and verify steganographic signatures from media files.

```bash
steganographer verify [OPTIONS]
```

| Option | Short | Default | Description |
| --- | --- | --- | --- |
| `--input <PATH>` | `-i` | Required | Input file path |
| `--stego-type <TYPE>` | — | `lsb_video` | Algorithm: `lsb_video`, `lsb_audio`, `spread_spectrum_video`, `dct_video` |
| `--public-key <HEX>` | — | None | Public key for signature verification |
| `--embedding-key <HEX>` | — | None | Embedding key (hex, 32 bytes) for audio/spread-spectrum extraction |
| `--embedding-key-file <PATH>` | — | Config | File containing the embedding key |
| `--bits <VALUE>` | — | `auto` | Auto-probe 1–4 LSBs or require an exact value |
| `--input-format <FORMAT>` | — | Auto | `raw_rgb`, `raw_s16le`, `png`/`image`, or `wav` |
| `--width <N>` / `--height <N>` | — | None | Explicit headerless raw RGB dimensions |
| `--format <FORMAT>` | — | `plain` | Output format: `plain` (human-readable) or `json` (machine-readable) |
| `--decrypt` | — | `false` | Decrypt an AEAD-encrypted payload (ChaCha20-Poly1305) |
| `--decryption-key <HEX>` | — | None | ChaCha20-Poly1305 decryption key (hex, 32 bytes) |
| `--decryption-key-file <PATH>` | — | None | File containing the decryption key |
| `--ecc` | — | `false` | Apply Reed-Solomon error correction during extraction |
| `--ecc-parity <N>` | — | `4` | Reed-Solomon parity symbols (maximum 16) |
| `--spread <N>` | — | `1` | Multi-frame spreading: the signature was spread across N frames |
| `--hash-algorithm <ALGO>` | — | `blake3` | Hash algorithm: `blake3` (default), `sha256`, `sha3-256` |
| `--revoked-list <PATH>` | — | `keys/revoked.json` | Path to the revoked-keys JSON list checked after a valid signature |

**Examples**:

```bash
# Extract signature (no verification)
steganographer verify -i frame_signed.rgb --stego-type lsb_video

# Extract and verify with public key
steganographer verify -i frame_signed.rgb \
    --stego-type lsb_video \
    --public-key a1b2c3d4e5f6...

# Verify audio
steganographer verify -i audio_signed.raw \
    --stego-type lsb_audio \
    --public-key a1b2c3d4e5f6...

# Machine-readable JSON output
steganographer verify -i frame_signed.rgb \
    --stego-type lsb_video \
    --public-key a1b2c3d4e5f6... \
    --format json
```

**Output** (plain, default):

```text
=== Signature Found ===
  Frame index: 0
  Hash:        a1b2c3d4e5f6a7b8...
  Signature:   1234abcd5678ef90...
  Status:      ✅ VALID
```

**Output** (`--format json`):

```json
{
  "found": true,
  "stego_type": "lsb_video",
  "frame_index": 0,
  "hash": "a1b2c3d4e5f6a7b8...",
  "signature_preview": "1234abcd5678ef90...",
  "status": "valid",
  "message": "Signature is valid"
}
```

Without `--public-key`:

```text
  Status:      ⚠️  No public key provided (signature not verified)
```

If no signature found:

```text
No steganographic signature found in the file.
```

**Status values** (JSON `status` field):

| Status | Meaning | Exit code |
| --- | --- | --- |
| `valid` | Signature cryptographically valid, key not revoked | 0 |
| `valid_revoked` | Signature valid but the key is in the revoked-keys list — treat as untrusted | 0 |
| `invalid` | Signature verification failed | 3 |
| `no_signature` | No embedded signature found | 0 |
| `not_verified` | Signature extracted but no `--public-key` was given | 0 |

---

### `extract` — Packet Payload Extraction

Extract a generic packet payload from a carrier (`lsb_video` / `lsb_audio`).
This is the raw-payload counterpart of `decode`: it recovers the embedded
bytes without the decode-path envelope checks (digest verification, transform
reversal) and is the command the native `stegovideo`/`stegoaudio` elements'
wire format targets.

```bash
steganographer extract [OPTIONS] --input <PATH> --output <PATH>
```

| Option | Short | Default | Description |
| --- | --- | --- | --- |
| `--input <PATH>` | `-i` | Required | Encoded carrier |
| `--output <PATH>` | `-o` | Required | Payload destination |
| `--bits <VALUE>` | — | `auto` | Probe 1–4 LSBs, or require an exact strength |
| `--force` | — | `false` | Replace an existing payload output |
| `--password <TEXT>` | — | None | Password for password-derived packet decoding (Argon2id, PKT-007); reverses a `TRANSFORM_KDF_ARGON2ID` transform chain. **Mutually exclusive with `--decryption-key`/`--decryption-key-file` in `decode`; visible in shell history/`ps`** |
| `--password-file <PATH>` | — | None | File containing the password for password-derived packet decoding |

```bash
steganographer extract -i frame.rgb -o payload.bin --bits auto --force

# Password-protected carrier (Argon2id KDF)
steganographer extract -i packed.png -o payload.bin --password-file secret.txt
```

Exit behavior follows the shared contract: a carrier with no embedded packet
is a usage/packet-not-found error (exit 2), everything else failing is a
runtime error (exit 1), and a successful extraction exits 0.

---

---

### `keygen` — Key Generation

Generate a new Ed25519 signing key pair.

```bash
steganographer keygen [OPTIONS]
```

| Option | Short | Default | Description |
| ------ | ----- | ------- | ----------- |
| `--output <PATH>` | `-o` | `steganographer` | Base path for key files |

**Output files**:

- `<path>.key` — Private signing key (64 hex characters = 32 bytes)
- `<path>.pub` — Public verifying key (64 hex characters = 32 bytes)

**Example**:

```bash
steganographer keygen --output keys/session-001
# Creates: keys/session-001.key
#          keys/session-001.pub
```

---

### `dashboard` — Live Verification Dashboard

Launch a web-based dashboard for real-time round-trip steganography verification.

```bash
steganographer dashboard [OPTIONS]
```

| Option | Short | Default | Description |
| ------ | ----- | ------- | ----------- |
| `--port <PORT>` | `-p` | `8080` | Port to serve the dashboard on |
| `--backend <BACKEND>` | — | `ed25519` | Signing backend: `ed25519` or `ethereum` |
| `--host <ADDR>` | — | `127.0.0.1` | Bind address: `127.0.0.1` (local-only, default) or `0.0.0.0` (all interfaces) |
| `--auth-token <TOKEN>` | — | None | Auth token for mutating API endpoints (`POST /api/config`, `POST /api/metrics/reset`); clients must send `Authorization: Bearer <token>`. Omitted = auth disabled |

**Examples**:

```bash
# Default: Ed25519 on port 8080
steganographer dashboard

# Ethereum backend on custom port
steganographer dashboard --port 3000 --backend ethereum

# Via run.sh (press 'd' for dashboard, 'a' for run-all)
./run.sh
```

The dashboard opens a web UI at `http://localhost:<port>` displaying:

- **Left panel**: Live encode feed with frame metrics
- **Right panel**: Real-time decode and verification results
- **Footer**: Backend, uptime, resolution, payload information

---

### `info` — Capacity Reporting

Report steganographic capacity of a media file.

```bash
steganographer info [OPTIONS]
```

| Option | Short | Default | Description |
| --- | --- | --- | --- |
| `--input <PATH>` | `-i` | Required | Input file path |
| `--stego-type <TYPE>` | — | `lsb_video` | Algorithm: `lsb_video`, `lsb_audio`, `spread_spectrum_video`, `dct_video` |
| `--bits <N>` | — | `1` | LSB bits per sample/pixel (1–4) |
| `--embedding-key <HEX>` | — | None | Report keyed-placement capacity (subtracts the recognition-tag units) |
| `--width <N>` / `--height <N>` | — | None | Explicit dimensions for headerless raw RGB input |
| `--format <FORMAT>` | — | `plain` | Output format: `plain` or `json` |

For LSB kernels the JSON report also includes `generic_max_packet_bytes` and
`generic_usable_units`, computed with the same descriptor/slot math the
`encode`/`decode` kernels use.

**Example**:

```bash
steganographer info -i frame.rgb --stego-type lsb_video --bits 1
```

---

### `config` — Configuration Validation

Validate a TOML configuration file without running any pipeline.

```bash
steganographer config [ACTION]
```

| Argument | Default | Description |
| --- | --- | --- |
| `<ACTION>` | `check` | Config action to perform (currently only `check`) |

**Example**:

```bash
# Validate the default config file
steganographer config check

# Validate a specific config file
steganographer --config my-config.toml config check
```

**Output** (valid config):

```text
✓ Configuration valid: config/example.toml
  Sections: global, video, audio
  Hash algorithm: blake3
```

`config check` also validates the optional `[limits]` table (all seven
`DecodeLimits` overrides must be > 0, and `max_body_len` must not exceed
`max_packet_len`) and the optional `[profiles.<name>]` tables (each
profile's `limits` validate the same way, and its `scan.detectors` set must
only contain known detector IDs). Profiles are listed in the output when
present.

---

### `analyze` — Steganographic Analysis

Analyze a file for steganographic artifacts using statistical tests.

```bash
steganographer analyze [OPTIONS] --input <FILE>
```

| Option | Default | Description |
| --- | --- | --- |
| `--input <FILE>` | Required | Input file to analyze |
| `--analysis-type <TYPE>` | `combined` | Analysis type: `combined` (default), `chi_squared`, `sample_pairs` (also `spa`), or `rs` (also `rs_analysis`) |
| `--format <FORMAT>` | `plain` | Output format: `plain` or `json` |

**Examples**:

```bash
# Basic chi-squared analysis
steganographer analyze --input signed.rgb

# JSON output for CI integration
steganographer analyze --input signed.rgb --format json
```

---

### `scan` — Bounded Forensic Scan

Run structural (entropy, magic-byte family, embedded signature/packet magic),
statistical (chi-squared, sample-pairs, RS), text (Unicode stego), and
container (ZIP/OOXML `ZIP_TOPOLOGY`, DOC-001, DOC-002) detectors over a file
or recursively over a directory. Top-level symlinked inputs are rejected by
default (usage error); recursion never follows symlinks, and recursion and
per-file reads are bounded.

```bash
steganographer scan [OPTIONS] --input <PATH>
```

| Option | Default | Description |
| --- | --- | --- |
| `--input <PATH>` | Required | File or directory to scan |
| `--profile <NAME>` | None | Apply the named `[profiles.<name>]` profile from the config file (limits + `scan.detectors` selection; unknown profiles and config errors are usage errors, exit 2) |
| `--follow-input-symlink` | `false` | Scan the target of a top-level symlinked input instead of rejecting it |
| `--max-depth <N>` | `8` | Maximum directory depth (`0` = top-level files only) |
| `--max-files <N>` | `10000` | Maximum number of files to scan |
| `--max-bytes <N>` | `67108864` | Maximum bytes read per file (larger files truncated) |
| `--format <FORMAT>` | `plain` | `plain`, `json`, or `jsonl` |

Without a profile every detector reports; a profile's `scan.detectors` set
selects which findings are reported (container findings always contribute).
Detector IDs, budgets, and false-positive limits are documented in the
`detector_registry()` in `steganographer-core/src/forensics.rs`.

`jsonl` writes one finding per line to stdout and the summary to stderr. The
exit code is `0` when no findings are present, `1` when at least one file is
flagged, and `2` on a usage error.

```bash
# Scan one file
steganographer scan --input suspicious.png --format json

# Recursively scan a directory, one finding per line
steganographer scan --input ./exports --format jsonl

# Scan with a named config profile (SUR-006: detector selection + limits)
steganographer scan --input ./exports --profile strict
```

---

### `derive` — Key Derivation

Derive signing, encryption, and embedding keys from **either** a high-entropy
master secret (BLAKE3 `derive_key`) **or** a human-chosen password (Argon2id).
The two modes are mutually exclusive — providing both fails.

```bash
steganographer derive [OPTIONS] --output <DIR>
```

| Option | Default | Description |
| --- | --- | --- |
| `--master-secret <HEX>` | — | Master secret (hex-encoded). **WARNING**: visible in shell history and `ps` output. |
| `--master-secret-file <PATH>` | — | Read master secret from a file (hex-encoded). Safer than `--master-secret`. |
| `--master-secret-stdin` | `false` | Read master secret from stdin (hex-encoded). |
| `--password <TEXT>` | — | Password for Argon2id stretching. **WARNING**: visible in shell history and `ps` output. |
| `--password-file <PATH>` | — | Read the password from a file (raw bytes, trailing newline trimmed). |
| `--password-stdin` | `false` | Read the password from stdin (raw bytes, trailing newline trimmed). |
| `--salt <HEX>` | random | Hex-encoded Argon2id salt (≥ 16 bytes). Generated and printed when omitted. |
| `--argon2-memory <KIB>` | `19456` | Argon2id memory cost in KiB (default 19 MiB). |
| `--argon2-iterations <N>` | `2` | Argon2id time cost. |
| `--argon2-parallelism <N>` | `1` | Argon2id lane count. |
| `--output <DIR>` | `keys` | Output directory for derived keys |

**Outputs**:
- `signing.key` / `signing.pub` — Ed25519 signing keypair
- `encryption.key` — ChaCha20-Poly1305 encryption key
- `embedding.key` — LSB PRNG embedding key

> **Security note:** BLAKE3 `derive_key` is a fast KDF, not a slow password
> hashing function. The master secret must be high-entropy random data (at
> least 32 bytes / 64 hex chars). A memorable passphrase will be
> brute-forceable at hash speed. For passwords, use `--password*` to stretch
> with Argon2id instead.
>
> **Argon2id note:** the salt (and parameters) must be saved to re-derive the
> same keys later. When `--salt` is omitted, a random salt is generated and
> printed. Parameters below the OWASP floor (19 MiB / 2 iterations) trigger a
> warning but are accepted.

**Examples**:

```bash
# From a file (recommended)
steganographer derive --master-secret-file secret.hex --output keys

# From stdin
echo "a1b2c3..." | steganographer derive --master-secret-stdin --output keys

# Direct argument (not recommended — visible in ps/history)
steganographer derive --master-secret a1b2c3... --output keys

# Password derivation (Argon2id) — save the printed salt for re-derivation
steganographer derive --password-file passphrase.txt --output keys

# Password derivation with an explicit, reproducible salt
steganographer derive --password-file passphrase.txt \
  --salt 000102030405060708090a0b0c0d0e0f --output keys
```

---

## Exit Codes

| Code | Meaning |
| ---- | ------- |
| 0    | Success (for `scan`: no findings present) |
| 1    | Runtime error (I/O, config parse, pipeline failure); for `scan`: at least one finding |
| 2    | Usage error (bad argument shape/unknown value) or packet-not-found: `decode`/`extract` on a carrier with no embedded generic packet |
| 3    | Signature verification failed (`verify` returning status `invalid`) |

**JSON output contract**: commands with `--format json` always print a single
JSON document (one JSON value, newline-terminated by pretty printing), never
trailing logs or multiple concatenated documents, and the JSON never contains
secret key material (private/seed bytes are never serialized; only public
identifiers such as public-key hex, digests, and signature bytes appear).

## Environment Variables

| Variable | Description |
| -------- | ----------- |
| `RUST_LOG` | Override log level (alternative to `--log-level`) |
| `GST_PLUGIN_PATH` | Additional GStreamer plugin search paths |
| `GST_DEBUG` | GStreamer debug level (e.g., `3` for warnings) |
| `PKG_CONFIG_PATH` | Path to GStreamer `.pc` files (build-time) |

### `revoke` - Revoke a Signing Key

Append a public key to the revoked-keys list. The `verify` command checks
this list and warns if a signature was made with a revoked key.

```bash
steganographer revoke --public-key <HEX> [--output <PATH>]
```

| Option | Default | Description |
| --- | --- | --- |
| `--public-key <HEX>` | - | Public key to revoke (hex-encoded, 32 bytes / 64 hex chars) |
| `--output <PATH>` | `keys/revoked.json` | Path to the revoked-keys file |

---

### `ots` - OpenTimestamps Attestation

Stamp a file's BLAKE3 Merkle root with the OpenTimestamps service, or verify
a `.ots` proof. Subcommands: `stamp`, `verify`. See
[OTS Integration](ots-integration.md) for the full workflow.

```bash
steganographer ots stamp --input report.pdf [--method bitcoin] [--format plain]
steganographer ots verify --input report.pdf [--proof report.pdf.ots] [--format plain]
```

| Option (stamp) | Default | Description |
| --- | --- | --- |
| `--input <PATH>` | - | File to attest |
| `--output-dir <DIR>` | from config or `./ots_proofs/` | Directory for `.ots` proof files |
| `--method <M>` | `bitcoin` | Attestation method: `bitcoin` or `ethereum` |
| `--force` | `false` | Re-stamp even if a proof already exists for this digest |
| `--format <F>` | `plain` | Output format: `plain` or `json` |

| Option (verify) | Default | Description |
| --- | --- | --- |
| `--input <PATH>` | - | File whose digest to check |
| `--proof <PATH>` | `<input>.ots` | Proof file to verify against |
| `--format <F>` | `plain` | Output format: `plain` or `json` |

---

## Configuration-Driven Defaults

The CLI and `run.sh` read pipeline parameters from `steganographer.toml`. All pipeline settings (resolution, framerate, opacity, LSB bits, overlay text, signing backend) are configurable:

```bash
# Uses resolution/framerate from [video.pipeline] in steganographer.toml
steganographer video

# Override source pipeline (config values still used for stego modules)
steganographer video --source "videotestsrc ! videoconvert ! video/x-raw,format=RGB,width=1280,height=720"

# Launch dashboard with config-driven signing backend
steganographer dashboard
```

See [Configuration](configuration.md) for full TOML schema including `[video.pipeline]` with resolution, framerate, opacity, payload, and signing backend settings.

## Further Reading

- [Getting Started](getting-started.md) — First-time setup and tutorial
- [Configuration](configuration.md) — Full TOML config schema
- [Algorithms](algorithms.md) — How the stego modules work
- [Cryptography](cryptography.md) — BLAKE3/SHA-256/SHA-3 + Ed25519 and Ethereum signing
- [Steganography Theory](steganography-theory.md) — Information hiding fundamentals
- [Security](security.md) — Threat models and deployment guidance
- [API Reference](api-reference.md) — Rust API, traits, and HTTP routes
