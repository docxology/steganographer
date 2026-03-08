# Frequently Asked Questions

## General

### What is steganography?

Steganography is the practice of hiding information within other data. Unlike encryption (which makes data unreadable), steganography makes hidden data invisible or inaudible within carrier media like images, video, or audio.

### How is this different from a digital watermark?

Digital watermarking is a subset of steganography focused on marking ownership or authenticity. Steganographer embeds cryptographic signatures (not arbitrary data) to prove a frame was produced by a specific key holder and hasn't been tampered with.

### Can I hide arbitrary messages in video/audio?

The current implementation only embeds `SignaturePayload` structs (104 bytes: frame index + BLAKE3 hash + Ed25519 signature). Extending to embed arbitrary data would require modifying `lsb_video.rs` or `lsb_audio.rs` to accept custom payloads.

### Is the hidden data visible/audible?

**LSB (1-2 bits)**: No. The changes are below human perception:

- Video: ±1–3 out of 256 luminance levels (imperceptible)
- Audio: ±1–3 out of 32,768 sample levels (~90 dB SNR — completely inaudible)

**Text Overlay**: Yes by design — it's a visible watermark.

---

## Build & Install

### Do I need GStreamer to build?

**Only for the `steganographer-gst` and `steganographer-cli` crates.** The core crate builds and tests without it:

```bash
cargo build -p steganographer-core    # No GStreamer needed
cargo test -p steganographer-core     # No GStreamer needed
```

### `gstreamer-1.0.pc` not found during build

GStreamer development headers are missing. Install them:

```bash
# macOS
brew install gstreamer

# Ubuntu/Debian
sudo apt install libgstreamer1.0-dev libgstreamer-plugins-base1.0-dev

# Fedora
sudo dnf install gstreamer1-devel gstreamer1-plugins-base-devel
```

### `cargo: command not found`

Rust toolchain is not in your PATH. If you installed via rustup:

```bash
source "$HOME/.cargo/env"
```

Or use the full path: `~/.cargo/bin/cargo build`

---

## Usage

### How do I verify a watermarked file?

```bash
steganographer verify --input file.rgb --public-key <hex> --stego-type lsb_video
```

You need the public key that was printed when the file was encoded. Without it, you can only confirm a signature exists but not verify its authenticity.

### Can I get machine-readable JSON output from verify?

Yes. Use `--format json`:

```bash
steganographer verify --input file.rgb --stego-type lsb_video --format json
```

This outputs a JSON object with `found`, `stego_type`, `frame_index`, `hash`, `signature_preview`, `status`, and `message` fields — ideal for CI/CD pipelines or scripted batch verification.

### Can I add timestamps or frame numbers to the overlay text?

Yes. Use template placeholders in the `text` field:

```toml
[video.stego.overlay]
text = "{date} {time} F{frame_index}"
```

Supported placeholders:

- `{timestamp}` — full UTC datetime (e.g., `2026-03-07 20:25:52`)
- `{frame_index}` — current frame number
- `{date}` — UTC date only
- `{time}` — UTC time only

Each placeholder is expanded at embed-time, so every frame gets a unique value.

### What file formats are supported for encode/verify?

Currently:

- **Video**: Raw RGB pixel data (3 bytes/pixel, no headers)
- **Audio**: Raw S16LE PCM (2 bytes/sample, mono, no headers)

For container formats (MP4, WAV, MKV), use the live pipeline with GStreamer's `filesrc` and `decodebin`.

### How many frames can I watermark per second?

On a modern machine (Apple M1/M2 or x86_64):

- BLAKE3 hash of 1080p frame: **<1 ms**
- Ed25519 sign: **<0.1 ms**
- LSB embed (1-bit): **<0.5 ms**
- **Total**: ~1.5 ms/frame → **600+ fps** throughput (limited by GStreamer I/O in practice)

### Does it survive re-encoding (H.264, JPEG)?

**No.** LSB data is destroyed by any lossy codec because codecs quantize frequency coefficients, which changes pixel/sample values. The text overlay partially survives (it's visible text burned into pixels).

For codec-robust watermarking, see the [Roadmap](roadmap.md) for planned DCT-domain and Video Seal integration.

### Can I use this on livestreams (Zoom, OBS)?

Yes, on Linux with v4l2loopback:

1. Create a virtual camera: `sudo modprobe v4l2loopback video_nr=42`
2. Run steganographer: `steganographer video --sink "v4l2sink device=/dev/video42"`
3. Select "Steganographer" as your camera in Zoom/OBS

On macOS:

1. Run Steganographer to open a live preview window (`osxvideosink`)
2. In OBS, create a "Window Capture" source targeting the Steganographer window
3. Start the OBS Virtual Camera
4. Select "OBS Virtual Camera" in Zoom/Teams

---

## Cryptography

### Why BLAKE3 instead of SHA-256?

BLAKE3 is ~6× faster than SHA-256 on modern CPUs and supports tree hashing for parallelism. For real-time video processing, this speed difference matters. Both provide 128-bit collision resistance.

### Why Ed25519 instead of RSA?

| Property         | Ed25519   | RSA-2048   |
| ---------------- | --------- | ---------- |
| Key size         | 32 bytes  | 256 bytes  |
| Signature size   | 64 bytes  | 256 bytes  |
| Sign speed       | ~50 µs    | ~1 ms      |
| Verify speed     | ~100 µs   | ~30 µs     |
| Payload overhead | 104 bytes | 520+ bytes |

Ed25519's compact signatures (64 bytes vs 256+ for RSA) are critical for steganography — every byte of payload requires more carrier capacity.

### Is this quantum-resistant?

No. Ed25519 would be broken by a sufficiently large quantum computer running Shor's algorithm. Post-quantum signature schemes (ML-DSA) are tracked in the [Roadmap](roadmap.md).

### What happens if my private key is compromised?

An adversary with your private key can:

- Forge valid signatures on any data
- Create watermarked media that appears authentic
- They **cannot** read or modify existing watermarks without the actual frame data

**Mitigation**: Rotate keys per-session and securely delete old private keys.

---

## Troubleshooting

### `No steganographic signature found in the file`

Possible causes:

1. File was not encoded with steganographer
2. File was lossy-compressed after encoding (H.264, JPEG, etc.)
3. Wrong `--stego-type` specified (using `lsb_video` for an audio file)
4. File was truncated

### `Capacity error: frame too small`

The frame doesn't have enough bytes to embed the 104-byte payload. Minimum sizes:

- 1-bit LSB: 864 pixel bytes (288 RGB pixels, ~17×17)
- 2-bit LSB: 432 pixel bytes (144 RGB pixels, ~12×12)

### `Status: ❌ INVALID`

The signature was found but verification failed. This means:

- The frame data was modified after signing, OR
- The wrong public key was used, OR
- The frame was partially corrupted

### GStreamer pipeline hangs

1. Enable debug: `GST_DEBUG=3 steganographer video ...`
2. Ensure format compatibility: add `videoconvert` or `audioconvert` between elements
3. Check permissions: camera/microphone access may be blocked by the OS

---

## Configuration

### How do I change the video resolution?

Edit `steganographer.toml`:

```toml
[video.pipeline]
width = 1280
height = 720
framerate = 30
```

`run.sh` reads these values automatically. See [Configuration](configuration.md) for the full schema.

### What is the `[video.pipeline.payload]` section for?

It configures the cryptographic payload embedded in each frame:

```toml
[video.pipeline.payload]
type = "signature"    # "signature" (BLAKE3+Ed25519) or "custom"
size = 104            # 8 (frame index) + 32 (BLAKE3) + 64 (Ed25519)
```

### Can I increase the embedding capacity?

Yes, increase the LSB bits from 1 to 2–4 in `[video.stego.lsb_signature]`. But higher bits make the embedding more detectable. See [Steganography Theory](steganography-theory.md) for the capacity–security tradeoff.

### Where can I learn about the theory behind this?

- [Steganography Theory](steganography-theory.md) — Information-theoretic foundations, steganalysis
- [Cryptography](cryptography.md) — BLAKE3, Ed25519, Kerckhoffs' principle, post-quantum
- [Security](security.md) — Threat model, Cachin's framework

---

## Dashboard

### How do I launch the dashboard?

```bash
./run.sh    # Choose option 'd' (Dashboard) or 'a' (All including dashboard)
# Or directly:
cargo run -p steganographer-cli -- dashboard --port 8080 --backend ed25519
```

Then open [http://localhost:8080](http://localhost:8080).

### What is the QR data matrix overlay?

The dashboard renders a small red/black binary grid in the bottom-right corner of the video feed. Each frame encodes 20 bytes of metadata: frame counter, BLAKE3 hash prefix, timestamp, backend ID, and verification status. The Overlay Opacity slider controls its visibility.

### Can I use MetaMask for signing?

Yes. Click "Connect MetaMask" in the dashboard header. The dashboard will request `personal_sign` (EIP-191) via MetaMask. Select "Ethereum" in the Sign Backend dropdown.

### What do the live config controls do?

| Control | Effect |
| --------- | -------- |
| **Overlay Opacity** | Controls QR overlay transparency (0.0–1.0) |
| **LSB Bits** | Number of least-significant bits used for embedding (1–4) |
| **Sign Backend** | Switch between Ed25519 and Ethereum signing |
| **Overlay Text** | Custom text displayed above the QR grid |
| **Sign Rate** | How often frames are signed (0.2/s – 5/s) |
| **QR Scale** | Size of QR overlay (5% = small corner, 100% = full frame) |
| **Resolution** | Video capture resolution (320×240 to 1920×1080) |
| **Record** | Toggle video/audio recording with steganographic data embedded |

Changes take effect immediately and are synced to the server via `POST /api/config`.

### Are there keyboard shortcuts?

Yes. The dashboard supports the following keyboard shortcuts:

| Key | Action |
| ----- | -------- |
| `Space` | Toggle camera on/off |
| `R` | Toggle video recording |
| `1` / `2` / `3` | Switch to Video / Audio / Docs tab |
| `+` / `-` | Increase / decrease LSB bits |
| `E` | Export session report as JSON |

Shortcuts are disabled when typing in input fields.

### Can I auto-start the camera?

Yes. Add `?autostart=1` to the dashboard URL:

```text
http://localhost:8080?autostart=1
```

The camera will start automatically without requiring a click.

### Can I export session data?

Yes. Click the `📥 Export` button in the footer (or press `E`). This downloads a JSON report containing session duration, config snapshot, video metrics, and the last verification result.

### Does the dashboard support audio steganography?

Yes! Click the **Audio** tab at the top of the dashboard. The audio tab provides:

- **Left panel**: Live microphone waveform and spectrum visualization
- **Right panel**: Audio steganography config (LSB Bits, Sign Backend, Buffer Size, Sample Rate) and verification results
- **Record**: Export signed audio as WAV files with LSB-embedded integrity data

### Can I record and save the signed video/audio?

Yes. Both the Video and Audio tabs have a **Record** button (red dot in the stats bar):

- **Video**: Records the canvas output (with QR overlay) as a WebM file
- **Audio**: Records PCM audio chunks as a WAV file
- Files auto-download with timestamped filenames when you click **Stop**

### What security scenarios does steganographer address?

See the [Security documentation](security.md) for detailed threat models including:

- Deepfake defense
- Evidence chain of custody
- Broadcast authentication
- Confidential document recording
- Audio forensics

### What do the tooltips show?

Every control in the dashboard has a detailed mouseover tooltip explaining:

- What the control does
- Recommended values
- Security implications
- Trade-offs (e.g., capacity vs. detectability)

---

## Further Reading

- [Getting Started](getting-started.md) — Installation and first steps
- [CLI Reference](cli-reference.md) — All commands and options
- [Configuration](configuration.md) — Full TOML config schema and dashboard live controls
- [Algorithms](algorithms.md) — How the stego modules work
- [Security](security.md) — Threat models, use cases, deployment guidance
