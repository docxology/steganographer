# Frequently Asked Questions

## General

### What is steganography?

Steganography is the practice of hiding information within other data. Unlike encryption (which makes data unreadable), steganography makes hidden data invisible or inaudible within carrier media like images, video, or audio.

### How is this different from a digital watermark?

Watermarking can carry an ownership/authentication claim, but a valid signature proves only a relationship to a key. Steganographer's legacy workflow signs canonical media excluding kernel-owned regions, not every container bit or displayed metadata field. Identity needs an independently pinned public key; signatures do not establish that content depicts a true event.

### Can I hide arbitrary messages in video/audio?

Yes, through the opt-in generic packet alpha for lossless PNG/raw RGB spatial
LSB and S16LE audio. Use `encode --payload-file` or `--payload-text`, then
`decode` (full envelope checks) or `extract` (raw payload) to recover it.
Legacy encode/verify remains the default signed-carrier workflow. Generic
packets support keyed placement (`--embedding-key`), payload signing
(`--signing-key`), compression, AEAD encryption, and Reed-Solomon ECC.

### Is the hidden data visible/audible?

Low-bit embedding makes small integer changes, but visibility/audibility depends on content, playback and bit depth. Imperceptibility is not statistical undetectability. Visible rendering APIs are separate and are not supported as signed dashboard overlays.

---

## Build & Install

### Do I need GStreamer to build?

Only native GStreamer functionality needs it. Core and WASM do not. The CLI can be built without its native `gst` feature using `--no-default-features`; a default CLI build includes GStreamer:

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

You need the public key of the expected signer, obtained through a trusted channel. A key printed by the encoder or supplied in the same archive is extraction metadata, not independent identity proof. Without `--public-key`, legacy `verify` is extraction-only and explicitly not verified. Generic decode/extract can require `--trusted-signer`.

### Can I get machine-readable JSON output from verify?

Yes. Use `--format json`:

```bash
steganographer verify --input file.rgb --stego-type lsb_video --format json
```

JSON distinguishes extraction from verification and reports outcomes for scripts. Missing payload is exit 2; failed verification, including a revoked signer, is exit 3. Use [CLI Reference](cli-reference.md) for the current schema and exit policy.

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

Each placeholder expands at rendering time. The text is not an independently verified timestamp or signer identity, and visible overlays cannot be mixed into the signed native invisible-kernel pipeline.

### What file formats are supported for encode/verify?

Offline encode/verify supports decoded lossless images (including PNG), raw RGB and S16LE/WAV audio subject to the chosen kernel and output policy. JPEG and other lossy outputs cannot preserve exact LSB evidence. Native file pipelines produce exact RGB Matroska or PCM WAV; arbitrary source/sink pipelines require appropriate plugins and may invalidate embedded data if they transcode lossily.

### How many frames can I watermark per second?

Throughput depends on dimensions, kernel, codec, build and hardware. Signing microbenchmarks are not end-to-end capture/delivery rates. Dashboard signing is sampled and backpressured, not a promise to sign every camera frame.

### Does it survive re-encoding (H.264, JPEG)?

There is no universal codec guarantee. LSB generally requires exact lossless preservation. DCT checks clean integer reconstruction and rejects unstable saturated covers, but sharing JPEG's transform family does not ensure JPEG survival. Current SS is keyed bounded residue/QIM with majority detection, not additive DSSS; ordinary texture can recover cleanly without destructive averaging, but noise/codec resilience remains channel dependent. Re-embed older SS artifacts from original media.

The optional learned model's synthetic quantization evaluation is not a real H.264 test; recorded real-codec experiments did not establish reliable recovery. Its short payload and decoder score do not prove identity. See [Algorithms](algorithms.md).

### Can I use this on livestreams (Zoom, OBS)?

Native output can feed a virtual device if the OS and installed plugins support it (for example, v4l2loopback on Linux). Zoom/OBS and similar applications may resize, screen-capture or lossy-encode the media, destroying the hidden data. A working preview is not evidence of a verifiable downstream livestream.

On macOS, the CLI owns Cocoa bootstrap for native video/audio dispatch; reusable headless library calls do not create a process-global Cocoa loop. Embedding applications own any required native main-loop integration.

---

## Cryptography

### Why BLAKE3 instead of SHA-256?

BLAKE3 supports parallel hashing and is the default live hash. Actual speed depends on input size, CPU and implementation; it is not a fixed multiple of SHA-256. Offline supported hash selection does not imply the dashboard accepts that selection.

### Why Ed25519 instead of RSA?

Ed25519 has compact 32-byte public keys and 64-byte signatures, useful where carrier capacity is limited. Strict verification and weak imported-key rejection are enforced. Core's optional alternative backends do not change the fixed Ed25519 legacy media payload or the dashboard's supported backend.

### Is this quantum-resistant?

Ed25519 is not quantum-resistant. Optional library ML-DSA-44/65/87 and hybrid Ed25519 + ML-DSA backends exist, with larger signatures. They are not working dashboard alternatives or drop-in replacements for fixed Ed25519 legacy media signatures. See [Cryptography](cryptography.md).

### What happens if my private key is compromised?

A compromised key can sign arbitrary attacker-chosen content under that identity. Neither a watermark nor prior possession of the public key prevents forgery after compromise. Rotate the key, revoke the old public key through a trusted policy, secure/delete old private material and tell verifiers which key is trusted. Revocation policy is external to the signature bytes.

See [Key Rotation](key-rotation.md) for the historical incident and current CLI policy.

---

## Troubleshooting

### `No steganographic signature found in the file`

Possible causes:

1. File was not encoded with steganographer
2. File was lossy-compressed after encoding (H.264, JPEG, etc.)
3. Wrong `--stego-type` specified (using `lsb_video` for an audio file)
4. File was truncated

### `Capacity error: frame too small`

Capacity includes framing, not just the 109-byte signature. One-bit legacy LSB needs 904 carrier bytes/samples; two-bit LSB needs 452. Other kernels count eligible units differently: SS traits use green pixels/first-channel PCM frames; DCT uses complete 8×8 blocks. Use the capacity report for the actual settings.

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
size = 109            # 4 magic + 1 version + 8 frame + 32 hash + 64 signature
```

### Can I increase the embedding capacity?

Higher LSB bit depth increases raw capacity and maximum change. Generic transforms/framing and the selected kernel still determine usable payload size. Higher capacity is not a promise of acceptable distortion or stealth; see [Steganography Theory](steganography-theory.md).

### Where can I learn about the theory behind this?

- [Steganography Theory](steganography-theory.md) — Information-theoretic foundations, steganalysis
- [Cryptography](cryptography.md) — BLAKE3, Ed25519, Kerckhoffs' principle, post-quantum
- [Security](security.md) — Threat model, Cachin's framework

---

## Dashboard

### How do I launch the dashboard?

```bash
./run.sh    # Choose option 1 (Dashboard)
# Or directly:
cargo run -p steganographer-cli -- dashboard --port 8080 --backend ed25519
```

Then open [http://localhost:8080](http://localhost:8080).

### Are QR overlays and MetaMask supported?

No. Signed visual overlays/QR, MetaMask and Ethereum signing are unavailable in the dashboard. These are disabled controls, not working alternate modes. The live signer is Ed25519/BLAKE3 with LSB. Preview opacity affects display only, not signed pixels or exported bytes.

### What do the live config controls do?

Supported controls change LSB bit depth, capture resolution and sampling cadence. The client hydrates config before serialized full-object writes to the snake_case API. Encoding records per-artifact parameters so later verification does not incorrectly use the newest slider settings. Unsupported hash/kernel/encryption/ECC/backend requests reject rather than silently acting as defaults.

### Which transport is selected?

Video uses URL `transport` query, then saved preference, then server default. `auto` can fall back from WebRTC to WebSocket without saving the fallback as your preference. Pinned WebRTC fails visibly when unavailable. Audio uses WebSocket. `/api/webrtc/config` requires bearer auth when configured, as do guarded mutation routes; public read routes are not blanket-authenticated.

RTC sends JSON/base64 (`jpeg_b64`, a historical name; browser content is PNG)
inside STGO 20-byte binary chunk headers, not raw binary JPEG images.
Chunks are ≤16 KiB; full serialized JSON/base64 must fit 4 MiB. Oversize
errors report actual/maximum bytes and suggest smaller resolution or WebSocket;
that transport has its own limits. Signed replies contain lossless PNG.

Default bind is loopback. Tokenless browser mutations reject foreign Origin, and WebSocket upgrades enforce Origin/token gates. Origin/CORS are not a replacement for authentication or TLS on an exposed deployment.

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

The browser attempts camera startup; permissions, secure-context rules and device availability still apply.

### Can I export session data?

The footer Export action (or `E`) downloads session/config/metric information. Metrics and verification labels are server-reported. This report is not independent verification of downloaded signed artifacts.

Decode disconnect clears the verdict without releasing an outstanding encode.
After encode reconnect, previous global cached results stay historical until
the new epoch has a target. Archive ownership is bound at submission, not reply
arrival; a recording started later cannot adopt the earlier request. Repeated
cached audio verification replies do not inflate processed/verified counters.

### Does the dashboard support audio steganography?

The Audio tab captures microphone input and displays waveform/spectrum and server-reported verification. Signed output is the **returned PCM**, not the original microphone buffer. Its extraction metadata includes frame index, LSB depth and a public embedding/extraction key.

### Can I record and save the signed video/audio?

Yes. Record exports bounded stored-ZIP archives:

- **Video:** sampled lossless signed PNG snapshots.
- **Audio:** returned signed PCM wrapped as separate WAV chunks.
- **Manifest:** per-entry public key, indices, bit depth and audio extraction metadata.

These are not continuous VP9/WebM video or uninterrupted microphone capture. Sampling, request backpressure and device gaps matter. Reaching a size/entry cap stops recording visibly rather than silently discarding entries.

Verify downloaded PNG/WAV entries independently with the CLI and their manifest parameters (`--frame-index` is needed for keyed legacy audio). Pin the expected public key through a trusted channel; the archive's own key is not independent identity evidence. The GUI does not perform this archive verification in-browser.

### What do green verification counters establish?

The server extracts and checks the actual post-embed PNG/PCM using the public half of its real runtime signer. The UI matches results by index and server-wide cache revision to avoid attributing stale results to a new frame. Counters are still server-reported, not a proof of uninterrupted capture or a separately verified archive.

### How is the Docs tab rendered safely?

Markdown HTML is inserted only after sanitization. If the renderer or sanitizer is unavailable/fails, the tab displays text instead of inserting unsanitized HTML.

### Does a clean scan prove there is no hidden data?

No. RS/chi-squared outputs are diagnostics, not calibrated natural-image detection probabilities. Unavailable statistics are not clean. ZIP/OOXML, lexical PDF and Unicode scans are bounded and report findings, detection and completeness separately. An incomplete negative retains uncertainty; a positive remains positive if evidence display is capped.

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
