# AGENTS.md — steganographer-gst

## Purpose

GStreamer integration for real-time media pipeline processing.

## Module Map

| File | Lines | Key Functions |
| ------ | ------- | --------------- |
| `src/lib.rs` | 132 | `init()`, `launch()`, `SigningKernel`, bounded bridge lifecycle, `plugin_init` + `plugin_define!` (name `steganographer_gst` = cdylib file stem) |
| `src/video_filter.rs` | 516 | `run_video_filter()`, `extract_from_source()`, `process_video_file()`, `process_audio_file()` |
| `src/audio_filter.rs` | 290 | `run_audio_filter()`, `extract_from_source()` |
| `src/elements.rs` | 833 | `StegoVideo` native `BaseTransform` element: sequential (`SpatialLsb`) + keyed (`KeyedSpatialLsb`) placement, stride-safe pixel-only embedding, restricted pad templates, real clear-payload, `StreamState` frame-granularity property semantics, `register()` |
| `src/audio_element.rs` | 638 | `StegoAudio` native `BaseTransform` element over interleaved S16LE PCM (`AudioSpatialLsb`/`KeyedAudioSpatialLsb`), restricted S16LE/interleaved pad templates |
| `src/plugin.rs` | 50 | `register_elements()`, plugin metadata constants |
| `tests/gst_roundtrip.rs` | 405 | `stegoaudio` wire-format decode check + packet-hex printer for gst-launch acceptance runs |

## Data Flow

1. GStreamer source pipeline → `appsink name=sink`
2. Pull `Sample` → map buffer writable → parse `VideoInfo`/`AudioInfo` from caps
3. Create `VideoFrame`/`AudioBuffer` → call `stego.embed()`
4. Push modified buffer → `appsrc name=src` → GStreamer sink pipeline

## Supported Formats

- Native elements (`stegovideo`): restricted pad templates — packed one-plane
  `video/x-raw` formats only: `RGB`, `BGR`, `RGBx`, `BGRx`, `XRGB`, `XBGR`
  (negotiation fails loudly otherwise; a runtime allowlist in `transform_ip`
  is a backstop). Embedding is stride-safe: packet bits occupy pixel bytes
  only, never row-padding bytes.
- Native elements (`stegoaudio`): restricted pad templates —
  `audio/x-raw, format=S16LE, layout=interleaved` (any rate/channels).
- Legacy AppSink/AppSrc filters: RGB, BGRA (from GStreamer `video/x-raw`);
  interleaved S16LE with validated rate/channel count and complete sample frames.

## API cutover

- `init()` calls GStreamer initialization only; no `NSApplication` load or
  Cocoa loop. Repeated/threaded headless library calls do not own a UI loop.
  On macOS the CLI owns `gstreamer::macos_main` once at live-command dispatch,
  before Tokio. Never add per-filter Cocoa wrapping.
- Both filter configs require `signing_kernel: Option<SigningKernel>`.
  Video takes `Box<dyn VideoStegoModule>`; audio takes
  `&mut dyn AudioStegoModule`. With a signer the binding must match the actual
  kernel. Video supports LSB/DCT bindings; audio supports LSB only.
- Trait spread-spectrum signing rejects: video green-channel/audio first-channel
  mapping is not the offline CLI scalar carrier binding. Rendering-only APIs
  remain separate from signed invisible kernels; the CLI rejects mixed visible
  rendering/invisible signatures and ignored live crypto/spreading options.
- Sign packed logical pixels/PCM via `steganographer_core::carrier_binding`,
  not padding. Verify actual post-embed output before AppSrc; arbitrary
  downstream lossy codecs are not authenticated by that self-check.
- Forward each sample's caps, TIME segment, and buffer timing; propagate both
  buses' errors, drain queued input and downstream EOS, bound stalls, and stop
  pipelines on every exit.
- `video_filter::process_video_file` writes exact raw RGB Matroska `.mkv`;
  `video_filter::process_audio_file` writes exact S16LE PCM `.wav`. Both take
  explicit `signing_kernel` after `signer`, then the frame/buffer limit.
  File audio gathers selected PCM bounded to 64 MiB and embeds once at index 0;
  absent `max_buffers` means complete file, not silent truncation. Verify the
  whole delivered PCM, not decoder chunks. Paths are literal quoted properties.
- Parent release evidence includes delivered RGB Matroska/WAV and real
  downstream failures. It does not establish physical-camera or Windows runs.

Line inventory above is maintained by release integration, not API edits.
