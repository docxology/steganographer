# AGENTS.md — steganographer-gst

## Purpose

GStreamer integration for real-time media pipeline processing.

## Module Map

| File | Lines | Key Functions |
| ------ | ------- | --------------- |
| `src/lib.rs` | 132 | `init()`, `run_macos_main_loop()`, `launch()`, `plugin_init` + `gst_plugin_define!` (name `steganographer_gst` = cdylib file stem) |
| `src/video_filter.rs` | 516 | `run_video_filter()`, `extract_from_source()`, `process_video_file()` |
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
  S16LE mono/stereo (from GStreamer `audio/x-raw`).
