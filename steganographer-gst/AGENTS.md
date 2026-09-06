# AGENTS.md — steganographer-gst

## Purpose

GStreamer integration for real-time media pipeline processing.

## Module Map

| File | Lines | Key Functions |
| ------ | ------- | --------------- |
| `src/lib.rs` | ~129 | `init()`, `run_macos_main_loop()`, `launch()`, `plugin_init` + `gst_plugin_define!` (name `steganographer_gst` = cdylib file stem) |
| `src/video_filter.rs` | 488 | `run_video_filter()`, `extract_from_source()`, `process_video_file()` |
| `src/audio_filter.rs` | 204 | `run_audio_filter()`, `extract_from_source()` |
| `src/elements.rs` | ~515 | `StegoVideo` native `BaseTransform` element (sequential + keyed placement, real clear-payload), `register()` |
| `src/audio_element.rs` | ~440 | `StegoAudio` native `BaseTransform` element over interleaved S16LE PCM (`AudioSpatialLsb`/`KeyedAudioSpatialLsb`) |
| `src/plugin.rs` | 50 | `register_elements()`, plugin metadata constants |
| `tests/gst_roundtrip.rs` | ~80 | `stegoaudio` wire-format decode check + packet-hex printer for gst-launch acceptance runs |

## Data Flow

1. GStreamer source pipeline → `appsink name=sink`
2. Pull `Sample` → map buffer writable → parse `VideoInfo`/`AudioInfo` from caps
3. Create `VideoFrame`/`AudioBuffer` → call `stego.embed()`
4. Push modified buffer → `appsrc name=src` → GStreamer sink pipeline

## Supported Formats

- Video: RGB, BGRA (from GStreamer `video/x-raw`)
- Audio: S16LE mono/stereo (from GStreamer `audio/x-raw`)
