# AGENTS.md — steganographer-gst

## Purpose

GStreamer integration for real-time media pipeline processing.

## Module Map

| File | Lines | Key Functions |
| ------ | ------- | --------------- |
| `src/lib.rs` | 44 | `init()`, `launch_pipeline()`, re-exports |
| `src/video_filter.rs` | 232 | `run_video_filter()`, `extract_from_source()` |
| `src/audio_filter.rs` | 204 | `run_audio_filter()`, `extract_from_source()` |
| `src/plugin.rs` | 46 | `plugin_init()`, `gst_plugin_define!` skeleton |

## Data Flow

1. GStreamer source pipeline → `appsink name=sink`
2. Pull `Sample` → map buffer writable → parse `VideoInfo`/`AudioInfo` from caps
3. Create `VideoFrame`/`AudioBuffer` → call `stego.embed()`
4. Push modified buffer → `appsrc name=src` → GStreamer sink pipeline

## Supported Formats

- Video: RGB, BGRA (from GStreamer `video/x-raw`)
- Audio: S16LE mono/stereo (from GStreamer `audio/x-raw`)
