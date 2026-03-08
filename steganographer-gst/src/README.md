# steganographer-gst/src/

Source modules for GStreamer integration.

## Files

| File | Lines | Purpose |
| ------ | ------- | --------- |
| `lib.rs` | 44 | `init()` wraps `gstreamer::init()`, `launch_pipeline()` helper, re-exports |
| `video_filter.rs` | 232 | `run_video_filter()` — frame-by-frame AppSink/AppSrc with signing; `extract_from_source()` for verification |
| `audio_filter.rs` | 204 | `run_audio_filter()` — buffer-by-buffer AppSink/AppSrc with signing; `extract_from_source()` for verification |
| `plugin.rs` | 46 | Native `gst_plugin_define!` registration skeleton for future native plugin development |

## Key Patterns

- Buffer mapping via `buffer.make_mut().map_writable()` / `buffer.map_readable()`
- Format negotiation from caps: `VideoInfo::from_caps()` / `AudioInfo::from_caps()`
- Audio byte-to-i16 conversion via `unsafe std::slice::from_raw_parts_mut`
- Progress logging every 100 video frames / 1000 audio buffers
