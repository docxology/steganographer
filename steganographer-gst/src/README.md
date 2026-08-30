# steganographer-gst/src/

Source modules for GStreamer integration.

## Files

| File | Lines | Purpose |
| ------ | ------- | --------- |
| `lib.rs` | 107 | `init()` wraps `gstreamer::init()` (plus macOS NSApplication setup), `launch()` helper, module declarations |
| `video_filter.rs` | 488 | `run_video_filter()` — frame-by-frame AppSink/AppSrc with signing; `extract_from_source()` for verification; `process_video_file()` / `process_audio_file()` offline helpers |
| `audio_filter.rs` | 204 | `run_audio_filter()` — buffer-by-buffer AppSink/AppSrc with signing; `extract_from_source()` for verification |
| `elements.rs` | 424 | `StegoVideo` — native in-place `BaseTransform` element (`stegovideo`); `register()` adds it to the GStreamer registry |
| `plugin.rs` | 50 | `register_elements()` — plugin registration entry point with metadata constants; delegates to `elements::register()` |

## Key Patterns

- Buffer mapping via `buffer.make_mut().map_writable()` / `buffer.map_readable()`
- Format negotiation from caps: `VideoInfo::from_caps()` / `AudioInfo::from_caps()`
- Audio byte-to-i16 conversion via `unsafe std::slice::from_raw_parts_mut`
- Progress logging every 100 video frames / 1000 audio buffers
