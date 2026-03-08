# AGENTS.md — steganographer-gst/src/

## Module Details

### lib.rs

- `init()` — wraps `gstreamer::init()` with error context
- `launch_pipeline(desc)` — `gstreamer::parse::launch()` wrapper
- Re-exports: `video_filter`, `audio_filter`

### video_filter.rs

- `VideoFilterConfig` — `source_pipeline: String`, `sink_pipeline: String`
- `run_video_filter(config, stego, signer, max_frames)` — main processing loop
- `extract_from_source(pipeline_str, stego, max_frames)` → `Vec<(u64, Option<SignaturePayload>)>`
- Supports RGB and BGRA formats via `VideoInfo::from_caps()`

### audio_filter.rs

- `AudioFilterConfig` — `source_pipeline: String`, `sink_pipeline: String`
- `run_audio_filter(config, stego, signer, max_buffers)` — main processing loop
- `extract_from_source(pipeline_str, stego, max_buffers)` → `Vec<(u64, Option<SignaturePayload>)>`
- Uses `unsafe` for zero-copy byte↔i16 slice conversion

### plugin.rs

- `plugin_init()` — skeleton for future native GStreamer element registration
- `gst_plugin_define!` macro invocation (commented pending element implementation)
