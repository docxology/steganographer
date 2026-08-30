# AGENTS.md — steganographer-gst/src/

## Module Details

### lib.rs

- `init()` — wraps `gstreamer::init()` with error context (plus macOS NSApplication setup)
- `launch(desc)` — `gstreamer::parse::launch()` wrapper
- Declares modules: `video_filter`, `audio_filter`, `elements`, `plugin`

### video_filter.rs

- `VideoFilterConfig` — `source_pipeline: String`, `sink_pipeline: String`
- `run_video_filter(config, stego, signer, max_frames)` — main processing loop
- `extract_from_source(pipeline_str, stego, max_frames)` → `Vec<(u64, Option<SignaturePayload>)>`
- `process_video_file(input, output, stego, signer, max_frames)` — offline file processing
- Supports RGB and BGRA formats via `VideoInfo::from_caps()`

### audio_filter.rs

- `AudioFilterConfig` — `source_pipeline: String`, `sink_pipeline: String`
- `run_audio_filter(config, stego, signer, max_buffers)` — main processing loop
- `extract_from_source(pipeline_str, stego, max_buffers)` → `Vec<(u64, Option<SignaturePayload>)>`
- Uses `unsafe` for zero-copy byte↔i16 slice conversion

### elements.rs

- `StegoVideo` — native `BaseTransform` element registered as `stegovideo`,
  embedding generic packets in place (buffer size and caps unchanged)
- Properties: `packet-hex` (pre-encoded packet bytes), `clear-payload`
- Wire format matches `steganographer_core::carrier::SpatialLsb`, so output
  verifies with the existing `packet extract` CLI command
- `register(plugin)` — adds the element to the GStreamer registry

### plugin.rs

- `register_elements()` — plugin registration entry point; delegates to
  `crate::elements::register()`
- Plugin metadata constants: `PLUGIN_NAME`, `PLUGIN_DESCRIPTION`, `PLUGIN_VERSION`
