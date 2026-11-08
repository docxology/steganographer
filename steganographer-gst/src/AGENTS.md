# AGENTS.md — steganographer-gst/src/

## Module Details

### lib.rs

- `init()` — wraps GStreamer initialization only; Cocoa main-loop ownership stays with the application
- `launch(desc)` — `gstreamer::parse::launch()` wrapper
- Declares modules: `video_filter`, `audio_filter`, `elements`, `plugin`

### video_filter.rs

- `VideoFilterConfig` — source/sink pipeline strings plus `signing_kernel: Option<SigningKernel>`
- `run_video_filter(config, stego, signer, max_frames)` — main processing loop
- `extract_from_source(pipeline_str, stego, max_frames)` → `Vec<(u64, Option<SignaturePayload>)>`
- `process_video_file(input, output, stego, signer, signing_kernel, max_frames, overwrite)` — exact RGB Matroska
- `process_audio_file(input, output, stego, signer, signing_kernel, max_buffers, overwrite)` — bounded whole-selection PCM WAV at index 0
- Both require the new trailing bool; no shim. Reject aliases, stage privately,
  publish only after EOS and honor no-clobber. Filesink requires a trusted output directory.
- Packed plane access guards actual map size/offset/full stride extent before dependency slicing.
- Supports RGB and BGRA formats via `VideoInfo::from_caps()`

### audio_filter.rs

- `AudioFilterConfig` — source/sink pipeline strings plus `signing_kernel: Option<SigningKernel>`
- `run_audio_filter(config, stego, signer, max_buffers)` — main processing loop
- `extract_from_source(pipeline_str, stego, max_buffers)` → `Vec<(u64, Option<SignaturePayload>)>`
- Uses aligned sample storage and bounded complete interleaved S16LE frames

### elements.rs

- `StegoVideo` — native `BaseTransform` element registered as `stegovideo`,
  embedding generic packets in place (buffer size and caps unchanged)
- Properties: `packet-hex` (pre-encoded packet bytes), `clear-payload`
- Wire format matches `steganographer_core::carrier::SpatialLsb`, so output
  decodes with generic `decode` / `extract` using the matching carrier metadata
- `register(plugin)` — adds the element to the GStreamer registry

### plugin.rs

- `register_elements()` — plugin registration entry point; delegates to
  video and audio element registration
- Plugin metadata constants: `PLUGIN_NAME`, `PLUGIN_DESCRIPTION`, `PLUGIN_VERSION`
