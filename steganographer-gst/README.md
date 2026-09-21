# steganographer-gst

GStreamer integration crate for real-time video and audio steganographic processing.

Uses the AppSink/AppSrc pattern to intercept media buffers, apply steganography, and push modified data downstream.

## Modules

| Module | File | Description |
| -------- | ------ | ------------- |
| `lib` | `src/lib.rs` | GStreamer init (with macOS NSApplication setup), `launch()` pipeline helper |
| `video_filter` | `src/video_filter.rs` | Video AppSink→process→AppSrc pipeline with format negotiation |
| `audio_filter` | `src/audio_filter.rs` | Audio AppSink→process→AppSrc pipeline with S16LE conversion |
| `elements` | `src/elements.rs` | Native `stegovideo` in-place `BaseTransform` element (sequential + keyed LSB, stride-safe pixel-only placement, restricted pad templates, `StreamState` snapshot) with `register()` |
| `audio_element` | `src/audio_element.rs` | Native `stegoaudio` in-place `BaseTransform` element over interleaved S16LE PCM (restricted `S16LE`/interleaved pad templates) |
| `plugin` | `src/plugin.rs` | Native GStreamer plugin registration entry point (`register_elements()`) |

The crate also builds as a loadable GStreamer plugin (`crate-type = ["cdylib", "rlib"]`); see `docs/gstreamer.md` for `GST_PLUGIN_PATH` usage and the `stegovideo`/`stegoaudio` property reference. Round-trip acceptance lives in `tests/gst_roundtrip.rs`.

The native elements' **pad templates are restricted**: `stegovideo` negotiates
only packed one-plane `video/x-raw` formats (`RGB`, `BGR`, `RGBx`, `BGRx`,
`XRGB`, `XBGR`) and `stegoaudio` only `audio/x-raw, format=S16LE,
layout=interleaved`, so caps negotiation fails loudly for anything else.
Embedding is stride-safe (packet bits land only in pixel/sample bytes, never
in row-padding bytes), and property changes apply at frame/buffer granularity
(`key-hex`/`bits-per-unit` changes reset the frame counter).

## Dependencies

```toml
steganographer-core = { path = "../steganographer-core" }
gstreamer = "0.23"
gstreamer-app = "0.23"
gstreamer-video = "0.23"
gstreamer-audio = "0.23"
anyhow = "1"
log = "0.4"
```

## Architecture

```text
AppSink (pullsample) → [VideoFrame/AudioBuffer] → stego.embed() → AppSrc (push_buffer)
```

## Build Requirement

Requires GStreamer development libraries installed:

- **macOS**: `brew install gstreamer gst-plugins-base gst-plugins-good`
- **Linux**: `sudo apt install libgstreamer1.0-dev libgstreamer-plugins-base1.0-dev`
