# steganographer-gst/src/

Source modules for GStreamer integration.

## Files

| File | Purpose |
| --- | --- |
| `lib.rs` | GStreamer-only init, launch helper, actual-map plane-span guard, private file staging/publication and bridge lifecycle |
| `video_filter.rs` | Video AppSink/AppSrc signing/extraction; exact Matroska/PCM WAV convenience helpers |
| `audio_filter.rs` | Interleaved S16LE buffer signing/extraction with preserved boundaries |
| `elements.rs`, `audio_element.rs` | Native generic packet video/audio elements |
| `plugin.rs` | Both element registrations and plugin metadata |

## Key Patterns

- Buffer mapping via `buffer.make_mut().map_writable()` / `buffer.map_readable()`
- Format negotiation from caps: `VideoInfo::from_caps()` / `AudioInfo::from_caps()`
- Aligned complete-frame S16LE sample storage; no arbitrary byte-to-i16 cast
- File helpers require trailing `overwrite: bool` (no shim), reject aliases and
  publish private sibling output after EOS. Filesink reopens the pathname:
  output directories must be trusted.
- Plane access checks actual mapped span, offset and full stride extent before
  dependency slicing, not merely negotiated/forged metadata sizes.
