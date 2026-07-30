# AGENTS.md — steganographer-cli/src/

## Module Details

### main.rs

- `Cli` — `#[derive(Parser)]` with `--config`, `--log-level`, and `--quiet` global flags
- `Commands` — `Video`, `Audio`, `Encode`, `Decode`, `Verify`, `Keygen`,
  `Info`, `Analyze`, `Derive`, `Dashboard`, `Revoke`, and `Config`
- `main()` — initializes `env_logger`, dispatches to `cmd_*::run()`

### cmd_video.rs

- `run(config_path, source, sink, max_frames)` — loads TOML config, inits GStreamer, builds pipeline strings, calls `run_video_filter()`
- `build_source_pipeline()` / `build_sink_pipeline()` — construct GStreamer pipeline strings from config

### cmd_audio.rs

- `run(config_path, source, sink, max_buffers)` — loads TOML config, inits GStreamer, builds pipeline strings, calls `run_audio_filter()`
- `build_source_pipeline()` / `build_sink_pipeline()` — construct GStreamer pipeline strings from config
- `hex_encode()` — utility for key display

### cmd_encode.rs

- `run(...)` — descriptor-preserving legacy offline signing and embedding
- `keygen(output)` — generates Ed25519 keypair, writes `.key` and `.pub` files
- Supports spatial LSB, keyed audio LSB, spread-spectrum, and DCT paths with
  symmetric config, key, encryption, ECC, capacity, and format validation

### cmd_packet.rs

- Opt-in generic text/file payload encoding and payload decoding
- Current alpha carrier slice: PNG or raw RGB, sequential spatial LSB, 1–4 bits
- Validates packet digest, capacity, output aliasing, and overwrite policy

### cmd_verify.rs

- `run(...)` — mirrors legacy encode configuration, extracts, and verifies
- `VerifyResult` struct with `#[derive(Serialize)]` for structured JSON output
- `--format plain|json` — plain text (default) or JSON for machine-readable output / CI pipelines
- Prints: frame index, hash (hex), signature preview, verification status
- Supports auto-detecting 1–4 LSB strengths and key resolution from direct,
  file, or TOML sources

### media_io.rs

- Decodes PNG/images and WAV before capacity or embedding
- Preserves image dimensions and WAV sample specification
- Rejects lossy/destructive output combinations; accepts explicit raw RGB
  dimensions

### carrier_binding.rs

- Produces the kernel-canonical carrier representation for signing and
  verification so mutable embedding slots cannot invalidate their own signature
