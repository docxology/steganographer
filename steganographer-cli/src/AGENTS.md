# AGENTS.md — steganographer-cli/src/

## Module Details

### main.rs

- `Cli` — `#[derive(Parser)]` with `--config`, `--log-level`, and `--quiet` global flags
- `Commands` — `Video`, `Audio`, `Encode`, `Verify`, `Keygen`, `Info`, `Analyze`, `Derive`, `Config`, `Dashboard` variants
- `main()` — initializes `env_logger`, dispatches to `cmd_*::run()`

### cmd_video.rs

- `run(config_path, source, sink, max_frames)` — loads TOML config, inits GStreamer, builds pipeline strings, calls `run_video_filter()`
- `build_source_pipeline()` / `build_sink_pipeline()` — construct GStreamer pipeline strings from config

### cmd_audio.rs

- `run(config_path, source, sink, max_buffers)` — loads TOML config, inits GStreamer, builds pipeline strings, calls `run_audio_filter()`
- `build_source_pipeline()` / `build_sink_pipeline()` — construct GStreamer pipeline strings from config
- `hex_encode()` — utility for key display

### cmd_encode.rs

- `run(config_path, input, output, stego_type, bits)` — reads raw file, generates `Signer`, embeds signature
- `keygen(output)` — generates Ed25519 keypair, writes `.key` and `.pub` files
- Supports: `lsb_video` (raw RGB), `lsb_audio` (raw S16LE PCM)

### cmd_verify.rs

- `run(config_path, input, public_key, stego_type, format)` — reads raw file, extracts signature payload
- `VerifyResult` struct with `#[derive(Serialize)]` for structured JSON output
- `--format plain|json` — plain text (default) or JSON for machine-readable output / CI pipelines
- Prints: frame index, hash (hex), signature preview, verification status
- `verify_video()` / `verify_audio()` — type-specific extraction helpers
