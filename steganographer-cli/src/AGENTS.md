# AGENTS.md — steganographer-cli/src/

## Module Details

### main.rs

- `Cli` — `#[derive(Parser)]` with `--config`, `--log-level`, `--quiet`, and
  `--schema-version` global flags (v1 gates the machine JSON envelope)
- `Commands` — `Video`, `Audio`, `Encode`, `Decode`, `Verify`, `Keygen`,
  `Info`, `Analyze`, `Scan`, `Derive`, `Dashboard`, `Revoke`, `Config`, and `Ots`
- `main()` — initializes `env_logger`, dispatches to `cmd_*::run()`

### envelope.rs

- `steganographer.cli/v1` JSON envelope (`schema`, `command`, `status`,
  `result`, `warnings`, `errors`, `timing`, `tool`) wrapping every
  `--format json` output; `partial` = a resource-limit-truncated scan
- Stable error codes (`usage_error`, `packet_not_found`,
  `verification_failed`, `scan_error`, `internal_error`) and the finalized
  exit-code table (0/1/2/3/4/5/6) via `classify_exit`
- JSON-mode context so the central error path emits error envelopes on
  stdout; secrets are never serialized

### cmd_video.rs

- `run(config_path, source, sink, max_frames)` — loads TOML config, inits GStreamer, builds pipeline strings, calls `run_video_filter()`
- `build_source_pipeline()` / `build_sink_pipeline()` — construct GStreamer pipeline strings from config

### cmd_audio.rs

- `run(config_path, source, sink, max_buffers)` — loads TOML config, inits GStreamer, builds pipeline strings, calls `run_audio_filter()`
- `build_source_pipeline()` / `build_sink_pipeline()` — construct GStreamer pipeline strings from config
- `hex_encode()` — utility for key display

### cmd_encode.rs

- `run(...)` — descriptor-preserving legacy offline signing and embedding
- `keygen(output, format)`, `info`, `analyze`, `revoke_key`, `derive_keys`,
  `derive_keys_from_password` — all emit the envelope in `--format json`
- Exit-code mapping: usage → 1, packet-not-found → 2, verify invalid → 3,
  scan findings → 4, truncated scan → 5, internal/I-O → 6
- Supports spatial LSB, keyed audio LSB, spread-spectrum, and DCT paths with
  symmetric config, key, encryption, ECC, capacity, and format validation

### cmd_packet.rs

- Opt-in generic text/file payload encoding and payload decoding
- Current alpha carrier slice: PNG or raw RGB, sequential spatial LSB, 1–4 bits
- Validates packet digest, capacity, output aliasing, and overwrite policy

### cmd_scan.rs

- `run(...)` — bounded forensic scan of one file or a directory tree;
  returns 0 clean / 4 findings / 5 truncated-inconclusive; JSONL emits one
  schema-wrapped record per file plus a final summary envelope
- Delegates to `steganographer_core::forensics::scan_bytes()`, which pairs
  structural probes (Shannon entropy, file family, embedded magic bytes) with
  `steganalysis::analyze_combined()`
- Bounded by `--max-depth`, `--max-files`, and `--max-bytes`; emits
  deterministic plain/JSON/JSONL findings

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

- `canonicalize()` — produces the kernel-canonical carrier representation for
  signing and verification so mutable embedding slots cannot invalidate their
  own signature
