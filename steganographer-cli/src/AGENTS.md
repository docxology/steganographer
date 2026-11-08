# AGENTS.md — steganographer-cli/src/

## Module Details

### cli.rs and main.rs

- `cli.rs` defines `Cli`, `Commands` and `OtsAction`; the binary and `build.rs`
  share this schema for parsing, five shell completions and all manual pages.
- The shared schema includes exact `Capacity` plus generic `Decode`/`Extract`;
  GStreamer-free builds omit live `Video` and `Audio`.
- `main.rs` initializes logging/envelope context and dispatches commands.

### envelope.rs

- `steganographer.cli/v1` JSON envelope (`schema`, `command`, `status`,
  `result`, `warnings`, `errors`, `timing`, `tool`) wrapping every
  `--format json` output; `partial` means incomplete analysis, including scans
  and statistical analysis with no available method
- Stable error codes (`usage_error`, `packet_not_found`,
  `verification_failed`, `scan_error`, `internal_error`) and the finalized
  exit-code table (0/1/2/3/4/5/6) via `classify_exit`
- JSON-mode context so the central error path emits error envelopes on
  stdout; secrets are never serialized

### key_policy.rs

- `load_signing_key` — zeroized fixed-size secret ingestion and known-compromise denial
- `load_revocations` — one shared registry load per command; only an omitted,
  genuinely absent default is optional, never an explicit or malformed policy

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
- `capacity` lives in `cmd_packet.rs`: core-encoded sequential file-packet sizing
  with exact filename/MIME/signature overhead and effective limits, no synthetic
  payload allocation. Match metadata and signing policy at encode.
- Exit-code mapping: usage → 1, packet-not-found → 2, verify invalid → 3,
  scan findings → 4, incomplete scan/no usable analysis → 5, internal/I-O → 6
- Supports spatial LSB, keyed audio LSB, spread-spectrum, and DCT paths with
  symmetric config, key, encryption, ECC, capacity, and format validation

### cmd_packet.rs

- Opt-in generic text/file payload encoding and payload decoding
- Generic carrier slice: PNG/raw RGB or WAV/raw S16LE, sequential/keyed LSB, 1–4 bits
- Validates packet digest, capacity, output aliasing, and overwrite policy

### cmd_scan.rs

- `run(...)` — bounded forensic scan of one file or a directory tree;
  returns 0 clean / 4 findings / 5 truncated-inconclusive; JSONL emits one
  schema-wrapped record per file plus a final summary envelope
- Delegates to `steganographer_core::forensics::scan_bytes()`, which pairs
  structural probes (Shannon entropy, file family, embedded magic bytes) with
  `steganalysis::analyze_combined()`
- Bounded by traversal/file/read and detector budgets. Descriptor-relative
  regular-file/no-follow opens prevent recursive link traversal; skipped
  max-depth directories mark incompleteness. Positive findings precede exit 5.
- Revocation updates lock a persistent `<registry>.lock` companion over
  read/merge/atomic-publication; do not remove or replace its inode.

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

### Shared carrier binding

Canonicalization lives in `steganographer_core::carrier_binding`; CLI callers use
the shared core implementation, not a private `src/carrier_binding.rs` copy.
