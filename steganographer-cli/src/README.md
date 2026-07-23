# steganographer-cli/src/

Source modules for the CLI binary.

## Files

| File | Lines | Purpose |
| ------ | ------- | --------- |
| `main.rs` | ~360 | Clap `#[derive(Parser)]` CLI with 10 subcommands, logging init, dispatch |
| `cmd_video.rs` | ~130 | Loads config, builds GStreamer video source/sink pipelines, runs `run_video_filter()` |
| `cmd_audio.rs` | ~100 | Loads config, builds GStreamer audio source/sink pipelines, runs `run_audio_filter()` |
| `cmd_encode.rs` | ~150 | Reads raw file → auto-generates signing key → embeds LSB → writes output. Also handles `keygen` |
| `cmd_verify.rs` | ~340 | Reads raw file → extracts LSB signature → `--format plain\|json` output → `VerifyResult` struct |

## Subcommands

```text
steganographer
├── video      --source <gst> --sink <gst> [--max-frames N]
├── audio      --source <gst> --sink <gst> [--max-buffers N]
├── encode     --input <file> --output <file> --stego-type <type> --bits <1-4>
├── verify     --input <file> --stego-type <type> [--public-key <hex>] [--format plain|json]
├── keygen     --output <path>     → writes <path>.key + <path>.pub
└── dashboard  --port <port> [--backend ed25519|ethereum]
```

## Design

- Each `cmd_*.rs` is an independent module with a single `pub fn run()` entry point
- Config loading is done per-command (no shared state)
- Logging via `env_logger` with configurable level
- `cmd_verify.rs` supports `--format json` for CI/machine-readable output via `VerifyResult` struct
