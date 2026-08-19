# steganographer-cli/src/

Source modules for the CLI binary.

## Files

| File | Lines | Purpose |
| ------ | ------- | --------- |
| `main.rs` | ~729 | Clap `#[derive(Parser)]` CLI with 13 subcommands, logging init, dispatch |
| `cmd_video.rs` | ~257 | Loads config, builds GStreamer video source/sink pipelines, runs `run_video_filter()` |
| `cmd_audio.rs` | ~141 | Loads config, builds GStreamer audio source/sink pipelines, runs `run_audio_filter()` |
| `cmd_encode.rs` | ~1371 | Reads raw file → auto-generates signing key → embeds LSB → writes output. Also handles `keygen`, `info`, `analyze`, `derive`, `revoke` |
| `cmd_verify.rs` | ~1158 | Reads raw file → extracts LSB signature → `--format plain\|json` output → `VerifyResult` struct |
| `cmd_packet.rs` | ~326 | Opt-in generic packet v1 alpha encode/decode |
| `cmd_ots.rs` | ~398 | OpenTimestamps `stamp` / `verify` attestation |
| `media_io.rs` | ~326 | Descriptor-preserving image/WAV/raw I/O and output policy |
| `carrier_binding.rs` | ~132 | Kernel-canonical carrier bytes for signing |

## Subcommands

```text
steganographer
├── video      --source <gst> --sink <gst> [--max-frames N]
├── audio      --source <gst> --sink <gst> [--max-buffers N]
├── encode     --input <file> --output <file> --stego-type <type> --bits <1-4>
├── decode     --input <file> --output <file> [--bits auto|<1-4>]
├── verify     --input <file> --stego-type <type> [--public-key <hex>] [--format plain|json]
├── keygen     --output <path>     → writes <path>.key + <path>.pub
├── info       --input <file> --stego-type <type> --bits <1-4>
├── analyze    --input <file> [--analysis-type combined|chi_squared|sample_pairs|rs]
├── derive     (--master-secret <hex> | --master-secret-file <path> | --master-secret-stdin)
├── config     check
├── revoke     --public-key <hex>
├── dashboard  --port <port> [--backend ed25519|ethereum]
└── ots        stamp|verify --input <file>
```

## Design

- Each `cmd_*.rs` is an independent module with a single `pub fn run()` entry point
- Config loading is done per-command (no shared state)
- Logging via `env_logger` with configurable level
- `cmd_verify.rs` supports `--format json` for CI/machine-readable output via `VerifyResult` struct
