# steganographer-cli/src/

Source modules for the CLI binary.

## Files

| File | Lines | Purpose |
| ------ | ------- | --------- |
| `main.rs` | 916 | Clap `#[derive(Parser)]` CLI with 14 subcommands, logging init, dispatch |
| `cmd_video.rs` | 257 | Loads config, builds GStreamer video source/sink pipelines, runs `run_video_filter()` |
| `cmd_audio.rs` | 141 | Loads config, builds GStreamer audio source/sink pipelines, runs `run_audio_filter()` |
| `cmd_encode.rs` | 1461 | Reads raw file → auto-generates signing key → embeds LSB → writes output. Also handles `keygen`, `info`, `analyze`, `derive`, `revoke` |
| `cmd_verify.rs` | 1158 | Reads raw file → extracts LSB signature → `--format plain\|json` output → `VerifyResult` struct |
| `cmd_packet.rs` | 656 | Opt-in generic packet v1 alpha encode/decode |
| `cmd_scan.rs` | 235 | Bounded forensic scan over files and directory trees |
| `cmd_ots.rs` | 398 | OpenTimestamps `stamp` / `verify` attestation |
| `media_io.rs` | 345 | Descriptor-preserving image/WAV/raw I/O and output policy |
| `carrier_binding.rs` | 132 | Kernel-canonical carrier bytes for signing |

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
├── scan       --input <file|dir> [--max-depth N] [--max-files N] [--max-bytes N] [--format plain|json|jsonl]
├── derive     (--master-secret <hex> | --master-secret-file <path> | --master-secret-stdin)
├── config     check
├── revoke     --public-key <hex>
├── dashboard  --port <port> [--backend ed25519|ethereum]
└── ots        stamp|verify --input <file>
```

## Design

- Each `cmd_*.rs` is an independent module: `cmd_video`, `cmd_audio`, `cmd_verify`, and `cmd_scan` expose a single `run()`; `cmd_encode` also exposes `keygen()`, `info()`, `analyze()`, `derive_keys()`, `revoke_key()`, and batch/multi-frame helpers, `cmd_packet` exposes `encode()` / `decode()`, and `cmd_ots` exposes `stamp()` / `verify()`
- Config loading is done per-command (no shared state)
- Logging via `env_logger` with configurable level
- `cmd_verify.rs` supports `--format json` for CI/machine-readable output via `VerifyResult` struct
- `cmd_scan.rs` calls `steganographer_core::forensics::scan_bytes()` (which itself folds in `steganalysis::analyze_combined()`) under bounded budgets (depth, file count, bytes per file)
