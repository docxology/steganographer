# steganographer-cli/src/

Source modules for the CLI binary.

## Files

| File | Purpose |
| --- | --- |
| `cli.rs` | Shared Clap schema for the binary, generated completions and manuals |
| `main.rs` | Logging/envelope initialization and command dispatch |
| `envelope.rs` | Versioned machine output and semantic exit codes |
| `key_policy.rs` | Zeroized signing-key loading, immutable compromise checks and shared fail-closed revocation policy |
| `cmd_video.rs` | Config-driven native video pipelines |
| `cmd_audio.rs` | Config-driven native audio pipelines |
| `cmd_encode.rs` | Offline signing/embedding, keygen, info, analyze, derive and revoke |
| `cmd_verify.rs` | Signature extraction, mathematical verification and authorization status |
| `cmd_packet.rs` | Generic packet encode/decode/extraction |
| `cmd_scan.rs` | Bounded forensic scans of files and directory trees |
| `cmd_ots.rs` | OpenTimestamps stamp/verify |
| `media_io.rs` | Descriptor-preserving image/WAV/raw I/O and atomic output policy |

Canonical carrier binding is the shared
[`steganographer_core::carrier_binding`](../../steganographer-core/src/carrier_binding.rs)
API, not a CLI source module.

## Subcommands

```text
steganographer
├── video      --source <gst> --sink <gst> [--max-frames N]
├── audio      --source <gst> --sink <gst> [--max-buffers N]
├── encode     --input <file> --output <file> --stego-type <type> --bits <1-4>
├── decode     --input <file> --output <file> [--bits auto|<1-4>]
├── verify     --input <file> --stego-type <type> [--public-key <hex>] [--format plain|json]
├── extract    --input <file> --output <file> [--revoked-list <file>]
├── keygen     --output <path>     → writes <path>.key + <path>.pub
├── info       --input <file> --stego-type <type> --bits <1-4>
├── analyze    --input <file> [--analysis-type combined|chi_squared|sample_pairs|rs]
├── scan       --input <file|dir> [--max-depth N] [--max-files N] [--max-bytes N] [--format plain|json|jsonl]
├── derive     (--master-secret <hex> | --master-secret-file <path> | --master-secret-stdin)
├── config     check
├── revoke     --public-key <hex>
├── dashboard  --port <port> [--backend ed25519]
└── ots        stamp|verify --input <file>
```

## Design

- Each `cmd_*.rs` is an independent module: `cmd_video`, `cmd_audio`, `cmd_verify`, and `cmd_scan` expose a single `run()`; `cmd_encode` also exposes `keygen()`, `info()`, `analyze()`, `derive_keys()`, `revoke_key()`, and batch/multi-frame helpers, `cmd_packet` exposes `encode()` / `decode()`, and `cmd_ots` exposes `stamp()` / `verify()`
- Config loading is done per-command (no shared state)
- Logging via `env_logger` with configurable level
- `cmd_verify.rs` supports `--format json` for CI/machine-readable output via `VerifyResult` struct
- `cmd_scan.rs` calls `steganographer_core::forensics::scan_bytes()` (which itself folds in `steganalysis::analyze_combined()`) under bounded budgets (depth, file count, bytes per file)
