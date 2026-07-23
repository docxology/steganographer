# steganographer-cli

![CI](https://github.com/docxology/steganographer/actions/workflows/ci.yml/badge.svg)
![Tests](https://img.shields.io/badge/tests-10-brightgreen)
User-facing command-line binary for all steganographic functions.

Built with [Clap](https://docs.rs/clap) for argument parsing with 11 subcommands.

## Commands

| Command | Description |
| --------- | ------------- |
| `video` | Run live video pipeline: capture → steganography → virtual device |
| `audio` | Run live audio pipeline: capture → steganography → virtual device |
| `encode` | Embed steganographic data into a raw file (offline) |
| `verify` | Extract and verify steganographic signatures (`--format plain\|json`) |
| `keygen` | Generate a new Ed25519 signing key pair |
| `dashboard` | Launch web-based live verification dashboard |

## Modules

| Module | File | Description |
| -------- | ------ | ------------- |
| `main` | `src/main.rs` | Clap CLI definition, logging init, command dispatch |
| `cmd_video` | `src/cmd_video.rs` | Config-driven GStreamer video pipeline launch |
| `cmd_audio` | `src/cmd_audio.rs` | Config-driven GStreamer audio pipeline launch |
| `cmd_encode` | `src/cmd_encode.rs` | Offline LSB video/audio encoding + keygen |
| `cmd_verify` | `src/cmd_verify.rs` | Signature extraction + `--format plain\|json` output |

## Usage

```bash
# Show help
steganographer --help

# Launch the live dashboard
steganographer dashboard --port 8080 --backend ed25519

# Encode a file
steganographer encode --input frame.rgb --output frame_signed.rgb --stego-type lsb_video

# Verify a file (plain text output)
steganographer verify --input frame_signed.rgb --stego-type lsb_video --public-key <hex>

# Verify a file (JSON output for CI)
steganographer verify --input frame_signed.rgb --stego-type lsb_video --format json

# Generate keys
steganographer keygen --output mykey
```

## Dependencies

```toml
steganographer-core = { path = "../steganographer-core" }
steganographer-gst = { path = "../steganographer-gst" }
steganographer-dashboard = { path = "../steganographer-dashboard" }
clap = { version = "4", features = ["derive"] }
anyhow = "1"
log = "0.4"
env_logger = "0.11"
serde_json = "1"
chrono = "0.4"
```
