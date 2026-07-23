# AGENTS.md — steganographer-cli

## Purpose

User-facing CLI binary built with Clap. Wires together core algorithms, GStreamer integration, and the web dashboard.

## Module Map

| File | Lines | Key Functions |
| ------ | ------- | --------------- |
| `src/main.rs` | ~360 | `Cli` struct, `Commands` enum (10 subcommands), `main()` |
| `src/cmd_video.rs` | ~130 | `run(config, source, sink, max_frames)` |
| `src/cmd_audio.rs` | ~100 | `run(config, source, sink, max_buffers)` |
| `src/cmd_encode.rs` | ~150 | `run(config, input, output, stego_type, bits)`, `keygen(output)` |
| `src/cmd_verify.rs` | ~340 | `run(config, input, public_key, stego_type, format)`, `VerifyResult` struct |

## Subcommands

| Command | Description |
| --------- | ------------- |
| `video` | Run live video pipeline: capture → steganography → virtual device |
| `audio` | Run live audio pipeline: capture → steganography → virtual device |
| `encode` | Encode steganographic data into a file (offline) |
| `verify` | Verify steganographic signatures in a media file (`--format plain\|json`) |
| `keygen` | Generate a new Ed25519 signing key pair |
| `info` | Report steganographic capacity of a media file |
| `analyze` | Analyze a file for steganographic artifacts (chi-squared test) |
| `derive` | Derive keys (signing, encryption, embedding) from a master secret |
| `config` | Validate a TOML configuration file |
| `dashboard` | Launch the live round-trip verification dashboard (web GUI) |

## Global Options

| Flag | Default | Purpose |
| ------ | --------- | --------- |
| `--config, -c` | `config/example.toml` | TOML config path |
| `--log-level, -l` | `info` | Logging verbosity |

## Features

| Feature | Purpose |
| --------- | --------- |
| `ethereum` | Enable Ethereum/secp256k1 signing backend for dashboard |

## Binary Name

`steganographer` (from `[[bin]]` in Cargo.toml)
