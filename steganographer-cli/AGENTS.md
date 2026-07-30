# AGENTS.md — steganographer-cli

## Purpose

User-facing CLI binary built with Clap. Wires together core algorithms, GStreamer integration, and the web dashboard.

## Module Map

| File | Lines | Key Functions |
| ------ | ------- | --------------- |
| `src/main.rs` | 646 | `Cli` struct, `Commands` enum (12 subcommands), `main()` |
| `src/cmd_video.rs` | 254 | `run(config, source, sink, max_frames)` |
| `src/cmd_audio.rs` | 141 | `run(config, source, sink, max_buffers)` |
| `src/cmd_encode.rs` | 1328 | Legacy offline encode, keygen, info, and analysis |
| `src/cmd_packet.rs` | 304 | Opt-in generic packet encode/decode |
| `src/cmd_verify.rs` | 1006 | Legacy extraction/verification and `VerifyResult` |
| `src/media_io.rs` | 326 | Descriptor-preserving image/WAV/raw I/O and output policy |
| `src/carrier_binding.rs` | 132 | Kernel-canonical carrier bytes for signing |

## Subcommands

| Command | Description |
| --------- | ------------- |
| `video` | Run live video pipeline: capture → steganography → virtual device |
| `audio` | Run live audio pipeline: capture → steganography → virtual device |
| `encode` | Encode steganographic data into a file (offline) |
| `decode` | Decode and validate an opt-in generic packet payload |
| `verify` | Verify steganographic signatures in a media file (`--format plain\|json`) |
| `keygen` | Generate a new Ed25519 signing key pair |
| `info` | Report steganographic capacity of a media file |
| `analyze` | Analyze a file for steganographic artifacts (chi-squared test) |
| `derive` | Derive keys (signing, encryption, embedding) from a master secret |
| `config` | Validate a TOML configuration file |
| `revoke` | Add a signing identity to a revoked-key list |
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
