# AGENTS.md — config/

## Purpose

Reference TOML configuration files for steganographer pipelines.

## Contents

| File           | Description                                                          |
| -------------- | -------------------------------------------------------------------- |
| `example.toml` | Full annotated config with video + audio endpoints, LSB settings, overlay, and key |

## Schema Keys

- `[global]` — log_level
- `[video.input]` / `[video.output]` — endpoint type, backend, device
- `[video.pipeline]` — width, height, framerate, opacity
- `[video.pipeline.payload]` — type, size, signing_backend (ed25519/ethereum)
- `[video.stego]` — pipeline order, lsb_signature (bits, key), overlay (text, position, font_size)
- `[audio.input]` / `[audio.output]` — endpoint type, backend
- `[audio.stego]` — pipeline order, lsb_signature (bits, key)
