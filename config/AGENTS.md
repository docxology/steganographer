# AGENTS.md — config/

## Purpose

Reference TOML configuration files for steganographer pipelines.

## Contents

| File           | Description                                                          |
| -------------- | -------------------------------------------------------------------- |
| `example.toml` | Full annotated config with video + audio endpoints, LSB settings, overlay, info_bar, and key |

## Schema Keys

- `[global]` — log_level, hash_algorithm, key_file
- `[video.input]` / `[video.output]` — endpoint type, backend, device
- `[video.pipeline]` — width, height, framerate, opacity
- `[video.pipeline.payload]` — type, size, signing_backend, encrypt, encryption_key, encryption_key_file, error_correction, multi_frame_spread
- `[video.stego]` — pipeline order, lsb_signature (bits, key, key_file), overlay (text, position, font_size), info_bar (label, show_barcode, show_qr, show_timestamp)
- `[audio.input]` / `[audio.output]` — endpoint type, backend
- `[audio.stego]` — pipeline order, lsb_signature (bits, key, key_file)
