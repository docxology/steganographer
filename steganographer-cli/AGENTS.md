# AGENTS.md — steganographer-cli

## Purpose and ownership

`steganographer` is the user-facing CLI binary. Read nested source instructions
before changing implementation. The argument schema in `src/cli.rs` is shared
by the binary and `build.rs` completion/manual generation; do not maintain a
second schema in `main.rs` or tests.

## Module map

| Module | Responsibility |
| --- | --- |
| `cli.rs` | Clap commands/arguments |
| `main.rs` | Early machine mode, validated config/effective limits, dispatch, exit policy, macOS application-loop ownership |
| `envelope.rs` | `steganographer.cli/v1`, typed error classification |
| `cmd_encode.rs` | Legacy encode, key generation/derivation, capacity, analysis, revocation |
| `cmd_packet.rs` | Generic encode and shared decode/extract recovery |
| `cmd_verify.rs` | Legacy signature recovery, authentication and revocation |
| `cmd_scan.rs` | Bounded forensic file/directory scan and completeness |
| `cmd_ots.rs` | Real standard OpenTimestamps file stamp/verify |
| `cmd_video.rs`, `cmd_audio.rs` | Feature-gated native live pipelines |
| `media_io.rs` | Descriptor-preserving media I/O and atomic publication |

Canonical carrier binding lives in `steganographer_core::carrier_binding`, not
a private CLI copy. Hex helpers are shared core crypto APIs.

## Command contracts

- Encode without payload flags is legacy format-4 signed media; with
  `--payload-file` / `--payload-text` it is generic STG3 protocol-v1. Preserve
  immutable generic wire fixtures; re-encode legacy format 2/3 media.
- Encode key flags are `--encryption-key*`; **both decode and extract** use
  `--decryption-key*`. Extract has no old encryption-key aliases and no
  `--decrypt` switch. It shares bounded transform/digest/signature recovery
  with decode, not an unchecked payload bypass.
- `--trusted-signer` on decode/extract requires a matching Ed25519 signer;
  reports distinguish embedded signer key from trusted identity. Generic
  signatures authenticate logical bytes, not arbitrary semantic metadata.
- Verify without `--public-key` is extraction-only `not_verified`.
  `no_signature` is exit 2 / `packet_not_found`; `valid_revoked` and invalid
  authentication are exit 3 / `verification_failed`, retaining result evidence
  in JSON error envelopes. Malformed/explicit missing revocation files fail.
- Effective limits must reach carrier extraction, parsing and transform
  reversal. Auto-bits really probes supported depths and must not mask known
  authentication failure with unrelated candidate noise.
- Unsupported legacy password/generic-only options fail before writes.
  Password-file input is preferred; no secret serialization. JSON must reject
  encoding that would lose a generated encryption/placement secret; require
  recoverable supplied credentials instead.
- Atomic no-clobber publication is the default. Decode/extract `--force`
  replaces entries without truncating symlink/hardlink targets. Preflight key
  paths; Unix secrets are mode 0600 before content, not chmod-after-write.
- Legacy spreading is offline RGB LSB only, 2–8 shards (1 disabled).
  Generic/audio/SS/DCT unsupported spreading fails before output.
- Shipped live defaults are single invisible LSB signing kernels, Ed25519.
  No mixed visible/signed chains or ignored live crypto/ECC/spreading.
  Native signed audio is LSB-only; trait SS signing is rejected because its
  mapping differs from offline scalar binding. Visible modules stay separate.
- Native exact files are RGB Matroska `.mkv` / PCM `.wav`, not a guarantee for
  arbitrary downstream sinks. The macOS CLI owns Cocoa dispatch; libraries
  do not seize main-loop ownership.
- Dashboard supports Ed25519/BLAKE3/LSB, not Ethereum/MetaMask/live ECC/crypto.
  Public identity must be its actual signer. Record/startup artifacts are
  sampled signed PNG/WAV with manifests, not continuous signed media.
- OTS commits SHA-256(input), supports Bitcoin only, and defaults to
  `proof_dir/<digest-hex>.ots` for both stamp/verify. Pending is not verified;
  canonical-chain verification trusts the configured Esplora provider.

## Features and checks

- `gst` (default): native Video/Audio commands; `--no-default-features` removes
  them without removing offline/dashboard/OTS commands.
- `webrtc`: dashboard optional transport/media dependencies.
- `ethereum`: core alternative-signing APIs, **not** a dashboard backend.
- `learned`: optional core analysis feature.

Root `AGENTS.md` owns canonical counts. Do not retain line-count inventories,
repin wording/default/property-echo tests or select a stale debug executable in
integration tests; use `env!("CARGO_BIN_EXE_steganographer")`. Preserve meaningful
behavior, tamper, boundary and immutable-wire checks. Main integration runs
checks after code work lands; workers do not run concurrent build/test/lint or
format passes. See [CLI Reference](../docs/cli-reference.md) and
[Compatibility](../docs/compatibility.md) for user migration.
