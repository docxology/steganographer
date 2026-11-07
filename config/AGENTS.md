# AGENTS.md — config/

## Purpose

`example.toml` is the CLI's default annotated video/audio configuration.
The root `steganographer.toml` is an explicitly selectable alternative.
Authoritative types are in `steganographer-core/src/config.rs` and
`ots_config.rs`; the user reference is [Configuration](../docs/configuration.md).

## Contracts

- Shipped signed video/audio pipelines are `["lsb_signature"]`; populated
  overlay/info-bar tables do not activate modules. Visible rendering is
  separate from signed invisible kernels.
- Native signed video permits exactly one supported invisible kernel; audio
  signing is LSB-only. Native trait SS signing is not the offline scalar path.
  No ignored live encryption, ECC or multi-frame spreading is acceptable.
- `[video.pipeline.payload]` describes video/offline payload options, not
  audio fields or generic packet CLI selection. Legacy signatures are format
  4 (109 bytes). Spreading is offline RGB LSB only, 2–8; 1 disables it.
- Preserve the distinction between modeled fields and consumed settings.
  Endpoint `type`/`path` are not automatic file/network routing; direct native
  CLI builders use backend or explicit pipeline fragments. Info-bar model
  toggles are not effective direct-CLI controls merely because they deserialize.
- `[limits]` are effective generic extraction/parse/transform ceilings.
  `[profiles.<name>]` has limits plus `scan.detectors`; CLI selection is
  `scan --profile`, not an invented global profile flag.
- OTS is opt-in, Bitcoin-only, with a standard calendar and explicitly trusted
  Esplora provider. Reference the full [OTS guide](../docs/ots-integration.md),
  not an invented REST timestamp protocol.
- Explicit invalid/missing config fails; only absence of the implicit default
  can use minimal defaults. Example inline keys are public examples, not secrets.

Keep examples and docs aligned with actual consumers. Do not add stale
inventory sizes, test totals, wording assertions or unexercised hardware claims.
