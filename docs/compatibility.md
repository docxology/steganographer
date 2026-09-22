# Compatibility & Deprecation Policy

This document is the normative compatibility contract for the Steganographer
workspace. It defines versioning semantics, wire-format compatibility rules,
deprecation procedure, the MSRV policy, and the supported platform matrix.

## 1. Semantic Versioning (0.x crate semantics)

All workspace crates are published at `0.x` versions. Under 0.x SemVer:

- **Patch releases** (`0.7.z`) contain bug fixes only. No API, wire-format, or
  MSRV changes.
- **Minor releases** (`0.7.0` → `0.8.0`) MAY contain breaking API changes,
  wire-format changes, deprecation removals, and MSRV bumps. A minor bump is
  therefore the compatibility horizon: code that compiles against
  `steganographer-core = 0.7` is not guaranteed to compile against `0.8`
  without a migration note in the [CHANGELOG](../CHANGELOG.md).
- **Pre-1.0 maturity**: the wire packet format (see §2) is treated as more
  stable than the Rust API. Breaking the wire format is never a patch-level
  change and is avoided outside minor releases.

## 2. Wire-Format Compatibility

### 2.1 Generic packet (major v1)

The generic packet locator declares a protocol version (`STG3` magic +
`1.0`). Within packet major version **v1**:

- **Additive only.** New envelope TLV field ids, new placement/kernel
  algorithm ids, and new flag bits may be added in minor releases. Decoders
  MUST ignore unknown non-critical fields and reject unknown critical fields
  (fail closed).
- **No field removals or re-orderings.** Existing field ids, flag bit values,
  descriptor encodings, and the locator layout are immutable within v1.
- **Breaking changes → `/v2`.** Any change that removes/reorders a field,
  changes the magic, or invalidates the locator/accounting layout requires a
  new packet major version (`2.0` in the locator), a new parser module, and a
  migration note. v1 decoders reject v2 packets loudly, never silently
  misdecode.

### 2.2 Legacy signature payload (`crypto::FORMAT_VERSION`)

The 109-byte legacy payload (`MAGIC || FORMAT_VERSION || frame_index ||
hash || signature`) carries its own format version byte. Bumping
`crypto::FORMAT_VERSION` is a wire-format change that makes older payloads
loudly rejected (`Unsupported payload version`) instead of misdecoded:

- Bump `FORMAT_VERSION` **only** when the legacy wire layout or its
  cryptographic primitives change (precedent: 2 → 3 with the Reed-Solomon
  `ALPHA` 2 → 3 change).
- Every `FORMAT_VERSION` bump MUST land in a **minor release** with a
  migration note in the CHANGELOG ("no in-place migration path; re-encode
  from source media" where applicable) and MUST be accompanied by the
  version-coupling tests in `steganographer-core/src/crypto.rs`.

### 2.3 Golden vectors

The golden-vector corpus in
`steganographer-core/testdata/packets/` is **stable** (owner-approved
2026-09-21, see `manifest.json` `status`):

- Stable vectors change **only** in a minor release, with a version-tagged
  migration note in the CHANGELOG explaining the derivation change.
- The manifest (`manifest.json`) and fixtures (`<id>.hex` plus
  `.sha256` sidecars) are immutable between releases; the CI
  `immutability` job (`golden_vectors` + `calibration` drift gates) fails on
  any uncommitted drift.
- Materialization of new fixtures happens only via the owner-facing
  `--ignored` test in `steganographer-core/tests/golden_vectors.rs`, and only
  as part of a reviewed minor-release change.

## 3. Deprecation Policy

A deprecated API or behavior:

1. Is annotated with `#[deprecated]` (or documented as deprecated) in a
   **minor release**, with the replacement named in the CHANGELOG.
2. Remains functional for **at least one full minor cycle**. Removal happens
   no earlier than the next minor release after the one that deprecated it.
3. Removal of a deprecated item MUST be called out in the CHANGELOG under the
   release that removes it, with a migration path.

Wire formats and golden vectors are **never** deprecated silently: see §2.

## 4. MSRV Policy

- The workspace MSRV is **1.88** (`[workspace.package] rust-version`).
- The MSRV is bumped **only in minor releases**, never in patches, and the
  bump must be justified by a concrete dependency or language need recorded
  in the CHANGELOG.
- CI enforces the MSRV via the `msrv` job (`dtolnay/rust-toolchain@1.88.0`
  + `cargo check --workspace --locked`).

## 5. Supported Platform Matrix

| Crate / surface | macOS | Linux | Windows | wasm32 |
| ---------------- | ----- | ----- | ------- | ------ |
| `steganographer-core` | yes | yes | yes (gst-free) | yes (subset: packet encode/decode, RGB/PCM carriers, forensic scan) |
| `steganographer-cli` | yes | yes | yes (gst-free, `--no-default-features`) | — |
| `steganographer-dashboard` | yes | yes | best effort | — |
| `steganographer-gst` | yes (via brew) | yes (via apt) | not supported (gst feature excluded) | — |

GStreamer is macOS/Linux-only. The Windows CI job (`test-windows`) builds and
tests `steganographer-core`, `steganographer-cli`, and `steganographer-wasm`
with `--no-default-features` (gst-free). Windows support for the gst
dashboard transport is not offered; build the CLI there without default
features.
