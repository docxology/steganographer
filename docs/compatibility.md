# Compatibility and Migration

## Versioning

These docs target proposed 0.9.0; version metadata/publication are separate.
Before 1.0, a minor release may make
breaking Rust/API or legacy format changes with an explicit migration note;
patch releases do not change wire contracts or MSRV. Generic packet protocol
versioning is independent of the crate version. See [CHANGELOG](../CHANGELOG.md)
for release changes and [CLI Reference](cli-reference.md) for current flags.

## 0.8 to proposed 0.9 cutover

- Native convenience callers must pass
  `process_video_file(input, output, stego, signer, signing_kernel, max_frames, overwrite)`
  or `process_audio_file(input, output, stego, signer, signing_kernel, max_buffers, overwrite)`.
  Use `false` for new user outputs; `true` only when replacement is intended.
  Input/output aliases always reject. Both helpers stage a private sibling and
  publish after successful EOS; failures preserve an existing destination.
  Filesink reopens that pathname, so the output directory must remain trusted.
  There is no old-signature overload or compatibility shim.
- Use `capacity`, not raw `info` capacity minus a guessed constant, for
  sequential generic logical payload sizing. Match filename/MIME/signing
  policy exactly between sizing and encoding. See [CLI Reference](cli-reference.md).
- An unavailable `analyze` result is now partial/inconclusive, exit 5, not a
  clean negative. Scan detector/traversal cutoffs remain incomplete even when
  all input bytes were read; positive findings still take exit 4 precedence.
- Generic wire-v1 fixtures remain unchanged. Compression uses a shared 64 MiB
  logical admission ceiling (CLI limits may be lower); sequential/keyed flags
  must match placement. Nested decode treats STG3-shaped bytes as opaque until
  an identifiable parent-id field opts in, then requires strict complete linkage.
- OTS `verify_with_upgrade(proof, expected_digest)` returns the verdict plus
  optional changed proof bytes. Completed Bitcoin proofs skip calendars but
  still verify through the configured trusted explorer. Preserve old receipts
  on publication; `verify` discards returned upgrade bytes if not needed.
- RTC is JSON/base64 over a data channel, not raw JPEG binary. Migrate custom
  clients to `jpeg_b64` encode requests and STGO 20-byte chunk headers.
  The 4 MiB limit covers serialized JSON/base64; chunks are at most 16 KiB.
  WebSocket image input remains raw binary; signed replies contain PNG.
- Default release builds capture committed Git-tree blobs/modes. Explicit
  `--allow-dirty` captures the working tree, even if clean, and is not
  commit-bound. It is not a shortcut to a qualified/published release.

## 0.7 to 0.8 cutover

### Legacy media signatures: format 4

The fixed 109-byte legacy `SignaturePayload` remains magic, version, index,
hash and Ed25519 signature, but its format version is now **4**. Canonical
hash input unambiguously frames index, video length, audio presence and audio
length. Legacy versions 2/3 are rejected, not silently verified using the old
ambiguous hash. **Re-encode original source media**; changing a version byte is
not migration. Keyed legacy audio placement also changed with format 4; use
matching encoder/extractor and the actual signed chunk index.

Signatures bind canonical media content, excluding kernel-owned regions/low
bits as appropriate. They do not authenticate every container byte, rendered
metadata or the semantics of arbitrary envelopes. A pinned trusted signer is
needed for identity; a public key carried alongside a signature does not
independently prove a person or organization.

### Legacy encryption: `STGE` wrapper

Legacy encrypted payloads now require wrapper version 1 with a fresh random
128-bit packet ID, adding 41 bytes. There is no raw/zero-ID legacy fallback.
Re-encode from source with retained explicit encryption credentials. This does
**not** change frozen generic STG3 protocol-v1 raw AEAD bytes. Callers of the
raw encryption API must ensure packet-ID uniqueness for each key.

### Generic packets: STG3 protocol v1 preserved

The STG3 locator and protocol-v1 golden packet/carrier bytes remain unchanged.
Within that protocol, unknown non-critical fields can be ignored; unknown
critical fields fail closed. Existing field IDs, descriptors, flags, locator
layout and transform signature/AAD encodings must not be repurposed. A breaking
wire layout requires a new protocol major version, not a rewritten fixture.
Frozen `.hex` vectors and integrity sidecars are evidence, not outputs to
regenerate to make a changed implementation pass.

Generic signatures authenticate logical payload bytes, not arbitrary semantic
metadata. Decode/extract now support `--trusted-signer` to require the expected
Ed25519 public key. Reports distinguish `signer_public_key` from
`signer_trusted`; unsigned/mismatched packets fail when a pin is supplied.
Both commands also enforce the shared `--revoked-list` registry and immutable
known-compromise policy before payload output, with or without a pin. Empty or
absent local policy cannot restore the documented compromised identity.

### CLI behavior and flags

- Both **decode and extract** use `--decryption-key` /
  `--decryption-key-file`; extract's old encryption-key spellings are removed,
  not retained as aliases. Encode uses `--encryption-key*`.
- Extract uses the same bounded validation, transform reversal and digest/
  signature checks as decode. It is not a raw unchecked envelope bypass.
- Verify with no public key returns extraction-only `not_verified`.
  `no_signature` is exit 2, `packet_not_found`; `valid_revoked` is exit 3,
  `verification_failed`. Both error envelopes retain their result.
- Machine output uses `steganographer.cli/v1`, not an unwrapped result.
  User/config errors are exit 1; runtime errors are exit 6; scans distinguish
  positive findings (4) from inconclusive cutoffs without findings (5).
- Explicit missing/invalid config and revocation files fail. Effective packet
  limits reach extraction/parsing/transform reversal. Auto-bits probes real
  depths and preserves recognized authentication failure precedence.
- Password options are generic-packet-only, not accepted-and-ignored on legacy
  encode. Prefer `--password-file`. Generated encryption/placement secrets may
  not be silently lost in JSON: supply recoverable explicit credentials.
- Outputs are atomic and no-clobber by default. Explicit decode/extract force
  replaces the directory entry without truncating another symlink/hardlink
  target. Secret creation uses Unix 0600 before bytes; Windows ACLs remain the
  caller's deployment responsibility.
- Legacy offline spreading is RGB LSB only, 2–8 shards (1 disables). Unsupported
  audio/SS/DCT spreading and generic spreading fail before writes.

Dashboard `create_router` now returns `Result<Router>` and rejects a known
compromised signing identity. Propagate/handle that result instead of assuming
router construction cannot fail. Native managed signing APIs reject the same key;
raw core signature mathematics remains separate from authorization.

### Live/native contracts

Shipped signed defaults are LSB-only. Native signed video uses exactly one
invisible kernel; adding overlays/info bars or multiple signing kernels is not
supported. Visible modules are separate rendering operations. Signed native
audio is LSB-only. Native trait SS signing is rejected because its channel
mapping differs from offline CLI scalar binding. Offline SS now uses bounded
integer residue/quantization modulation, not additive/pair-averaging behavior;
re-encode older SS carriers rather than assume placement/modulation identity.
Current low-level SS sample helpers use typed `u8` / `i16` input and fallible
results; downstream callers must retain error propagation.

Live encryption, ECC and spreading are unsupported; they must not become
ignored live settings. Use offline encode for supported transform workflows.
The dashboard supports Ed25519 + BLAKE3 + LSB only; core alternative signer
APIs do not imply live Ethereum/MetaMask support.

Native exact-file APIs use RGB Matroska `.mkv` and PCM `.wav`, not arbitrary
lossy codecs. Audio file signing uses one bounded gathered selection (64 MiB),
index 0, honoring `max_buffers`. macOS application callers own Cocoa main-loop
setup; library file calls do not seize the main thread. The CLI handles its
own live-command dispatch. Startup/Record exports are sampled PNG snapshots /
PCM chunks with extraction manifests, not continuous signed media.

### WASM and other Rust callers

WASM packet report schema is **`steganographer.packet-report.v2`**. All `u64`
fields are exact decimal strings; migrate consumers away from JavaScript
Number arithmetic/parsing that loses precision. Original JS numeric inputs
are range-checked before narrowing. Custom decode limits remain effective at
the carrier and transform boundaries; callers must handle rejected inputs.
See [WASM guide](../steganographer-wasm/README.md) for generated binding APIs.

Native filter signing uses an explicit signing-kernel binding. Propagate
fallible embed/extract operations rather than replacing errors with apparent
success. Hash-chain verification of a later segment requires a trusted prior
hash; exact segment ordinal remains external trusted metadata. See
[API Reference](api-reference.md) and [GStreamer](gstreamer.md).

### OTS protocol

Only Bitcoin attestations are supported. CLI commitments are SHA-256 of exact
input files; standard detached proofs live at configured
`proof_dir/<digest-hex>.ots`, also the omitted-`--proof` verify default. Pending
is not verified. Verification requires the expected digest and trusted
canonical-chain Esplora provider; it is not independent full-node validation.
See [OTS Integration](ots-integration.md) for protocol and proof I/O migration.

## Deprecation and evidence policy

Ordinary API deprecations should name their replacement and migration horizon.
Security/correctness cutovers may remove unsafe behavior at the minor release
boundary, as above; unsupported behavior is not kept as a silent shim. Wire
changes and fixture changes are never silent or patch-level migrations.

Do not preserve wording/default/property echoes as acceptance tests or repin
them to a new implementation. Preserve meaningful behavior, negative,
boundary and immutable-wire evidence instead. Canonical test/inventory totals
are maintained in root `AGENTS.md`, not copied into this policy.

## MSRV

The workspace MSRV remains **Rust 1.91**, raised in 0.8 because the RTC
dependency uses
[`Ipv4Addr::from_octets`](https://doc.rust-lang.org/1.91.0/std/net/struct.Ipv4Addr.html#method.from_octets),
stabilized in 1.91. CI is configured for the locked all-feature workspace on
1.91; that configuration is not evidence of a current hosted run. Dependencies
are not vendored or silently downgraded to preserve an inaccurate MSRV.

## Platform boundaries

| Surface | Release boundary |
| --- | --- |
| macOS / Linux | Native workspace CI targets; GStreamer integration supported |
| Windows | GStreamer-free core/CLI/WASM build/test CI subset; no native GStreamer support |
| wasm32 | Generated-binding facade for packets, RGB/PCM carriers and forensics; no native pipelines/network OTS |

A configured CI job is not evidence of a particular successful hosted run.
Synthetic headless tests and fake browser media do not establish physical
camera/microphone, virtual-device or conferencing application coverage.
Dashboard H.264 preview and third-party lossy pipelines are not exact signed
artifact transports. See [Platforms](platforms.md) for setup and limitations.
