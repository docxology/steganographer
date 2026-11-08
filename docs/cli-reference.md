# CLI Reference

This reference describes the proposed 0.9.0 CLI behavior. The authoritative argument schema is
`steganographer-cli/src/cli.rs`, shared with completion/manual generation.
Run `steganographer <command> --help` for argument spelling in your build.
`video` and `audio` exist only with the default `gst` feature enabled.

## Global options

```text
steganographer [OPTIONS] <COMMAND>
```

| Option | Default | Meaning |
| --- | --- | --- |
| `--config`, `-c` | `config/example.toml` | TOML configuration path |
| `--log-level`, `-l` | `info` | `trace`, `debug`, `info`, `warn`, `error` |
| `--quiet`, `-q` | off | Suppress logging, not the final result |
| `--schema-version` | `v1` | Machine envelope version; other values fail |
| `--help`, `-h` | — | Help |
| `--version`, `-V` | — | Binary version |

Configuration is loaded and validated before command dispatch. Only a missing
*implicit* `config/example.toml` can fall back to minimal defaults. An explicitly
supplied missing file, malformed TOML, or invalid supported configuration fails
with exit 1. See [Configuration](configuration.md) for effective limits and the
separation between offline settings and live capabilities.

## `encode`: legacy attestation or generic packet

Both modes require `--input/-i` and `--output/-o`. Existing carrier outputs are
not overwritten; there is no encode `--force` flag.

| Option | Default | Meaning |
| --- | --- | --- |
| `--stego-type` | `lsb_video` | Legacy: `lsb_video`, `lsb_audio`, `spread_spectrum_video`, `dct_video`; generic: LSB video/audio only |
| `--bits` | `1` | LSB depth 1–4; non-LSB kernels require 1 |
| `--input-format` | inferred | `raw_rgb`, `raw_s16le`, `png`/`image`, `wav` |
| `--width`, `--height` | absent | Paired dimensions for raw RGB; needed for dimension-dependent kernels |
| `--format` | `plain` | `plain` or `json` |
| `--signing-key` | ephemeral for legacy; unsigned generic | Hex-encoded 32-byte Ed25519 private-key file |
| `--embedding-key`, `--embedding-key-file` | mode/config dependent | 32-byte hex placement key; legacy audio/SS or generic keyed LSB |
| `--encrypt` | off | ChaCha20-Poly1305 encryption |
| `--encryption-key`, `--encryption-key-file` | absent | 32-byte hex encryption key; use the file form where possible |
| `--ecc` | off | Reed-Solomon correction |
| `--ecc-parity` | `4` | Parity symbols, 1–16 when enabled |
| `--spread` | `1` | Legacy offline RGB LSB only: 2–8 shards; 1 disables |
| `--hash-algorithm` | config or `blake3` | Legacy only: `blake3`, `sha256`, `sha3-256` |
| `--dir` | off | Legacy batch input/output directories |

Without `--payload-file` or `--payload-text`, encode signs a canonical carrier
using the legacy format-4 payload. The result provides the public key needed
for verification. LSB video supports raw RGB and decoded images with lossless
PNG output; LSB audio supports raw S16LE and integer PCM16 WAV. SS uses keyed,
bounded integer residue/quantization modulation; it is not a promise of
survival through arbitrary noise or codecs. DCT uses RGB dimensions and direct
signed payloads; encryption, ECC and spreading are unsupported there. An
unrecoverable embedding fails instead of reporting corrupt output as success.

Legacy spreading is not generic-packet spreading: it uses the core shard
format across suffixed outputs `<output>_001`, `<output>_002`, etc. Pass the
unsuffixed output base and the same `--spread` to verify. Audio, SS and DCT
spreading are rejected before writes. Retain every required shard.

### Generic-only options

| Option | Meaning |
| --- | --- |
| `--payload-file` or `--payload-text` | Explicit generic STG3 protocol-v1 mode; mutually exclusive |
| `--mime-type` | Public MIME metadata |
| `--filename` | Safe display filename, not a path |
| `--compress` | DEFLATE before embedding |
| `--password-file` | Argon2id-derived encryption; preferred password input |
| `--password` | Same, but exposed to shell history/process listings |
| `--no-verify-write` | Skip generic carrier re-read/exact packet recovery check |

Password sources conflict with explicit encryption keys. The packet stores
public Argon2id salt/parameters, not the password. Passwords, compression,
packet metadata and `--no-verify-write` fail on legacy mode; they are not
silently ignored. Generic mode rejects `--dir`, `--hash-algorithm`, and
`--spread > 1`.

Generic payload signatures authenticate logical payload bytes, not arbitrary
semantic envelope metadata or carrier provenance. A self-contained signer key
proves mathematical consistency, not authorship; pin the expected key during
recovery with `--trusted-signer`.

```bash
# Persistent legacy signing identity
steganographer keygen --output mykey
steganographer encode -i frame.rgb -o signed.rgb --signing-key mykey.key
steganographer verify -i signed.rgb --public-key "$(cat mykey.pub)"

# Generic password-encrypted, signed packet (cover.png must have capacity)
steganographer encode -i cover.png -o packed.png --payload-file report.pdf \
  --password-file secret.txt --signing-key mykey.key --compress --bits 2
steganographer decode -i packed.png -o recovered.pdf --password-file secret.txt \
  --trusted-signer "$(cat mykey.pub)" --bits auto
```

Machine output never serializes secret keys. JSON encoding that would generate
an unrecoverable encryption or legacy audio/SS embedding secret fails: supply
recoverable explicit keys (or a password for generic encryption). Retain the
key files yourself. An ephemeral signing public key can verify that run, but
does not establish a stable person/organization identity.

## `decode` and `extract`: generic packet recovery

Both commands recover the logical payload through the same bounded packet
validation, transform reversal, digest and signature checks. `extract` is **not**
a bypass around these checks and does not decode a legacy signature payload.

| Option | Default / behavior |
| --- | --- |
| `--input/-i`, `--output/-o` | Required carrier and payload destination |
| `--stego-type` | Decode defaults to `lsb_video`; extract infers `lsb_audio` for WAV, otherwise `lsb_video` |
| `--input-format` | Inferred; raw RGB, raw S16LE, decoded image, PCM16 WAV |
| `--bits` | `auto`: actually probes depths 1–4; an exact value restricts recovery |
| `--embedding-key`, `--embedding-key-file` | Keyed placement credentials |
| `--decryption-key`, `--decryption-key-file` | Encryption credentials; **these spellings apply to both commands** |
| `--password-file`, `--password` | Argon2id credentials; file preferred; conflict with explicit decryption keys |
| `--trusted-signer` | Expected Ed25519 public key in hex; unsigned or mismatched packets fail |
| `--revoked-list` | Additional hex-key JSON registry; omitted reads `keys/revoked.json` when present; known compromise policy always applies |
| `--force` | Atomically replace an existing payload destination |
| `--format` | `plain` or `json` |

Decode additionally accepts `--decrypt`; explicit credentials enable the
corresponding recovery path. Extract has no `--decrypt` switch: supplying its
key/password is sufficient. Old extract `--encryption-key` and
`--encryption-key-file` spellings are not aliases and fail.

```bash
steganographer decode -i packed.png -o recovered.pdf --bits auto --format json
steganographer extract -i encrypted.png -o recovered.bin \
  --decryption-key-file keys/encryption.key --trusted-signer "$(cat mykey.pub)"
steganographer decode -i packed.wav -o recovered.bin --stego-type lsb_audio \
  --embedding-key-file keys/embedding.key --password-file secret.txt
```

Configured `[limits]` apply to extraction, parsing, transform reversal and
logical output bounds. Auto-depth probing does not turn a recognized packet's
authentication failure into success or generic absence. Reports expose
`signer_public_key` and `signer_trusted`: only an explicit matching pin sets
trust. Without one, a signed packet is not an authenticated external identity.

Payload publication is atomic and no-clobber by default. With `--force`, a
symlink/hardlink destination is replaced as a directory entry; its other target
or carrier is not opened for truncation. Secret outputs are created with Unix
mode 0600 before writing. This does not replace filesystem access controls or
provide a Windows ACL guarantee.

## `verify`: legacy media attestations

| Option | Default / meaning |
| --- | --- |
| `--input/-i` | Required carrier, or unsuffixed spread-output base |
| `--public-key` | Expected Ed25519 public key in hex |
| `--stego-type` | `lsb_video`; also `lsb_audio`, `spread_spectrum_video`, `dct_video` |
| `--bits` | `auto` (real 1–4 probing) or exact LSB depth |
| `--input-format` | Inferred; same media choices as legacy encode |
| `--width`, `--height` | Paired raw RGB dimensions |
| `--embedding-key`, `--embedding-key-file` | Audio/SS extraction key |
| `--frame-index` | `0`; actual signed chunk index for keyed legacy audio |
| `--decrypt` | Enable legacy decryption |
| `--decryption-key`, `--decryption-key-file` | Legacy decryption key |
| `--ecc`, `--ecc-parity` | Match encoding; default parity 4 |
| `--spread` | Match encoding; offline RGB LSB only, 1 or 2–8 |
| `--hash-algorithm` | Match encoding; config or BLAKE3 |
| `--revoked-list` | `keys/revoked.json` |
| `--format` | `plain` or `json` |

Without `--public-key`, verify is **extraction-only**: `not_verified` is not a
cryptographic or identity assertion. Valid signatures bind canonical media
regions, not every container byte, rendered metadata or arbitrary transcode.
For dashboard audio exports use the manifest's index, bits, public key and
embedding key; the default index is not interchangeable with later chunks.

| Result status | Exit | Envelope status / error code |
| --- | --- | --- |
| `valid` | 0 | `success` |
| `not_verified` | 0 | `success` (extraction only) |
| `no_signature` | 2 | `error` / `packet_not_found` |
| `invalid` | 3 | `error` / `verification_failed` |
| `valid_revoked` | 3 | `error` / `verification_failed` |

The error envelope retains the verification `result`, including its status.
A malformed/unreadable revocation file or explicitly selected missing file fails.
Only a genuinely absent implicit default omits additional local revocations.
The documented compromised identity remains revoked regardless. Decode/extract
also enforce this policy before publishing a payload, even without a signer pin.

## Live `video` / `audio`

Both accept `--source`, `--sink` (GStreamer fragments), and `--signing-key`
(Ed25519 private-key file; ephemeral if omitted). Video accepts `--max-frames`;
audio accepts `--max-buffers`. They require their corresponding config section.

```bash
steganographer --config config/example.toml video \
  --source 'videotestsrc ! videoconvert ! video/x-raw,format=RGB' \
  --sink 'fakesink' --max-frames 20 --signing-key mykey.key
steganographer --config config/example.toml audio \
  --source 'audiotestsrc ! audioconvert ! audio/x-raw,format=S16LE,channels=1,rate=44100' \
  --sink 'fakesink' --max-buffers 20 --signing-key mykey.key
```

Shipped signed defaults are LSB-only. Signed video requires exactly one
invisible kernel, with no overlay/info-bar combination; signed audio supports
LSB only. Native trait SS signing is rejected because its channel mapping is
not the offline scalar binding. Visible rendering modules remain separate,
unsigned operations. Live encryption, ECC and multi-frame spreading are not
supported; use offline encode for those features, not decorative live settings.

The CLI owns Cocoa main-loop dispatch for live macOS commands; reusable native
library calls do not seize the process main thread. Native exact file outputs
are RGB Matroska `.mkv` and PCM `.wav`; do not substitute a lossy sink and assume
watermarks survive. Audio file signing gathers a bounded selection (64 MiB),
signs once at index 0, and honors `max_buffers`. See
[GStreamer integration](gstreamer.md) for library file APIs and sink policy.

## `dashboard`

`--port/-p` defaults to 8080; `--host` to `127.0.0.1`; `--backend` supports
`ed25519` only. `--auth-token` enables bearer authentication. `--transport`
accepts `auto`, `websocket`, `webrtc`; repeatable `--ice-server` supplies STUN/TURN
URLs when the build has `webrtc`. Pinned WebRTC fails visibly if unavailable;
only auto may fall back. Avoid exposing a tokenless instance to a network.

```bash
steganographer dashboard --backend ed25519 --transport websocket
```

Startup/demo captures and Record exports are sampled signed artifacts, not
continuous signed media. Record downloads contain signed PNG snapshots or
PCM WAV chunks plus extraction manifests in stored ZIP archives. Lossy H.264
preview is not the signed evidence surface. The displayed public identity is
the actual runtime signer, not a verified human/organization identity.

## `capacity`: exact generic logical payload bound

```bash
steganographer capacity --carrier-units 12288 --stego-type lsb_video \
  --bits 1 --filename payload.bin --mime-type application/octet-stream --format json
# Alternatively decode an actual carrier:
steganographer capacity -i cover.png --bits 2 --filename payload.bin \
  --signing-key mykey.key --format json
```

Select exactly one of `--carrier-units N` or `--input/-i FILE`. Units are
decoded RGB bytes (width × height × 3), or S16 samples across all channels,
**not** encoded file bytes or PCM byte count. `--stego-type` accepts
`lsb_video` (default) or `lsb_audio`; `--bits` is 1–4 (default 1).
Actual input accepts `--input-format` and paired raw-RGB `--width/--height`.

This sizes an uncompressed, unencrypted, non-ECC **sequential generic file
packet**, optionally signed with the actual `--signing-key` policy. It uses
the core 32-byte locator and canonical envelope encoding, including variable-width
logical length and metadata TLVs, under effective decode limits. Ed25519 adds
96 bytes of public-key/signature parameters **plus** their transform-descriptor
and envelope framing; the report sizes all of it, not a guessed 64-byte deduction.
It is not `info`'s raw packet budget or a bound for keyed/transformed packets.
If even empty framing cannot fit, it fails rather than advertising an
embeddable zero-byte payload.

The JSON `steganographer.cli/v1` envelope has `command: "capacity"` and
`result` fields `max_payload_bytes`, `max_packet_bytes`,
`packet_overhead_bytes`, `carrier_units`, `bits`, `signed`, `filename`,
`mime_type` (absent metadata is null). `max_packet_bytes` is the encoded
packet size at the reported maximum logical payload; overhead is their
difference, not a universal constant. Pass identical `--filename`,
`--mime-type`, bit depth and signing key to encode; file encoding otherwise
derives filename metadata from the payload path. Capacity does not generate
an identity or allocate the advertised logical payload.

## Other commands

- `keygen --output/-o <BASE> [--format plain|json]`: writes `<BASE>.key` and
  `<BASE>.pub`, no-clobber. Default base: `steganographer`.
- `derive --output/-o <DIR>`: choose one high-entropy hex source
  (`--master-secret`, `--master-secret-file`, `--master-secret-stdin`) or password
  source (`--password`, `--password-file`, `--password-stdin`). Password mode
  accepts `--salt`, `--argon2-memory`, `--argon2-iterations`,
  `--argon2-parallelism`. Save generated salt and parameters for re-derivation.
  Writes `signing.key`, `signing.pub`, `encryption.key`, `embedding.key`;
  default directory `keys`. Supports `--format plain|json`.
- `info -i <FILE> [--stego-type <TYPE>] [--bits 1..4] [--width <W> --height <H>]
  [--embedding-key <HEX>] [--format plain|json]`: decoded carrier capacity,
  including generic LSB descriptor/placement overhead.
- `config [check] [--format plain|json]`: validates the selected config,
  including limits and every named profile; no pipeline is started.
- `revoke --public-key <HEX> [--output/-o <PATH>] [--format plain|json]`:
  updates a JSON array of hex public keys (default `keys/revoked.json`).
  Malformed existing data fails rather than being discarded. A persistent
  `<output>.lock` companion serializes cooperating read/merge/atomic-publication
  operations across registry replacement. Do not unlink it: replacing its
  inode splits lock ownership. This advisory lock does not constrain unrelated
  writers that ignore the protocol.
- `analyze -i <FILE> [--analysis-type combined|chi_squared|sample_pairs|rs]
  [--format plain|json]`: statistical evidence, not a calibrated probability of
  hidden content in natural media. Results expose overall and per-method
  `available`; unavailable individual methods are not negative findings.
  Combined analysis is available if at least one method is usable. With none,
  plain output says inconclusive, JSON is `status: "partial"`, and exit is 5.
- `scan -i <PATH> [--max-depth 8] [--max-files 10000] [--max-bytes 67108864]
  [--profile <NAME>] [--follow-input-symlink] [--format plain|json|jsonl]`:
  bounded structural/statistical/text/container analysis. Recursion opens
  files/directories relative to pinned directories with no-follow checks,
  validates regular files after opening, and never follows recursive links.
  The flag permits only the top-level link target. Skipped subdirectories at
  `--max-depth` mark `max_depth` incompleteness, not a clean result.
  Profiles select supported detector IDs; container findings always contribute.
  Reports retain findings and incompleteness separately, including detector
  budgets even when the CLI read was not truncated. Positive findings take
  exit 4 precedence over an incomplete negative's exit 5. JSONL emits one
  schema-wrapped file record plus a final summary envelope on stdout. Plain
  summaries go to stdout; plain error/coverage diagnostics go to stderr.

## `ots`: Bitcoin OpenTimestamps

```bash
steganographer ots stamp -i report.pdf --method bitcoin --output-dir ots_proofs --format json
steganographer ots verify -i report.pdf --format json
```

CLI stamping commits **SHA-256 of the exact input file**. `stamp` accepts
`--input/-i`, `--output-dir`, `--method` (Bitcoin only), `--force`, `--format`.
`verify` accepts `--input/-i`, optional `--proof`, and `--format`.
The default proof path is the configured proof directory plus
`<sha256-hex>.ots`, for both commands, not `<input>.ots`. This exact-file
`sha256-file` scheme differs from the optional legacy encode/verify OTS hook's
SHA-256 of kernel-canonical media. Dashboard video commits delivered PNG file
bytes; dashboard audio commits raw signed PCM, not its exported WAV wrapper.
Pending is not verified. Completed Bitcoin proofs skip calendar upgrades but
still require trusted explorer verification. Changed upgrades are saved
append-only; verify's `proof_file` still identifies the selected input receipt.
See [OTS Integration](ots-integration.md) for the lifecycle and trust boundary.
Dashboard routes are `/ots/status`, `/ots/stamp`, `/ots/verify`.

## Machine output and exit codes

JSON results use `schema: "steganographer.cli/v1"` with `command`, `status`,
optional `result`, `warnings`, `errors`, `timing`, and `tool`. Errors have stable
snake_case `code` and `message`. JSON is a single stdout document, not the
unwrapped command result; diagnostics go to stderr. Secret keys/passwords are
not serialized.

| Exit | Meaning |
| --- | --- |
| 0 | Success; verify may still be extraction-only and OTS may still be pending |
| 1 | User/configuration/format error |
| 2 | Packet/signature absent or decode unavailable |
| 3 | Authentication/signature/pinned-signer or revocation failure |
| 4 | Scan findings |
| 5 | Inconclusive analysis (no usable statistical method, or incomplete scan without a positive finding) |
| 6 | Unexpected internal/runtime/I/O error |

## 0.8 migration

Legacy format 2/3 signatures are rejected; re-encode original media with format
4. The keyed legacy audio placement changed with that version. Legacy encrypted
payloads now require the version-1 `STGE` wrapper containing a fresh 128-bit
packet ID (41-byte overhead); there is no raw zero-ID decryption fallback.
Generic STG3 protocol-v1 wire bytes remain compatible. See
[Compatibility](compatibility.md) for Rust/WASM and platform migration notes.

For the 0.9 API/transport cutover, see [Compatibility](compatibility.md#08-to-proposed-09-cutover).
