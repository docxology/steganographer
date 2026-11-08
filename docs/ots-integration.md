# OpenTimestamps (OTS) integration

The optional `ots` feature implements standard OpenTimestamps v1 detached binary
`.ots` proofs and Bitcoin calendar submission/upgrade. It does not implement
Ethereum attestations, a custom JSON timestamp protocol, or automatic anchoring
of every signed segment. Dedicated CLI `ots stamp`/`ots verify` commit to
**SHA256 of the exact input file** (`digest_scheme: "sha256-file"`), not a
BLAKE3 Merkle root. The optional legacy encode/verify hook instead hashes
kernel-canonical media with SHA-256; it is not an exact-file commitment.
A proof is stored separately from the carrier media.

A Bitcoin timestamp establishes that the committed bytes existed **no later
than the attesting block's timestamp** under the verification trust model below.
It does not establish an exact creation time, authorship, or signer identity.

## Submission privacy and standard proof operations

For each fresh submission, including `--force`, the core obtains a fresh 32-byte
nonce from the operating system's cryptographic random source. Entropy failure
returns an error; there is no predictable fallback. Given `d = SHA256(file)`:

```text
original proof root: d
append operation (0xf0): d || nonce
SHA256 operation (0x08): SHA256(d || nonce)
calendar request body:  SHA256(d || nonce)  [32 bytes]
```

Only the blinded commitment is sent to the configured calendar with binary
`POST /digest`. The returned standard timestamp tree is attached after these
two operations. The detached proof still records the original SHA256(file),
and carries the exact nonce and operations needed to reproduce the request.
There is no new wire version or private attestation format.

Repeated submissions of the same file have independently randomized commitments;
calendars do not receive a recognizable raw file hash from fresh submissions.
This is commitment blinding, not anonymous networking: the server can still
observe request timing and network metadata. Sharing a detached proof reveals
its original digest, nonce, and calendar commitment. Existing unblinded standard
proofs remain readable and verifiable through the same operation evaluator.

## Pending is not confirmed

A successful submission normally returns a **pending calendar receipt**. It is
not a verified Bitcoin timestamp. Upgrading queries
`GET /timestamp/<commitment-hex>` at the explicitly configured calendar, using
the message at the matching pending attestation. For fresh blinded proofs that
message is the blinded commitment, not the original file digest. A calendar
HTTP 404 leaves the proof pending.

Verification requires the expected file digest, evaluates all proof operations,
and checks Bitcoin attestations against the actual raw 80-byte header:

- The computed commitment must equal the header's Merkle root.
- The header hash must match the block hash supplied for the attested height.
- The compact difficulty target and header proof of work must satisfy the
  implemented Bitcoin mainnet checks.
- The configured **trusted Esplora height index** supplies the canonical block
  hash at that height. The default is `https://blockstream.info/api`.

This is **not independent full-node chain validation**. The explorer remains a
canonical-chain trust boundary; local header and proof-of-work checks do not
remove it. Pending URIs cannot redirect requests to arbitrary services: upgrades
use only the configured calendar, and HTTP redirects are disabled. Unsupported
attestations and operations are rejected, not reported as verified.

The regression fixture uses the public Bitcoin genesis transaction and its real
header to exercise historical, unblinded proof verification. A newly blinded
submission of that transaction cannot reuse the genesis Merkle commitment.
Neither the fixture nor a successful new calendar submission demonstrates fresh
Bitcoin confirmation.

## CLI

```bash
steganographer ots stamp --input signed.png --output-dir ots_proofs --format json
steganographer ots verify --input signed.png --format json
```

`stamp` streams SHA256 over the input file and saves the receipt under
`proof_dir/<SHA256(file)-hex>.ots`. `verify` recomputes the same digest, defaults
to that same digest-based path and runs the shared verify/upgrade lifecycle.
Use `--proof path/to/receipt.ots` to select a different proof explicitly. It is
not necessary for the input filename to match the proof filename. Verify's
`proof_file` field identifies that selected input receipt, not a newly saved
upgrade; changed upgrade bytes are published append-only alongside it.

| Stamp option | Behavior |
| --- | --- |
| `--input` / `-i` | Required regular input file |
| `--output-dir` | Overrides the configured proof directory |
| `--method` | Only `bitcoin` is accepted; otherwise uses configuration |
| `--force` | Submits again instead of reusing the digest-path receipt; never overwrites old evidence |
| `--format` | `plain` (default) or `json` |

| Verify option | Behavior |
| --- | --- |
| `--input` / `-i` | Required original file; wrong-file proofs fail before network verification |
| `--proof` | Optional explicit proof; otherwise configured digest-based path |
| `--format` | `plain` (default) or `json` |

Without `--force`, a cached digest-path proof is parsed and checked for digest
binding, then reused without submission. Cache reuse is not Bitcoin verification.
Fresh stamp output has `verified: false`; the JSON success envelope's `result`
contains `digest_scheme: "sha256-file"`, `digest_hex`, `proof_path`, `pending`,
and `status`. Verify output includes `verified`, `pending`, `timestamp` (null
while pending), and trust-boundary details. A successful command can report
`pending`; consumers must inspect these fields rather than treating command
success as on-chain confirmation. Operational, malformed-proof, and wrong-file
errors propagate to the CLI error envelope and nonzero exit status.

Detached proofs use the standard format described by
[OpenTimestamps](https://opentimestamps.org/) and can be inspected by compatible
tools. Supply the original input file when independently verifying a proof whose
digest-based filename differs from the input's filename.

## Configuration and core API

```toml
[ots]
enabled = true
server_url = "https://alice.btc.calendar.opentimestamps.org"
bitcoin_explorer_url = "https://blockstream.info/api"
method = "bitcoin"
interval_secs = 300
proof_dir = "ots_proofs"
timeout_secs = 30
```

These are the defaults except `enabled`, which defaults to `false`. Configuration
is validated; unsupported methods and invalid explicit configuration do not
silently fall back. Calendar/explorer base URLs must use HTTPS, except explicit
loopback HTTP endpoints for local use. Credentials, queries, and fragments in
endpoint URLs are rejected. `interval_secs` must be 1–86400 and `timeout_secs`
1–300. The proof directory must be nonempty.

Explicit CLI `ots` commands opt in to their requested operation even if the
configuration's `enabled` switch is false. The dashboard uses that switch to
create its OTS client; merely signing media does not submit it automatically.

Core callers construct `OTSClient::from_config`, then use `stamp_digest` for an
already computed 32-byte SHA256 digest or `stamp_data` to hash bytes first.
`stamp_digest_force` explicitly bypasses interval admission. The client reserves
an attempt atomically before I/O: concurrent normal submissions cannot both
pass admission, and failed attempts consume the interval. Force also records an
attempt. This limit is per client instance, not a persistent cross-process quota.

`verify_with_upgrade(proof, expected_digest)` returns
`(OTSVResult, Option<Vec<u8>>)`: `None` means unchanged proof bytes. Proofs with
Bitcoin attestations skip calendar upgrades even if old pending branches remain,
but still require explorer/header verification. Pending-only proofs may upgrade
through the configured calendar. Merging preserves original branches.
`verify` delegates to that lifecycle and returns only its verdict;
`verify_attestations` checks without calendar contact. `upgrade` is the explicit
upgrade-only API. `validate_proof` checks local format/digest binding only.
Callers may save changed bytes through `save_proof` / `save_proof_to`, preserving
earlier receipts instead of replacing them.

## Dashboard

The dashboard exposes actual local OTS routes, distinct from the remote calendar
protocol:

| Route | Behavior |
| --- | --- |
| `GET /ots/status` | Configuration/readiness, current delivered-media digest, and matching operation outcome |
| `POST /ots/stamp` | Empty body selects SHA256 of latest delivered signed PNG bytes (video) or raw signed S16LE PCM bytes (audio); no media is a conflict |
| `POST /ots/verify` | Raw binary proof body, at most 64 KiB; requires `X-Expected-Digest` with the expected 64-character SHA256 hex digest |

Both POST routes honor the dashboard's configured mutation authentication.
Disabled OTS reports disabled; remote or verification failures are surfaced as
errors, not manufactured timestamps. The OTS panel distinguishes pending,
verified, and operational failures. Signing/rendering is separate from these
explicit timestamp actions; no claim of automatic per-segment confirmation is
made.

The audio commitment excludes the WAV header added for archive export. To
independently match it, hash the exact returned signed PCM, not the WAV file;
dedicated CLI `ots stamp exported.wav` instead commits that entire WAV file.
Video commits delivered PNG bytes, not decoded RGB or an H.264 preview.

## Proof persistence and resource limits

Proof publication never truncates or replaces an existing final file. It writes
and syncs a private temporary regular file, then publishes with an atomic
**hard-link/no-clobber** operation in a pinned directory handle. A filesystem
supporting hard links is required. Identical existing proof bytes can reuse a
path. If a force stamp or upgrade produces different bytes, publication uses
`<original-name>.<SHA256(proof)-hex>.ots`, preserving the original receipt. The
CLI reports the actual stamp path; explicitly select an alternate receipt with
`--proof` when needed. Verification also preserves the original receipt when
saving changed upgrade bytes.

Directory configuration and its acquisition path are trusted; ordinary system
aliases such as `/tmp` are accepted. Once opened, the directory handle pins file
operations. Final-file reads do not follow symlinks and require a bounded,
single-link regular file; symlinks, multiply linked files, FIFOs, malformed
proofs, and oversized files are rejected. Final-name collisions cannot clobber
such objects or their targets. On Unix, newly created proof temporaries use mode
`0600`.

Core limits include:

- 1 MiB detached proofs; 10,000-byte successful calendar responses.
- 256 tree levels, 4,096 operations/branches, 4,096-byte messages, and 64
  attestations. Fresh blinding operations count against the same final limits.
- At most eight distinct pending calendar upgrade requests and eight Bitcoin
  attestations per operation.
- A configured total network-operation deadline, bounded response-body reads,
  and capped proof I/O. Cancelled blocking disk work may finish after the caller's
  deadline but cannot publish a partial proof.

Protect proof files if the original digest or nonce should remain private, and
retain the exact original file for later digest-bound verification. A signature
or visually equivalent re-encoding is not a substitute for matching file bytes.
