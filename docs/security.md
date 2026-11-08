# Security

## Security model

Steganographer 0.8 provides bounded extraction, cryptographic payload verification and canonical-media tamper evidence. It is **not tamper-proof**, a deepfake detector, a person-identity service, or a complete forensic examination. Its guarantees depend on the chosen API, trusted verification context and preservation of the supported carrier representation.

Keep these questions separate:

1. Was a payload found and decoded within the configured limits?
2. Does its signature verify over the authenticated bytes?
3. Does the verified full public key match an independently trusted signer?
4. Does verification bind the delivered media, the logical payload, or exact file bytes?
5. Was the examination complete within the detector's declared scope?

Success at one step does not imply success at the others. See [Cryptography](cryptography.md) for byte-level contracts and [Threat Model](threat-model.md) for adversaries and residual risks.

## Historical signing key exposure

Commit `5dcb2e2669e135cd32f6d2615d279f1f0d8dbf35` contains a private Ed25519
signing seed at `keys/daf.key`. Its public identity is
`d2a05f7c69249dbfba5408dd8c35551317b04bfcc6f793c5e76221778c61d552`.
Treat that identity as compromised: anyone with the historical blob can sign
as it. The private bytes are not reproduced here or included in 0.8.0 artifacts.

The [incident record](key-rotation.md) declares this identity revoked effective
2026-07-22. Core's shared compromise policy denies it in managed CLI signing,
legacy verification, generic decode/extract, native signed pipelines and dashboard
router/processing boundaries. An absent or empty local registry cannot restore it.
Raw core cryptographic primitives remain mathematical operations, not authorization;
library applications must apply revocation and independently trusted public-key pins.

Retire this identity from external allowlists, provision replacement keys independently,
and rotate secrets derived from the exposed seed. Current source/artifact scanning has
no blanket directory exemption. `.gitleaksignore` acknowledges only the documented
historical commit/path/rule/line fingerprint; it does not waive the key value, another
commit, or new source exposure. An audit without that acknowledgment still detects
the historical blob. No history rewrite or universal downstream-retirement claim is
made: removing files/history cannot revoke copies or repair external trust.

## Integrity, authorship and coverage

| Property | Implemented boundary |
| --- | --- |
| Legacy frame integrity | `SignaturePayload` v4 hashes a domain, frame index, explicit video/audio lengths and audio presence; strict Ed25519 verifies the digest |
| Generic payload integrity | Optional Ed25519 transform signs recovered logical payload bytes, not arbitrary envelope metadata |
| Expected signer | A separately trusted full public-key pin; a self-supplied packet key alone proves no authorship |
| Exact-artifact commitment | Dedicated CLI OTS hashes the entire input file; legacy optional hooks hash canonical media, dashboard video hashes delivered PNG, audio raw signed PCM rather than WAV |
| Confidentiality | Optional authenticated encryption of the payload, not the visible/audible carrier or every metadata field |
| Ordering | Signed indices can support an external sequence policy; isolated frame verification does not prove stream completeness or freshness |

Media verification uses canonical bytes that exclude regions modified by the selected embedding kernel. LSB clears selected low bits; other supported kernels exclude their owned regions. Thus not every changed pixel/sample bit is authenticated. File headers, container metadata, display timestamps and other rendered interpretation are not automatically signed. An attacker may alter excluded data without invalidating the canonical hash. Preserve exact artifacts and their independent digest when whole-file evidence matters.

Weak imported Ed25519 keys are rejected and verification uses strict checks. These controls prevent permissive-key/signature acceptance; they do not repair an untrusted identity distribution channel or compromised signer. Old legacy v2/v3 media must be re-encoded, and historical raw zero-ID legacy ciphertext is not accepted by the new wrapper.

## Supported compositions, not decorative settings

- **Live signed native pipelines:** Ed25519 with exactly one supported invisible signing kernel. Encryption, ECC or spreading settings that would be ignored are rejected. Invisible signing combined with a visible overlay/info bar is rejected rather than reporting false output verification. Standalone rendering/kernel APIs are separate.
- **Native spread-spectrum signing:** the trait kernel's channel mapping differs from offline scalar binding; this signing composition is rejected. Do not treat the presence of a plain kernel API as end-to-end signature support.
- **Offline legacy spreading:** RGB LSB only, shard count 2–8 (1 unspread), actual first-shard binding and body-length-aware recovery. Generic packets and audio/SS/DCT sharding reject unsupported compositions before output.
- **Dashboard:** Ed25519 and supported LSB settings, not Ethereum/MetaMask signing. Unsupported backend, crypto and kernel selections fail explicitly. Preview opacity is a UI effect, not a burned-in authenticated overlay; unavailable overlay controls are disabled.
- **Lossless artifacts:** native file paths preserve RGB in Matroska and PCM in WAV. Dashboard recording archives contain exact signed PNG snapshots or signed PCM WAV chunks plus an extraction manifest in stored ZIP. These are not continuous signed WebM recordings.

DCT/spread-spectrum are not universal compression-resistant substitutes for LSB. Carrier capacity, recoverability, codec behavior and the exact binding must all work; unsupported/unsuitable inputs may reject instead of producing an unverifiable success. Arbitrary downstream lossy encoders may destroy the watermark. No cross-codec robustness claim is made.

## CLI fail-closed behavior

The machine-readable envelope is `steganographer.cli/v1`. Its top-level `status` is `success`, `error` or `partial`; inspect both the envelope and the command-specific result. Secret/password values are not serialized as recoverable output secrets.

| Exit | Meaning |
| ---: | --- |
| 0 | Command completed successfully; may include extraction-only `not_verified`, not trusted authentication |
| 1 | Invalid arguments, format, explicit configuration or unsupported composition |
| 2 | Packet/signature not found or decoding unavailable |
| 3 | Authentication/signature verification failure, including a revoked otherwise-valid signer |
| 4 | Scan findings meet the selected failure threshold |
| 5 | No usable statistical method, or a resource/coverage cutoff leaves a scan inconclusive without qualifying findings |
| 6 | Internal/runtime error, including unexpected I/O failures |

`verify` **without a public key** is extraction-only and reports `not_verified`. Exit 0 must not be used as a shortcut for trusted verification. A missing signature is `packet_not_found`/exit 2, and authentication failure is `verification_failed`/exit 3. Generic `decode`/`extract --trusted-signer` requires a matching signed payload; inspect `signer_public_key` and `signer_trusted` separately.

Configuration loading is fallible and validated. An absent implicit default may use defaults; an explicitly selected missing/invalid config is an error, not silently ignored configuration. Effective `DecodeLimits` apply to packet extraction/decoding. Malformed revocation data is an error, not an empty revocation list. Legacy paths reject generic-only/password flags they cannot honor. JSON encryption/placement workflows require recoverable caller-supplied credentials or the supported explicit secure key-output route; they do not report success while silently losing a generated secret.

`verify`, `decode` and `extract` share the additional `--revoked-list` JSON policy.
Only an omitted, genuinely absent `keys/revoked.json` is optional. Explicit missing
paths (including that literal default name), malformed files and dangling symlinks
fail closed. Generic packets signed by a revoked identity fail before payload
publication, even without `--trusted-signer`; a pin never overrides revocation.

Revocation mutation holds a persistent `<registry>.lock` companion over
read/merge/atomic replacement. Never remove its inode during use; advisory
locking serializes cooperating writers, not unrelated filesystem changes.

### Filesystem boundary

Offline media, payload and key output helpers stage in a private same-directory temporary file and publish atomically. Existing paths, including dangling symlinks, are refused by default. Where `--force` is supported, replacement changes the directory entry rather than truncating a symlink target or another hard link to the carrier. Secret files are created with mode 0600 on Unix before bytes are written. Key destinations are preflighted before generation/publication.

These guarantees are not a transactional commit across several output files, nor a sandbox against an attacker controlling parent directories, the process account or the filesystem. Use trusted output directories and secure permissions; retain backups before deliberate replacement. Native media pipelines have their own output/codec constraints and are not covered by a blanket claim that every writer shares the offline helper.

Native convenience file APIs now require trailing `overwrite: bool`; there is
no old-signature shim. They reject aliases and privately stage output until
successful EOS. The CLI grants replacement only for its own outer temporary.
Filesink reopens a pathname: trusted output directories remain a prerequisite.
Packed video checks actual mapped span/offset/full stride extent including
trailing padding before dependency plane slicing; metadata acceptance alone
does not establish safe backing.

## OpenTimestamps: pending is not verified

OTS uses bounded **standard detached `.ots` proofs**, actual calendar `POST /digest` and upgrade operations. Only Bitcoin attestations are supported; Ethereum/unknown attestations are not relabeled as Bitcoin. HTTP success, arbitrary JSON or elapsed process uptime cannot establish a timestamp.

Verification requires the caller's expected 32-byte digest, evaluates the proof operations and Merkle commitment, checks the raw Bitcoin header/hash and proof of work, and consults a configured **trusted Esplora canonical-height provider** (default `https://blockstream.info/api`). It is **not independent full-node validation**, accumulated-chain-work validation or an identity attestation. The configured calendar (default `https://alice.btc.calendar.opentimestamps.org`) is used for submission/upgrades; proof-embedded URLs do not authorize arbitrary upgrade destinations.

A calendar receipt with `pending: true` and `verified: false` is not Bitcoin-confirmed. Preserve it for later upgrade rather than treating it as completed evidence. A completed commitment establishes an upper time bound under the stated Bitcoin/provider assumptions, not a precise capture time. No new live Bitcoin confirmation is asserted by this documentation.

Proof parsing, HTTP bytes, operations/depth, requests and deadlines are bounded. Proofs are capped at 1 MiB. Proof I/O pins a trusted parent directory and uses no-follow regular/single-link file checks, complete-file reads and atomic hard-link no-clobber publication. It requires a hard-link-capable filesystem and preserves earlier receipts when publishing distinct upgrades/forced proofs. Parent-directory configuration remains trusted; this is not unrestricted-path sandboxing. CLI omitted `--proof` verification uses the digest-derived configured proof path, matching stamping.

`verify_with_upgrade` skips calendar contact for Bitcoin-attested proofs but
still verifies them through the trusted explorer; pending-only proofs may upgrade.
Optional changed proof bytes preserve prior branches and publish append-only.
CLI verify's `proof_file` remains the selected receipt, not the upgraded copy.

## Bounded forensics and honest statistics

A forensic report contains **findings**, a content-derived **`detected`** indicator and independent **`incomplete` / `incomplete_reasons`** fields. Evidence can be positive even if the rest of the examination is incomplete. Display caps do not clear an already latched positive. Conversely, an empty retained findings list or unavailable statistical result is not proof of a clean input.

Current coverage includes inline `STEG`/`STG3` magic, bounded Unicode/text patterns, ZIP/OOXML structure and selected text parts, and lexical PDF inspection. Important limits include:

- Magic scan: first 16 MiB, up to 256 retained locations.
- Statistical/entropy observations: first 64 MiB. Text analysis: bounded 1 MiB windows.
- ZIP/OOXML: up to 4,096 entries, 4 MiB inflated per entry and 8 MiB per package, bounded findings. Local/central structure, CRC/deflate and XML decoding are checked within supported formats. Unsupported archive features, malformed structures and budget exhaustion are reported as incomplete rather than a clean negative.
- PDF: bounded lexical objects, strings and selected streams, not full rendering, glyph/CMap interpretation or universal object-stream/filter support. Unsupported interpretation and cutoffs are incomplete.
- Detector-specific byte/finding/attempt budgets mark incompleteness even if the
  CLI read every byte; increasing `--max-bytes` does not remove detector ceilings.
- Directory scans use pinned-directory no-follow opens and post-open regular-file
  checks. Only explicit top-level link following is allowed. Skipped deeper
  directories at `--max-depth` are incomplete; findings retain exit 4 precedence.

`detector_registry()` documents per-detector scope, budgets and false-positive caveats. ZIP inventory, entropy, file-family observations, DOC-001 topology anomalies and PDF structural observations do not alone set the concealment verdict. Inline magic may also occur in ordinary text; a finding is not necessarily a recovered valid packet, malware or malicious intent. Keyed placement may hide the unkeyed magic signature; a negative scan cannot rule it out.

Statistical fields need particular care:

| Method | Honest interpretation |
| --- | --- |
| Chi-squared | Pair-frequency equalization compatibility; upper-tail p-value is not the probability of steganography |
| Sample-pairs | Adjacent-pair/histogram heuristic, not a validated embedding-rate estimator |
| RS | Conditional random-LSB replacement-rate estimate on suitable correlated samples; degenerate/nonphysical fits are unavailable/inconclusive |
| Combined confidence | Method-specific score aggregation, not a posterior probability or security verdict |

Synthetic replacement controls exercise RS estimator behavior; historical ramp fixtures exercise defined observations. Neither establishes accuracy on natural images, a detector ROC curve, or calibrated detection probabilities. Low embedding rate, keyed/interleaved placement or choosing one LSB does not prove statistical invisibility. Cachin's distributional/KL-divergence framework is useful theory, not a measured security bound for this implementation.


Compression admission shares a 64 MiB logical ceiling; configured limits may
be lower, and descriptors record compression only on shrinkage. Sequential/keyed
locator policy must match placement. Nested decode treats packet-looking bytes
as opaque until an identifiable parent-id field opts in, then strictly checks
child framing, complete span, parent/depth/aggregate/cycle limits.

RTC exact artifacts use bounded JSON/base64 and STGO 20-byte chunk framing,
not raw binary JPEG. Whole chunks are ≤16 KiB and full serialized requests
≤4 MiB; oversize pre-send errors recommend smaller resolution or WebSocket.
Browser verdicts remain server-reported; encode request/epoch and archive
submission ownership prevent stale current labeling, not malicious-server forgery.
Use separate trusted-key verification of exported artifacts.

## Key and deployment responsibilities

- Protect plaintext signing and encryption keys with restrictive permissions and trusted storage. Keep signing, encryption and placement roles separate. Do not use published fixture keys for real media.
- Owned secret buffers are zeroized where implemented; borrowed passwords, exported bytes, caller copies, command-line history, crash dumps and backups remain the caller's responsibility. Prefer protected file/input routes over shell arguments when available.
- Pin trusted verification keys before accepting media. Rotate/revoke through an authenticated process; per-session keys alone do not establish continuity. Master-derived session keys do not provide forward secrecy.
- Preserve lossless signed artifacts, manifests, extraction keys/context and exact-file digests. Verify independently with the expected key, not only against a server's own success display. A recording manifest supplies extraction context but is not itself automatically a signed identity certificate.
- The dashboard advertises its actual runtime signer public key, stable for that server runtime, not an independent organization/person identity. Protect the signer host and capture inputs; the server can sign synthetic input too.
- Keep tokenless dashboard mode local. Configured bearer-token checks protect mutation/transport surfaces, and browser Origin gates mitigate foreign-origin mutation/WebSocket requests. They are not general network authentication, TLS or protection against local non-browser clients. Use network access controls and HTTPS for remote deployment; avoid leaking tokens through URLs/logs.
- Input budgets reduce parser/resource risk, not all denial of service. Native GStreamer/codecs, browser capture, the host OS, dependencies and trusted timestamp providers remain part of the attack surface.

Dependency advisory checks and test/smoke results cover specific observed states, not exhaustive security, side-channel resistance or regulatory/legal certification. This guide deliberately makes no final test-count or performance claim; see the release evidence for exercised checks.

## Responsible disclosure

Report suspected vulnerabilities privately using the repository's security policy/maintainer contact rather than posting sensitive exploit details publicly. Include affected versions, minimal reproduction and impact; avoid exposing private keys or unrelated personal data.

## Source map and further reading

Operational contracts: [`envelope.rs`](../steganographer-cli/src/envelope.rs), [`media_io.rs`](../steganographer-cli/src/media_io.rs), [`cmd_packet.rs`](../steganographer-cli/src/cmd_packet.rs), [`ots_client.rs`](../steganographer-core/src/ots_client.rs), [`forensics.rs`](../steganographer-core/src/forensics.rs), [`steganalysis.rs`](../steganographer-core/src/steganalysis.rs), and dashboard [`lib.rs`](../steganographer-dashboard/src/lib.rs) / [`ws_handler.rs`](../steganographer-dashboard/src/ws_handler.rs).

See [Cryptography](cryptography.md), [Threat Model](threat-model.md), [Configuration](configuration.md), [CLI Reference](cli-reference.md), [OpenTimestamps](ots-integration.md), and [Steganography Theory](steganography-theory.md).
