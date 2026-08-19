# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **`verify --bits auto` now detects the correct LSB strength and reports
  `valid`.** When the encoder used a non-default LSB strength (e.g. `--bits 2`),
  auto-detection tried each candidate `[1,2,3,4]` and returned the *first* that
  merely parsed a magic-matching buffer. That buffer could come from the wrong
  strength, so carrier canonicalization masked the wrong low bits and the
  signature hash never matched — every `encode`/`verify` round-trip reported
  `"status": "invalid"`. Auto-detection now *verifies* each candidate against
  the public key and returns the strength that genuinely validates (falling back
  to magic-only only when no key is supplied). Added
  `test_lsb_video_encode_verify_roundtrip_with_ecc_auto_bits` pinning the
  `--bits 2` + `--ecc` case.

  The `v0.7.0` change from `ALPHA = 2` to `ALPHA = 3` altered the Reed-Solomon
  evaluation points, but `SignaturePayload::FORMAT_VERSION` was left at `2`. A
  payload written by a pre-`v0.7.0` build is stamped `FORMAT_VERSION = 2`, so a
  `v0.7.0` reader accepted it (`has_valid_magic` passed) and then decoded it with
  the *wrong* evaluation points — producing corrupted output rather than an error.
  Bumped `FORMAT_VERSION` to `3` so older payloads are now rejected loudly by both
  `has_valid_magic` and `from_bytes`. There is no in-place migration path
  (re-encode from source media).

- **OpenTimestamps verification now fails closed.** `parse_verify_response`
  previously defaulted `verified` to `true` whenever the endpoint returned an
  HTTP 200 that carried no explicit `verified` / `status` / `success` field — an
  error-shaped body (e.g. `{"error": "not found"}`) or any non-JSON plain-text
  response would be reported as a confirmed on-chain attestation. The parser now
  requires an *affirmative* success signal; ambiguous or non-JSON responses
  report `verified: false`. Added `parse_verify_response` tests pinning the
  fail-closed behavior.

- **`verify --bits auto` canonicalizes audio with the audio mask.** Auto LSB
  detection for `lsb_audio` routed through the video carrier-binding path, so
  public-key–confirmed detection silently failed for audio and fell back to the
  first magic-matching strength. `verify_extracted_bits` now takes the real
  `stego_type` and canonicalizes with the matching low-bit mask.

- Removed dead `candidate_has_valid_signature` / `has_signature_payload` helpers
  (superseded by `verify_extracted_bits`) — clears unused-function build
  warnings from `cargo build --all-targets`.

- **Doc/CI accuracy sweep.** The test-count badge and every test summary
  (`README.md`, `AGENTS.md`, per-crate `README.md`/`AGENTS.md`, `docs/README.md`,
  `docs/getting-started.md`, `docs/contributing.md`) drifted from the real
  count — 311 claimed versus 431 actually passing (core 375 = 262 unit + 113
  integration, CLI 31, dashboard 23, gst 2). The CI badge job counted
  `#[test]` attributes with `grep`, which misses `#[tokio::test]` and
  macro-generated tests, so it could never converge on the real number. It now
  sums `cargo test --workspace` result lines. Also fixed the stale CLI
  subcommand count (13, including `ots`) and the `run.sh` info text.

### Added

- **Generic packet transform pipeline (`PKT-004` slice).** New
  `steganographer-core::transforms` applies opt-in DEFLATE compression,
  ChaCha20-Poly1305 AEAD encryption, and chunked Reed-Solomon error correction
  to a generic packet body, records the ordered `TransformDescriptor`s in the
  envelope, and sets the `FLAG_COMPRESSED` / `FLAG_ENCRYPTED` /
  `FLAG_ERROR_CORRECTED` locator flags. The AEAD ciphertext is bound to the
  packet identity (id + kind + length) as associated data and seeded with the
  packet nonce, so a fresh packet never reuses a nonce. Chunked RS lifts the
  255-symbol codeword ceiling so arbitrary payloads are covered, and
  compression is recorded only when it actually shrinks the payload.
  `encode --compress/--encrypt/--ecc` and `decode --decrypt` now round-trip
  transformed generic packets; unknown critical transforms and missing
  decryption keys fail closed.
- **Argon2id password-based key derivation (`PKT-007`).** New
  `steganographer-core::password` module stretches human-chosen passwords with
  Argon2id (RFC 9106) into a high-entropy master secret, then reuses the
  existing domain-separated BLAKE3 `kdf::derive_all` for the signing/encryption/
  embedding keys. Defaults are OWASP minimums (19 MiB, 2 iterations, 1 lane);
  `Argon2Params::validate` enforces the algorithmic floor while
  `meets_recommendation` exposes the stronger policy floor. The `derive` CLI
  command gains `--password` / `--password-file` / `--password-stdin` plus
  `--salt` / `--argon2-memory` / `--argon2-iterations` / `--argon2-parallelism`,
  and warns when parameters fall below the recommendation.
- `multi_frame::reconstruct` now validates that shards form a complete,
  non-duplicated n-of-n cover (unique in-range `shard_index`, consistent
  `total_shards`) and XORs in canonical shard order, so a duplicate/missing
  shard is a clear error rather than a silent XOR-to-garbage. The module
  docstring was corrected: it is XOR n-of-n sharing, **not** Shamir's Secret
  Sharing (there is no `k < n` threshold recovery).
- `error_correction` tests `alpha_is_primitive` and
  `evaluation_points_are_distinct_at_max_length` — guard against `ALPHA` ever
  regressing to a non-primitive element (its multiplicative order must be exactly
  255). `round_trip_at_real_payload_size` pins the 104-byte signature payload
  that broke when `ALPHA` was non-primitive.
- `crypto` tests `stale_format_version_payload_is_rejected` and
  `current_format_version_is_accepted` — tripwire ensuring a stale-version payload
  is rejected and the current version accepted.

## [0.7.0] — 2026-07-30

### Added

- **OpenTimestamps attestation (opt-in).** New `steganographer-core` OTS module
  (`OTSClient`, `OtsConfig`, `ots_handler`) anchors BLAKE3 Merkle roots to the
  Bitcoin or Ethereum blockchain via the OpenTimestamps REST API, giving every
  signed stego segment an independently verifiable "this existed at time T"
  proof that is orthogonal to the Ed25519/secp256k1 authorship signature. OTS
  is disabled by default and degrades gracefully — an unreachable calendar
  server reports `unavailable` (HTTP 503) and never blocks the stego pipeline.
- **`ots` CLI command group** — `steganographer ots stamp [--method bitcoin|ethereum]`
  and `steganographer ots verify` submit a digest to a calendar server, persist
  the returned `.ots` proof under the configured `proof_dir`, and verify proofs
  later. Both support `--format plain|json` output.
- **Dashboard OTS endpoints** — `GET /ots/status`, `POST /ots/stamp`, and
  `POST /ots/verify` expose the OTS client to the web UI, backed by
  `static/js/ots.js` and a live status panel. The dashboard defaults to
  disabled until a config enables it.
- **Packet envelope OTS extension fields** — `FIELD_OTS_DIGEST` (128),
  `FIELD_OTS_METHOD` (129), and `FIELD_OTS_TIMESTAMP_HEX` (130) carry a small
  attestation reference in the TLV envelope so verifiers can display the
  on-chain timestamp without re-fetching the full `.ots` proof. The full proof
  is never embedded in carrier media.
- **OTS metrics and info-bar indicator** — `StegoMetrics` now tracks
  `ots_proofs_generated`, `ots_verifications_passed/failed`, and the last
  attestation Unix timestamp; the info bar can render an `OTS` badge when
  stamping is active.
- **OTS guide** — `docs/ots-integration.md` documents the trust model, REST
  flow, graceful-degradation guarantees, and CLI/dashboard usage.
- Opt-in generic packet v1 alpha with a fixed 32-byte public locator, bounded
  canonical TLV envelope, CRC32C corruption filter, content digest, typed
  limits/errors, and legacy `SignaturePayloadCodec`.
- Shared carrier descriptors, `EmbeddingConfig`, checked capacity reports, and
  a generic sequential spatial-LSB embed/extract contract.
- `encode --payload-file` / `--payload-text` and the new `decode` command for
  digest-validated generic PNG/raw RGB payload round-trips at one through four
  LSBs. Legacy signed-carrier encoding remains the default.
- Format-aware offline media I/O, deterministic embedding-key flags/files,
  auto-probed verify bit strength, raw RGB dimensions, and combined-analysis
  JSON details.
- Declared Rust 1.88 MSRV CI job and the repository MIT `LICENSE` artifact.

### Changed

- Reed-Solomon decoding now uses 255 distinct GF(2^8) evaluation points and a
  bounded Berlekamp-Welch solver. Active tests cover zero through four symbol
  errors; uncorrectable codewords fail instead of returning best-effort bytes.
- Offline encode/verify inherits payload transforms and keys from configuration
  when the CLI does not override them.
- WAV output preserves its source channel/rate/sample specification, capacity
  uses decoded carrier units, and DCT uses its canonical core implementation.

### Fixed

- Carrier signatures are computed over kernel-canonical bytes so post-embedding
  verification can reproduce the signed carrier digest.
- Spatial LSB output to lossy JPEG and PCM LSB output to lossy audio extensions
  are rejected.
- Audio/spread encode and verify now use the same resolved embedding key.
- Verify no longer hard-codes one LSB, DCT no longer stops at a CLI stub, and
  JSON tests assert exact `valid` status instead of matching `"invalid"`.

## [0.4.0] — 2026-07-23

### Added

- **Key revocation CLI command** — `steganographer revoke --public-key <hex>` adds a
  public key to a JSON revoked-keys list (`keys/revoked.json` by default). The verify
  command can check this list to warn about revoked signing identities. Implements the
  minimum viable key lifecycle system from the Strategic findings.
- **cargo-release workflow** — `release.toml` config for automated version bumps,
  CHANGELOG section moves, tagging, and pushing via `cargo release`.
- **Live test-count badge** — CI job counts `#[test]` attributes and auto-updates the
  README badge on every push to main. Prevents future count drift.
- **`revoke` subcommand** — 11th CLI subcommand (was 10).

### Changed

- RS decode Chien search and Forney algorithm updated to use `alpha^pos` convention
  (matching the evaluation-based code's DFT syndromes). Single-error correction remains
  the reliable path; multi-error BM needs syndrome convention fix (2 tests `#[ignore]`d).

### Fixed

- BM multi-error debug output removed; tests properly `#[ignore]`d with explanation.

## [0.3.0] — 2026-07-23

### Added

- **Berlekamp-Massey RS decoder infrastructure** — `error_correction.rs` now includes
  proper syndrome computation, Berlekamp-Massey algorithm, Chien search, and Forney
  algorithm functions. Single-error correction works via brute-force (reliable for
  small steganographic payloads); multi-error correction via BM is implemented but
  needs convention fixes for the non-systematic evaluation code (2 tests `#[ignore]`d).
- **Live pipeline `--signing-key` option** — `steganographer video --signing-key <path>`
  and `steganographer audio --signing-key <path>` now accept a persistent Ed25519 signing
  key file instead of generating an ephemeral keypair per run. Enables reproducible
  verification across sessions.
- **Fuzz CI job** — Nightly fuzz job in CI (`.github/workflows/ci.yml`) running all 3
  fuzz targets for 60s each with `cargo +nightly fuzz`.
- **GF(2^8) polynomial helpers** — `gf_poly_eval`, `gf_poly_mul`, `gf_div` functions
  added to `error_correction.rs` for the BM/Chien/Forney pipeline.
- **4 new error correction tests** — `test_two_error_correction`, `test_two_errors_with_higher_parity`
  (ignored — BM convention fix needed), `test_gf_poly_eval`, `test_gf_poly_mul`.
- **C2PA interoperability decision** — Recorded in `docs/architecture.md`: deferred,
  monitor but do not implement. Rationale: C2PA operates on files, not live streams.
  Revisit when C2PA adds a streaming profile.
- **Dashboard DOCS array** — `key-rotation.md` added to the embedded docs list so the
  in-dashboard documentation viewer can serve it.

### Changed

- RS decode now uses syndrome-based error detection (polynomial-time) before falling
  back to brute-force correction, rather than pure brute-force.
- Test badge updated to 286 (was 282).
- Doc file count updated to 18 in all references (was 17 — `key-rotation.md` added
  in v0.2.0 but missed in some count references).

### Fixed

- **Stale doc counts** — All test counts, module counts, and subcommand counts
  corrected across every file (zero stale references remaining per comprehensive grep).

## [0.2.0] — 2026-07-22

### Security (Critical)

- **Key purge + history scrub** — Removed a real Ed25519 private key (`keys/daf.key`) that was committed to this public repository since v0.1.0. Scrubbed from git history via `git filter-repo`. Key rotated; old key revoked. See [`docs/key-rotation.md`](docs/key-rotation.md).
- **.gitignore hardened** — Added `keys/`, `output/`, `*.key`, `*.pub` to `.gitignore`, mirroring the existing `.dockerignore` exclusions that were missing from `.gitignore`.
- **Secret-scanning CI gate** — Added `gitleaks` to CI (`.github/workflows/ci.yml`) with custom `.gitleaks.toml` config. Any future key/credential leak fails CI.
- **Dashboard authentication** — Default bind changed from `0.0.0.0` to `127.0.0.1`. Added `--host` flag for explicit `0.0.0.0` opt-in. Added `--auth-token` flag with Bearer token auth on POST routes (`/api/config`, `/api/metrics/reset`) using constant-time comparison via `subtle` crate. Replaced `CorsLayer::permissive()` with restrictive CORS.
- **Cargo.lock committed** — For reproducible builds and dependency auditability (was gitignored).
- **Dockerfile non-root** — Container now runs as `stego` user instead of root. Dashboard CMD uses `--host 127.0.0.1`.

### Security (Major crypto fixes)

- **AEAD nonce reuse fixed** — `encryption.rs` now prepends a 4-byte random salt to the ChaCha20-Poly1305 nonce derivation. Each invocation gets a unique nonce even with identical `frame_index` (prevents key+nonce reuse in batch encodes). Ciphertext format: `salt(4) || ciphertext || tag`.
- **CLI spread-spectrum key wiring fixed** — `embed_ss_bit` now uses the secret key from `SpreadSpectrumVideo` to seed the PN-sequence RNG (was ignored, breaking round-trip verification and confidentiality).
- **RS decode DoS bound** — `error_correction::decode()` now caps `parity_count` (≤16) and `data_len` (≤65536) symmetric with `encode()`, preventing CPU-exhaustion via crafted media.
- **`unreachable!()` removed** — `gf_inv` now returns 0 with an error log instead of panicking (defense-in-depth).
- **`dct_video` CLI stub fixed** — Now returns a clear error instead of silently falling back to LSB embedding (core library `DctVideo` is correct; CLI raw-byte path was a stub).
- **Config bits validation** — Added `LsbVideo::try_new()` / `LsbAudio::try_new()` returning `Result`. CLI callers now validate bits from config/CLI args instead of panicking.
- **lsb_audio verify** — Now `bail!`s on missing `--embedding-key` instead of silently using a zero key.
- **KDF context dedup** — `cmd_encode.rs` now calls `kdf::derive_all()` instead of hand-copying context strings.

### Added

- **CLI integration tests** — 10 integration tests in `steganographer-cli/tests/cli_integration_tests.rs` covering keygen, lsb_video/audio round-trips, encryption, ECC, spread-spectrum, dct_video error, config check, unsigned media verify, and info capacity. First test coverage for the CLI crate.
- **`--master-secret-file` / `--master-secret-stdin`** — Safer alternatives to `--master-secret` for the `derive` command (secrets no longer visible in shell history / `ps`).
- **Entropy warning** — `derive` command warns if master secret is < 32 bytes (BLAKE3 derive_key is not a slow KDF).
- **Public key visibility** — Live video/audio pipelines now print the signing public key via `eprintln!` (unconditional stderr) so `--quiet` doesn't hide it.
- **Fuzz harness** — Proper `cargo-fuzz` targets with `Cargo.toml` and `fuzz_target!` macros: `fuzz_lsb_video_extract`, `fuzz_payload_from_bytes`, `fuzz_rs_decode` (regression test for the DoS finding).
- **`rust-toolchain.toml`** — Pins stable Rust + clippy + rustfmt for deterministic builds.
- **`SpreadSpectrumVideo::key()`** — Public accessor for the secret key (used by CLI embed/verify).
- **`LsbVideo::try_new()` / `LsbAudio::try_new()`** — Fallible constructors for untrusted input.
- **Nonce-reuse regression test** — `test_same_frame_index_different_salt` verifies the fix.
- **Key rotation documentation** — `docs/key-rotation.md` with incident report, new public key, and revocation notice.
- **CLI reference for `analyze` and `derive`** — Full documentation in `docs/cli-reference.md` including Mermaid diagram, options, examples, and security notes.

### Changed

- **CLI subcommands** — 10 (was 6): added `info`, `analyze`, `derive`, `config`.
- **Core modules** — 21 (was 16): added `adaptive`, `hash_chain`, `kdf`, `mdct_audio`, `steganalysis`.
- **Test count** — 282 (was 132 at v0.1.0): 171 core unit + 76 core integration + 10 CLI integration + 23 dashboard + 1 GStreamer + 1 doc-test.
- **`deny.toml`** — Advisory policy now matches its comment: `deny = ["medium", "high", "critical"]`.
- **`docs/threat-model.md`** — T2 "Residual Risk: None" replaced with scoped statement acknowledging T4 (signature stripping).
- **`docs/platforms.md`** — Windows section relabeled "Community-Supported — No CI Coverage".
- **`docs/roadmap.md`** — Real Gantt dates (2026-2027), correct test count, correct subcommand count.
- **Dockerfile example** — `docs/platforms.md` Docker example synced with real Dockerfile (rust:1.97, pkg-config, /build workdir).

### Fixed

- **`--quiet` hiding public key** — Live pipelines now print the public key to stderr unconditionally.
- **`deny.toml` policy mismatch** — Advisory severity policy now enforces what the comment claims.
- **Threat model contradiction** — T2/T4 residual risk statements reconciled.
- **Fuzz harness** — Was not a runnable cargo-fuzz target; now properly structured with `Cargo.toml` and `fuzz_target!` macros.
- **Stale documentation** — All test counts, module counts, and subcommand counts updated across README.md, AGENTS.md, per-crate AGENTS.md files, roadmap.md, and cli-reference.md.

## [0.1.0] — 2026-03-06

### Added

- **LSB Video Steganography** — sequential embedding with 1–4 bits, length prefix, round-trip extraction
- **LSB Audio Steganography** — keyed PRNG permutation (ChaCha8), 1–4 bits, length prefix extraction
- **Text Overlay** — built-in 8×8 bitmap font, configurable position/color/scale
- **Info Bar** — QR code, Code-128 barcode, and metadata overlay that survives compression
- **BLAKE3 + Ed25519 Signing** — per-frame hashing and signing with 104-byte payload
- **Pluggable Signing Backends** — Ed25519 and Ethereum/secp256k1 via `SignerBackend` trait
- **GStreamer Integration** — real-time processing via AppSink/AppSrc (V4L2, AVFoundation, PulseAudio, PipeWire)
- **CLI** — 6 subcommands: `video`, `audio`, `encode`, `verify`, `keygen`, `dashboard`
- **Configuration** — full TOML config with modular pipeline chains
- **Web Dashboard** — three-tab GUI (Video | Audio | Docs) with real-time encode/decode verification
- **Audio Dashboard** — microphone capture with waveform/spectrum visualization, WAV recording
- **Documentation Viewer** — browse all project docs in-dashboard with syntax highlighting
- **MetaMask / Ethereum** — browser-based `personal_sign` via EIP-1193
- **Dynamic LSB Configuration** — live config changes via `POST /api/config`
- **QR Data Matrix Overlay** — 13×13 binary grid encoding metadata with timestamp
- **Keyboard Shortcuts** — Space=camera, R=record, 1/2/3=tabs, +/−=LSB, E=export
- **Session Export** — download session report as JSON
- **Copy-to-Clipboard** — buttons on hash and signature fields
- **Help Tooltips** — custom JavaScript tooltips
- **Session Stats API** — `GET /api/session` endpoint
- **Auto-Start Camera** — `?autostart=1` URL parameter
- **Footer Verified Counter** — live ✅ X / ❌ Y ratio
- **132 Tests** — 56 core unit + 58 core integration + 12 dashboard + 1 GStreamer + 5 Ethereum (feature-gated)
- **17 Documentation Files** — architecture, cryptography, algorithms, CLI, config, GStreamer, platforms, API, security, threat model, theory, contributing, roadmap, FAQ

[Unreleased]: https://github.com/docxology/steganographer/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/docxology/steganographer/releases/tag/v0.4.0
[0.3.0]: https://github.com/docxology/steganographer/releases/tag/v0.3.0
[0.2.0]: https://github.com/docxology/steganographer/releases/tag/v0.2.0
[0.1.0]: https://github.com/docxology/steganographer/releases/tag/v0.1.0
