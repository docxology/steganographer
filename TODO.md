# TODO

Scoped improvements and future plans.
See [docs/roadmap.md](docs/roadmap.md) for the full release timeline.

> **Audit note (2026-07-22):** This file was reconciled against a full deep
> review + RedTeam adversarial analysis (3 code/infra exploration passes + an
> 8-agent strategic red-team). Every item below cites file:line evidence.
> Severity is ranked by impact, matching the convention in
> [docs/threat-model.md](docs/threat-model.md).

---

## 🚨 CRITICAL — Security Incidents (act on these first, independent of everything else in this file)

- [ ] **Real Ed25519 private key committed to this public repo** — `keys/daf.key`
  (`keys/daf.pub` is its matching public key; independently re-derived and
  confirmed to match byte-for-byte during this audit). Introduced in the
  very first commit (`5dcb2e2`, "Release v0.1.0", 2026-03-08) and **still
  tracked at HEAD today**. File mode is `644` (world-readable), contradicting
  this project's own documented 0600 convention. Not the documented example
  path (`docs/cli-reference.md` uses `keys/session-001.key` / `keys/stego.key`)
  — this looks like a real operator key, not a fixture.
  **Root cause:** `.dockerignore` explicitly excludes `keys/`, `output/`,
  `*.key`, `*.pub` as "sensitive" (`.dockerignore:19-23`), but `.gitignore`
  (`.gitignore:1-9`) has no equivalent rule — Docker builds were protected,
  git commits were not.
  **Action:** rotate/revoke this key independently of any other work here;
  scrub it from git history (`git filter-repo` or BFG, then force-push +
  notify any clones/forks); add `keys/`, `*.key` to `.gitignore`; add a
  pre-commit or CI secret-scanning gate (e.g. `gitleaks`) so this class of
  leak fails closed next time, since nothing currently would have caught it.
- [ ] **Regenerable build artifacts committed alongside the key** —
  `output/demo_frame.rgb`, `output/demo_frame_signed.rgb` — same root cause
  (`output/` is in `.dockerignore` but not `.gitignore`). Remove from git,
  add `output/` to `.gitignore`, regenerate via `run.sh` on demand.
- [ ] **No key lifecycle model for the Ed25519 signing identity** — this is
  the systemic gap the `daf.key` leak exposes, not a one-off mistake. There
  is no rotation, revocation, or expiry mechanism anywhere in code or docs
  for the *signing* key (the existing "session key rotation" in the
  Implemented list below is the unrelated LSB *embedding* KDF key — see
  `kdf.rs`). `docs/security.md` and `docs/threat-model.md` only say to
  "consider" rotation/HSM as future work. Every RedTeam agent independently
  converged on this as the most damaging finding in the whole review: a
  provenance tool that cannot demonstrate key hygiene in its own repo has
  no standing to vouch for third-party authenticity. Design and ship a
  minimal revocation mechanism (even a simple published revoked-keys list)
  before extending the roadmap's PQ/X.509 items (see Strategic section).
- [ ] **Live dashboard has zero authentication on any route, including a
  config-mutating endpoint** — `steganographer-dashboard/src/lib.rs:155`
  (`CorsLayer::permissive()`), `:162` (binds `0.0.0.0:{port}`, not
  `127.0.0.1`), and every route in the router (`:139-154`) — `POST
  /api/config`, both encode/decode websockets, and metrics-reset — has no
  auth middleware, token check, or session gate of any kind. Combined with
  the `0.0.0.0` bind, anyone on the same network (or, if port-forwarded,
  the internet) can reconfigure a running signer or pull metrics with no
  credential. This directly undermines the tool's own tamper-evidence
  mission — an unauthenticated control-plane sitting next to the signing
  identity is an attack surface the project's own threat model doesn't
  cover. Add at minimum a shared-secret/token check on mutating routes and
  default-bind to `127.0.0.1`, requiring an explicit opt-in flag for
  `0.0.0.0`.

---

## 🔴 MAJOR — Cryptographic / Functional Breaks

- [ ] **AEAD nonce reuse across repeated/batch encodes with a fixed key** —
  `steganographer-core/src/encryption.rs:97-101` (`derive_nonce`) derives
  the 12-byte ChaCha20-Poly1305 nonce purely from `frame_index`. The
  single-file `encode` path hardcodes `frame_index = 0`
  (`steganographer-cli/src/cmd_encode.rs:272,278`), and `verify --decrypt`
  decrypts with `frame_index = 0` too (`cmd_verify.rs:182`). The doc
  comment's invariant ("each frame index is unique per key") is never
  enforced across CLI invocations. `batch_process()`
  (`cmd_encode.rs:991-1035`) — a documented, normal workflow — calls
  `encode` once per file with one shared `--encryption-key`, guaranteeing
  nonce=0 reuse under the same key for every file in the batch. Reused
  key+nonce with ChaCha20-Poly1305 allows plaintext-XOR recovery and
  universal auth-tag forgery — a full break of confidentiality and
  authenticity for any batch-encrypted run. **Fix:** derive nonces from a
  per-invocation random value or a monotonic counter persisted per key,
  never a constant.
- [ ] **CLI spread-spectrum embedding never uses the secret key it prints** —
  `steganographer-cli/src/cmd_encode.rs:565-594` (`embed_ss_bit`) seeds its
  PN-sequence RNG from `frame_index`/`bit_pos` only — the `_ss` parameter
  holding the actual key is unused (underscore-prefixed). `extract_ss_bit`
  in `cmd_verify.rs:478-501` seeds with the key XORed in. These are
  different formulas: the embed side is fully public and reconstructable
  by anyone without the key (defeating the confidentiality property
  documented in `spread_spectrum.rs:13-15`), **and** `verify
  --stego-type spread_spectrum_video --embedding-key <printed key>` will
  not correctly recover the payload, because verify's extraction doesn't
  match what was actually embedded. This is simultaneously a security hole
  and a broken round-trip, and it has zero test coverage (see below), which
  is how it went unnoticed.
- [ ] **Unbounded Reed-Solomon decode brute force — DoS via crafted media or
  large `--ecc-parity`** — `encode()` bounds `parity_count <= 16`
  (`error_correction.rs:78-79`), but `decode()` has no equivalent bound
  (confirmed: no check before the `for pos in 0..n { for error_val in
  1u8..=255 { ... } }` loop at `error_correction.rs:191-215`, an
  `O(n · 255 · k²)` operation). `cmd_verify.rs`'s `extract_raw_lsb_video`
  only caps the attacker-controlled length prefix at 100,000 bytes
  (`cmd_verify.rs:347`), so a crafted image whose fake length prefix
  approaches that ceiling, run through `verify --ecc` (a normal documented
  flag), drives the brute-force loop to `k≈100,000` — an effectively
  unbounded CPU-exhaustion DoS on any automated verification pipeline
  processing untrusted media. **Fix:** cap `parity_count`/`data_len` in
  `decode()` symmetrically to `encode()`, and validate the length prefix
  against a much tighter realistic ceiling before invoking ECC.
- [ ] **`dct_video` CLI stego type silently falls back to plain LSB and can
  never verify** — `cmd_encode.rs:596-639` (`embed_raw_dct_video` /
  `embed_dct_bit`)'s own comment admits: *"Simplified direct DCT embedding
  for raw bytes. Falls back to LSB for raw byte case."* — none of the real
  DCT/quantization logic in `steganographer-core/src/dct_video.rs` (which
  is correctly implemented and tested) is used. `cmd_verify.rs:316-321`
  then explicitly returns `Ok(None)` for `dct_video` — *"DCT extraction of
  raw bytes is not yet implemented for arbitrary payloads."* The
  "JPEG/compression-resistant embedding" claimed in the module doc, README,
  and `main.rs:16-18` CLI help text is not what happens when a user runs
  `steganographer encode --stego-type dct_video`; verification of that
  path can never succeed. **Fix:** either wire the CLI raw-byte path
  through the real `DctVideo` implementation, or remove/relabel the CLI
  flag until it is.
- [ ] **Zero automated test coverage for `steganographer-cli`** — no
  `tests/` directory, no `#[cfg(test)]` modules anywhere under
  `steganographer-cli/src/`, versus 266 tests in `steganographer-core`.
  Every CLI-layer bug above (nonce reuse, broken spread-spectrum, the
  `dct_video` stub) is exactly the kind of divergence a hand-rolled
  reimplementation produces when nothing exercises it. Add integration
  tests that round-trip `encode`→`verify` for every `--stego-type` ×
  `--encrypt`/`--ecc`/`--spread` combination.
- [ ] **Unvalidated config `bits` field panics the live pipeline** —
  `steganographer-core/src/lsb_video.rs:23` and `lsb_audio.rs:26`
  (`assert!((1..=4).contains(&bits), …)`) are reachable from
  `steganographer-cli/src/cmd_video.rs:153` / `cmd_audio.rs:94`, fed by
  `config.rs:169-171`'s `LsbSignatureConfig.bits: u8` which serde accepts
  with no range validation, and from `encode`'s `--bits` CLI flag
  (`cmd_encode.rs:1093`) with no CLI-side check either. A TOML config with
  `bits = 0` or `bits = 8` (typo, copy-paste from elsewhere) crashes the
  whole live capture/signing process instead of returning a graceful
  `anyhow` error — unacceptable for an unattended pipeline. **Fix:**
  validate `bits` at config-load and CLI-parse time, return `Result`
  instead of panicking in the constructors.

---

## 🟡 MEDIUM

- [ ] **No slow-KDF / salt for master-secret derivation** — `kdf.rs:38-51`
  (`derive_signing_key`/`derive_encryption_key`/`derive_embedding_key`) are
  single-pass, unsalted `blake3::derive_key` calls — appropriate for
  splitting an already-high-entropy secret, but the CLI exposes this
  directly via `steganographer derive --master-secret <hex>`
  (`cmd_encode.rs:110-166`) with no entropy guidance. A memorable
  passphrase hex-encoded here is brute-forceable at BLAKE3 speed rather
  than facing Argon2/scrypt-class resistance. Add a guard or docs warning,
  or route through a deliberately slow KDF when the secret isn't already
  high-entropy key material.
- [ ] **Inconsistent failure mode for a missing `--embedding-key`** —
  `cmd_verify.rs:292-300` silently substitutes an all-zero key for
  `lsb_audio` when `--embedding-key` is omitted, while the
  `spread_spectrum_video` branch three lines down (`:308-310`) correctly
  `bail!`s with a clear error. Make `lsb_audio` fail the same way instead
  of producing a confusing silent "no signature found."
- [ ] **`--quiet` can hide the only copy of a live session's public key** —
  `cmd_video.rs:55-61` / `cmd_audio.rs:33-37` generate a fresh ephemeral
  Ed25519 keypair per run (no `--signing-key` option exists for the live
  pipeline) and only ever print the public key via `log::info!`. Passing
  the global `--quiet` flag (`main.rs:213-224`) sets logging to `Off` with
  no `println!` fallback — the stream becomes silently unverifiable.
  Print the public key unconditionally on stdout/stderr regardless of log
  level.
- [ ] **`AGENTS.md` doc drift understates the crypto surface** —
  `steganographer-core/src/AGENTS.md:1-77` documents 10 of 19 actual
  modules, omitting `adaptive`, `dct_video`, `encryption`,
  `error_correction`, `hash_chain`, `kdf`, `mdct_audio`, `multi_frame`,
  `spread_spectrum`, `steganalysis` — all present in `lib.rs:24-59`.
  `steganographer-cli/AGENTS.md:9-26` and `steganographer-cli/README.md:9-28`
  describe "6 subcommands," omitting `info`, `analyze`, `derive`, `config`
  (4 of the actual 10 `Commands` variants in `main.rs`). An agent or
  engineer onboarding from these files would materially misjudge the
  crate's encryption/ECC/KDF/hash-chain surface.
- [ ] **Duplicated KDF context strings** — `cmd_encode.rs:117-119`
  hand-copies the three context-string literals from `kdf.rs:23-25`
  instead of calling `steganographer_core::kdf::derive_all()`. They match
  today but nothing enforces it; a future change to `kdf.rs`'s contexts
  would silently desync CLI-derived keys from the library's. Call the
  library function directly.
- [ ] **`deny.toml` advisory policy doesn't match its own comment** — the
  documented severity policy in `deny.toml` isn't actually what's
  configured; tighten `[advisories]` to `deny` for the severities the
  comment claims are enforced.
- [ ] **`Cargo.lock` is gitignored** (`.gitignore:2`) despite the workspace
  shipping a CLI binary and a Docker image — commit it for reproducible
  builds and auditability of exactly which dependency versions ship in a
  given release.
- [ ] **`docs/threat-model.md` internal contradiction** — T2 states
  "Residual Risk: None" while T4, in the same document, admits signature
  stripping is possible. Reconcile the two so the document doesn't
  overstate the guarantee in one place and correctly scope it in another.
- [ ] **Fuzz harness isn't wired to cargo-fuzz or CI** —
  `steganographer-core/fuzz/fuzz_targets.rs` has no `Cargo.toml`, no
  `fuzz_target!` macros, and `#[cfg(fuzzing)]` is never set — it is not a
  runnable cargo-fuzz target despite `TODO.md`'s Implemented list crediting
  "Fuzz targets," and it never runs in `.github/workflows/ci.yml`. Either
  convert it into a real `cargo-fuzz` target and add a CI job (even a
  short timed run), or stop claiming it as implemented.
- [ ] **CI has no Windows job despite docs claiming Windows support** —
  `.github/workflows/ci.yml` has no Windows matrix entry, while
  `docs/platforms.md` documents Windows build/test support (labeled
  "Experimental" in one place, unqualified in another — also worth
  reconciling). Add a Windows CI job or soften the doc claim.
- [ ] **Dockerfile runs as root; base image pinned by floating tag** — no
  `USER` directive, and the base image is referenced by a mutable tag
  rather than a digest. `docs/platforms.md`'s own embedded Dockerfile
  example diverges from the real one (different Rust version, no
  multi-stage build) — sync the two and add a non-root `USER`.

---

## 🟢 MINOR — Polish & Documentation Accuracy

- [ ] **Stale test counts, three different numbers in three places** —
  `TODO.md` (this file, prior version) claimed 271; actual `#[test]` count
  across the workspace is **266**; `README.md` and root `AGENTS.md` still
  say **187** (the stalest of the three). The README's test badge is a
  static image URL, not live-generated, so it will keep drifting silently.
  Point it at a generated badge or a CI-computed count instead of a
  hand-edited number.
- [ ] **Stale CLI subcommand count** — README's architecture diagram and
  root `AGENTS.md` both say "8 subcommands"; `main.rs`'s `Commands` enum
  actually has **10** (adds `Analyze`, `Derive`). `docs/cli-reference.md`'s
  own Mermaid diagram also only shows 8 and doesn't document `analyze` or
  `derive`, despite this file's own "Implemented" section already crediting
  both commands.
- [ ] **Stale module count in `AGENTS.md`** — claims the core crate has "16
  modules"; actual `steganographer-core/src/*.rs` is 21 files (20 modules +
  `lib.rs`). This is itself one of the Release Acceptance Criteria checkbox
  items below, and it is currently failing.
- [ ] **`docs/roadmap.md` has fictional/aspirational Gantt dates** — the
  timeline shows v0.1.0 "done" 2024-01→06, v0.2.0 "active" 2024-06→12,
  v0.3.0 2025-01→06, v1.0.0 "Production Ready" 2025-06→12 — all now in the
  past relative to today (2026-07-22), yet the actual v0.1.0 release was
  2026-03-06 per `CHANGELOG.md` and v0.2.0 is still unreleased. The
  document's own bottom-of-page "132 Tests (Current State v0.1.0)" line was
  never updated despite ~40 later "(NEW)" bullets added since. Replace the
  placeholder Gantt with real dates or remove it until real target dates
  exist.
- [ ] **`rand` version fragmentation** — root `Cargo.toml:29` pins
  `rand = "0.8"`, but `Cargo.lock` resolves both `rand 0.8.6` and `rand
  0.9.4` transitively (via `qrcode`/other deps), alongside three different
  `getrandom` versions. No known CVE in the resolved versions, but
  consolidate to one major line. (`ed25519-dalek` 2.2.0, `chacha20poly1305`
  0.10.1, `blake3` 1.8.5, `curve25519-dalek` 4.1.3, `k256` 0.13.4 all look
  current — no action needed there.)
- [ ] **Latent `unreachable!()` in `gf_inv`** —
  `error_correction.rs:38-48` is safe under current GF(2^8) math for
  `a != 0`, but any future change to `gf_mul`/`ALPHA` that broke the field
  arithmetic would turn a silent math bug into a hard panic reachable from
  `decode()`. Informational only — no exploit path found — but replace with
  a proper `Result` return for defense-in-depth.
- [ ] **Secrets passed as CLI arguments land in shell history / `ps`** —
  `derive --master-secret <hex>` and any future `--encryption-key <hex>`
  usage. Key *files* are correctly handled with 0600 perms
  (`cmd_encode.rs:88-95,154-159`); the plaintext-on-argv path has no
  equivalent protection. Prefer `--master-secret-file` / stdin / env var
  over a raw CLI argument for secret material.
- [ ] **Local build note (environment-specific, not necessarily a repo
  defect):** `cargo test --workspace` fails to build in at least one
  sandboxed environment because `built@0.8.1` requires rustc 1.87 and
  `image@0.25.10` requires 1.88, while only 1.86.0 was present. CI uses
  `dtolnay/rust-toolchain@stable` (always-latest), so this may be
  environment-specific — but consider pinning an explicit MSRV in CI to
  catch this class of drift deterministically rather than relying on
  "whatever stable is today."

---

## 📐 Strategic — from RedTeam Adversarial Analysis

An 8-agent parallel red-team (engineers, architects, pentesters, "naive
questioner"/"devil's intern" personas) attacked the project's keystone
strategic claims, not just its code. Full methodology in
[`~/.claude/skills/RedTeam`](https://github.com/) (internal skill). Findings,
ranked by convergence and impact:

- **Key lifecycle is the load-bearing weak point, and it already failed once
  in production (8/8 agent convergence).** The cryptographic primitives
  themselves (BLAKE3 hash-then-Ed25519-sign, constant-time comparison) are
  sound, correctly-scoped engineering — `docs/security.md`/`threat-model.md`
  honestly frame the guarantee as "tamper-evident, not tamper-proof" rather
  than overselling. But the project has no operational key-hygiene process
  (rotation, revocation, secret-scanning), and the `keys/daf.key` incident is
  direct, checkable proof the gap is real, not theoretical. **Resequence the
  backlog:** ship basic key lifecycle (rotation + a revocation mechanism +
  CI secret-scanning) before investing further in "Post-quantum signatures"
  and "Certificate chain support" below — those add cryptographic
  sophistication on top of a foundation that just demonstrated it can't keep
  a single Ed25519 key out of git.
- **The headline "survives re-encoding/transcoding/AI-upscaling" pitch
  outruns what's actually shipped.** `docs/steganography-theory.md:271`
  itself states the *current default* pipeline is intra-frame LSB, "which
  maximizes embedding capacity at the cost of robustness" — the genuinely
  robust approach (a learned watermarking encoder resistant to re-encoding/
  cropping/AI upscaling, in the spirit of Meta's Video Seal) is explicitly
  roadmap-only. The narrower framing in `security.md`/`threat-model.md`
  ("verify these are the exact bytes signed at capture time") is honest and
  defensible; the marketing-facing framing elsewhere leads with threats
  (transcoding, AI upscaling) that the shipped default doesn't yet resist.
  Narrow the leading claim to match the default pipeline, or move the
  robust method up the roadmap before leading with it in messaging.
- **Shipping an unauthenticated live dashboard next to a signing identity
  is a self-inflicted attack surface expansion** — confirmed in the
  Critical section above (`0.0.0.0` bind, permissive CORS, no auth on any
  route). This is not a hypothetical second-order effect; it's exploitable
  today.
- **Open strategic question, not a proven flaw:** in a landscape with
  mature, industry-backed content-provenance standards (C2PA / Content
  Credentials, backed by Adobe/Google/Microsoft), what is this project's
  differentiated edge, and is re-implementing C2PA-adjacent
  tamper-evidence from scratch the right long-term bet versus
  interoperating with or emitting C2PA manifests alongside the custom
  format? Worth an explicit decision recorded in `docs/architecture.md`
  rather than left implicit.
- **Steelman, for balance:** the Reed-Solomon + adaptive-embedding-strength
  combination is genuinely solid, decades-proven coding-theory engineering
  correctly matched to the problem (bit-flip/rounding noise in LSB/DCT/MDCT
  payloads), and it's real, tested, working code — not vaporware dressed up
  in security language. The project is honestly self-scoped in its own
  threat-model prose even where its marketing overreaches; that's a real
  and uncommon strength worth preserving as the key-lifecycle and dashboard
  gaps get fixed.

---

## ✅ Release Acceptance Criteria

**Every release** — including patch and minor releases — must satisfy all of the following before merge:

### Tests

- [ ] `cargo test --workspace` — **all tests pass**, 0 failures, 0 ignored (currently 266, not 271 — see Minor findings above)
- [ ] `cargo build --workspace` — **clean build**, no warnings
- [ ] `cargo clippy --workspace` — no new warnings introduced
- [ ] Any new feature has at least one corresponding test
- [ ] Test count in documentation matches actual count across all files — **currently failing**, see Minor findings above

### Documentation

- [ ] All changed or new public APIs are documented (doc comments or `docs/*.md`)
- [ ] `README.md` accurately reflects current feature set
- [ ] `AGENTS.md` (root + per-crate) file/module counts are up to date — **currently failing**, see Minor findings above
- [ ] `docs/roadmap.md` "Implemented" list includes any new features
- [ ] `docs/api-reference.md` covers any new HTTP/WebSocket endpoints
- [ ] `docs/cli-reference.md` covers any new CLI flags or subcommands — **currently failing** (`analyze`/`derive` undocumented)
- [ ] `docs/configuration.md` covers any new TOML fields
- [ ] `docs/faq.md` is reviewed for stale answers
- [ ] `docs/threat-model.md` is updated if new attack surfaces are introduced — **currently has an internal contradiction**, see Medium findings above

### Code Quality

- [ ] No `TODO`, `FIXME`, or `HACK` comments left unresolved
- [ ] No `unwrap()` or `expect()` in production code paths (tests excepted)
- [ ] All `log::` calls use appropriate levels (`info`, `warn`, `error`, `debug`)
- [ ] No hardcoded secrets, keys, or credentials in source — **currently failing**, see Critical findings above

### Security

- [ ] Dependencies audited: `cargo audit` reports no known vulnerabilities
- [ ] New dependencies reviewed for license compatibility (MIT/Apache-2.0)
- [ ] Cryptographic code uses audited libraries only (no custom primitives)
- [ ] **New:** secret-scanning gate (e.g. `gitleaks`) runs in CI and blocks merge on any detected key/credential
- [ ] **New:** `.gitignore` mirrors `.dockerignore`'s sensitive-path exclusions (`keys/`, `output/`, `*.key`, `*.pub`)

### Build & Compatibility

- [ ] `cargo build --workspace --release` compiles without error
- [ ] Core crate builds without GStreamer (`cargo build -p steganographer-core`)
- [ ] `./run.sh` interactive menu launches successfully

---

## ✅ Implemented (v0.2.0 — unreleased)

### Security

- [x] **Payload encryption** — ChaCha20-Poly1305 AEAD (`encryption.rs`) — *note: see Major finding above re: nonce derivation for repeated/batch encodes*
- [x] **Magic header + version** — `STEG` magic (4B) + version (1B) in payload
- [x] **Constant-time hash comparison** — `subtle` crate prevents timing attacks
- [x] **Key file loading** — `key_file = "path"` in TOML config for LSB keys
- [x] **Fixed hardcoded zero-key** — Audio CLI and dashboard now use random keys
- [x] **Secure keygen** — private key files have 0600 permissions — *note: this convention was itself violated by the committed `keys/daf.key` (mode 644), see Critical findings above*
- [x] **Key derivation** — BLAKE3 `derive_key` from master secret (`kdf.rs`)
- [x] **Session key rotation** — per-session **embedding** keys from master + counter (distinct from the Ed25519 **signing** identity key, which has no rotation — see Critical findings above)
- [x] **Hash chain streaming auth** — Merkle tree for segment-level tamper detection (`hash_chain.rs`)

### Power

- [x] **Spread-spectrum steganography** — PN-sequence modulation (`spread_spectrum.rs`) — *note: the CLI's raw-byte path doesn't correctly wire in the key, see Major finding above; the core library module itself is correct and tested*
- [x] **DCT-domain embedding** — compression-resistant 8×8 DCT blocks (`dct_video.rs`) — *note: the CLI's raw-byte `dct_video` path doesn't use this and falls back to LSB, see Major finding above; the core library module itself is correct and tested*
- [x] **Reed-Solomon error correction** — GF(2^8) for payload recovery (`error_correction.rs`) — *note: `decode()` has an unbounded brute-force path, see Major finding above*
- [x] **Multi-frame signature spreading** — XOR n-of-n secret sharing (`multi_frame.rs`)
- [x] **Capacity reporting** — `steganographer info` CLI command
- [x] **Steganalysis** — chi-squared, sample-pair, RS analysis (`steganalysis.rs`)
- [x] **Combined analysis** — multi-detector summary with confidence
- [x] **Adaptive embedding** — content-aware pixel selection (`adaptive.rs`)
- [x] **Multi-frame video file support** — encode/verify multi-frame raw RGB files
- [x] **MDCT audio embedding** — frequency-domain audio steganography for MP3/AAC resistance (`mdct_audio.rs`, fully implemented with 8 tests, registered in `lib.rs:36` — reconciled out of "Upcoming," was already done)

### Flexibility

- [x] **Configurable hash algorithm** — BLAKE3, SHA-256, SHA-3 via config
- [x] **New CLI stego types** — `spread_spectrum_video`, `dct_video`
- [x] **New CLI flags** — `--encrypt`, `--decrypt`, `--ecc`, `--spread`, `--hash-algorithm`, `--signing-key`, `--embedding-key`, `--input-format`, `--dir`
- [x] **Info bar config** — `[video.stego.info_bar]` with toggleable features
- [x] **GStreamer pipeline integration** — spread_spectrum and dct as pipeline steps
- [x] **Hash algorithm in live pipelines** — cmd_video.rs and cmd_audio.rs
- [x] **Dashboard LiveConfig** — stego_type, hash_algorithm, encrypt, ecc fields
- [x] **New CLI commands** — `analyze` (chi-squared), `derive` (key derivation) — *note: undocumented in `docs/cli-reference.md` and both `AGENTS.md` files, see Medium finding above*
- [x] **Batch processing** — `--dir` flag for directory encoding — *note: this is the workflow that triggers the nonce-reuse Major finding above when combined with `--encrypt`*
- [x] **PNG/WAV format I/O** — image + hound crates for file format support
- [x] **Container format I/O** — GStreamer decodebin/encodebin for MP4/MKV/WAV (`process_video_file`, `process_audio_file`)

### Platform & Distribution

- [x] **Docker image** — multi-stage build with GStreamer runtime — *note: runs as root, floating base-image tag, see Medium finding above*
- [x] **cargo audit** — security advisory check in CI
- [x] **cargo deny** — license and vulnerability audit — *note: advisory severity policy comment doesn't match config, see Medium finding above*
- [x] **CI clippy** — lint check in CI workflow
- [x] **Shell completions** — bash/zsh/fish via clap_complete (build.rs)
- [x] **Man pages** — `steganographer.1` via clap_mangen (build.rs)
- [x] **Criterion benchmarks** — sign, LSB, spread-spectrum, DCT, audio
- [x] **Fuzz targets** — *reconciled: not actually wired to cargo-fuzz or CI, see Medium finding above — this item should be considered reopened, not done*

### Dashboard

- [x] **Mutex lock recovery** — `expect()` replaced with `.unwrap_or_else(|e| e.into_inner())`
- [x] **Dark/light theme toggle** — persisted in localStorage
- [x] **Mobile-responsive layout** — media queries for ≤768px viewport
- [x] **Frame diff viewer** — side-by-side original vs. watermarked with pixel diff (`steganographer-dashboard/src/static/app.js`: `diffViewerEnabled`, `renderDiffViewer()`; CSS block in `style.css:2345+` — reconciled out of "Upcoming," was already done)
- [x] **Historical metrics charts** — FPS, latency, verify rate over time (`app.js`: `chartFps`, `chartSignLatency`, `chartVerifyLatency`, `chartVerifyCounts`, `drawCharts()` — reconciled out of "Upcoming," was already done)
- [x] **Multi-camera support** — device selector dropdown (`index.html:109` `<select id="camera-select">`, `navigator.mediaDevices.enumerateDevices()` wired into `getUserMedia` — reconciled out of "Upcoming," was already done)
- [ ] **⚠️ Authentication** — see Critical finding above; the dashboard should not ship further features until this is addressed.

---

## 🔜 Upcoming (Minor Improvements)

- [ ] **Berlekamp-Massey decoder** — full multi-error RS correction. Genuinely
  still open — `error_correction.rs` only implements brute-force
  single-error correction (see Major finding above re: its unbounded cost);
  no Berlekamp-Massey algorithm exists anywhere in the codebase
  (`grep -i berlekamp` = 0 hits). This is also the fix for the DoS finding
  above: a real Berlekamp-Massey decoder is both more capable *and*
  polynomial-time bounded, unlike the current brute force.

*(The other four items previously listed here — frame diff viewer,
historical metrics charts, multi-camera support, MDCT audio embedding — were
all already fully implemented; moved to Implemented above with evidence.)*

---

## 📋 Backlog (Future Features)

Larger items requiring design work or architecture changes.

> **Resequencing note (2026-07-22):** per the Strategic findings above, key
> lifecycle (rotation + revocation + secret-scanning) should ship *before*
> the "Core Improvements" items below — adding post-quantum/certificate-chain
> sophistication on top of a signing-key story that just leaked a real key
> compounds complexity without addressing the actual gap.

### Core Improvements

- [ ] **Key lifecycle: rotation + revocation** *(new, promoted ahead of the items below — see Critical/Strategic findings)* — minimum viable version: documented rotation procedure + a published revoked-keys list checked at verify time.
- [ ] **Post-quantum signatures** — ML-DSA (FIPS 204) as Ed25519 alternative
- [ ] **Hybrid signing** — Ed25519 + ML-DSA via multi-frame spreading
- [ ] **Certificate chain support** — X.509 or WebPKI for identity binding
- [ ] **C2PA interoperability decision** — record an explicit architectural decision on whether/how to interoperate with or emit C2PA (Content Credentials) manifests alongside the custom format (see Strategic findings above)

### Platform & Distribution

- [ ] **WASM build** — browser-based encode/verify via WebAssembly
- [ ] **`cargo install` support** — publish to crates.io (make GStreamer optional)
- [ ] **Homebrew formula** — `brew install steganographer`
- [ ] **Windows support** — Media Foundation sources/sinks *(currently claimed as supported in `docs/platforms.md` with no CI coverage — see Medium finding above; treat the doc claim as aspirational until this ships)*
- [ ] **Native GStreamer plugin** — full `BaseTransform` for zero-copy pipelines

### Dashboard Enhancements

- [ ] **WebRTC streaming** — replace WebSocket frame-by-frame with WebRTC
- [ ] **Dashboard authentication** — see Critical finding above; blocking item for any further dashboard feature work

### Documentation & Tooling

- [ ] **`cargo-release` workflow** — automated version bumps and CHANGELOG updates
- [ ] **Secret-scanning CI gate** *(new)* — `gitleaks` or equivalent, blocking merge

---

Contributions welcome — see [docs/contributing.md](docs/contributing.md) for the workflow.
