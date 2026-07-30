# Validation, Security, Corpus, and Release Quality

## Objective

Make correctness, compatibility, detectability, robustness, resource safety,
and performance measurable. Feature presence alone is not acceptance.

## Quality model

Each capability is evaluated along independent dimensions:

- **Correctness**: exact encode/decode behavior.
- **Compatibility**: legacy, cross-version, Rust/WASM, and format round-trip.
- **Security**: authentication, key separation, hostile-input safety, secrecy.
- **Stealth**: statistical detectability at a specified payload/utilization.
- **Robustness**: survival under declared transforms.
- **Fidelity**: perceptual/numeric carrier distortion.
- **Performance**: time, memory, streaming latency, and output size.
- **Forensic quality**: detector false positives/negatives and evidence quality.

Reports and documentation must not substitute one dimension for another.

## Test pyramid

### Unit tests

- field encodings, canonicality, checked arithmetic;
- transform stage ordering and failures;
- carrier descriptors and slot eligibility;
- schedule uniqueness/range/determinism;
- kernel bit/symbol operations;
- detector rules and evidence locations;
- config validation and redaction;
- typed error and exit-code mapping.

### Property tests

- decode(encode(x)) equals x within supported capacity;
- canonical encode is stable;
- accepted envelope re-encodes identically;
- schedules never duplicate/out-of-range;
- capacity never overstates successful embedding;
- format descriptor spans never exceed buffers;
- parser limits hold for generated lengths/nesting;
- arbitrary malformed input does not panic.

### Integration tests

Vertical slices:

- legacy v2 PNG/WAV/raw encode → write → reopen → extract → verify;
- generic packet PNG/WAV;
- encrypted/compressed/ECC packet;
- explicit and auto/keyed discovery;
- DCT/MDCT/spread paths;
- scan → finding → bounded decode → explicit extract;
- OOXML → part traversal → embedded image detector;
- Rust CLI and WASM on shared fixtures.

### End-to-end tests

- CLI stdout/stderr/exit codes;
- atomic write and overwrite refusal;
- config migration;
- dashboard browser-local workflows;
- batch/JSONL partial failure;
- resource cancellation and truncation;
- release package feature combinations.

## Golden corpus

Repository layout:

```text
testdata/
  manifests/
  packets/
  carriers/
    clean/
    encoded/
    malformed/
  documents/
    ooxml/
    pdf/
  attacks/
  expected/
```

Large or redistributability-constrained artifacts may use a separately versioned
fixture release. CI verifies hashes and manifest versions.

### Fixture manifest

Every generated fixture records:

```yaml
id:
license:
source:
generator_version:
seed:
carrier:
packet:
embedding:
transforms:
expected_decode:
expected_findings:
expected_limits:
hashes:
```

No fixture exists only as an unexplained binary. Generators are deterministic
when a seed is supplied.

### Corpus classes

1. **Clean negatives**
   - common cameras, image editors, audio tools, Office/LibreOffice/Google Docs
     exports, PDF producers, scanners, and metadata patterns.
2. **Known positives**
   - every supported kernel/profile at payload utilization bands.
3. **Near misses**
   - magic without valid envelope, corrupt CRC, wrong key, invalid AEAD,
     damaged ECC, invalid signature, truncated packet.
4. **Malformed/hostile**
   - extreme lengths, offsets, ZIP/XML/PDF bombs, cycles, duplicate parts,
     pathological Unicode, decompression bombs.
5. **Transform attacks**
   - recompression, scaling, crop, rotate, color conversion, noise, filtering,
     resampling, channel changes, transcoding, metadata stripping.
6. **Interoperability**
   - immutable packet/placement/carrier vectors for each stable version.

## Robustness matrix

Every kernel declares expected outcomes:

| Transform | Spatial LSB | DCT/F5 | Spread | Audio LSB | MDCT |
| --- | --- | --- | --- | --- | --- |
| lossless rewrite | required | required | required | required | required |
| metadata strip | required | required | required | required | required |
| JPEG/codec transcode | not promised | measured profile | measured | not promised | measured |
| resize/crop | not promised | measured | measured | n/a | n/a |
| color conversion | not promised | measured | measured | n/a | n/a |
| noise/filter | measured | measured | measured | measured | measured |
| resample/channel mix | n/a | n/a | n/a | not promised | measured |

“Measured” requires parameters, corpus, success percentage, and payload size.
It does not become “guaranteed” without a release profile and threshold.

## Fidelity and detectability

For image/video:

- changed-sample count;
- MSE, PSNR, and SSIM where appropriate;
- per-component histograms and LSB balance;
- chi-square, SPA, RS, and combined local results;
- utilization and spatial distribution.

For audio:

- changed-sample count;
- signal-to-noise ratio;
- peak/rms error;
- spectral difference;
- listening-test plan for stable profiles where warranted.

For detectors:

- negative corpus size and provenance;
- true/false positive rates by strength/utilization;
- threshold and calibration version;
- confusion matrix;
- bounded parameter-search coverage.

Release documents state the corpus and limitations. A synthetic-only benchmark
is insufficient for a detector marked stable.

## Performance budgets

Initial targets are budgets to validate and revise with evidence:

| Operation | Budget |
| --- | --- |
| Packet parse | O(packet bytes), no carrier-sized allocation |
| Spatial embed/extract | O(visited slots), bounded schedule memory |
| Public locator probe | sublinear bootstrap work plus fixed parse |
| Standard scan | one pass per selected detector family where practical |
| OOXML standard scan | O(parts + bounded expanded bytes) |
| Browser main-thread blocking | none for long operations; use workers |
| Live pipeline overhead | regression threshold recorded against v0.6 baseline |

Benchmarks capture:

- throughput and p50/p95/p99 latency;
- peak allocation/RSS;
- schedule setup cost;
- file decode/write cost;
- scan work by detector;
- representative low/high-capacity carriers.

CI uses generous regression thresholds or comparison reports to avoid flaky
microbenchmark failures. Release gates use reproducible benchmark hosts where
available.

## Security requirements

### Cryptography

- ChaCha20-Poly1305 remains the initial AEAD.
- Argon2id parameters are serialized, bounded, and have platform-specific safe
  defaults.
- High-entropy master-key derivation and password KDF APIs are distinct.
- Locator, placement, encryption, and signing contexts use separate subkeys.
- Nonces cannot repeat under the same key in supported workflows.
- Downgrades, unknown critical algorithms, and transform reordering fail closed.
- Secret-bearing types redact `Debug` and avoid serialization.
- Consider zeroization for transient secrets after dependency/behavior review.

### Parser and resource safety

- validate before allocation;
- checked arithmetic for all capacity/offset calculations;
- recursion/expanded-byte/entry/node/finding/time limits;
- no panic on attacker-controlled input;
- no external entity or relationship retrieval;
- no script, macro, font, embedded object, or media execution;
- safe temporary files and atomic writes;
- safe extraction names and overwrite policy.

### Side channels

The primary threat is offline file analysis, not a remote constant-time oracle,
but:

- cryptographic verification uses library constant-time operations;
- authentication error details are intentionally coarse;
- key material is not included in logs, telemetry, JSON, panic messages, or
  fixture manifests;
- keyed discovery work is bounded and does not fall back to unbounded guessing.

### Supply chain and licensing

- `cargo audit`, `cargo deny`, gitleaks, and fuzzing remain gates;
- no AGPL/GPL code copied from ST3GG;
- F5/matrix encoding uses reviewed permissive upstream material or a clean Rust
  implementation with notices;
- generated fixtures record source and redistribution license;
- new JS/WASM dependencies receive the same audit/license review;
- repository must contain its declared MIT license file.

## Fuzzing

Add targets incrementally:

- locator decode;
- canonical envelope/TLV decode;
- transform descriptor decode;
- packet transform pipeline;
- carrier descriptor/slot math;
- generic spatial extraction;
- PNG/WAV adapter boundaries;
- Unicode detector;
- ZIP/OOXML topology;
- PDF adapter;
- recursive scan orchestration;
- JSON/config deserialization.

Seed corpora include all golden and malformed fixtures. Fuzz failures become
minimal regression fixtures.

Nightly fuzz CI:

- fails on crash, panic, timeout beyond harness bounds, excessive allocation, or
  sanitizer finding;
- does not mask failures with unconditional `|| true`;
- records target duration and versions;
- rotates longer campaigns across expensive parsers.

## CI matrix

Required jobs as capabilities land:

- stable Rust: Linux, macOS, and planned Windows;
- declared MSRV if the project adopts one;
- default and minimal feature sets;
- core-only, full native, and WASM builds;
- format/document feature combinations;
- rustfmt and clippy with warnings denied;
- unit/integration/doc tests;
- schema and golden-vector immutability;
- corpus manifest/hash validation;
- audit, deny, and secret scan;
- fuzz smoke per PR and longer scheduled fuzz;
- browser headless integration for WASM/dashboard;
- package/publish dry run.

Network-dependent test setup is isolated from deterministic test execution.

## Release gates

### Alpha capability

- contract documented;
- positive/negative/malformed tests;
- limits implemented;
- no legacy regression;
- feature is opt-in and clearly labeled.

### Beta capability

- golden vectors;
- fuzz target;
- representative corpus;
- cross-surface integration;
- performance and memory data;
- security review complete;
- migration/documentation drafted.

### Stable capability

- compatibility policy;
- calibrated quality thresholds;
- schema/CLI/API semver review;
- no unresolved high/critical findings;
- release package and platform checks;
- support and deprecation plan.

## Work packages

| ID | Scope | Depends on | Acceptance |
| --- | --- | --- | --- |
| `QUA-001` | Corpus manifest/schema/generator harness | none | deterministic hash-verified sample set |
| `QUA-002` | Legacy immutable fixtures | `QUA-001` | current v2 media decodes across changes |
| `QUA-003` | Packet/placement vectors | protocol | Rust/CLI/WASM equality |
| `QUA-004` | Attack transformation harness | formats | parameterized robustness reports |
| `QUA-005` | Detector calibration harness | forensics | confusion matrices and threshold versions |
| `QUA-006` | Performance benchmark suite | vertical slices | baseline and regression reports |
| `SEC-001` | Protocol/key security review | packet/key hierarchy | documented findings resolved/accepted |
| `SEC-002` | Parser/resource review | formats/forensics/documents | hostile corpus and fuzz evidence |
| `SEC-003` | Supply-chain/license review | each dependency | deny/audit/notices pass |
| `CI-001` | Feature/MSRV/WASM matrix | crates introduced | documented supported combinations pass |
| `CI-002` | Vector/schema/corpus gates | `QUA-001`, `QUA-003` | unintended drift fails CI |

## Exit criteria

- Stable claims are tied to reproducible fixtures and measurements.
- Hostile input is bounded across packet, format, recursion, and detector layers.
- Legacy and new vectors remain immutable.
- Rust and WASM agree on stable protocol behavior.
- CI does not suppress fuzz/parser failures.
- Licensing provenance is documented for dependencies, borrowed algorithms, and
  fixtures.

