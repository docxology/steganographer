# Threat Model

## Scope: version 0.8

This is an implementation-bounded threat model for generic packets, legacy signed media, native/dashboard delivery, CLI processing and forensic inspection. It is not an exhaustive security assessment. See [Cryptography](cryptography.md) for exact authenticated bytes and migration rules, and [Security](security.md) for operational controls and status codes.

The primary goal is **tamper evidence under an expected key and a defined binding**, not tamper prevention, truth detection, invisibility or guaranteed watermark survival. A valid signature can authenticate fabricated content if an authorized signer signs it.

## Assets and trusted inputs

| Asset or input | Required trust / responsibility |
| --- | --- |
| Signing secret and signer process | Protect from disclosure and unauthorized signing; the application cannot distinguish legitimate capture from synthetic input supplied to its signer |
| Encryption key / master / password | High entropy or suitable password derivation, separate key roles, controlled storage and caller-memory lifetimes |
| Expected public key | Obtain out-of-band and pin the full key; an embedded or server-advertised key is not independent identity evidence |
| Extraction/binding context | Preserve kernel, bit depth, dimensions, hash algorithm, indices, audio embedding key and format as needed; not all context is signed |
| Sequence/session policy | Independently define expected start/end, order, session and freshness requirements |
| Exact artifacts and custody records | Retain delivered bytes, manifests and exact-file digests; media signatures do not cover every container byte |
| Timestamp provider configuration | Trust configured calendar for availability/upgrades and Esplora for canonical-height selection; neither is a person-identity authority |
| Local filesystem/configuration | Use trusted parent directories, effective decode budgets and protected configuration/revocation data |

Cryptographic assumptions include the hardness of forging the selected signature and finding relevant hash collisions, adequate OS randomness and correct dependency behavior. Strict Ed25519 verification and weak imported-key rejection are implemented controls, not proof that host compromise or side channels are impossible. Owned-buffer zeroization does not erase borrowed caller passwords, exported keys or copies outside those buffers.

## Adversaries

An adversary may read or replace files/packets, edit media or metadata, strip/re-embed/re-sign watermarks, replay valid old artifacts, supply malicious containers and unauthenticated descriptors, exhaust resources, or send browser/network requests to a dashboard. A steganalyst may know the algorithms and use statistical or learned detectors. Algorithm secrecy is not a security assumption.

Key theft, malicious capture inputs, a compromised signing host and a dishonest trusted chain provider are explicit residual risks, not capabilities dismissed as impossible. Protection of the operating system, camera/microphone source, browser and native codec stack is outside the cryptographic payload contract.

## Threats, controls and residual risks

| Threat | Implemented control / required workflow | Residual risk |
| --- | --- | --- |
| Fabricated/deepfake media presented as authentic | Verify against the independently pinned expected key and required binding | An authorized or compromised signer can sign synthetic media; unsigned media is not necessarily fake |
| Signature forgery / weak-key acceptance | Strict Ed25519 verification and rejection of weak imported public keys | Depends on crypto assumptions and host/key security; does not establish a human identity |
| Content edits | Recompute version-framed canonical-media hash or verify logical-payload signature, depending on API | Kernel-owned exclusions and unsigned metadata remain editable; generic signatures do not authenticate arbitrary carrier pixels |
| Ambiguous video/audio partition or absent/empty audio | Legacy v4 domain, explicit media lengths and audio-presence framing | Old v2/v3 signatures/carriers require re-encoding; no silent historical verification fallback |
| Re-signing under attacker's own key | Reject a signature not matching the trusted key; generic `--trusted-signer` rejects unsigned/mismatched packets | Self-supplied keys verify mathematically without proving expected authorship |
| Envelope/filename/MIME manipulation | Validate framing, limits and critical descriptors; AEAD binds packet ID, payload kind and original length | Payload signature alone does not authorize every semantic envelope field; CRC/unkeyed digest can be recomputed by an attacker |
| Audio/video substitution | Verify each actual delivered carrier with its correct context | Separate signatures do not establish audiovisual synchronization, capture time or complete track coverage |
| Frame/chunk splice, omission, reorder or replay | Enforce an external expected sequence/session policy in addition to signed indices; use trusted chain roots where applicable | A valid isolated frame can be replayed; unsigned gaps, whole-session replay and truncation need external expectations |
| Signature stripping or destructive transcoding | Retain lossless originals; classify missing payload separately from authentication failure | Watermarks can be removed with small perceptual changes; no availability guarantee |
| Payload interception | Optional ChaCha20-Poly1305 with separate encryption key; fresh packet IDs for raw calls | Carrier remains visible; unencrypted metadata and traffic can leak information; placement is not confidentiality |
| AEAD nonce misuse | Legacy versioned `STGE` wrapper generates a fresh random 128-bit ID; raw callers must supply a fresh ID for every encryption under a key | Repeated raw IDs, including retry reuse, are unsafe with only the four-byte random salt; historical zero-ID ciphertext has no fallback |
| Partial corruption | Supported offline ECC/sharding can recover within their actual redundancy/placement limits | Not arbitrary edit resistance; unsupported live/kernel compositions reject rather than imply protection |
| Malicious config/revocation input | Fallible validated explicit config and revocation parsing; effective decode limits | Trusted local policy can still choose unsuitable limits/keys; no silent invalid-policy fallback is acceptable |
| Output overwrite / alias damage | Offline output helpers use private temporary files, no-clobber publication and atomic replacement where force is supported | Trusted parent directories remain required; multi-file output is not one transaction; not a blanket native-writer sandbox |
| Parser/resource attacks | Bounded packet, nesting, KDF, proof, ZIP/inflate/XML and PDF processing; incomplete coverage is explicit | Bounds can cause inconclusive results, not absence evidence; native codecs/OS remain separate surfaces |
| Forged timestamp / pending receipt sold as confirmed | Verify exact expected digest, proof operations, Merkle/root/header/hash/PoW and trusted provider's height lookup | Pending is not verified; configured provider's canonical-chain view is trusted, not independently full-node validated |
| Foreign-origin dashboard mutation / WebSocket hijacking | Configured bearer-token checks and browser Origin gates | Tokenless mode is local-only policy, not general access control; missing-Origin non-browser clients and host compromise require network/OS controls |

## Binding boundaries that change the conclusion

### Canonical media versus every rendered bit

Supported signed-media workflows canonicalize logical packed pixels or complete PCM samples. Selected low bits or larger kernel-owned regions are excluded so embedding does not invalidate its own signature. Row padding is not logical video content. This means:

- A successful media verification is not a guarantee that every pixel/sample bit is unchanged.
- DCT/spread-spectrum exclusions can cover larger regions than the payload's individual bits.
- Headers, sample-rate/geometry interpretation, display metadata, filename and container packaging are not automatically authenticated.
- A copied valid payload must still be checked against the actual delivered carrier's canonical bytes; a pre-embed self-check is insufficient.

OTS CLI `SHA256(file)` is an **exact file-byte commitment**, not this canonical binding. It detects repackaging changes but does not provide author identity or verify media semantics. Preserve both commitments when both meanings matter.

### Logical payload versus metadata

Generic protocol-1.0 signatures authenticate recovered logical bytes. An application that needs filename, MIME, timestamp, session ID or carrier descriptors to carry signer-authorized meaning must encode that meaning inside its signed logical content and validate it under its own schema. Neither canonical TLV encoding nor CRC32C is a substitute for authentication.

The historically frozen `STG3` protocol-v1 packet/carrier fixtures, raw AEAD layout and signature/AAD bytes are unchanged by the legacy v4 cutover. Their fixed salts and documented keys exist for reproducibility, not production use. See the [cryptography guide](cryptography.md#frozen-protocol-v1-vectors).

### Ordering and chains

A signed frame index binds that index to the supplied media bytes, not to a wall clock, unique capture session or externally expected stream length. Consumers must decide whether missing, repeated or unexpected indices are acceptable. Per-frame verification alone does not enforce continuity.

`HashChain::verify_chain(root, frames, previous_hash)` requires a **trusted root and predecessor**; zero is the predecessor for segment zero only. Later-segment verification cannot restart from zero. Frame start/order/count are checked, but the historical leaf domain does not independently bind the exact segment ordinal: retain that ordinal as trusted external context. A Merkle root provided by the same untrusted party as the frames is not an authentication anchor.

## Transport, recording and unsupported compositions

Preserve the actual signed delivery representation. Native exact file output uses RGB Matroska and PCM WAV. Dashboard records a bounded stored-ZIP archive of signed PNG snapshots or signed PCM WAV chunks and extraction metadata, not continuous signed WebM. The manifest helps recover indices, bit depth, public key and audio placement context; its presence alone does not authenticate that context or identify an organization.

The dashboard's public identity is the actual server-runtime Ed25519 key. A server can correctly verify its own output without proving to a remote consumer who operates that server. Independently pin the key and verify retained artifacts. Preview opacity/disabled visual-overlay controls do not provide a second signed channel. There is no dashboard MetaMask/wallet signing or automatic blockchain identity registration.

Live signed paths require a single supported invisible kernel and reject ignored encryption/ECC/spreading or invisible-plus-visible-overlay combinations. Native trait spread-spectrum signing is unsupported because its channel mapping differs from offline scalar binding. Offline generic sharding is RGB LSB only (2–8 shards); audio/SS/DCT sharding rejects. A library backend or rendering API being available does not make these compositions supported.

LSB is fragile under JPEG, H.264, MP3, resampling and other lossy transformations. DCT, spread-spectrum, redundancy or visible marks may have different failure modes, but none is a universal transcoding fallback. Successful preservation requires testing the actual delivery path, not assuming a kernel name guarantees robustness. Extraction absence after transport can reflect stripping, corruption, an unsupported representation, a wrong extraction key or genuinely unsigned content; it does not uniquely attribute an attack.

## Forensic detection is scoped evidence

Forensics separates content-derived findings from observations and completeness. `detected` can stay true when display evidence is capped or later analysis is incomplete. ZIP inventory, topology anomalies, entropy and statistical scores do not alone establish concealment. Magic strings and Unicode findings may also have benign explanations; investigate them rather than equating them with a recovered authenticated message or malicious intent.

ZIP/OOXML examination checks supported structure, bounded inflate/CRC and selected decoded XML/text parts. Unsupported archive features, entities/encodings and resource cutoffs constrain coverage. PDF inspection is lexical and bounded, not full rendering, arbitrary filter/object-stream execution, CMap/glyph interpretation or every invisible-text mechanism. `incomplete_reasons` must travel with the result. A budget-limited negative, unreadable file or unavailable estimator is not a clean bill of health.

Chi-squared scores describe pair-equalization compatibility; sample-pairs is a heuristic; RS estimates random-LSB replacement rate only on suitable correlated samples with an admissible fit. `confidence` is not a calibrated posterior probability of steganography. Synthetic controls and frozen historical fixtures do not calibrate natural-image accuracy. No “one bit is undetectable,” low-KL-divergence bound, false-positive-free detector or exhaustive scanner claim is made.

## Deployment examples with qualified conclusions

### Journalism or evidence retention

Pin the source key through an editorial/organizational channel, retain lossless signed artifacts and extraction manifests, verify independently, and record exact-file digests plus custody history. A verified artifact supports “these authenticated bytes were signed by this key,” not “this scene is true,” “all frames were retained” or automatic courtroom admissibility.

### Remote inspection or broadcast

Protect the signing device and transport, retain an original lossless branch, and define session/sequence expectations separately. A transcoded broadcast copy may lose extractability. A signed inspection image does not prove that the physical inspection occurred or that the camera input was honest.

### Confidential or pseudonymous material

Encrypt the logical payload if its contents are confidential; do not confuse a pseudonymous public key with anonymity. The visible carrier, traffic, metadata, identity pinning channel and endpoint compromise can reveal the source. Signed media is not, by itself, whistleblower protection or a regulatory-compliance guarantee.

## Residual risk and assurance limits

Key compromise, authorized false signing, excluded-region edits, replay without session policy, lossy destruction, hostile filesystem parents, endpoint compromise and dishonest trusted-provider chain selection remain live risks. Tests, regression smokes and dependency-advisory tools are evidence for specific exercised behaviors, not proofs that all attacks are excluded. No unobserved performance, exhaustive coverage or final release-count claim is made here.

Further reading: [Security](security.md), [Cryptography](cryptography.md), [OpenTimestamps](ots-integration.md), [CLI Reference](cli-reference.md), and [Steganography Theory](steganography-theory.md).
