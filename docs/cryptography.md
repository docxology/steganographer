# Cryptography

## Scope and trust

Steganographer 0.8 separates three different commitments:

| Mechanism | Authenticated content | Not established by that mechanism |
| --- | --- | --- |
| Legacy `SignaturePayload` v4 | Version-framed frame index and supplied video/audio binding bytes | Person identity, capture truth, arbitrary file/container metadata |
| Generic `STG3` payload-signature transform | Exact recovered logical payload bytes | Arbitrary envelope metadata or the surrounding carrier |
| OpenTimestamps detached proof | The caller's expected SHA-256 digest; CLI uses SHA256 of the complete input file | Signer identity, media semantics, independent full-node validation |

A valid signature means the corresponding private key signed the authenticated bytes. To attribute it to an expected source, obtain and **pin the full public key through a separately trusted channel**. A key bundled with a packet is not independent identity evidence. Neither a signature nor a timestamp proves that a recorded event happened, or that signed media is not synthetic.

Steganography places bytes in a carrier; signing authenticates bytes; optional encryption protects payload confidentiality. These are separate operations. Keyed placement is not encryption, and a visible overlay is not automatically an authenticated backup proof. See [Security](security.md) and [Threat Model](threat-model.md) for operational boundaries.

## Legacy frame hashing and migration

`crypto::HashAlgorithm` supports BLAKE3 (default), SHA-256 and SHA3-256, each producing 32 bytes. The configured hash must match at signing and verification. Selecting a standardized algorithm does not certify the application or deployment as FIPS compliant. No platform-specific speed guarantee is implied.

Version 4 hashes the following exact sequence with the selected algorithm:

```text
"steganographer-frame-v4\0"
|| frame_index:u64 LE
|| video_length:u64 LE || video_bytes
|| audio_present:u8
|| audio_length:u64 LE || audio_bytes
|| "\0end"
```

`audio_present` is 0 for `None`, 1 for `Some`, including `Some(&[])`. Explicit lengths distinguish different video/audio partitions of the same concatenated bytes; the presence byte distinguishes absent from empty audio. Ed25519 signs the resulting digest. The configurable media hash is not a replacement for Ed25519's internal hash processing.

The legacy serialized payload remains **109 bytes**:

| Field | Bytes | Encoding |
| --- | ---: | --- |
| Magic | 4 | ASCII `STEG` |
| Version | 1 | `4` |
| Frame index | 8 | u64 little-endian |
| Media digest | 32 | Selected hash output |
| Ed25519 signature | 64 | Signature over the digest |

`SignaturePayload::from_bytes` validates magic and version; `has_valid_magic` is only a framing check, not signature verification. The fixed payload does not carry the selected hash algorithm; preserve it as verification context.

Legacy versions 2 and 3 are rejected, not silently retried under historical hashing. Version 2 also used incompatible Reed-Solomon evaluation points. The v4 keyed legacy audio Feistel mapping has changed as well. **Re-encode from source media with 0.8**; changing only the version byte does not migrate an old signature, ciphertext or carrier.

## Canonical media is not the exact artifact

Embedding changes a carrier. Offline and supported native/dashboard signing paths use `carrier_binding::canonicalize` so verification can recompute the same binding from delivered pixels or samples rather than a private pre-embed snapshot:

- LSB RGB clears the selected low bits of all color bytes. Packed BGRA keeps alpha intact. Row padding is not logical pixel content.
- LSB S16LE clears the selected low bits of each complete sample.
- Offline scalar spread-spectrum excludes its payload-length-dependent modified prefix (including its length prefix).
- DCT binding excludes the green-channel samples in the blocks owned by the signature kernel.

These exclusions are deliberate **unauthenticated regions**, not a promise to detect every visible or audible edit. In particular, excluding a whole kernel-owned block/prefix can omit much more than a single embedded bit. Container headers, filenames, display timestamps, sample-rate labels and other rendered metadata are not automatically covered by the media signature. Geometry and other extraction context must be preserved and trusted as required by the consuming workflow.

A library verification example for one delivered packed RGB frame:

```rust
use steganographer_core::{carrier_binding::canonicalize, SignaturePayload, Verifier};

fn verify_delivered_rgb(
    pinned_public_key: &[u8; 32],
    extracted_payload: &SignaturePayload,
    delivered_rgb: &[u8],
    width: u32,
    height: u32,
) -> anyhow::Result<bool> {
    let binding = canonicalize(delivered_rgb, "lsb_video", 1, width, height, 109)?;
    let verifier = Verifier::from_bytes(pinned_public_key)?;
    Ok(verifier.verify(extracted_payload, &binding, None))
}
```

The caller supplies the payload actually extracted from those delivered pixels and a separately trusted public key. This example uses one LSB and the default BLAKE3 hash; preserve the matching bit depth/hash for other settings. Verification of a standalone payload against unrelated supplied bytes is not proof that those bytes were delivered in a file.

For an exact-artifact commitment, retain the original file and its SHA-256 digest. CLI OTS commits to **every input file byte**, unlike canonical media signing. Repackaging identical pixels into a different PNG or Matroska container changes that file digest even if media verification still succeeds.

## Strict Ed25519 and other library backends

Ed25519 uses a 32-byte signing seed, 32-byte public key and 64-byte signature. Generation uses OS randomness. Verification uses strict Ed25519 checks; raw public-key imports reject weak keys, including small-order identities. Generic payload-signature and hybrid verification also enforce strict Ed25519 verification rather than permissive acceptance.

`SignerBackend` exposes additional **library** implementations:

| Backend | Contract |
| --- | --- |
| `Ed25519Backend` | Ed25519 signing and strict verification |
| `EthereumBackend` (feature `ethereum`) | secp256k1 EIP-191 personal-message prefix and Keccak-256; address derived from the public key |
| `MlDsaBackend` / `MlDsaVerifier` | Real FIPS 204 ML-DSA-44/65/87 through RustCrypto `ml-dsa`; public-key-only verification is available |
| `HybridBackend` / `HybridVerifier` | Ed25519 and ML-DSA concatenation; both signature halves must verify |

ML-DSA signatures are 2,420 / 3,309 / 4,627 bytes, with public keys of 1,312 / 1,952 / 2,592 bytes for levels 44/65/87. These are not drop-in replacements for the fixed 109-byte legacy Ed25519 payload. Historical placeholder “ML-DSA” MACs cannot be verified by the real implementation and must be re-signed. The RustCrypto ML-DSA implementation is not claimed to be independently audited.

Ed25519 and secp256k1 are not post-quantum signatures. Available ML-DSA/hybrid library APIs do not make every CLI, dashboard or carrier path post-quantum. Live signed pipelines and the dashboard currently support **Ed25519**, not wallet-driven signing. EIP-191 compatibility in a library is not MetaMask integration, on-chain publication or proof of a person's identity.

## Generic packet signatures and metadata

The generic packet magic is `STG3`, with protocol version **1.0**, independently of legacy `FORMAT_VERSION = 4`. Its transform pipeline is:

```text
sign logical payload → optional DEFLATE → optional password KDF / AEAD
→ optional Reed-Solomon ECC → embed
```

The Ed25519 descriptor contains `public_key(32) || signature(64)`. Verification occurs over the recovered logical bytes after reversing the other transforms. It does **not** sign every semantic envelope field. CRC32C and the unkeyed content digest provide structural/corruption checks, not trusted authorship. Filename, MIME, timestamps and other metadata must not be treated as signer-authorized merely because payload verification succeeds. If such meaning must be authenticated, include it in the signed logical payload using an application-defined encoding.

AEAD associated data is specifically:

```text
packet_id(16) || payload_kind:u16 BE || original_length:u64 BE
```

This is not full-envelope authentication. Unknown critical fields/unsupported transforms and flag/transform inconsistencies fail closed; preserving unknown non-critical metadata does not authenticate it.

Compression is admitted only for logical input at most 64 MiB in the shared
transform APIs, and recorded only if DEFLATE shrinks it; configured CLI limits
may be lower. Readers preflight stage order, versions, singleton descriptors
and bounded work before credentials/KDF/body allocation, then enforce declared
logical length and output limits during reversal. Locator keyed flags must
agree with placement. For nested decoding, an identifiable parent-id field is
the opt-in marker: mere `STG3` prefix bytes stay opaque. Once opted in, child
framing, exact span, parent linkage, depth/aggregate bounds and cycles are strict.

Generic CLI `decode`/`extract --trusted-signer <full-public-key-hex>` rejects unsigned packets and mismatched signing keys. Reports distinguish `signer_public_key` from `signer_trusted`. Without a trusted pin, a mathematically valid self-supplied signer is still untrusted.

### Timestamp commitment scope

Dedicated `ots stamp` / `ots verify` use exact-file SHA-256 (`sha256-file`);
legacy optional encode/verify OTS hashes kernel-canonical media instead.
Dashboard video hashes delivered PNG file bytes, while audio hashes raw signed
PCM, not its export WAV wrapper. These scopes are not interchangeable.
`verify_with_upgrade` returns optional changed proof bytes for append-only
publication; completed Bitcoin proofs skip calendars but still require trusted
explorer verification. Pending is not confirmed. See [OTS Integration](ots-integration.md).

### Frozen protocol-v1 vectors

The historical packet and placement `.hex` fixtures and SHA-256 sidecars under [`steganographer-core/testdata/packets/`](../steganographer-core/testdata/packets/) remain frozen. Their [`manifest.json`](../steganographer-core/testdata/packets/manifest.json) records the documented test keys, deterministic inputs, raw AEAD nonce/AAD derivation and protocol-1.0 framing. They are compatibility evidence, not production secrets or secure nonce-generation examples. The v4 legacy cutover does not rewrite these generic packet/carrier bytes.

## Payload encryption and nonce responsibility

ChaCha20-Poly1305 uses a separate 32-byte key. Raw `encryption::encrypt` / `decrypt` retain the protocol-v1 layout:

```text
salt(4) || ciphertext || Poly1305_tag(16)
nonce = BLAKE3(salt || packet_id)[..12]
```

**Raw callers must supply a fresh 16-byte packet ID for every encryption under a key, including retries.** A four-byte random salt alone is not sufficient protection for repeated packet IDs; do not use a zero ID or infer nonce safety from frame indices or public locator nonces. Encryption is randomized, not a mathematical guarantee of collision-free nonces for an unlimited number of messages.

Legacy workflows use `encrypt_legacy` / `decrypt_legacy` instead:

```text
STGE(4) || wrapper_version(1 byte = 1) || random_packet_id(16)
|| salt(4) || ciphertext || tag(16)
```

The wrapper generates a fresh random 128-bit packet ID and adds **41 bytes** (`LEGACY_ENCRYPTION_OVERHEAD`). Its version is separate from both legacy signature v4 and STG3 protocol 1.0. Decryption requires this wrapper; there is **no historical raw zero-ID fallback**. Capacity calculations must use actual transformed ciphertext length. Authentication failure is an error, never a request to try plaintext.

## Derivation, storage and caller-owned secrets

BLAKE3 context-separated derivation produces signing, encryption and embedding keys from high-entropy master material (`steganographer-signing-v1`, `steganographer-encryption-v1`, `steganographer-embedding-v1`). This fast KDF does not make a weak password strong. Password routes use Argon2id with a persisted salt and bounded work parameters; preserve the parameters needed for recovery. Generic password transforms and legacy encryption are different supported interfaces, not interchangeable flags.

Owned encryption-key and master/derived-key buffers use zeroization. This does not erase caller-owned borrowed passwords, exported key arrays/strings, copies, command-line history, swap, crash dumps or backups. Callers remain responsible for secret lifetimes and storage. Session derivation is not forward secrecy: possession of the master can regenerate derived keys.

Use separate signing/encryption/placement keys, restrict access to plaintext `.key` files, back up necessary decryption/extraction context securely, and distribute public keys out-of-band. Rotation needs an authenticated key transition/revocation policy; generating a fresh key alone does not establish continuity.

## Source map and further reading

Implementation contracts: [`crypto.rs`](../steganographer-core/src/crypto.rs), [`carrier_binding.rs`](../steganographer-core/src/carrier_binding.rs), [`encryption.rs`](../steganographer-core/src/encryption.rs), [`transforms.rs`](../steganographer-core/src/transforms.rs), [`signer_backend.rs`](../steganographer-core/src/signer_backend.rs), [`kdf.rs`](../steganographer-core/src/kdf.rs).

See [Security](security.md), [Threat Model](threat-model.md), [OpenTimestamps](ots-integration.md), and [Steganography Theory](steganography-theory.md). Primitive security assumptions and dependency advisories are not an exhaustive security assessment of the composed application.
