# Cryptography

## Overview

Steganographer uses a two-layer cryptographic scheme to produce tamper-evident signatures for each media frame:

1. **Hashing** — Configurable hash function (BLAKE3 default, also SHA-256, SHA-3-256) producing a 256-bit digest
2. **Signing** — Ed25519 (default) or secp256k1/Ethereum (EIP-191) digital signature scheme

The combination provides both **integrity** (hash detects any modification) and **authenticity** (signature proves the frame was signed by the holder of the private key).

> For the broader theoretical context of information hiding and its relationship to cryptography, see [Steganography Theory](steganography-theory.md).

---

## Foundational Principles

### Kerckhoffs' Principle

Auguste Kerckhoffs (1883) established that **a cryptographic system should be secure even if everything about the system, except the key, is public knowledge**. In Steganographer:

| Component | Public Knowledge | Secret |
| --- | --- | --- |
| LSB embedding algorithm | ✅ Known | — |
| Hash + signing scheme | ✅ Known | — |
| Payload format (109 bytes) | ✅ Known | — |
| Ed25519 / secp256k1 signing key | — | ✅ Private key |
| Audio PRNG permutation key | — | ✅ 32-byte key |
| Payload encryption key (optional) | — | ✅ 32-byte ChaCha20 key |

Security relies entirely on key secrecy, never on algorithm secrecy.

### Composing Steganography and Cryptography

Steganography and cryptography serve complementary purposes:

| Layer | Purpose | Steganographer Component |
| --- | --- | --- |
| **Cryptographic signing** | Ensures authenticity and integrity | Ed25519 signature over BLAKE3 hash |
| **Steganographic embedding** | Hides the signed payload from observers | LSB embedding in pixel/sample data |
| **Exoteric overlay** | Provides visible, machine-readable proof | Info Bar with QR code and barcode |

The composition `Stego(Sign(Hash(frame)))` provides defense in depth:

1. Even if the steganographic layer is broken (data extracted), the payload is a cryptographic signature — meaningless without context
2. Even if the overlay is visible, the LSB layer provides a hidden backup channel
3. Even if the LSB data is destroyed (re-encoding), the overlay survives

---

## Hash Construction

### Configurable Hash Algorithm

The hash algorithm is configurable via `[global]` in `steganographer.toml`:

```toml
[global]
hash_algorithm = "blake3"  # default
# hash_algorithm = "sha256"     # FIPS 180-4
# hash_algorithm = "sha3-256"   # FIPS 202 (Keccak)
```

| Algorithm | Config String | Standard | Speed (single core) | Use Case |
| --- | --- | --- | --- | --- |
| BLAKE3 | `"blake3"` | — | ~6 GB/s | Default — fastest, best for real-time |
| SHA-256 | `"sha256"` or `"sha-256"` | FIPS 180-4 | ~0.5 GB/s | FIPS compliance |
| SHA-3 256 | `"sha3"` or `"sha3-256"` | FIPS 202 | ~0.3 GB/s | NIST-approved sponge |

The hash algorithm is parsed by `HashAlgorithm::parse()` and falls back to BLAKE3 for unrecognized values.

### Input Domain

The BLAKE3 hash covers a deterministic concatenation of frame metadata and raw media bytes:

```mermaid
flowchart LR
    IDX["frame_index\n8 bytes (u64 LE)"] --> HASHER["🔑 BLAKE3\nHasher"]
    VID["video_bytes\nRaw pixel data"] --> HASHER
    AUD["audio_bytes\n(optional PCM)"] -.-> HASHER
    HASHER --> HASH["256-bit Hash\n(32 bytes)"]
    style HASHER fill:#333,stroke:#e53935,color:#e0e0e0
```

| Field | Size | Description |
| --- | --- | --- |
| `frame_index` | 8 bytes | Little-endian u64 frame counter |
| `video_bytes` | Variable | Raw pixel data (RGB8, BGRA8, or Y plane) |
| `audio_bytes` | Variable (optional) | Raw PCM samples, if present |

### Why BLAKE3 (Default)?

| Property | BLAKE3 | SHA-256 | SHA-3 256 |
| --- | --- | --- | --- |
| Speed (single core) | ~6 GB/s | ~0.5 GB/s | ~0.3 GB/s |
| Parallelizable | ✅ (tree hash) | ❌ | ❌ |
| Output size | 256 bits | 256 bits | 256 bits |
| Security level | 128-bit | 128-bit | 128-bit |
| FIPS certified | ❌ | ✅ | ✅ |

For real-time video at 30 fps with 1080p frames (~6 MB/frame), BLAKE3 can hash a frame in **<1 ms**, making it viable for live pipelines. SHA-256 and SHA-3-256 are available for FIPS-compliant deployments at the cost of higher latency.

### Implementation

```rust
// HashAlgorithm is configurable: Blake3 (default), Sha256, or Sha3_256
let hash = signer.hash_algorithm().hash(frame_index, video_bytes, audio_bytes);
// → 32-byte digest

// The Signer handles this internally:
let payload = signer.sign_frame(frame_index, video_bytes, audio_bytes);
// Uses the configured hash algorithm + Ed25519 signature
```

---

## Signature Scheme

### Ed25519 Parameters

| Parameter | Value |
| --- | --- |
| Curve | Curve25519 (twisted Edwards form) |
| Key size | 256 bits (32 bytes) |
| Signature size | 512 bits (64 bytes) |
| Security level | ~128-bit |
| Standard | RFC 8032 |

### Key Types

| Type | Rust Type | Size | Purpose |
| --- | --- | --- | --- |
| Signing key | `SigningKey` | 32 bytes | Private key for producing signatures |
| Verifying key | `VerifyingKey` | 32 bytes | Public key for checking signatures |
| Signature | `Signature` | 64 bytes | The Ed25519 signature output |

### Key Generation

```rust
let signer = Signer::generate();           // Random keypair from OsRng
let pub_key = signer.verifying_key();       // Extract public key
let priv_bytes = signer.signing_key_bytes(); // Export private key
```

Keys are hex-encoded for storage:

```bash
steganographer keygen --output mykey
# Creates: mykey.key (64 hex chars = 32 bytes private key)
#          mykey.pub (64 hex chars = 32 bytes public key)
```

---

## Pluggable Signing Backends

Steganographer supports multiple signing backends via the `SignerBackend` trait, configurable through `steganographer.toml`:

```toml
[video.pipeline.payload]
signing_backend = "ed25519"   # default
# signing_backend = "ethereum"  # requires --features ethereum
```

### Backend Comparison

| Property              | Ed25519 (default)              | Ethereum (secp256k1)                    |
| --------------------- | ------------------------------ | --------------------------------------- |
| Curve                 | Curve25519 (twisted Edwards)   | secp256k1 (Koblitz)                     |
| Hash function         | BLAKE3 (for frame hash)        | Keccak-256 (EIP-191 personal_sign)      |
| Signature size        | 64 bytes                       | 64 bytes (r, s)                         |
| Signing speed         | ~50 μs                         | ~50 μs                                  |
| Key format            | 32-byte raw                    | 32-byte raw (SEC1)                      |
| Identity format       | Hex public key (64 chars)      | Ethereum address (0x + 40 hex chars)    |
| Standard              | RFC 8032                       | EIP-191 / SEC 2                         |
| Feature flag          | (default, always available)    | `--features ethereum`                   |

### Ethereum / EIP-191 Signing

The Ethereum backend implements the `personal_sign` message format used by MetaMask and other Ethereum wallets:

1. **Message prefix**: `"\x19Ethereum Signed Message:\n" + len(data)` is prepended
2. **Keccak-256 hash**: The prefixed message is hashed with Keccak-256 (32 bytes)
3. **secp256k1 ECDSA**: The hash is signed using `sign_prehash` to produce a 64-byte (r, s) signature

The Ethereum address is derived from the public key: `Keccak-256(uncompressed_pubkey[1..65])[12..32]`.

```rust
use steganographer_core::EthereumBackend;

let backend = EthereumBackend::generate();
let sig = backend.sign(frame_data);
assert!(backend.verify(frame_data, &sig));
println!("Address: {}", backend.ethereum_address()); // 0x...
```

---

## SignaturePayload Format

The `SignaturePayload` is the atomic unit of cryptographic data embedded into media frames. The v2 format includes a magic header and version number for format identification and future compatibility:

```mermaid
block-beta
    columns 5
    A["magic\n4 bytes (\"STEG\")"]:1
    B["version\n1 byte (= 2)"]:1
    C["frame_index\n8 bytes (u64 LE)"]:1
    D["hash\n32 bytes"]:1
    E["signature\n64 bytes"]:1
    style A fill:#5c1a1a,stroke:#a33c3c,color:#fff
    style B fill:#3a3a3a,stroke:#888,color:#fff
    style C fill:#5c1a1a,stroke:#a33c3c,color:#fff
    style D fill:#1a3a5c,stroke:#2d6da3,color:#fff
    style E fill:#2d5016,stroke:#4a8c2a,color:#fff
```

**Total: 109 bytes** (`SERIALIZED_SIZE = 4 + 1 + 8 + 32 + 64`)

### Format Identification

Every payload begins with:
- **Magic header** (4 bytes): ASCII `STEG` — identifies the data as a Steganographer payload
- **Version** (1 byte): Currently `2` — allows future format evolution

Extraction validates both the magic header and version before parsing. Non-matching data returns `None` (no payload found), preventing false positives from random LSB data. The `has_valid_magic()` helper provides a quick check without full deserialization.

### Serialization

```rust
// Serialize to 109-byte array
let bytes: [u8; 109] = payload.to_bytes();

// Deserialize from 109-byte array (validates magic + version)
let payload = SignaturePayload::from_bytes(&bytes)?;

// Quick check without full deserialization
if SignaturePayload::has_valid_magic(&some_bytes) {
    // Likely a valid steganographer payload
}
```

All multi-byte fields use **little-endian** byte order.

---

## Signing Flow

```mermaid
sequenceDiagram
    participant F as Frame Data
    participant H as Hasher
    participant S as Signer (Ed25519/Ethereum)
    participant P as SignaturePayload

    F->>H: frame_index || video_bytes || audio_bytes
    H->>H: Compute 256-bit hash
    H->>S: hash (32 bytes)
    S->>S: Sign(private_key, hash)
    S->>P: SignaturePayload { magic, version, frame_index, hash, signature }
```

## Verification Flow

```mermaid
sequenceDiagram
    participant F as Frame Data
    participant E as Extractor
    participant H as Hasher
    participant V as Ed25519 Verifier

    E->>E: Extract SignaturePayload from LSBs
    E->>E: Validate magic header "STEG" + version
    F->>H: frame_index || video_bytes || audio_bytes
    H->>H: Recompute 256-bit hash
    H->>V: Constant-time comparison (ct_eq) of extracted vs computed hash
    V->>V: Verify(public_key, hash, signature)
    V-->>V: ✅ VALID or ❌ INVALID
```

---

## Threat Model

### What This Protects Against

| Threat | Protection |
| --- | --- |
| Frame content modification | BLAKE3 hash will mismatch |
| Frame index manipulation (replay/reorder) | Frame index is included in the hash domain |
| Signature forgery | Ed25519 requires the private key |
| Audio-video desynchronization | Combined hash covers both streams |

### What This Does NOT Protect Against

| Limitation | Notes |
| --- | --- |
| Side-channel attacks | Hash comparison uses constant-time `ct_eq`; no constant-time guarantees for signing beyond what `ed25519-dalek` provides |
| Quantum adversaries | Ed25519 is not post-quantum (consider ML-DSA for future) |
| Key compromise | If the private key leaks, all signatures can be forged |
| Frame removal | Missing frames are detectable only by frame index gaps |
| Re-encoding attacks | Lossy transcoding destroys LSB-embedded data |

### Key Management Recommendations

1. **Generate keys per-session** — Each recording session should use a fresh keypair
2. **Store private keys securely** — Use OS keychain or encrypted storage
3. **Distribute public keys out-of-band** — Share verification keys through a trusted channel
4. **Rotate keys regularly** — Limit the blast radius of any key compromise

---

## Provable Security Model

### EUF-CMA Security

Steganographer's signature scheme provides **Existential Unforgeability under Chosen Message Attack (EUF-CMA)**:

- An adversary with access to a signing oracle (can request signatures on arbitrary frames) still cannot forge a valid signature on a *new* frame without the private key
- Ed25519 achieves EUF-CMA security under the Discrete Logarithm assumption on Curve25519

### Collision Resistance

BLAKE3 (and SHA-256/SHA-3-256) provides **128-bit collision resistance**: finding two distinct frame payloads with the same hash requires ~2^128 operations. This ensures:

- **Preimage resistance**: Given a hash, finding any frame that produces it is infeasible
- **Second preimage resistance**: Given a frame, finding another frame with the same hash is infeasible
- **Collision resistance**: Finding any two frames with the same hash is infeasible

---

## Post-Quantum Cryptography Considerations

### Current Vulnerability

Ed25519 relies on the hardness of the Elliptic Curve Discrete Logarithm Problem (ECDLP). Shor's algorithm on a sufficiently large quantum computer would solve ECDLP in polynomial time, breaking Ed25519.

### Migration Path

| Component | Current | Post-Quantum Replacement | Status |
| --- | --- | --- | --- |
| Signing | Ed25519 (64B sig) | ML-DSA-65 / Dilithium3 (3,309B sig) | FIPS 204 standardized |
| Hashing | BLAKE3 (32B) | BLAKE3 (unchanged) | Quantum-resistant (Grover: 128→64 bit, still safe) |
| Key generation | `OsRng` | `OsRng` (unchanged) | N/A |

**Impact on Steganography**: ML-DSA signatures are ~50× larger than Ed25519 (3,309 bytes vs 64 bytes). The payload would grow from 109 bytes to ~3,354 bytes, requiring ~26,832 pixel bytes at LSB-1 (still easily fits in a 640×480 frame with 921,600 bytes).

---

## Cryptographic Dependencies

| Crate | Version | Purpose | Audited |
| --- | --- | --- | --- |
| `blake3` | 1.5.x | Hashing (default) | [Official audits](https://github.com/BLAKE3-team/BLAKE3) |
| `sha2` | 0.10.x | SHA-256 hashing (FIPS 180-4) | Widely reviewed |
| `sha3` | 0.10.x | SHA-3-256 hashing (FIPS 202) + Keccak-256 for Ethereum | Widely reviewed |
| `ed25519-dalek` | 2.x | Ed25519 signing/verification | [Dalek audits](https://github.com/dalek-cryptography/ed25519-dalek) |
| `k256` | 0.13.x | secp256k1/Ethereum signing (feature-gated) | Reviewed |
| `chacha20poly1305` | 0.10.x | Payload encryption (AEAD) | Audited, RFC 8439 |
| `subtle` | 2.x | Constant-time comparison | Audited, anti-timing-attack |
| `rand` | 0.8.x | Key generation (OsRng) | Widely reviewed |

All dependencies use the standard Ed25519 specification (SHA-512 internal prehash per RFC 8032). The configurable hash algorithm (BLAKE3/SHA-256/SHA-3) is used **only** for hashing frame data, not as a replacement for Ed25519's internal hash.

---

## Further Reading

- [Steganography Theory](steganography-theory.md) — Information-theoretic foundations and steganalysis
- [Security](security.md) — Threat analysis and steganalysis resistance
- [Threat Model](threat-model.md) — Adversary types, attack scenarios, and residual risks
- [Algorithms](algorithms.md) — Implementation details of LSB embedding protocols
