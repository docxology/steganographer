# OpenTimestamps (OTS) Integration

The steganographer workspace includes an **opt-in** OpenTimestamps
integration that anchors BLAKE3 Merkle roots to the Bitcoin (or Ethereum)
blockchain via [OpenTimestamps](https://opentimestamps.org). This provides
**independently verifiable timestamp attestation** for every signed stego
segment — proof that a piece of content existed at a specific point in time,
without trusting any single party.

## What OTS adds

| Without OTS | With OTS |
| --- | --- |
| Ed25519/secp256k1 signature proves **who** signed and **integrity** | Signature + blockchain timestamp proves **who**, **integrity**, **and when** |
| No external attestation | Anchored to Bitcoin blockchain (independently verifiable) |
| Tampering detectable by signature check | Tampering detectable **and** creation time provable |

### How it works

1. The stego pipeline builds a BLAKE3 **hash chain** (Merkle tree) over
   signed frame payloads.
2. When OTS is enabled, the SHA-256 of the current Merkle root is submitted
   to an OpenTimestamps calendar server (`POST /api/v1/timestamp`).
3. The server returns a binary `.ots` proof file that attests the digest was
   seen by the calendar at a given time. The calendar periodically commits
   batches of digests to the Bitcoin blockchain.
4. The `.ots` proof is saved to disk under the configured `proof_dir`. Only
   a small digest + method + timestamp reference is carried in the
   **packet envelope extension fields** — the full proof is never embedded in
   carrier media.
5. Later, anyone can verify the proof (`POST /api/v1/verify`) to confirm the
   content was timestamped on-chain.

> **Graceful degradation.** If the OTS server is unreachable, the stego
> pipeline continues normally — no stamp is recorded, and the dashboard
> shows "unavailable" rather than erroring. OTS is purely additive.

## CLI usage

### Stamp a file's Merkle root

```bash
steganographer ots stamp --input merkle_root.bin \
    --output-dir ots_proofs --method bitcoin --format json
```

| Flag | Default | Description |
| --- | --- | --- |
| `--input` | (required) | File whose contents will be SHA-256 hashed and stamped |
| `--output-dir` | from config / `ots_proofs` | Directory for the `.ots` proof file |
| `--method` | `bitcoin` | Attestation method: `bitcoin` or `ethereum` |
| `--force` | `false` | Overwrite an existing proof file |
| `--format` | `plain` | Output format: `plain` or `json` |

### Verify a proof

```bash
steganographer ots verify --input merkle_root.bin --proof merkle_root.ots --format json
```

| Flag | Default | Description |
| --- | --- | --- |
| `--input` | (required) | Original file that was stamped |
| `--proof` | (required) | Path to the `.ots` proof file |
| `--format` | `plain` | Output format: `plain` or `json` |

JSON output includes `verified`, `method`, `timestamp`, and `details` fields.

## Configuration

OTS is configured under the `[ots]` block in `steganographer.toml`. When the
block is absent or `enabled = false`, the feature is completely disabled and
the project behaves exactly as before — no network calls, no proof files.

```toml
[ots]
enabled = true
server_url = "https://opentimestamps.org"
method = "bitcoin"           # or "ethereum"
interval_secs = 300          # min seconds between stamps (default: 5 min)
proof_dir = "ots_proofs"     # where .ots files are written
timeout_secs = 30            # HTTP request timeout
```

| Field | Default | Description |
| --- | --- | --- |
| `enabled` | `false` | Master switch |
| `server_url` | `https://opentimestamps.org` | Calendar server base URL |
| `method` | `bitcoin` | Blockchain attestation method |
| `interval_secs` | `300` | Minimum interval between stamps (rate-limiting) |
| `proof_dir` | `ots_proofs` | Directory for `.ots` proof files |
| `timeout_secs` | `30` | HTTP timeout for OTS server calls |

## Dashboard usage

When the dashboard is launched with OTS enabled in the config, three REST
endpoints are available:

| Endpoint | Method | Description |
| --- | --- | --- |
| `/ots/status` | GET | Current OTS configuration + readiness status |
| `/ots/stamp` | POST | Stamp the current Merkle root immediately |
| `/ots/verify` | POST | Verify a `.ots` proof file |

The dashboard includes an **OTS panel** (served from `/ots.js`) that shows:

- **Status indicator** — green (ready), grey (disabled), or red (unavailable)
- **Last timestamp** — the Unix time of the most recent on-chain attestation
- **Proof count** — total `.ots` proofs generated this session
- **Verified** — whether the last proof verified successfully
- **Stamp Now** button — triggers an immediate stamp via `POST /ots/stamp`

WebSocket metrics streams also include OTS fields
(`ots_proofs_count`, `ots_last_timestamp`, `ots_verified`) so the UI updates
in real time.

## Proof files

Proof files are named `<digest-hex>.ots` and stored in `proof_dir`. They are
standard OpenTimestamps binary proofs and can be verified independently with
the `ots` CLI tool or any OTS-compatible verifier:

```bash
ots verify merkle_root.ots
```

## Security notes

- The `.ots` proof attests to `SHA-256(merkle_root)` where `merkle_root` is a
  BLAKE3 digest — OTS protocol requires SHA-256.
- Proof files are **external** to the carrier media. Only a 32-byte digest
  reference + 1-byte method tag + 8-byte timestamp are carried in the packet
  envelope.
- Stamping rate is limited by `interval_secs` to avoid flooding the calendar
  server. The `Stamp Now` button respects this rate limit.
- If the OTS server is down, the dashboard shows "unavailable" — the stego
  pipeline is never blocked.
