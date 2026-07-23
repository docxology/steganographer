# Key Rotation and Revocation

## Verification policy

A signature authenticates a key relationship, not the real-world identity or continued authorization of its holder. Obtain and pin the expected public key through a trusted channel. The dashboard's advertised key is its actual runtime Ed25519 identity, but a key supplied with an artifact or manifest is not independent trust evidence. Raw core cryptographic primitives remain mathematical operations; applications must apply authorization and revocation policy.

For current managed CLI verification and recovery:

- Supply `--public-key` to verify; omitting it is extraction-only / not verified.
- `--revoked-list` adds a JSON array of hex public keys for `verify`, `decode` and `extract`. Omission reads `keys/revoked.json` when present. Explicit missing paths, malformed/unreadable files and dangling symlinks are errors.
- A revoked signature is a verification failure, **exit 3**, even when its mathematics is valid. Missing payload is **exit 2**.
- Registry updates use a persistent `<output>.lock` companion inode across the
  read/merge/atomic-publication transaction. Keep it in place; unlinking it splits
  cooperating lock owners. Advisory locking does not constrain unrelated writers.
- Generic decode/extract uses `--trusted-signer` for explicit pinning and applies revocation before payload publication, even without a pin. A pin never overrides revocation.
- Built-in revocations apply with an absent or empty local registry. Managed
  CLI signing and verification, native signed pipelines, and dashboard
  signing and processing enforce this policy.

## Replace a signing identity

1. Remove the retiring public key from active trust and record the revocation.
   The CLI creates or updates the registry atomically.

   ```bash
   steganographer revoke --public-key "$retired_public_key" --output keys/revoked.json
   ```

2. Distribute the updated policy through an authenticated channel to every
   verifier, including applications using the core library directly.
3. Generate an independent replacement signer in protected storage. Key
   generation creates private files with restrictive permissions and rejects
   unsafe existing paths. Authenticate the new public key before updating pins.
4. Rotate dependent secrets if they were derived from the retiring private key.
   Apply the verifier's own policy to previously signed media and keep the
   retired signer out of active trust.
