# Key Rotation Record

## Current Verification and Rotation Policy

A signature authenticates a key relationship, not the real-world identity or continued authorization of its holder. Obtain and pin the expected public key through a trusted channel. The dashboard's advertised key is its actual runtime Ed25519 identity, but a key supplied with an artifact or manifest is not independent trust evidence. Raw core cryptographic primitives remain mathematical operations; applications must apply authorization and revocation policy.

For current managed CLI verification and recovery:

- Supply `--public-key` to verify; omitting it is extraction-only / not verified.
- `--revoked-list` adds a JSON array of hex public keys for `verify`, `decode` and `extract`. Omission reads `keys/revoked.json` when present. Explicit missing paths, malformed/unreadable files and dangling symlinks are errors.
- A revoked signature is a verification failure, **exit 3**, even when its mathematics is valid. Missing payload is **exit 2**. Do not treat either as success.
- Add a compromised key with `steganographer revoke --public-key <old-public-key-hex> --output keys/revoked.json`, distribute the policy through a trusted channel, then provision/pin a fresh signer separately.
- Generic decode/extract uses `--trusted-signer` for explicit pinning and applies revocation before payload publication, even without a pin. A pin never overrides revocation.
- The exposed identity below is always revoked by the shared core policy, independently of missing or empty local registries. Managed CLI signing, native signed pipelines and dashboard router/processing APIs reject it.

Key generation creates private files with restrictive permissions and rejects unsafe existing paths. Permissions and deletion cannot retract a leaked key or signatures already forged with it. Rotate dependent secrets where appropriate, preserve incident evidence and distinguish pre-/post-compromise trust according to external policy.

## Historical Incident Record

The dated account below records the earlier incident and remediation, not actions performed for the current release. The recorded replacement public key is not a globally trusted default or proof of current custody.

## 2026-07-22 — Emergency Rotation (daf.key leak)

### Incident

A real Ed25519 private signing key (`keys/daf.key`) was committed to this
public repository in the first release commit (`5dcb2e2`, 2026-03-08) and
remained tracked at HEAD until discovered during a security audit on
2026-07-22. The key was confirmed live (its derived public key matched
`keys/daf.pub` byte-for-byte).

### Root Cause

`.dockerignore` excluded `keys/`, `output/`, `*.key`, `*.pub` as sensitive,
but `.gitignore` had no equivalent rule. Docker builds were protected;
git commits were not.

### Remediation

1. **Key rotated**: The compromised keypair has been replaced with a new
   Ed25519 keypair generated locally via `steganographer keygen --output keys/daf`.
   The old key should be considered compromised and revoked.
2. **History remains exposed**: Earlier remediation notes claimed a rewrite,
   but current reachable history still contains the exposed blob in commit
   `5dcb2e2669e135cd32f6d2615d279f1f0d8dbf35`. Do not rely on a scrub claim.
3. **.gitignore hardened**: Added `keys/`, `output/`, `*.key`, `*.pub` to
   `.gitignore`, mirroring the existing `.dockerignore` exclusions.
4. **Secret-scanning CI gate**: Current provider/file rules reject new exposures.
   The sole historical acknowledgment in `.gitleaksignore` is scoped to the
   documented commit/path/rule/line; no key-value or directory waiver applies.
5. **File permissions**: The new private key has `0600` permissions
   (owner-read-write only), per the project's documented convention.

### Recorded Replacement Public Key

```
81b125e627eb88d59959c493573c712b156e83a20c79b8b513b1bd366f4a2a9a
```

### Revoked Key

The exposed public identity is
`d2a05f7c69249dbfba5408dd8c35551317b04bfcc6f793c5e76221778c61d552`,
declared revoked effective 2026-07-22. Its signatures are untrusted even when
mathematically valid. The recorded replacement above is not a trusted default
or evidence of current private-key custody.

### Notification

Clones and forks may retain the exposed seed. Users of that identity should:

1. Remove it from active trust and distribute the revocation through a trusted channel.
2. Provision an independent replacement signer and authenticate its full public key.
3. Rotate derived/related secrets as appropriate; preserve necessary incident evidence
   and securely remove unneeded private copies. Deleting a clone alone is not revocation.
