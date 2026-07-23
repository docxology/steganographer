# Key Rotation Record

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
2. **History scrubbed**: `git filter-repo` was used to remove `keys/daf.key`,
   `keys/daf.pub`, `output/demo_frame.rgb`, and `output/demo_frame_signed.rgb`
   from all commits in the repository history. The repo was force-pushed.
3. **.gitignore hardened**: Added `keys/`, `output/`, `*.key`, `*.pub` to
   `.gitignore`, mirroring the existing `.dockerignore` exclusions.
4. **Secret-scanning CI gate**: Added `gitleaks` to the CI pipeline
   (`.github/workflows/ci.yml`) with a custom `.gitleaks.toml` config.
   Any future key/credential leak will fail CI.
5. **File permissions**: The new private key has `0600` permissions
   (owner-read-write only), per the project's documented convention.

### New Public Key

```
81b125e627eb88d59959c493573c712b156e83a20c79b8b513b1bd366f4a2a9a
```

### Revoked Key

The old keypair (public key hash available in pre-rewrite history) is
revoked effective 2026-07-22. Any signature verifiable against the old
public key should be treated as untrusted, as the private key was exposed.

### Notification

Anyone with a clone or fork of this repository made before 2026-07-22
should:
1. Delete the old clone and re-clone from the rewritten history.
2. Delete any copy of `keys/daf.key` from their local filesystem.
3. Regenerate any keys they may have derived from or stored alongside
   the compromised key.
