# Getting Started

## Requirements and build

Rust **1.91+** is required. `rust-toolchain.toml` selects the development stable
toolchain; CI additionally checks the declared 1.91 floor with all features.
See [Compatibility](compatibility.md) for the dependency/API justification.

```bash
git clone https://github.com/docxology/steganographer.git
cd steganographer

# Offline CLI + dashboard, without native GStreamer video/audio commands
cargo build -p steganographer-cli --no-default-features --locked
```

Use `target/debug/steganographer` below (or install/place the binary on PATH).
All examples assume a repository-root working directory and fresh output
paths. Existing outputs are not silently clobbered.

GStreamer is optional for this walkthrough. To build the full native workspace,
install development libraries and then build with default features:

```bash
# macOS
brew install gstreamer

# Debian/Ubuntu
sudo apt install libgstreamer1.0-dev libgstreamer-plugins-base1.0-dev \
  gstreamer1.0-plugins-good gstreamer1.0-plugins-bad gstreamer1.0-tools

cargo build --workspace --locked
```

Platform/plugin availability is not proof of camera, microphone or virtual
device operation. See [Platforms](platforms.md), especially Windows limitations.

## 1. Create a persistent signing identity

```bash
target/debug/steganographer keygen --output mykey
```

Keep `mykey.key` private; share/pin `mykey.pub` through a trusted channel.
Key generation refuses existing files (including links). Unix secret files are
created mode 0600 before their contents are written. A public key identifies a
key, not independently a person or organization.

## 2. Sign and verify a raw RGB carrier

```bash
# A 100x100 RGB frame; no image encoder required
dd if=/dev/urandom of=frame.rgb bs=30000 count=1

target/debug/steganographer encode -i frame.rgb -o signed.rgb \
  --stego-type lsb_video --bits 1 --signing-key mykey.key

target/debug/steganographer verify -i signed.rgb \
  --public-key "$(cat mykey.pub)" --bits auto --format json
```

Expect a `steganographer.cli/v1` envelope with `status: "success"` and
`result.status: "valid"`. `--bits auto` really probes supported depths.
Omitting `--public-key` yields **extraction-only** `not_verified`; it does not
verify authenticity. Absence is exit 2; invalid or revoked-key verification is
exit 3, with an error envelope retaining the result.

This is a legacy format-4 carrier attestation over canonical media bytes, not
a signature over every container byte or arbitrary visual metadata. Do not
convert the output to JPEG or assume transcoding preserves its LSBs.

## 3. Embed and recover a signed generic payload

Generic STG3 protocol-v1 packets hold logical payload bytes, distinct from
legacy carrier attestations. Opt in explicitly:

```bash
target/debug/steganographer encode -i frame.rgb -o packed.rgb \
  --payload-text 'A signed message' --signing-key mykey.key --bits 2

target/debug/steganographer decode -i packed.rgb -o message.txt \
  --bits auto --trusted-signer "$(cat mykey.pub)" --format json
```

Use `--payload-file report.pdf` for arbitrary bytes, with a large enough
carrier. PNG/raw RGB and PCM16 WAV/raw S16LE LSB are supported. Generic mode
supports optional keyed placement, signing, compression, encryption and ECC;
not multi-frame spreading. A packet's embedded signer key alone is not trusted
identity: `--trusted-signer` pins the expected key and rejects unsigned or
mismatched packets. Signatures authenticate logical payload, not arbitrary
envelope metadata or media provenance.

## 4. Password-protect a generic packet

Create a private password file using your normal secret-management workflow;
do not put a password directly in shell history or process arguments.

```bash
target/debug/steganographer encode -i frame.rgb -o encrypted.rgb \
  --payload-text 'Private signed message' --password-file secret.txt \
  --signing-key mykey.key --bits 2

target/debug/steganographer extract -i encrypted.rgb -o private.txt \
  --password-file secret.txt --trusted-signer "$(cat mykey.pub)"
```

Decode and extract share bounded validation, digest checks and transform
reversal. Explicit raw keys use `--encryption-key-file` on **encode** and
`--decryption-key-file` on **both decode and extract**. Old extract encryption-key
spellings are not aliases. Passwords conflict with explicit encryption keys;
legacy encode rejects password flags instead of ignoring them. JSON encoding
requires recoverable supplied keys/passwords when a secret would otherwise be
generated and lost; secrets are not serialized.

Decode/extract refuse existing payload files unless `--force` is explicit.
Force atomically replaces the destination entry without truncating another
file referenced by a symlink/hardlink. Explicit invalid config or revocation
files fail; there is no silent fallback to trusted-looking defaults.

## 5. Launch the sampled-artifact dashboard

```bash
target/debug/steganographer --config config/example.toml dashboard \
  --backend ed25519 --transport websocket --port 8080
```

Open <http://localhost:8080> and grant browser camera/microphone permission if
you choose those inputs. The dashboard signs sampled PNG frames and PCM audio
chunks using its actual session Ed25519 identity, and verifies delivered media.
Only Ed25519 + BLAKE3 + LSB is supported live; no Ethereum/MetaMask signing or
live encryption/ECC. Unavailable overlay controls are disabled; opacity affects
preview only, not signed evidence bytes.

Record downloads are stored-ZIP archives containing signed PNG snapshots or
PCM WAV chunks plus extraction manifests. They are **not continuous signed
video or uninterrupted microphone recordings**. Manifest public keys, bit
depths, chunk indices and audio placement keys are needed for independent CLI
verification; live metrics alone do not prove the downloads. Release validation
independently checked downloaded PNG and WAV artifacts against the separately
queried public API identity, including wrong-identity and high-bit-tamper
rejection. That demonstrates the sampled export path, not physical-hardware or
continuous-media coverage.

Keep the default loopback bind. Network exposure requires authentication and
an appropriate deployment boundary. Optional WebRTC needs the `webrtc` feature;
auto transport may fall back, while pinned unavailable WebRTC fails visibly.
Lossy H.264 preview is not signed archive evidence.

## 6. Native test source (optional GStreamer build)

```bash
target/debug/steganographer --config config/example.toml video \
  --source 'videotestsrc ! videoconvert ! video/x-raw,format=RGB' \
  --sink 'fakesink' --max-frames 20 --signing-key mykey.key
```

Shipped defaults select one LSB signing kernel. Mixing signing with visible
`overlay`/`info_bar` modules is rejected; visible rendering is separate.
Native signed audio supports LSB only; native trait SS signing is not the
offline CLI SS scalar path. Live crypto/ECC/spreading are unsupported; use
offline encode instead. Offline legacy spreading supports RGB LSB, 2–8 shards
only.

The macOS CLI owns Cocoa main-loop dispatch for live commands. Library callers
own their own application loop; headless native file APIs do not start Cocoa.
Exact native file outputs use RGB Matroska `.mkv` or PCM `.wav`, not arbitrary
lossy sinks. See [GStreamer](gstreamer.md) for exact-file contracts.

## Configuration, OTS and migration

- Validate with `target/debug/steganographer --config steganographer.toml config check`.
  `[limits]` are effective generic extraction/parse/transform ceilings;
  `scan --profile` is the only CLI profile selection surface.
- Bitcoin is the only OTS method. `ots stamp -i file` commits SHA-256 of the
  exact file; proofs default to configured `proof_dir/<digest-hex>.ots`, also
  used by `ots verify -i file`. Pending is not verified. See
  [OTS Integration](ots-integration.md) for protocol and provider trust.
- Legacy formats 2/3 require re-encoding source media to format 4; legacy
  encrypted data now uses the versioned `STGE` wrapper with fresh packet IDs.
  There is no old raw zero-ID fallback. Generic STG3 v1 remains wire-compatible.
- WASM packet reports use `steganographer.packet-report.v2`; all `u64` values
  are exact decimal strings, not rounded JavaScript numbers.

## Development checks

```bash
cargo test --workspace --locked
cargo test --workspace --all-features --locked
cargo test -p steganographer-core --locked
```

Test totals belong in root `AGENTS.md`, not duplicated walkthrough assertions.
These commands are instructions, not a claim that a particular platform run
has been exercised here.

## Further reading

[CLI Reference](cli-reference.md) · [Configuration](configuration.md) ·
[Compatibility](compatibility.md) · [Security](security.md) ·
[API Reference](api-reference.md) · [WASM](../steganographer-wasm/README.md)
