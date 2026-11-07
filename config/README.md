# Configuration examples

`example.toml` is the annotated default CLI configuration. The root
`steganographer.toml` is an alternative selected explicitly.

```bash
steganographer --config config/example.toml config check
steganographer --config steganographer.toml config check --format json
steganographer --config config/example.toml encode \
  --input frame.rgb --output signed.rgb --signing-key mykey.key
```

Both shipped signed pipelines are LSB-only. Overlay/info-bar settings are
inactive unless selected, and visible modules must not be mixed with signed
invisible kernels. Live encryption/ECC/spreading are unsupported; use offline
encode for supported transforms. Offline legacy spreading is RGB LSB, 2–8
shards only. Legacy payload format is 4; old formats require re-encoding.

Inline example keys are public examples. Use separately retained key files for
real placement/encryption, and prefer password files over command-line secrets.
Machine output never serializes secrets; workflows that would lose generated
secrets in JSON must supply recoverable credentials.

Explicit missing/invalid config fails rather than silently falling back.
`[limits]` applies to generic packet recovery and transforms; named profiles
are selected by `scan --profile`. OTS supports Bitcoin only; proof paths are
configured `proof_dir/<digest-hex>.ots` for SHA-256 input commitments.

See [Configuration](../docs/configuration.md) for actual fields and consumer
limitations, [CLI Reference](../docs/cli-reference.md) for flags, and
[OTS Integration](../docs/ots-integration.md) for protocol details.
