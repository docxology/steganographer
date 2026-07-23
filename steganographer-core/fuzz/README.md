# Fuzz Targets

These are proper `cargo-fuzz` targets that run under `libfuzzer-sys`.

## Running

```bash
# Install cargo-fuzz (requires nightly Rust)
cargo +nightly install cargo-fuzz

# Run each target (from the steganographer-core/ directory)
cd steganographer-core
cargo +nightly fuzz run fuzz_lsb_video_extract -- -max_total_time=60
cargo +nightly fuzz run fuzz_payload_from_bytes -- -max_total_time=60
cargo +nightly fuzz run fuzz_rs_decode -- -max_total_time=60
```

## Targets

| Target | What it tests |
| ------ | ------------- |
| `fuzz_lsb_video_extract` | LSB video extraction never panics on adversarial input |
| `fuzz_payload_from_bytes` | SignaturePayload deserialization never panics on arbitrary bytes |
| `fuzz_rs_decode` | Reed-Solomon decode is bounded and never panics on crafted input (regression test for the DoS finding) |

## CI

Fuzzing is not run in CI by default (requires nightly + is time-unbounded).
To add a short smoke run, add a job that runs `cargo +nightly fuzz run <target> -- -max_total_time=30`.
