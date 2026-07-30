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
cargo +nightly fuzz run fuzz_packet_decode -- -max_total_time=60 -max_len=8192
```

## Targets

| Target | What it tests |
| ------ | ------------- |
| `fuzz_lsb_video_extract` | LSB video extraction never panics on adversarial input |
| `fuzz_payload_from_bytes` | SignaturePayload deserialization never panics on arbitrary bytes |
| `fuzz_rs_decode` | Reed-Solomon decode is bounded and never panics on crafted input (regression test for the DoS finding) |
| `fuzz_packet_decode` | Generic locator, canonical TLV envelope, limits, and body validation remain bounded and panic-free |

## CI

The main workflow runs bounded 60-second smoke sessions for every target on its
weekly schedule. A crash or sanitizer failure fails the job.
