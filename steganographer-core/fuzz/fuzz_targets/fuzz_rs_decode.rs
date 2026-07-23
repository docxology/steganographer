#![no_main]

use steganographer_core::error_correction;
use libfuzzer_sys::fuzz_target;

// Fuzz Reed-Solomon decode: must never panic or run unboundedly on adversarial input.
// This is a direct regression test for the DoS finding (unbounded brute-force loop).
fuzz_target!(|data: &[u8]| {
    if data.len() < 6 {
        return;
    }
    // Derive data_len and parity_count from the first 2 bytes
    let data_len = (data[0] as usize).min(128);
    let parity_count = ((data[1] % 16) + 1) as usize;
    let encoded = &data[2..];
    // decode() should return an error or a result — it must never panic
    // or run for an unreasonable amount of time
    let _ = error_correction::decode(encoded, data_len, parity_count);
});
