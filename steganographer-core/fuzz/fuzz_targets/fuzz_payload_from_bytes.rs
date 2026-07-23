#![no_main]

use steganographer_core::crypto::SignaturePayload;
use libfuzzer_sys::fuzz_target;

// Fuzz SignaturePayload::from_bytes: must never panic on arbitrary 109-byte input.
fuzz_target!(|data: &[u8]| {
    if data.len() != SignaturePayload::SERIALIZED_SIZE {
        return;
    }
    let mut arr = [0u8; SignaturePayload::SERIALIZED_SIZE];
    arr.copy_from_slice(data);
    let _ = SignaturePayload::from_bytes(&arr);
    let _ = SignaturePayload::has_valid_magic(data);
});
