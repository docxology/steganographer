#![no_main]

use libfuzzer_sys::fuzz_target;
use steganographer_core::packet::TransformDescriptor;
use steganographer_core::transforms::{reverse, TransformContext};
use steganographer_core::EncryptionKey;

// Fuzz transforms::reverse with adversarial bodies and descriptors.
//
// Input layout (best-effort; truncated input is fine):
// packet_id:       [u8; 16]
// payload_kind:    u16 BE
// original_len:    u32 BE (may claim up to 4 GiB)
// transform_count: u8 (clamped to 8)
// per transform:   algorithm u16 BE, version u8, critical u8,
//                  params_len u16 BE (clamped to 256), params
// remainder:       encoded body
//
// Exercise missing-key/unauthenticated paths and AEAD with a fixed key.
// The decoder must remain panic-free and honor its internal allocation caps.
fuzz_target!(|data: &[u8]| {
    if data.len() < 23 {
        return;
    }
    let mut packet_id = [0u8; 16];
    packet_id.copy_from_slice(&data[..16]);
    let payload_kind = u16::from_be_bytes([data[16], data[17]]);
    let original_len = u32::from_be_bytes([data[18], data[19], data[20], data[21]]) as u64;

    let mut cursor = 22usize;
    let transform_count = usize::from(data[cursor]).min(8);
    cursor += 1;

    let mut transforms = Vec::with_capacity(transform_count);
    for _ in 0..transform_count {
        if data.len() - cursor < 6 {
            break;
        }
        let algorithm = u16::from_be_bytes([data[cursor], data[cursor + 1]]);
        let version = data[cursor + 2];
        let critical = data[cursor + 3] != 0;
        let params_len =
            usize::from(u16::from_be_bytes([data[cursor + 4], data[cursor + 5]])).min(256);
        cursor += 6;
        if data.len() - cursor < params_len {
            break;
        }
        transforms.push(TransformDescriptor {
            algorithm,
            version,
            critical,
            parameters: data[cursor..cursor + params_len].to_vec(),
        });
        cursor += params_len;
    }

    let body = &data[cursor..];
    let context = TransformContext {
        packet_id: &packet_id,
        payload_kind,
        original_len,
    };

    // Without a key: exercises missing-key, ECC geometry, decompression, and
    // signature paths. With a key: exercises the AEAD path (bogus bodies just
    // fail authentication).
    let _ = reverse(body, &context, None, &transforms, original_len);
    let key = EncryptionKey::from_bytes(&[0x5Au8; 32]);
    let _ = reverse(body, &context, Some(&key), &transforms, original_len);
});
