#![no_main]

use libfuzzer_sys::fuzz_target;
use steganographer_core::packet::LOCATOR_SIZE;
use steganographer_core::{DecodeLimits, GenericPacket, PacketEnvelope};

fuzz_target!(|data: &[u8]| {
    // Keep allocations deliberately small while still exercising every
    // locator, TLV, canonicalization, and body-validation branch.
    let limits = DecodeLimits {
        max_envelope_len: 4 * 1024,
        max_body_len: 4 * 1024,
        max_packet_len: 8 * 1024 + LOCATOR_SIZE,
        max_field_len: 1024,
        max_fields: 64,
        max_transforms: 16,
        max_extensions: 32,
        max_filename_len: 255,
        max_mime_len: 127,
    };

    let _ = GenericPacket::decode(data, &limits);
    if data.len() <= limits.max_envelope_len {
        let _ = PacketEnvelope::decode(data, &limits);
    }
});
