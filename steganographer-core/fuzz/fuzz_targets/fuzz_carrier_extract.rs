#![no_main]

use libfuzzer_sys::fuzz_target;
use steganographer_core::carrier::{
    KeyedInterleavedSpatialLsb, KeyedSpatialLsb, SpatialLsb,
};
use steganographer_core::packet::LOCATOR_SIZE;
use steganographer_core::{CarrierExtractor, DecodeLimits, EmbeddingConfig};

fuzz_target!(|data: &[u8]| {
    // Bounded limits keep every decode attempt small while still exercising
    // the locator, TLV, and envelope branches of the extract paths.
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
        ..DecodeLimits::default()
    };

    // A key derived from the fuzz input exercises the keyed schedules; the
    // all-zero key (empty input) is a valid key too.
    let mut key = [0u8; 32];
    for (index, byte) in data.iter().cycle().take(32).enumerate() {
        key[index] = *byte;
    }

    // Arbitrary carrier bytes at every supported bits-per-unit strength:
    // no spatial-LSB extractor may ever panic. This pins the regression where
    // a carrier of exactly `tag_units` units reached the zero-length keyed
    // schedule construction and panicked (attacker-crafted DoS).
    for bits in 1..=4u8 {
        let config = match EmbeddingConfig::new(bits) {
            Ok(config) => config,
            Err(_) => continue,
        };
        let _ = SpatialLsb.extract_packet(data, &config, &limits);
        let _ = KeyedSpatialLsb::new(key).extract_packet(data, &config, &limits);
        let _ = KeyedInterleavedSpatialLsb::new(key).extract_packet(data, &config, &limits);
    }
});
