#![no_main]

use libfuzzer_sys::fuzz_target;
use steganographer_core::packet::{DecodeLimits, GenericPacket};
use steganographer_core::EncryptionKey;

/// Fuzz [`GenericPacket::decode_nested`] (PKT-009) with arbitrary byte input.
///
/// The nested decoder must never panic and must never allocate beyond the
/// configured ceilings (per-packet locator bounds checked from the fixed
/// locator before any variable-size allocation, plus the aggregate nested
/// bytes ceiling checked from each child's locator before its body is
/// decoded) — whatever the input. Truncated, corrupt, and hostile chains
/// simply return typed errors.
///
/// The target runs keyless and with a fixed raw key: the keyless pass
/// exercises framing/CRC/envelope/missing-key paths, the keyed run exercises
/// the AEAD path (bogus bodies just fail authentication). No password is
/// supplied, so the Argon2id path fails closed at the typed missing-key check
/// without spending a derivation on hostile descriptors.
fuzz_target!(|data: &[u8]| {
    let limits = DecodeLimits::default();
    // Keyless: framing, CRC, envelope, nesting bounds, and missing-key paths.
    let _ = GenericPacket::decode_nested(data, &limits, None, None);
    // Fixed key: exercises the AEAD path on any decodable packet.
    let key = EncryptionKey::from_bytes(&[0x5Au8; 32]);
    let _ = GenericPacket::decode_nested(data, &limits, Some(&key), None);
});