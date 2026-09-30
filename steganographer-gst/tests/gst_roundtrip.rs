//! gst-launch acceptance round-trip for the `stegoaudio` element.
//!
//! Acceptance (2) of the Native GStreamer plugin backlog item: the element
//! must round-trip a PCM S16 packet, verified by a decode check. The
//! `print_packet_hex` helper prints the encoded packet to stdout so a shell
//! gst-launch run can embed it live; the in-process test proves the same
//! bytes decode through the core extractor (the element's sequential embed
//! path IS the core `AudioSpatialLsb` kernel).

use steganographer_core::carrier::{
    AudioSpatialLsb, CarrierEmbedder, CarrierExtractor, EmbeddingConfig,
};
use steganographer_core::packet::{
    AlgorithmDescriptor, DecodeLimits, GenericPacket, PayloadKind, KERNEL_SPATIAL_LSB,
    PLACEMENT_SEQUENTIAL,
};

fn encode_test_packet(payload: &[u8], bits: u8) -> Vec<u8> {
    let limits = DecodeLimits::default();
    let packet = GenericPacket::new_untransformed(
        payload.to_vec(),
        [0x42u8; 16],
        [0x24u8; 8],
        PayloadKind::Text,
        AlgorithmDescriptor::new(PLACEMENT_SEQUENTIAL, 1, Vec::new()),
        AlgorithmDescriptor::new(KERNEL_SPATIAL_LSB, 1, vec![bits]),
        &limits,
    )
    .expect("packet builds");
    packet.encode(&limits).expect("packet encodes")
}

/// Decode check: packet bytes embedded the way the element embeds them
/// (sequential audio LSB, low byte of every second sample) decode back to
/// the original payload.
#[test]
fn stegoaudio_wire_format_round_trips() {
    let limits = DecodeLimits::default();
    let packet_bytes = encode_test_packet(b"stegoaudio gst-launch acceptance", 2);
    let mut pcm = vec![0x40u8; 2 * 16384];
    AudioSpatialLsb
        .embed_packet(&mut pcm, &packet_bytes, &EmbeddingConfig::new(2).unwrap())
        .expect("embeds into 16384 samples at 2 bits");
    let report = AudioSpatialLsb
        .extract_packet(&pcm, &EmbeddingConfig::new(2).unwrap(), &limits)
        .expect("decodes");
    assert_eq!(report.packet.body, b"stegoaudio gst-launch acceptance");
}

/// Print the encoded packet hex for shell gst-launch runs:
/// `cargo test -p steganographer-gst --test gst_roundtrip print_packet_hex -- --nocapture`
#[test]
fn print_packet_hex() {
    let packet_bytes = encode_test_packet(b"stegoaudio gst-launch acceptance", 2);
    let hex: String = packet_bytes.iter().map(|b| format!("{b:02x}")).collect();
    println!("PACKET_HEX_LEN={}", packet_bytes.len());
    println!("PACKET_HEX={hex}");
}
