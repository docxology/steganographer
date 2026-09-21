//! Native integration tests for the `steganographer-wasm` facade.
//!
//! The same [`api`] functions back the `#[wasm_bindgen]` exports (cfg-gated to
//! `wasm32`), so these tests exercise the exact logic the browser will call;
//! wasm32 target correctness is verified by
//! `cargo check --target wasm32-unknown-unknown -p steganographer-wasm`.

use serde_json::{json, Value};
use steganographer_core::carrier::{
    CarrierDescriptor, CarrierEmbedder, EmbeddingConfig, SpatialLsb,
};
use steganographer_wasm::{
    capacity_pcm_s16le, capacity_rgb, decode_limits_default, decode_limits_from_json,
    embed_pcm_s16le, embed_rgb, extract_pcm_s16le, extract_rgb, forensic_scan, packet_decode,
    packet_encode, text_analyze_bytes, text_analyze_text,
};

fn encoded_packet(payload: &[u8], bits: u8) -> Vec<u8> {
    packet_encode(
        payload.to_vec(),
        1, // PayloadKind::Bytes
        b"0123456789abcdef".to_vec(),
        b"nonce123".to_vec(),
        bits,
        None,
    )
    .expect("packet encodes")
}

fn body_of(report: &Value) -> Vec<u8> {
    report["body"]
        .as_array()
        .expect("body is an array")
        .iter()
        .map(|v| v.as_u64().expect("body byte") as u8)
        .collect()
}

// ─── RGB round trip ─────────────────────────────────────────────────────────

#[test]
fn rgb_embed_extract_round_trip() {
    let payload = b"hello from the wasm facade";
    let packet = encoded_packet(payload, 1);

    // Carrier must hold the packet: 1 bit per byte unit.
    let carrier = vec![0x7Fu8; packet.len() * 8 + 64];
    let capacity = capacity_rgb(&carrier, 1).expect("capacity computes");
    assert!(capacity["max_packet_bytes"].as_u64().unwrap() >= packet.len() as u64);

    let (laced, report) = embed_rgb(carrier.clone(), &packet, 1).expect("embed succeeds");
    assert_eq!(report.packet_bytes, packet.len());
    assert!(laced != carrier, "carrier bytes must change");

    let extracted = extract_rgb(&laced, 1, None).expect("extract succeeds");
    assert_eq!(body_of(&extracted), payload);
    assert_eq!(
        extracted["packet_id"],
        json!("30313233343536373839616263646566")
    );
    assert_eq!(extracted["payload_kind_name"], json!("bytes"));
    assert_eq!(extracted["bits_per_unit"], json!(1));

    // Decode path agrees with the extract path.
    let decoded = packet_decode(packet, None).expect("decode succeeds");
    assert_eq!(body_of(&decoded), payload);
}

#[test]
fn rgb_embed_rejects_oversized_packet_and_bad_bits() {
    let packet = encoded_packet(b"tiny", 2);
    // 2 bits per unit needs packet.len() * 4 bytes; provide two bytes less
    // so the packet is 4 bits short of the carrier's capacity.
    let carrier = vec![0x55u8; packet.len() * 4 - 2];
    let err = embed_rgb(carrier, &packet, 2).unwrap_err();
    assert!(err.contains("are available"), "unexpected error: {err}");

    let err = capacity_rgb(&[0u8; 64], 5).unwrap_err();
    assert!(err.contains("1-4"), "unexpected error: {err}");
}

// ─── S16LE PCM round trip ───────────────────────────────────────────────────

#[test]
fn pcm_embed_extract_round_trip() {
    let payload = b"pcm payload";
    let packet = encoded_packet(payload, 2);
    // Carrier units are samples (one 2-byte little-endian sample each); at
    // 2 bits per sample the carrier must hold packet.len() * 8 bits, i.e.
    // packet.len() * 4 samples = packet.len() * 8 bytes.
    let carrier_len = packet.len() * 8;
    let carrier: Vec<u8> = (0..carrier_len as u32)
        .map(|i| ((i * 251) & 0xFF) as u8)
        .collect();
    let high_bytes: Vec<u8> = carrier.iter().skip(1).step_by(2).copied().collect();

    let (laced, report) = embed_pcm_s16le(carrier.clone(), &packet, 2).expect("embed succeeds");
    assert_eq!(report.packet_bytes, packet.len());
    let laced_high: Vec<u8> = laced.iter().skip(1).step_by(2).copied().collect();
    assert_eq!(
        laced_high, high_bytes,
        "sample upper bits must be untouched"
    );

    let extracted = extract_pcm_s16le(&laced, 2, None).expect("extract succeeds");
    assert_eq!(body_of(&extracted), payload);
}

#[test]
fn pcm_rejects_odd_byte_length() {
    let packet = encoded_packet(b"x", 1);
    let err = embed_pcm_s16le(vec![0u8; 9], &packet, 1).unwrap_err();
    assert!(err.contains("not a multiple of the 2-byte unit size"));
    let err = capacity_pcm_s16le(&[0u8; 7], 1).unwrap_err();
    assert!(err.contains("not a multiple of the 2-byte unit size"));
}

// ─── Capacity parity with core kernels ──────────────────────────────────────

#[test]
fn capacity_matches_core_sequential_lsb() {
    let bits = 3;
    let byte_len = 10_000usize;
    let carrier = vec![0u8; byte_len];

    let wasm = capacity_rgb(&carrier, bits).expect("capacity computes");
    let core = SpatialLsb
        .capacity(
            &CarrierDescriptor::rgb8(byte_len),
            &EmbeddingConfig::new(bits).unwrap(),
        )
        .unwrap();

    assert_eq!(wasm["usable_units"], json!(core.usable_units as u64));
    assert_eq!(wasm["available_bits"], json!(core.available_bits as u64));
    assert_eq!(
        wasm["max_packet_bytes"],
        json!(core.max_packet_bytes as u64)
    );
    assert_eq!(wasm["usable_units"], json!(byte_len));
    assert_eq!(wasm["max_packet_bytes"], json!(byte_len / 8 * 3));
}

// ─── Forensics ──────────────────────────────────────────────────────────────

#[test]
fn forensic_scan_clean_vs_laced() {
    let clean = b"the quick brown fox jumps over the lazy dog. ".repeat(50);
    let report = forensic_scan(&clean);
    assert_eq!(report["detected"], json!(false));
    assert_eq!(report["embedded_magic"], Value::Null);
    assert_eq!(report["magic_offsets"], json!([]));
    assert_eq!(report["text_findings"], json!([]));

    let mut laced = clean;
    laced.extend_from_slice(b"STG3 embedded generic packet marker");
    let report = forensic_scan(&laced);
    assert_eq!(report["detected"], json!(true));
    assert_eq!(report["embedded_magic"], json!("generic_packet"));
    assert!(!report["magic_offsets"].as_array().unwrap().is_empty());
}

#[test]
fn text_analysis_finds_zero_width_and_bidi() {
    let stego_text =
        "hello\u{200b}\u{200b}\u{200b}\u{200b}\u{200b}\u{200b}\u{200b}\u{200b}world\u{202e}tail";
    let report = text_analyze_text(stego_text);
    let detectors: Vec<&str> = report
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|f| f["detector_id"].as_str())
        .collect();
    assert!(detectors.contains(&"ZERO_WIDTH"), "findings: {report:?}");
    assert!(detectors.contains(&"BIDI_CONTROLS"), "findings: {report:?}");

    // Non-UTF-8 bytes are not text and yield no findings (core convention).
    assert_eq!(text_analyze_bytes(&[0xFF, 0xFE, 0x00]), json!([]));
}

// ─── Decode limits ──────────────────────────────────────────────────────────

#[test]
fn decode_limits_default_json_round_trips() {
    let default = decode_limits_default();
    let limits = decode_limits_from_json(Some(&default)).expect("defaults parse");
    let core = steganographer_core::packet::DecodeLimits::default();
    assert_eq!(limits, core);

    // Partial override keeps the untouched defaults.
    let limits = decode_limits_from_json(Some(&json!({"max_body_len": 1024}))).expect("parses");
    assert_eq!(limits.max_body_len, 1024);
    assert_eq!(limits.max_fields, core.max_fields);

    assert!(decode_limits_from_json(Some(&json!({"bogus_field": 1}))).is_err());
    assert!(decode_limits_from_json(Some(&json!({"max_body_len": -1}))).is_err());
    assert_eq!(
        decode_limits_from_json(None).unwrap(),
        steganographer_core::packet::DecodeLimits::default()
    );
}

#[test]
fn decode_limits_are_enforced_on_decode_and_extract() {
    let payload = vec![0xA5u8; 4096];
    let packet = encoded_packet(&payload, 1);

    // Tight envelope limit rejects a perfectly valid packet.
    let err = packet_decode(
        packet.clone(),
        Some(
            decode_limits_from_json(Some(&json!({
                "max_envelope_len": 16
            })))
            .unwrap(),
        ),
    )
    .unwrap_err();
    assert!(err.contains("exceeds"), "unexpected error: {err}");

    // Default limits accept it and the body round-trips.
    let decoded = packet_decode(packet.clone(), None).expect("default limits accept");
    assert_eq!(body_of(&decoded), payload);

    // The same limits gate extraction from a carrier.
    let carrier = vec![0x7Fu8; packet.len() * 8 + 64];
    let (laced, _) = embed_rgb(carrier, &packet, 1).unwrap();
    let err = extract_rgb(
        &laced,
        1,
        Some(
            decode_limits_from_json(Some(&json!({
                "max_envelope_len": 16
            })))
            .unwrap(),
        ),
    )
    .unwrap_err();
    assert!(err.contains("exceeds"), "unexpected error: {err}");
    let extracted = extract_rgb(&laced, 1, None).expect("default limits accept");
    assert_eq!(body_of(&extracted), payload);
}
