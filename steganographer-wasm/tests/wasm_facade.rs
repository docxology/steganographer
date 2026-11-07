//! Native integration tests for the `steganographer-wasm` facade.
//!
//! These exercise the plain-Rust implementation, not wasm-bindgen's generated
//! JavaScript glue. Actual wasm32/Node/browser smoke coverage is also required
//! for JS number validation, report parsing, and platform-sized decode limits.

use serde_json::{json, Value};
use steganographer_core::carrier::{
    CarrierDescriptor, CarrierEmbedder, EmbeddingConfig, SpatialLsb,
};
use steganographer_core::packet::{crc32c, DecodeLimits, GenericPacket, Locator};
use steganographer_wasm::{
    capacity_pcm_s16le, capacity_rgb, decode_limits_default, decode_limits_from_json,
    embed_pcm_s16le, embed_rgb, extract_pcm_s16le, extract_rgb, forensic_scan, packet_decode,
    packet_encode, text_analyze_bytes, text_analyze_text, PACKET_REPORT_SCHEMA,
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

#[test]
fn packet_strength_is_validated_before_encoding() {
    for bits in [0, 5, 255] {
        assert!(
            packet_encode(b"payload".to_vec(), 1, vec![0; 16], vec![0; 8], bits, None).is_err(),
            "accepted strength {bits}"
        );
    }
    for bits in 1..=4 {
        let packet = encoded_packet(b"all supported strengths", bits);
        let units = (packet.len() * 8).div_ceil(usize::from(bits));
        let (rgb, _) = embed_rgb(vec![0x7f; units], &packet, bits).unwrap();
        assert_eq!(
            body_of(&extract_rgb(&rgb, bits, None).unwrap()),
            b"all supported strengths"
        );
        let (pcm, _) = embed_pcm_s16le(vec![0x7f; units * 2], &packet, bits).unwrap();
        assert_eq!(
            body_of(&extract_pcm_s16le(&pcm, bits, None).unwrap()),
            b"all supported strengths"
        );
    }
}

fn encode_modified_packet(mut packet: GenericPacket, limits: &DecodeLimits) -> Vec<u8> {
    let envelope = packet.envelope.encode(limits).unwrap();
    packet.locator = Locator::new(
        packet.locator.flags,
        envelope.len(),
        packet.body.len(),
        crc32c(&envelope),
        packet.locator.nonce,
        limits,
    )
    .unwrap();
    packet.encode(limits).unwrap()
}

#[test]
fn packet_reports_preserve_exact_u64_metadata() {
    let limits = DecodeLimits::default();
    for timestamp in [9_007_199_254_740_993, u64::MAX] {
        let mut packet =
            GenericPacket::decode(&encoded_packet(b"exact metadata", 4), &limits).unwrap();
        packet.envelope.created_at_unix = Some(timestamp);
        let encoded = encode_modified_packet(packet, &limits);
        let decoded = packet_decode(encoded.clone(), None).unwrap();
        // Exercise the JSON-string transport that the JS bindings use.
        let decoded: Value = serde_json::from_str(&decoded.to_string()).unwrap();
        assert_eq!(decoded["schema"], PACKET_REPORT_SCHEMA);
        assert_eq!(decoded["created_at_unix"], timestamp.to_string());
        assert_eq!(decoded["original_len"], "14");
        let (carrier, _) = embed_rgb(vec![0x7f; encoded.len() * 2], &encoded, 4).unwrap();
        let extracted = extract_rgb(&carrier, 4, None).unwrap();
        assert_eq!(extracted["created_at_unix"], timestamp.to_string());
        assert_eq!(extracted["original_len"], decoded["original_len"]);
    }
    assert!(packet_decode(encoded_packet(b"x", 1), None).unwrap()["created_at_unix"].is_null());
}

#[test]
fn raised_envelope_limits_round_trip_rgb_and_pcm() {
    let defaults = DecodeLimits::default();
    let filename = "f".repeat(defaults.max_envelope_len + 1);
    let limits = DecodeLimits {
        max_filename_len: filename.len(),
        max_field_len: filename.len(),
        max_envelope_len: filename.len() + 8192,
        ..defaults
    };
    let mut packet =
        GenericPacket::decode(&encoded_packet(b"raised limits", 4), &defaults).unwrap();
    packet.envelope.filename = Some(filename.clone());
    let encoded = encode_modified_packet(packet, &limits);
    assert!(packet_decode(encoded.clone(), None).is_err());
    assert_eq!(
        packet_decode(encoded.clone(), Some(limits)).unwrap()["filename"],
        filename
    );
    let (rgb, _) = embed_rgb(vec![0x7f; encoded.len() * 2], &encoded, 4).unwrap();
    assert!(extract_rgb(&rgb, 4, None).is_err());
    let report = extract_rgb(&rgb, 4, Some(limits)).unwrap();
    assert_eq!(body_of(&report), b"raised limits");
    assert_eq!(report["filename"], filename);
    let (pcm, _) = embed_pcm_s16le(vec![0x7f; encoded.len() * 4], &encoded, 4).unwrap();
    assert!(extract_pcm_s16le(&pcm, 4, None).is_err());
    let report = extract_pcm_s16le(&pcm, 4, Some(limits)).unwrap();
    assert_eq!(body_of(&report), b"raised limits");
    assert_eq!(report["filename"], filename);
}

#[test]
fn raised_body_limit_round_trips_above_default_ceiling() {
    let defaults = DecodeLimits::default();
    let len = defaults.max_body_len + 1;
    let limits = DecodeLimits {
        max_body_len: len,
        max_original_len: len,
        max_packet_len: defaults.max_packet_len + 1,
        ..defaults
    };
    let packet =
        packet_encode(vec![0xa5; len], 1, vec![0; 16], vec![0; 8], 4, Some(limits)).unwrap();
    assert!(packet_decode(packet.clone(), None).is_err());
    let carrier = vec![0x7f; packet.len() * 2];
    let capacity = capacity_rgb(&carrier, 4).unwrap();
    assert_eq!(capacity["max_packet_bytes"], packet.len());
    let (carrier, _) = embed_rgb(carrier, &packet, 4).unwrap();
    assert!(extract_rgb(&carrier, 4, None).is_err());
    let report = extract_rgb(&carrier, 4, Some(limits)).unwrap();
    let body = report["body"].as_array().unwrap();
    assert_eq!(body.len(), len);
    assert!(body.iter().all(|byte| byte.as_u64() == Some(0xa5)));
    assert_eq!(report["original_len"], len.to_string());
}

#[test]
fn forensic_reports_preserve_container_evidence_and_completeness() {
    let report =
        forensic_scan(b"%PDF-1.7\n1 0 obj\n<< /Type /EmbeddedFile /Length 0 >>\nendobj\n%%EOF\n");
    assert_eq!(report["container_detected"], true);
    assert_eq!(report["detected"], true);
    let evidence = report["container_findings"].as_array().unwrap();
    assert!(
        evidence.iter().any(|finding| {
            finding["family"] == "DOC-004"
                && finding["path"]
                    .as_str()
                    .is_some_and(|path| !path.is_empty())
                && finding["detail"]
                    .as_str()
                    .is_some_and(|detail| !detail.is_empty())
        }),
        "missing container evidence: {report}"
    );
    assert!(report["incomplete"].is_boolean());
    assert!(report["incomplete_reasons"].is_array());

    let report = forensic_scan(&vec![
        b'a';
        steganographer_core::unicode_text::MAX_TEXT_SCAN_BYTES
            + 1
    ]);
    assert_eq!(report["incomplete"], true);
    assert!(report["incomplete_reasons"]
        .as_array()
        .unwrap()
        .iter()
        .any(|reason| reason == "text_byte_limit"));
}

#[test]
fn invalid_decode_limit_shapes_and_platform_overflow_are_rejected() {
    for value in [
        json!([]),
        json!("limits"),
        json!({"max_body_len": 1.5}),
        json!({"max_body_len": -1}),
        json!({"max_body_len": "1024"}),
    ] {
        assert!(decode_limits_from_json(Some(&value)).is_err());
    }
    assert_eq!(
        decode_limits_from_json(Some(&Value::Null)).unwrap(),
        DecodeLimits::default()
    );
    let width_boundary = decode_limits_from_json(Some(&json!({"max_body_len": 4_294_967_296u64})));
    if usize::BITS == 32 {
        assert!(width_boundary.is_err());
    } else {
        assert_eq!(
            width_boundary.unwrap().max_body_len,
            4_294_967_296u64 as usize
        );
    }
}
