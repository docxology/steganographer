//! Real lexical/coverage regressions. No renderer, network or fixture rewrites.
use flate2::write::{DeflateEncoder, ZlibEncoder};
use std::io::Write;
use steganographer_core::forensics::{
    analyze_pdf, scan_bytes, ContainerAnalysis, FileFamily, DOC_004_FAMILY, MAX_MAGIC_FINDINGS,
    MAX_MAGIC_SCAN_BYTES, PDF_MAX_OBJECTS_SCANNED,
};
use steganographer_core::{unicode_text, wasm_inspector};

fn pdf(objects: &[Vec<u8>], before_xref: &[u8]) -> Vec<u8> {
    let mut out = b"%PDF-1.7\n".to_vec();
    let mut offsets = Vec::new();
    for (index, body) in objects.iter().enumerate() {
        offsets.push(out.len());
        out.extend_from_slice(format!("{} 0\tobj\n", index + 1).as_bytes());
        out.extend_from_slice(body);
        out.extend_from_slice(b"\nendobj\n");
    }
    out.extend_from_slice(before_xref);
    let xref = out.len();
    out.extend_from_slice(
        format!("xref\n0 {}\n0000000000 65535 f \n", objects.len() + 1).as_bytes(),
    );
    for offset in offsets {
        out.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(
        format!(
            "trailer\n<</Size {}>>\nstartxref\n{xref}\n%%EOF\n",
            objects.len() + 1
        )
        .as_bytes(),
    );
    out
}

fn has(result: &ContainerAnalysis, text: &str) -> bool {
    result
        .findings
        .iter()
        .any(|finding| finding.family == DOC_004_FAMILY && finding.detail.contains(text))
}

fn partial(result: &ContainerAnalysis, code: &str) -> bool {
    result
        .incomplete_reasons
        .iter()
        .any(|reason| reason == code)
}

fn stream(bytes: &[u8], filter: &str) -> Vec<u8> {
    let mut out = format!("<</Length {} {filter}>>\nstream\n", bytes.len()).into_bytes();
    out.extend_from_slice(bytes);
    out.extend_from_slice(b"\nendstream");
    out
}

#[test]
fn pdf_tokens_respect_whitespace_escapes_strings_and_comments() {
    let suspicious = pdf(
        &[b"<</Title(endobj stream /Image)/Type/Embedded#46ile>>".to_vec()],
        b"",
    );
    let result = analyze_pdf(&suspicious);
    assert!(result.detected);
    assert!(has(&result, "/EmbeddedFile"));
    assert!(
        result.incomplete_reasons.is_empty(),
        "{:?}",
        result.incomplete_reasons
    );

    let prose = pdf(&[b"<</Title(This text describes /JavaScript and endobj stream)/Note<2F4A53>>>\n% /Launch /OpenAction\n".to_vec()], b"");
    let result = analyze_pdf(&prose);
    assert!(!result.detected, "{:?}", result.findings);
    assert!(result.incomplete_reasons.is_empty());
}

#[test]
fn every_direct_uri_is_classified_in_either_order() {
    for (first, second) in [
        ("https://example.org/", "file:///etc/passwd"),
        ("file:///etc/passwd", "https://example.org/"),
    ] {
        let object =
            format!("<</A<</S/URI/URI({first})/Next<</S/URI/URI({second})>>>>>>").into_bytes();
        let result = analyze_pdf(&pdf(&[object], b""));
        assert!(result.detected);
        assert!(has(&result, "scheme file:"));
        assert!(result
            .findings
            .iter()
            .any(|finding| finding.detail.contains("scheme https:")));
    }
    let clean = analyze_pdf(&pdf(
        &[b"<</S/URI/URI(https://example.org/)>>".to_vec()],
        b"",
    ));
    assert!(!clean.detected);
    assert!(clean.incomplete_reasons.is_empty());
}

#[test]
fn standard_zlib_flate_recovers_text_but_raw_deflate_is_incomplete() {
    let text = b"(\\342\\200\\256)";
    let mut zlib = ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    zlib.write_all(text).unwrap();
    let zlib = zlib.finish().unwrap();
    let result = analyze_pdf(&pdf(&[stream(&zlib, "/Filter/FlateDecode")], b""));
    assert!(has(&result, "BIDI_CONTROLS"));
    assert!(
        result.incomplete_reasons.is_empty(),
        "{:?}",
        result.incomplete_reasons
    );

    let mut raw = DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    raw.write_all(text).unwrap();
    let raw = raw.finish().unwrap();
    let result = analyze_pdf(&pdf(&[stream(&raw, "/Filter/FlateDecode")], b""));
    assert!(!result.detected);
    assert!(partial(&result, "pdf_flate_invalid"));
}

#[test]
fn unsupported_filter_chain_and_object_stream_are_not_clean_negatives() {
    let result = analyze_pdf(&pdf(
        &[stream(b"ignored", "/Filter[/ASCII85Decode/FlateDecode]")],
        b"",
    ));
    assert!(!result.detected);
    assert!(partial(&result, "pdf_filter_unsupported"));
    let result = analyze_pdf(&pdf(&[stream(b"ignored", "/Type/ObjStm")], b""));
    assert!(partial(&result, "pdf_object_stream_unsupported"));
}

#[test]
fn structural_image_subtype_not_title_prose_controls_stream_exemption() {
    let mut object = stream(b"(\\342\\200\\256)", "");
    drop(object.splice(2..2, b"/Title(/Image stream endobj)".iter().copied()));
    let result = analyze_pdf(&pdf(&[object], b""));
    assert!(has(&result, "BIDI_CONTROLS"));
}

#[test]
fn nested_image_names_cannot_exempt_the_outer_stream() {
    let object = stream(b"(\\342\\200\\256)", "/Note<</Subtype/Image>>");
    let result = analyze_pdf(&pdf(&[object], b""));
    assert!(has(&result, "BIDI_CONTROLS"));
}

#[test]
fn bounded_stream_search_stops_at_its_window_without_erasing_positive_names() {
    for suffix in [8 * 1024 * 1024 - 1, 8 * 1024 * 1024 + 1] {
        let mut data = b"%PDF-1.7\n1 0 obj\n<</Type/EmbeddedFile/Length 0>>\nstream\n".to_vec();
        data.extend_from_slice(&vec![b'A'; suffix]);
        let result = analyze_pdf(&data);
        assert!(result.detected);
        assert!(has(&result, "/EmbeddedFile"));
        assert!(partial(&result, "pdf_stream_unterminated"));
        assert!(!result
            .findings
            .iter()
            .any(|finding| finding.detail.contains("after the last %%EOF")));
    }
}

#[test]
fn oversized_pdf_keeps_examined_positive_and_reports_byte_cutoff() {
    let mut data = pdf(&[b"<</Type/EmbeddedFile>>".to_vec()], b"");
    data.resize(64 * 1024 * 1024 + 1, b' ');
    let result = analyze_pdf(&data);
    assert!(result.detected);
    assert!(has(&result, "/EmbeddedFile"));
    assert!(partial(&result, "pdf_file_byte_limit"));
}

#[test]
fn pdf_utf16_text_and_multibyte_aggregate_boundary_preserve_positives() {
    let result = analyze_pdf(&pdf(&[b"<</Title<FEFF0041200B0042>>>".to_vec()], b""));
    assert!(has(&result, "ZERO_WIDTH"));
    assert!(result.incomplete_reasons.is_empty());

    // Exact review boundary: before the last e-acute, 1 MiB minus two bytes.
    let mut objects = vec![b"<</Title<E280AE>>>".to_vec()];
    for _ in 0..255 {
        objects.push(format!("<</Title({})>>", "A".repeat(4095)).into_bytes());
    }
    objects.push(format!("<</Title({})>>", "A".repeat(4090)).into_bytes());
    objects.push(b"<</Title<C3A9>>>".to_vec());
    let result = analyze_pdf(&pdf(&objects, b""));
    assert!(has(&result, "BIDI_CONTROLS"));
    assert!(partial(&result, "pdf_text_byte_limit"));
}

#[test]
fn pdf_string_and_inflate_caps_retain_earlier_positive_evidence() {
    let result = analyze_pdf(&pdf(
        &[format!("<</Title(\\342\\200\\256{})>>", "A".repeat(5000)).into_bytes()],
        b"",
    ));
    assert!(has(&result, "BIDI_CONTROLS"));
    assert!(partial(&result, "pdf_string_limit"));

    let mut decoded = b"(\\342\\200\\256)\n".to_vec();
    decoded.extend_from_slice(&vec![b'A'; 256 * 1024]);
    let mut zlib = ZlibEncoder::new(Vec::new(), flate2::Compression::best());
    zlib.write_all(&decoded).unwrap();
    let compressed = zlib.finish().unwrap();
    let result = analyze_pdf(&pdf(&[stream(&compressed, "/Filter/FlateDecode")], b""));
    assert!(has(&result, "BIDI_CONTROLS"));
    assert!(partial(&result, "pdf_inflate_limit"));
}

#[test]
fn pdf_stream_count_cutoff_is_explicit_and_keeps_prior_evidence() {
    let mut encoder = ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(b"(clean)").unwrap();
    let clean = encoder.finish().unwrap();
    let mut objects = vec![b"<</Type/EmbeddedFile>>".to_vec()];
    for _ in 0..17 {
        objects.push(stream(&clean, "/Filter/FlateDecode"));
    }
    let result = analyze_pdf(&pdf(&objects, b""));
    assert!(result.detected);
    assert!(partial(&result, "pdf_inflate_limit"));
}

#[test]
fn pdf_display_cap_does_not_erase_positive_latch_or_visible_summary() {
    for observations in [63, 64, 65] {
        let mut objects = vec![b"<</AcroForm<</Fields[]>>>>".to_vec(); observations];
        objects.push(b"<</S/JavaScript/JS(run())>>".to_vec());
        let result = analyze_pdf(&pdf(&objects, b""));
        assert!(result.detected);
        assert!(result.findings.len() <= 64);
        assert!(has(&result, "JavaScript"));
        assert!(partial(&result, "pdf_finding_limit"));
    }
}

#[test]
fn eof_inventory_tracks_actual_final_marker_after_thousands_of_comments() {
    for comments in [4095, 4096, 4097] {
        let result = analyze_pdf(&pdf(&[b"<<>>".to_vec()], &b"% %%EOF\n".repeat(comments)));
        assert!(!result.detected, "{:?}", result.findings);
        assert!(result.incomplete_reasons.is_empty());
        assert!(result
            .findings
            .iter()
            .any(|finding| finding.detail.contains("1 %%EOF marker")));
    }
    let revisions = b"%%EOF\n".repeat(4097);
    let result = analyze_pdf(&pdf(&[b"<<>>".to_vec()], &revisions));
    assert!(!result.detected);
    assert!(result
        .findings
        .iter()
        .any(|finding| finding.detail.contains("4098 %%EOF marker")));
}

#[test]
fn pdf_object_cutoff_and_unterminated_large_suffix_are_bounded() {
    let objects = vec![b"<<>>".to_vec(); PDF_MAX_OBJECTS_SCANNED + 1];
    let result = analyze_pdf(&pdf(&objects, b""));
    assert!(!result.detected);
    assert!(partial(&result, "pdf_object_limit"));

    // Parent should run this test under a hard timeout. The old implementation
    // searched the entire 32 MiB suffix 8192 times; this lexer traverses once.
    let mut hostile = b"%PDF-1.7\n".to_vec();
    hostile.extend_from_slice(&b" obj".repeat(8192));
    hostile.extend_from_slice(&vec![b'A'; 32 * 1024 * 1024]);
    let result = analyze_pdf(&hostile);
    assert!(!result.detected);
    assert!(!result.incomplete_reasons.is_empty());
}

#[test]
fn bounded_top_level_text_magic_and_wasm_projection_are_honest() {
    let mut text = "A\u{202e}".as_bytes().to_vec();
    text.resize(unicode_text::MAX_TEXT_SCAN_BYTES - 1, b'A');
    text.extend_from_slice("é".as_bytes());
    text.push(0xff); // Invalid suffix beyond the bounded UTF-8 prefix.
    let scan = scan_bytes(&text);
    assert!(scan
        .text_findings
        .iter()
        .any(|finding| finding.detector_id == unicode_text::BIDI_CONTROLS));
    assert!(scan.incomplete);
    assert!(scan
        .incomplete_reasons
        .iter()
        .any(|code| code == "text_byte_limit"));
    let report = wasm_inspector::inspect_bytes(&text);
    assert!(report.incomplete);
    assert!(report
        .text_findings
        .iter()
        .any(|finding| finding.detector_id == unicode_text::BIDI_CONTROLS));

    let mut magic = vec![b'A'; MAX_MAGIC_SCAN_BYTES];
    magic.extend_from_slice(b"STG3");
    let scan = scan_bytes(&magic);
    assert!(scan.embedded_magic.is_none());
    assert!(scan
        .incomplete_reasons
        .iter()
        .any(|code| code == "magic_byte_limit"));
    let scan = scan_bytes(&b"STG3".repeat(MAX_MAGIC_FINDINGS + 1));
    assert!(scan.detected);
    assert_eq!(scan.magic_matches.len(), MAX_MAGIC_FINDINGS);
    assert!(scan
        .incomplete_reasons
        .iter()
        .any(|code| code == "magic_finding_limit"));

    let data = pdf(&[b"<</Type/EmbeddedFile>>".to_vec()], b"");
    let report = wasm_inspector::inspect_bytes(&data);
    assert!(report.container_detected);
    assert!(report
        .container_findings
        .iter()
        .any(|finding| finding.family == DOC_004_FAMILY));
    let mut prefixed = vec![0];
    prefixed.extend_from_slice(&data);
    let scan = scan_bytes(&prefixed);
    assert_eq!(scan.file_family, FileFamily::Pdf);
    assert!(scan.container_detected);
}

#[test]
fn zip_analysis_wiring_distinguishes_inventory_from_partial_coverage() {
    let mut comment_signature = b"PK\x05\x06".to_vec();
    comment_signature.extend_from_slice(&[0; 16]);
    comment_signature.extend_from_slice(b"\x04\x00PK\x05\x06");
    let scan = scan_bytes(&comment_signature);
    assert_eq!(scan.file_family, FileFamily::Zip);
    assert!(!scan.container_findings.is_empty());
    assert!(!scan.container_detected);
    assert!(!scan.detected);
    assert!(!scan.incomplete, "{:?}", scan.incomplete_reasons);

    let mut split = b"PK\x05\x06".to_vec();
    split.extend_from_slice(&[0; 18]);
    split[4..6].copy_from_slice(&1u16.to_le_bytes());
    split[6..8].copy_from_slice(&1u16.to_le_bytes());
    let scan = scan_bytes(&split);
    assert!(scan.incomplete);
    assert!(!scan.container_detected);
    assert!(!scan.detected);
}
