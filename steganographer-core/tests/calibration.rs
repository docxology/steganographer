//! FOR-001 calibration corpus runner (roadmap v0.8.0).
//!
//! Loads `testdata/corpus/manifest.json`, generates every benign/triggered
//! sample deterministically from the manifest's generator specs, runs
//! [`steganographer_core::forensics::scan_bytes`] over each, and asserts the
//! expected per-detector finding counts. Also asserts that the manifest and
//! [`steganographer_core::forensics::detector_registry`] cover exactly the
//! same detector IDs.
//!
//! Corpus samples are generated, never stored: every fixture is a small
//! deterministic byte array (<= 64 KiB) built from the manifest specs, so no
//! hand-computed hashes are involved.

use std::collections::HashSet;

use serde_json::Value;

use steganographer_core::forensics::{
    self, FileFamily, ForensicScan, DOC_001_FAMILY, DOC_002_FAMILY, ZIP_TOPOLOGY_FAMILY,
};

const MANIFEST: &str = include_str!("../testdata/corpus/manifest.json");

/// The hand-shuffled 26-letter alphabet used by `balanced_ascii`: every byte
/// value pair (2i, 2i+1) ends up count-balanced, keeping the statistical
/// detectors quiet so each detector is calibrated in isolation.
const BALANCED_ALPHABET: &str = "anbocpdqerfsgthuivjwkxlym";

/// Generate a corpus sample from one manifest `benign`/`triggered` spec.
fn corpus_bytes(spec: &Value) -> Vec<u8> {
    let kind = spec["kind"].as_str().expect("generator kind");
    match kind {
        "balanced_ascii" => BALANCED_ALPHABET
            .repeat(spec["reps"].as_u64().unwrap_or(3) as usize)
            .into_bytes(),
        "ascending_ramp" => (0u16..256)
            .map(|v| v as u8)
            .cycle()
            .take(spec["reps"].as_u64().unwrap_or(1) as usize * 256)
            .collect(),
        "even_ramp" => (0u16..128)
            .map(|v| (v * 2) as u8)
            .cycle()
            .take(spec["reps"].as_u64().unwrap_or(1) as usize * 128)
            .collect(),
        "png_header" => {
            let mut data = b"\x89PNG\r\n\x1a\n".to_vec();
            data.extend_from_slice(BALANCED_ALPHABET.as_bytes());
            data
        }
        "inline_packet_magic" => b"report body STG3 tail".to_vec(),
        "text_zero_width" => {
            let pairs = spec["run_pairs"].as_u64().unwrap_or(6) as usize;
            let mut text = String::from("lorem ipsum ");
            for i in 0..pairs * 2 {
                text.push(if i % 2 == 0 { '\u{200B}' } else { '\u{200C}' });
            }
            text.push_str(" dolor sit");
            text.into_bytes()
        }
        "text_variation_selector" => "lorem ipsum a\u{E0100} tail".to_string().into_bytes(),
        "text_bidi" => "abc\u{202E}def".to_string().into_bytes(),
        "text_trailing_whitespace" => {
            let lines = spec["lines"].as_u64().unwrap_or(6) as usize;
            let run = spec["run"].as_u64().unwrap_or(4) as usize;
            let mut text = String::new();
            for line in 0..lines {
                text.push_str(&format!("line {line}"));
                text.push_str(&" ".repeat(run));
                text.push('\n');
            }
            text.into_bytes()
        }
        "text_homoglyph" => "p\u{0430}ypal account".to_string().into_bytes(),
        "docx_clean" => docx(BALANCED_ALPHABET.repeat(3).as_str(), None),
        "docx_laced" => {
            let pairs = spec["run_pairs"].as_u64().unwrap_or(6) as usize;
            let mut body = BALANCED_ALPHABET.to_string();
            for i in 0..pairs * 2 {
                body.push(if i % 2 == 0 { '\u{200B}' } else { '\u{200C}' });
            }
            docx(&body, None)
        }
        "docx_oversized_claim" => docx(
            BALANCED_ALPHABET,
            // Claim ~2 GiB uncompressed for the main part (central directory lie).
            Some(0x7FFF_FFFF),
        ),
        "zip_generic" => zip(
            vec![("notes/readme.txt", BALANCED_ALPHABET.as_bytes().to_vec())],
            &[],
        ),
        other => panic!("unknown corpus generator kind: {other}"),
    }
}

fn crc32(data: &[u8]) -> u32 {
    let mut table = [0u32; 256];
    for (i, slot) in table.iter_mut().enumerate() {
        let mut c = i as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
        }
        *slot = c;
    }
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc = table[((crc ^ b as u32) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc ^ 0xFFFF_FFFF
}

/// Assemble a minimal deterministic ZIP (stored entries only) with optional
/// central-directory uncompressed-size lies for hostile fixtures.
fn zip(entries: Vec<(&str, Vec<u8>)>, lies: &[(&str, u32)]) -> Vec<u8> {
    let lie_for =
        |name: &str| -> Option<u32> { lies.iter().find(|(n, _)| *n == name).map(|(_, u)| *u) };
    let mut out: Vec<u8> = Vec::new();
    let mut central: Vec<u8> = Vec::new();
    for (name, data) in &entries {
        let offset = out.len() as u32;
        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes()); // version needed
        out.extend_from_slice(&0u16.to_le_bytes()); // flags
        out.extend_from_slice(&0u16.to_le_bytes()); // method: stored
        out.extend_from_slice(&0u16.to_le_bytes()); // mod time
        out.extend_from_slice(&0u16.to_le_bytes()); // mod date
        out.extend_from_slice(&crc32(data).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // extra len
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(data);

        central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes()); // version made by
        central.extend_from_slice(&20u16.to_le_bytes()); // version needed
        central.extend_from_slice(&0u16.to_le_bytes()); // flags
        central.extend_from_slice(&0u16.to_le_bytes()); // method
        central.extend_from_slice(&0u16.to_le_bytes()); // mod time
        central.extend_from_slice(&0u16.to_le_bytes()); // mod date
        central.extend_from_slice(&crc32(data).to_le_bytes());
        central.extend_from_slice(&(data.len() as u32).to_le_bytes());
        central.extend_from_slice(&lie_for(name).unwrap_or(data.len() as u32).to_le_bytes());
        central.extend_from_slice(&(name.len() as u16).to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes()); // extra
        central.extend_from_slice(&0u16.to_le_bytes()); // comment
        central.extend_from_slice(&0u16.to_le_bytes()); // disk start
        central.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        central.extend_from_slice(&0u32.to_le_bytes()); // external attrs
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name.as_bytes());
    }
    let cd_offset = out.len() as u32;
    let cd_size = central.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // disk
    out.extend_from_slice(&0u16.to_le_bytes()); // cd disk
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // comment len
    out
}

/// A minimal WordprocessingML package: `[Content_Types].xml` plus
/// `word/document.xml` with `body` in the first text run, stored uncompressed
/// so the fixture bytes are fully deterministic. `lie_uncompressed` overrides
/// the main part's claimed central-directory size.
fn docx(body: &str, lie_uncompressed: Option<u32>) -> Vec<u8> {
    let content_types =
        b"<Types><Default Extension=\"xml\" ContentType=\"application/xml\"/></Types>";
    let document = format!(
        "<w:document xmlns:w=\"w\"><w:body><w:p><w:r><w:t>{body}</w:t></w:r></w:p></w:body></w:document>"
    )
    .into_bytes();
    let entries = vec![
        ("[Content_Types].xml", content_types.to_vec()),
        ("word/document.xml", document),
    ];
    let lies: Vec<(&str, u32)> = match lie_uncompressed {
        Some(size) => vec![("word/document.xml", size)],
        None => Vec::new(),
    };
    zip(entries, &lies)
}

/// Findings attributed to one detector ID from a completed scan.
fn detector_count(id: &str, scan: &ForensicScan) -> usize {
    match id {
        "STAT_CHI2" => scan.statistical.chi_squared.detected as usize,
        "STAT_SPA" => scan.statistical.sample_pairs.detected as usize,
        "STAT_RS" => scan.statistical.rs_analysis.detected as usize,
        "MAGIC_FILE_FAMILY" => (scan.file_family != FileFamily::Unknown) as usize,
        "MAGIC_EMBEDDED" => scan.magic_matches.len(),
        "ZERO_WIDTH"
        | "VARIATION_SELECTORS"
        | "BIDI_CONTROLS"
        | "WHITESPACE_ANOMALY"
        | "HOMOGLYPH_SUSPECT" => scan
            .text_findings
            .iter()
            .filter(|f| f.detector_id == id)
            .count(),
        "ZIP_TOPOLOGY" => container_family_count(scan, ZIP_TOPOLOGY_FAMILY),
        "DOC-001" => container_family_count(scan, DOC_001_FAMILY),
        "DOC-002" => container_family_count(scan, DOC_002_FAMILY),
        other => panic!("unknown detector id in manifest: {other}"),
    }
}

fn container_family_count(scan: &ForensicScan, family: &str) -> usize {
    scan.container_findings
        .iter()
        .filter(|f| f.family == family)
        .count()
}

#[test]
fn calibration_corpus_matches_manifest() {
    let manifest: Value = serde_json::from_str(MANIFEST).expect("parse corpus manifest");
    let entries = manifest["detectors"].as_array().expect("detectors array");
    let registry = forensics::detector_registry();

    let mut manifest_ids: Vec<&str> = Vec::new();
    for entry in entries {
        let id = entry["id"].as_str().expect("detector id");
        assert!(
            registry.iter().any(|d| d.id == id),
            "manifest id {id} is not in the detector registry"
        );
        manifest_ids.push(id);

        let expected = entry["expected"].as_object().expect("expected counts");
        let benign_expected = expected["benign_findings"].as_u64().expect("benign count") as usize;
        let triggered_expected = expected["triggered_findings"]
            .as_u64()
            .expect("triggered count") as usize;

        let benign = corpus_bytes(&entry["benign"]);
        let triggered = corpus_bytes(&entry["triggered"]);
        assert!(benign.len() <= 64 * 1024 && triggered.len() <= 64 * 1024);

        let benign_scan = forensics::scan_bytes(&benign);
        assert_eq!(
            detector_count(id, &benign_scan),
            benign_expected,
            "benign sample for {id} triggered unexpectedly: {:?}",
            benign_scan.message
        );

        let triggered_scan = forensics::scan_bytes(&triggered);
        assert_eq!(
            detector_count(id, &triggered_scan),
            triggered_expected,
            "triggered sample for {id} did not produce the expected findings: {:?}",
            triggered_scan.message
        );
    }

    // Reverse coverage: every registered detector has a corpus entry.
    for detector in registry {
        assert!(
            manifest_ids.contains(&detector.id),
            "registry id {} has no corpus entry",
            detector.id
        );
    }
    // No duplicate manifest entries.
    let unique = manifest_ids.iter().collect::<HashSet<_>>().len();
    assert_eq!(unique, manifest_ids.len(), "duplicate manifest detector id");
}

#[test]
fn corpus_samples_are_deterministic() {
    let manifest: Value = serde_json::from_str(MANIFEST).expect("parse corpus manifest");
    for entry in manifest["detectors"].as_array().expect("detectors array") {
        let benign = corpus_bytes(&entry["benign"]);
        let again = corpus_bytes(&entry["benign"]);
        assert_eq!(
            benign, again,
            "generator for {} is not deterministic",
            entry["id"]
        );
        let triggered = corpus_bytes(&entry["triggered"]);
        assert_eq!(triggered, corpus_bytes(&entry["triggered"]));
    }
}
