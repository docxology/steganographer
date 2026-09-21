//! Structural forensic detectors for the standard media scan.
//!
//! Complements the statistical detectors in [`crate::steganalysis`] with cheap,
//! content-agnostic probes that need no container parsing: Shannon entropy,
//! magic-byte file identification, and embedded signature/packet-magic scanning.
//! Every probe here is non-recursive and bounded — it only looks at the bytes it
//! is given and never opens containers, follows links, or touches the network.
//! Unicode/text steganography probes delegate to [`crate::unicode_text`];
//! see [`detect_text_stego`].

use crate::steganalysis::{self, CombinedResult};
use crate::unicode_text;

mod ooxml;

pub use ooxml::{
    analyze_package, OoxmlError, ZipArchive, ZipEntry, CONTAINER_MAX_ENTRIES,
    CONTAINER_MAX_ENTRY_NAME_BYTES, CONTAINER_MAX_EOCD_SCAN_BYTES, CONTAINER_MAX_FINDINGS,
    CONTAINER_MAX_INFLATE_PER_ENTRY, CONTAINER_MAX_INFLATE_TOTAL, DOC_001_FAMILY, DOC_002_FAMILY,
    ZIP_TOPOLOGY_FAMILY,
};

/// Shannon entropy of a byte buffer, in bits per byte (`0.0 ..= 8.0`).
///
/// An empty buffer has entropy `0.0`. High entropy is expected for already
/// compressed or encrypted formats and is reported as an observation, not as a
/// detection on its own.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &counts {
        if count == 0 {
            continue;
        }
        let probability = count as f64 / len;
        entropy -= probability * probability.log2();
    }
    entropy
}

/// Broad file family identified by leading magic bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileFamily {
    Png,
    Jpeg,
    Gif,
    WebP,
    Wav,
    Bmp,
    Tiff,
    Pdf,
    Zip,
    Gzip,
    Tar,
    Ogg,
    Flac,
    Unknown,
}

impl FileFamily {
    /// Lowercase, stable identifier for reports.
    pub fn as_str(&self) -> &'static str {
        match self {
            FileFamily::Png => "png",
            FileFamily::Jpeg => "jpeg",
            FileFamily::Gif => "gif",
            FileFamily::WebP => "webp",
            FileFamily::Wav => "wav",
            FileFamily::Bmp => "bmp",
            FileFamily::Tiff => "tiff",
            FileFamily::Pdf => "pdf",
            FileFamily::Zip => "zip",
            FileFamily::Gzip => "gzip",
            FileFamily::Tar => "tar",
            FileFamily::Ogg => "ogg",
            FileFamily::Flac => "flac",
            FileFamily::Unknown => "unknown",
        }
    }
}

/// Identify a file family from leading magic bytes.
///
/// The probe reads at most the first 12 bytes and never decodes the file.
pub fn detect_file_family(data: &[u8]) -> FileFamily {
    if data.starts_with(b"\x89PNG\r\n\x1a\n") {
        return FileFamily::Png;
    }
    if data.starts_with(b"\xff\xd8\xff") {
        return FileFamily::Jpeg;
    }
    if data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a") {
        return FileFamily::Gif;
    }
    if data.len() >= 12 && &data[0..4] == b"RIFF" && &data[8..12] == b"WEBP" {
        return FileFamily::WebP;
    }
    if data.len() >= 12 && &data[0..4] == b"RIFF" && &data[8..12] == b"WAVE" {
        return FileFamily::Wav;
    }
    if data.starts_with(b"BM") {
        return FileFamily::Bmp;
    }
    if data.starts_with(b"II*\x00") || data.starts_with(b"MM\x00*") {
        return FileFamily::Tiff;
    }
    if data.starts_with(b"%PDF") {
        return FileFamily::Pdf;
    }
    if data.starts_with(b"PK\x03\x04")
        || data.starts_with(b"PK\x05\x06")
        || data.starts_with(b"PK\x07\x08")
    {
        return FileFamily::Zip;
    }
    if data.starts_with(b"\x1f\x8b") {
        return FileFamily::Gzip;
    }
    if data.starts_with(b"fLaC") {
        return FileFamily::Flac;
    }
    if data.starts_with(b"OggS") {
        return FileFamily::Ogg;
    }
    if data.len() >= 262 && &data[257..262] == b"ustar" {
        return FileFamily::Tar;
    }
    FileFamily::Unknown
}

/// An embedded steganographic magic recovered from a raw byte scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmbeddedMagic {
    /// Legacy `STEG` v2 `SignaturePayload` magic.
    LegacySignature,
    /// Generic packet `STG3` magic.
    GenericPacket,
}

impl EmbeddedMagic {
    pub fn as_str(&self) -> &'static str {
        match self {
            EmbeddedMagic::LegacySignature => "legacy_signature",
            EmbeddedMagic::GenericPacket => "generic_packet",
        }
    }
}

/// A specific location match for an embedded magic header found inline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmbeddedMagicMatch {
    pub magic: EmbeddedMagic,
    pub offset: usize,
}

/// Scan `data` for an embedded `STEG` (legacy) or `STG3` (generic) magic.
///
/// This finds signatures/packets that are stored *inline* in the raw bytes
/// (attachments, raw carriers, unencoded payloads). LSB/spectral carriers that
/// spread the payload across low bits are not detected here; those are covered
/// by the statistical detectors.
pub fn detect_embedded_magic(data: &[u8]) -> Option<EmbeddedMagic> {
    for window in data.windows(4) {
        if window == b"STEG" {
            return Some(EmbeddedMagic::LegacySignature);
        }
        if window == b"STG3" {
            return Some(EmbeddedMagic::GenericPacket);
        }
    }
    None
}

/// Find all occurrences and byte offsets of inline steganographic magics.
pub fn detect_embedded_magics_detailed(data: &[u8]) -> Vec<EmbeddedMagicMatch> {
    let mut matches = Vec::new();
    for (offset, window) in data.windows(4).enumerate() {
        if window == b"STEG" {
            matches.push(EmbeddedMagicMatch {
                magic: EmbeddedMagic::LegacySignature,
                offset,
            });
        } else if window == b"STG3" {
            matches.push(EmbeddedMagicMatch {
                magic: EmbeddedMagic::GenericPacket,
                offset,
            });
        }
    }
    matches
}

/// Scan decoded text for Unicode/text steganography markers (FOR-005).
///
/// Thin adapter over [`crate::unicode_text`]: validates UTF-8 and applies the
/// module's bounded 1 MiB scan cap. Non-UTF-8 buffers yield no text findings
/// (they are not text). Reported offsets are character offsets into the
/// decoded text, not byte offsets.
pub fn detect_text_stego(data: &[u8]) -> Vec<unicode_text::TextFinding> {
    unicode_text::analyze_bytes(data)
}

/// Byte budget for the inline embedded-magic scan: [`scan_bytes`] scans at
/// most the first [`MAX_MAGIC_SCAN_BYTES`] bytes for `STEG`/`STG3` magics.
pub const MAX_MAGIC_SCAN_BYTES: usize = 16 * 1024 * 1024;

/// One container-aware finding: an evidence location, the detector family
/// that produced it, and a bounded human-readable detail line.
///
/// Pinned contract (FOR-001, plan spec 03): `scan_bytes` fills
/// [`ForensicScan::container_findings`] for ZIP-family inputs. `path` is the
/// evidence location (a ZIP entry name, or `<package>` for package-level
/// evidence); `family` is a stable detector family ID —
/// `ooxml::ZIP_TOPOLOGY_FAMILY` (inventory observation, never triggers
/// `detected`), `ooxml::DOC_001_FAMILY` (package anomalies), or
/// `ooxml::DOC_002_FAMILY` (WordprocessingML concealment; triggers
/// `detected`); `detail` is bounded, human-readable evidence that never
/// reconstructs a hidden payload.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ContainerFinding {
    /// Evidence location: ZIP entry path or package-level location.
    pub path: String,
    /// Stable detector family/ID that produced the finding.
    pub family: String,
    /// Bounded human-readable evidence detail.
    pub detail: String,
}

/// A registered forensic detector's stable metadata (FOR-001; plan spec 03).
///
/// The registry documents every detector family behind [`scan_bytes`], fixes
/// its ID, budget, false-positive limits, and calibration notes, and drives
/// the detector ordering used by `scan_bytes` (statistical → magic → text →
/// container).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DetectorInfo {
    /// Stable detector ID used in reports and the calibration corpus.
    pub id: &'static str,
    /// One-line summary of what the detector observes.
    pub summary: &'static str,
    /// Bounded budget (bytes scanned / inflated / findings emitted).
    pub budget: &'static str,
    /// Documented false-positive limitations.
    pub fp_limits: &'static str,
    /// How the detector is calibrated against the corpus.
    pub calibration: &'static str,
}

/// The FOR-001 detector registry: one entry per detector family behind
/// [`scan_bytes`], in scan order.
///
/// Statistical adapters (`STAT_*`) run first, then the magic probes
/// (`MAGIC_*`), the Unicode/text detectors (stable IDs shared with
/// [`crate::unicode_text`]), and finally the container detectors
/// (`ZIP_TOPOLOGY`, `DOC-001`, `DOC-002`). The calibration corpus
/// (`testdata/corpus/manifest.json`) maps every ID here to benign/triggered
/// samples; `tests/calibration.rs` asserts the outcomes.
pub fn detector_registry() -> &'static [DetectorInfo] {
    &[
        DetectorInfo {
            id: "STAT_CHI2",
            summary: "Chi-squared attack over byte-value pairs (LSB embedding equalizes pair histograms).",
            budget: "single pass over the full input, O(n) time, constant memory",
            fp_limits: "high-entropy compressed/encrypted data can fire; reported as an observation backed by confidence, never a verdict alone",
            calibration: "benign: smooth gradient bitmap; triggered: LSB-laced bitmap (corpus STAT_CHI2)",
        },
        DetectorInfo {
            id: "STAT_SPA",
            summary: "Sample-pair analysis of LSB deviations between adjacent sample pairs.",
            budget: "single pass over the full input, O(n) time, constant memory",
            fp_limits: "natural noise-heavy imagery can produce weak positives; confidence below the aggregate threshold is ignored",
            calibration: "benign: smooth gradient bitmap; triggered: LSB-laced bitmap (corpus STAT_SPA)",
        },
        DetectorInfo {
            id: "STAT_RS",
            summary: "RS analysis of group regularity under LSB flipping, estimating the embedding rate.",
            budget: "single pass over the full input with fixed 8-byte groups",
            fp_limits: "dithered or quantized media can shift the discriminant; weak results are folded into the combined verdict",
            calibration: "benign: smooth gradient bitmap; triggered: LSB-laced bitmap (corpus STAT_RS)",
        },
        DetectorInfo {
            id: "MAGIC_FILE_FAMILY",
            summary: "Identify a file family from leading magic bytes (observation accompanying every scan).",
            budget: "first 12 bytes of input (262 bytes for tar ustar)",
            fp_limits: "prefix match only; extended headers, polyglots, and prepended-data containers are not resolved",
            calibration: "benign: plain text (unknown); triggered: PNG/JPEG/ZIP headers (corpus MAGIC_FILE_FAMILY)",
        },
        DetectorInfo {
            id: "MAGIC_EMBEDDED",
            summary: "Inline `STEG`/`STG3` signature and packet magic scan with byte offsets.",
            budget: "first MAX_MAGIC_SCAN_BYTES (16777216) bytes, 4-byte sliding window",
            fp_limits: "any ordinary text containing the ASCII letters STEG or STG3 matches; offsets are evidence, not payloads",
            calibration: "benign: plain text; triggered: inline STG3 packet bytes (corpus MAGIC_EMBEDDED)",
        },
        DetectorInfo {
            id: unicode_text::ZERO_WIDTH,
            summary: "Zero-width characters and zero-width bit-encoding runs in decoded text.",
            budget: "first unicode_text::MAX_TEXT_SCAN_BYTES (1048576) bytes",
            fp_limits: "a leading U+FEFF BOM is exempt; isolated zero-width separators in legitimately formatted text still flag",
            calibration: "benign: plain ASCII sentence; triggered: 12-char ZWSP/ZWNJ bit-encoding run (corpus ZERO_WIDTH)",
        },
        DetectorInfo {
            id: unicode_text::VARIATION_SELECTORS,
            summary: "Variation selectors outside emoji presentation context (the VS bit-encoding smuggle).",
            budget: "first unicode_text::MAX_TEXT_SCAN_BYTES (1048576) bytes",
            fp_limits: "approximate emoji-base allowlist: VS16 after a rare emoji base may flag (evidence, not verdict); CDP selectors always flag",
            calibration: "benign: plain ASCII sentence; triggered: CDP variation selector U+E0100 (corpus VARIATION_SELECTORS)",
        },
        DetectorInfo {
            id: unicode_text::BIDI_CONTROLS,
            summary: "Bidi embedding/override/isolate controls (trojan-source class).",
            budget: "first unicode_text::MAX_TEXT_SCAN_BYTES (1048576) bytes",
            fp_limits: "legitimately bidirectional document text flags; presence is treated as evidence by design",
            calibration: "benign: plain ASCII sentence; triggered: U+202E override (corpus BIDI_CONTROLS)",
        },
        DetectorInfo {
            id: unicode_text::WHITESPACE_ANOMALY,
            summary: "Non-ASCII whitespace plus trailing-whitespace runs at line ends.",
            budget: "first unicode_text::MAX_TEXT_SCAN_BYTES (1048576) bytes",
            fp_limits: "single trailing spaces are exempt; two-space runs (a common typo) do flag, per-line binary stego needs >= 2 levels",
            calibration: "benign: clean lines; triggered: lines with 4 trailing spaces (corpus WHITESPACE_ANOMALY)",
        },
        DetectorInfo {
            id: unicode_text::HOMOGLYPH_SUSPECT,
            summary: "Non-ASCII characters with strong ASCII confusables (Cyrillic/Greek/fullwidth).",
            budget: "first unicode_text::MAX_TEXT_SCAN_BYTES (1048576) bytes",
            fp_limits: "hand-picked confusable set, not the full UTS #39 table: rare lookalikes are missed, identical-looking non-ASCII text still flags",
            calibration: "benign: plain ASCII; triggered: Cyrillic a in 'paypal' (corpus HOMOGLYPH_SUSPECT)",
        },
        DetectorInfo {
            id: "ZIP_TOPOLOGY",
            summary: "ZIP-family inventory: entry counts, claimed sizes, compression methods, office-family identification. Observation only.",
            budget: "one EOCD window scan (ooxml::CONTAINER_MAX_EOCD_SCAN_BYTES = 66000 bytes), at most ooxml::CONTAINER_MAX_ENTRIES (4096) entries, ooxml::CONTAINER_MAX_FINDINGS (64) findings per package",
            fp_limits: "Zip64, multi-disk, and data-descriptor archives are rejected with typed errors; claimed sizes are unverified attacker-controlled values",
            calibration: "benign: non-ZIP input (no findings); triggered: any ZIP-family buffer yields the inventory finding (corpus ZIP_TOPOLOGY)",
        },
        DetectorInfo {
            id: "DOC-001",
            summary: "OOXML package topology anomalies: duplicate entries, encrypted entries, oversized claimed sizes, inflate-budget rejections, media entries claiming text. Observation, not concealment.",
            budget: "in-memory central-directory parse with hostile bounds; inflate capped at ooxml::CONTAINER_MAX_INFLATE_PER_ENTRY (4 MiB) per entry and ooxml::CONTAINER_MAX_INFLATE_TOTAL (8 MiB) per package",
            fp_limits: "zip-bomb and corrupt-package evidence is security-relevant but does not set the steganographic `detected` verdict; text-like media extensions in legitimately mixed packages can flag",
            calibration: "benign: minimal clean docx (no DOC-001 findings); triggered: docx whose main part claims 2 GiB uncompressed (corpus DOC-001)",
        },
        DetectorInfo {
            id: "DOC-002",
            summary: "WordprocessingML concealment in word/document.xml: Unicode/text stego channels plus long ASCII whitespace runs inside XML text nodes.",
            budget: "main part inflated within the DOC-001 budgets and capped at unicode_text::MAX_TEXT_SCAN_BYTES (1048576) bytes for text analysis",
            fp_limits: "only the main part is scanned (headers/footers and embedded media are DOC-003/DOC-005); pretty-printed XML with >= 8-space text-node runs can flag",
            calibration: "benign: minimal clean docx; triggered: docx with a zero-width-laced document.xml (corpus DOC-002)",
        },
    ]
}

/// Aggregated forensic scan of one byte buffer.
#[derive(Debug, Clone)]
pub struct ForensicScan {
    /// Shannon entropy in bits per byte.
    pub entropy: f64,
    /// File family inferred from magic bytes.
    pub file_family: FileFamily,
    /// Embedded signature/packet magic, if present inline.
    pub embedded_magic: Option<EmbeddedMagic>,
    /// All inline embedded magic matches and their offsets.
    pub magic_matches: Vec<EmbeddedMagicMatch>,
    /// Unicode/text steganography findings (FOR-005 detector IDs).
    pub text_findings: Vec<unicode_text::TextFinding>,
    /// Container findings from ZIP-family analysis (DOC-001/DOC-002 slice;
    /// empty for non-container inputs).
    pub container_findings: Vec<ContainerFinding>,
    /// Aggregated statistical detector results.
    pub statistical: CombinedResult,
    /// `true` if a content-derived detector (inline magic, Unicode/text, or
    /// DOC-002 container) flags the buffer as suspicious. Statistical
    /// detector results are observations (see [`statistical`]): high-entropy
    /// or structured input can trip them on clean data, so they never trigger
    /// the verdict by themselves.
    pub detected: bool,
    /// Human-readable summary of the strongest finding.
    pub message: String,
}

/// Run every forensic detector over `data`.
///
/// A buffer is reported `detected` when an inline `STEG`/`STG3` magic is
/// present, a Unicode/text detector fires, or a DOC-002 WordprocessingML
/// concealment finding exists. Statistical detector results are observations
/// that accompany the verdict but never trigger it by themselves (their
/// false-positive limits are documented in the detector registry); entropy,
/// file family, ZIP topology, and DOC-001 topology anomalies likewise stay
/// observational.
pub fn scan_bytes(data: &[u8]) -> ForensicScan {
    let statistical = steganalysis::analyze_combined(data);
    let entropy = shannon_entropy(data);
    let file_family = detect_file_family(data);
    let magic_matches =
        detect_embedded_magics_detailed(&data[..data.len().min(MAX_MAGIC_SCAN_BYTES)]);
    let text_findings = detect_text_stego(data);
    let container_findings = if file_family == FileFamily::Zip {
        ooxml::analyze_package(data)
    } else {
        Vec::new()
    };
    let embedded_magic = magic_matches.first().map(|m| m.magic);
    let container_detected = container_findings
        .iter()
        .any(|f| f.family == ooxml::DOC_002_FAMILY);
    let detected = embedded_magic.is_some() || !text_findings.is_empty() || container_detected;
    let message = if let Some(magic) = embedded_magic {
        format!("embedded {} magic found inline", magic.as_str())
    } else if !text_findings.is_empty() || container_detected {
        // The summary must reflect every non-statistical family that fired:
        // a laced document can trip both the Unicode text detectors and the
        // OOXML container detector simultaneously.
        let mut parts: Vec<String> = Vec::new();
        if !text_findings.is_empty() {
            let ids: Vec<&str> = text_findings.iter().map(|f| f.detector_id).collect();
            parts.push(format!("unicode text anomalies: {}", ids.join(", ")));
        }
        if container_detected {
            let families: Vec<String> = container_findings
                .iter()
                .filter(|f| f.family == ooxml::DOC_002_FAMILY)
                .map(|f| f.family.clone())
                .collect();
            parts.push(format!("container findings: {}", families.join(", ")));
        }
        parts.join("; ")
    } else if statistical.detected {
        // Statistical-only results are observations (see the STAT_CHI2
        // fp_limits note in the detector registry), not verdicts: compressed
        // or encrypted input can trip them on clean data. `detected` above
        // already excludes them; the message still surfaces the observation.
        statistical.message.clone()
    } else {
        "no forensic indicators".to_string()
    };
    ForensicScan {
        entropy,
        file_family,
        embedded_magic,
        magic_matches,
        text_findings,
        container_findings,
        statistical,
        detected,
        message,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_of_empty_and_constant_buffers() {
        assert_eq!(shannon_entropy(&[]), 0.0);
        // A constant buffer has zero entropy.
        assert_eq!(shannon_entropy(&[0xAB; 256]), 0.0);
        // A buffer with 256 distinct byte values has maximal entropy (8.0).
        let all: Vec<u8> = (0u8..=255).collect();
        assert!((shannon_entropy(&all) - 8.0).abs() < 1e-9);
    }

    #[test]
    fn file_family_detection() {
        assert_eq!(
            detect_file_family(b"\x89PNG\r\n\x1a\nrest"),
            FileFamily::Png
        );
        assert_eq!(
            detect_file_family(b"\xff\xd8\xff\xe0rest"),
            FileFamily::Jpeg
        );
        assert_eq!(detect_file_family(b"GIF89a..."), FileFamily::Gif);
        assert_eq!(
            detect_file_family(b"RIFF\x00\x00\x00\x00WAVEfmt "),
            FileFamily::Wav
        );
        assert_eq!(
            detect_file_family(b"RIFF\x00\x00\x00\x00WEBPVP8 "),
            FileFamily::WebP
        );
        assert_eq!(detect_file_family(b"%PDF-1.7\n"), FileFamily::Pdf);
        assert_eq!(detect_file_family(b"PK\x03\x04\x14\x00"), FileFamily::Zip);
        assert_eq!(detect_file_family(b"\x1f\x8b\x08\x00"), FileFamily::Gzip);
        assert_eq!(detect_file_family(b"fLaC\x00\x00"), FileFamily::Flac);
        assert_eq!(detect_file_family(b"OggS\x00\x02"), FileFamily::Ogg);
        assert_eq!(detect_file_family(b"random bytes"), FileFamily::Unknown);
        assert_eq!(detect_file_family(b""), FileFamily::Unknown);
    }

    #[test]
    fn embedded_magic_detection() {
        assert_eq!(
            detect_embedded_magic(b"junk STEG payload"),
            Some(EmbeddedMagic::LegacySignature)
        );
        assert_eq!(
            detect_embedded_magic(b"junk STG3 payload"),
            Some(EmbeddedMagic::GenericPacket)
        );
        assert_eq!(detect_embedded_magic(b"no magic here"), None);
        assert_eq!(detect_embedded_magic(b"ST"), None);

        let detailed = detect_embedded_magics_detailed(b"header STEG ... body STG3 end");
        assert_eq!(detailed.len(), 2);
        assert_eq!(detailed[0].magic, EmbeddedMagic::LegacySignature);
        assert_eq!(detailed[0].offset, 7);
        assert_eq!(detailed[1].magic, EmbeddedMagic::GenericPacket);
        assert_eq!(detailed[1].offset, 21);
    }

    #[test]
    fn scan_detects_inline_packet_and_reports_observations() {
        let scan = scan_bytes(b"prefix STG3 packet bytes");
        assert!(scan.detected);
        assert_eq!(scan.embedded_magic, Some(EmbeddedMagic::GenericPacket));
        assert!(scan.entropy > 0.0);
        assert_eq!(scan.file_family, FileFamily::Unknown);
    }

    #[test]
    fn scan_of_plain_text_is_clean() {
        // A normal ASCII text buffer should not trigger the statistical
        // detectors nor contain an inline magic.
        let data = b"the quick brown fox jumps over the lazy dog. ".repeat(50);
        let scan = scan_bytes(&data);
        assert_eq!(scan.embedded_magic, None);
        assert!(!scan.message.contains("magic"));
    }

    #[test]
    fn text_stego_entry_point_wiring() {
        // Cyrillic 'а' inside an ASCII word is a homoglyph suspect.
        let scan = scan_bytes("p\u{0430}ypal".as_bytes());
        assert!(scan.detected);
        assert!(scan
            .text_findings
            .iter()
            .any(|f| f.detector_id == unicode_text::HOMOGLYPH_SUSPECT));

        // Plain ASCII text produces no text findings.
        let data = b"the quick brown fox jumps over the lazy dog. ".repeat(10);
        let clean = scan_bytes(&data);
        assert!(clean.text_findings.is_empty());
    }

    #[test]
    fn detector_registry_is_complete_and_unique() {
        let registry = detector_registry();
        assert!(!registry.is_empty());
        let mut ids: Vec<&str> = registry.iter().map(|d| d.id).collect();
        let count = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), count, "registry IDs must be unique");
        // Every stable text detector ID is registered.
        for id in unicode_text::TEXT_DETECTOR_IDS {
            assert!(registry.iter().any(|d| d.id == *id), "missing {id}");
        }
        // Every registered detector carries budgets, FP limits, and
        // calibration notes.
        for detector in registry {
            assert!(!detector.summary.is_empty());
            assert!(!detector.budget.is_empty());
            assert!(!detector.fp_limits.is_empty());
            assert!(!detector.calibration.is_empty());
        }
        // Registry ordering drives scan order: statistical → magic → text →
        // container.
        assert_eq!(registry.first().map(|d| d.id), Some("STAT_CHI2"));
        assert_eq!(registry.last().map(|d| d.id), Some("DOC-002"));
    }

    #[test]
    fn scan_bytes_container_findings_on_zip_input() {
        // A minimal docx: inventory finding present, nothing concealed.
        let clean_docx = minimal_docx_bytes("Hello world");
        let scan = scan_bytes(&clean_docx);
        assert_eq!(scan.file_family, FileFamily::Zip);
        assert!(scan
            .container_findings
            .iter()
            .any(|f| f.family == ZIP_TOPOLOGY_FAMILY));
        assert!(!scan
            .container_findings
            .iter()
            .any(|f| f.family == DOC_002_FAMILY));

        // A laced document.xml trips DOC-002 and sets `detected`.
        let laced_scan = scan_bytes(&minimal_docx_bytes(
            "Hello\u{200b}\u{200c}\u{200b}\u{200c}\u{200b}\u{200c}\u{200b}\u{200c}\u{200b}\u{200c}\u{200b}\u{200c} world",
        ));
        assert!(laced_scan.detected);
        assert!(laced_scan
            .container_findings
            .iter()
            .any(|f| f.family == DOC_002_FAMILY));
        assert!(laced_scan.message.contains("container findings"));

        // Non-ZIP input yields no container findings (contract unchanged).
        let plain = scan_bytes(b"plain text buffer");
        assert!(plain.container_findings.is_empty());
        assert_eq!(
            serde_json::to_string(&plain.container_findings).expect("serde"),
            "[]"
        );
        assert!(serde_json::to_string(&ContainerFinding {
            path: "word/document.xml".to_string(),
            family: DOC_002_FAMILY.to_string(),
            detail: "evidence".to_string(),
        })
        .is_ok());
    }

    /// Build a minimal docx zip in-test (flate2-compressed main part) using
    /// the same deterministic layout as the calibration corpus fixtures.
    fn minimal_docx_bytes(document_text: &str) -> Vec<u8> {
        // Reuse the ooxml test fixture writer through a tiny local builder.
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
        let entries: Vec<(&str, u16, Vec<u8>, Vec<u8>)> = vec![
            (
                "[Content_Types].xml",
                0,
                b"<?xml version=\"1.0\"?><Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"/>".to_vec(),
                b"<?xml version=\"1.0\"?><Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"/>".to_vec(),
            ),
            (
                "word/document.xml",
                8,
                {
                    let xml = format!(
                        "<?xml version=\"1.0\"?><w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\"><w:body><w:p><w:r><w:t>{}</w:t></w:r></w:p></w:body></w:document>",
                        document_text
                    );
                    let mut encoder = flate2::write::DeflateEncoder::new(
                        Vec::new(),
                        flate2::Compression::default(),
                    );
                    std::io::Write::write_all(&mut encoder, xml.as_bytes())
                        .expect("deflate write");
                    encoder.finish().expect("deflate finish")
                },
                {
                    let xml = format!(
                        "<?xml version=\"1.0\"?><w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\"><w:body><w:p><w:r><w:t>{}</w:t></w:r></w:p></w:body></w:document>",
                        document_text
                    );
                    xml.into_bytes()
                },
            ),
        ];
        let mut out: Vec<u8> = Vec::new();
        let mut central: Vec<u8> = Vec::new();
        for (name, method, compressed, uncompressed) in &entries {
            let offset = out.len();
            out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
            out.extend_from_slice(&20u16.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&method.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&crc32(uncompressed).to_le_bytes());
            out.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
            out.extend_from_slice(&(uncompressed.len() as u32).to_le_bytes());
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(compressed);

            central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
            central.extend_from_slice(&20u16.to_le_bytes());
            central.extend_from_slice(&20u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&method.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&crc32(uncompressed).to_le_bytes());
            central.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
            central.extend_from_slice(&(uncompressed.len() as u32).to_le_bytes());
            central.extend_from_slice(&(name.len() as u16).to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u32.to_le_bytes());
            central.extend_from_slice(&(offset as u32).to_le_bytes());
            central.extend_from_slice(name.as_bytes());
        }
        let cd_offset = out.len();
        let cd_size = central.len();
        out.extend_from_slice(&central);
        out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&(cd_size as u32).to_le_bytes());
        out.extend_from_slice(&(cd_offset as u32).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }
}
