//! Unicode/text steganography detectors (FOR-005; plan spec 03 §Text and
//! Unicode; roadmap v0.8.0 "text detectors").
//!
//! Complements the structural probes in [`crate::forensics`] with
//! evidence-oriented text analysis: every detector reports the character
//! offsets where suspicious code points occur plus a bounded detail string,
//! and never decodes or reconstructs a hidden payload. All scans are
//! non-recursive and bounded — analysis covers at most the first
//! [`MAX_TEXT_SCAN_BYTES`] bytes of the input.
//!
//! Detector IDs are stable strings (Phase 2 wires them into CLI scan
//! output): [`ZERO_WIDTH`], [`VARIATION_SELECTORS`], [`BIDI_CONTROLS`],
//! [`WHITESPACE_ANOMALY`], [`HOMOGLYPH_SUSPECT`].
//!
//! Reported offsets are character offsets (index of the character in the
//! scanned text), not byte offsets.

use std::collections::BTreeMap;

/// Stable detector ID: zero-width characters and zero-width bit-encoding runs.
pub const ZERO_WIDTH: &str = "ZERO_WIDTH";
/// Stable detector ID: variation selectors used outside emoji presentation
/// context (the VS bit-encoding smuggle).
pub const VARIATION_SELECTORS: &str = "VARIATION_SELECTORS";
/// Stable detector ID: bidi control characters (trojan-source class).
pub const BIDI_CONTROLS: &str = "BIDI_CONTROLS";
/// Stable detector ID: non-ASCII whitespace and trailing-whitespace runs.
pub const WHITESPACE_ANOMALY: &str = "WHITESPACE_ANOMALY";
/// Stable detector ID: non-ASCII characters with strong ASCII confusables.
pub const HOMOGLYPH_SUSPECT: &str = "HOMOGLYPH_SUSPECT";

/// Maximum input scanned, in bytes. Inputs longer than this are truncated to
/// their first [`MAX_TEXT_SCAN_BYTES`] bytes (cut at a char boundary) before
/// analysis, mirroring the bounded-scan budget of [`crate::forensics`].
pub const MAX_TEXT_SCAN_BYTES: usize = 1024 * 1024;

/// Minimum length of a consecutive zero-width run before it is reported as a
/// bit-encoding pattern (runs of ZWSP/ZWNJ are the classic binary channel).
const ZERO_WIDTH_RUN_MIN: usize = 8;

/// Minimum trailing whitespace run length (spaces/tabs at end of line)
/// reported by [`WHITESPACE_ANOMALY`]. A single trailing space is a common
/// typo; per-line binary whitespace stego needs at least two levels anyway.
const TRAILING_WS_RUN_MIN: usize = 2;

/// One detector's evidence: stable ID, character offsets of the suspicious
/// code points, and a human-readable detail line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextFinding {
    /// Stable detector ID, e.g. [`ZERO_WIDTH`].
    pub detector_id: &'static str,
    /// Character offsets (into the scanned text) of the flagged characters.
    pub offsets: Vec<usize>,
    /// Bounded human-readable detail (counts, run patterns); never decodes
    /// hidden payloads.
    pub detail: String,
}

/// Run every Unicode/text detector over `input`.
///
/// Inputs longer than [`MAX_TEXT_SCAN_BYTES`] bytes are truncated to the
/// first [`MAX_TEXT_SCAN_BYTES`] bytes (at a char boundary) before scanning;
/// findings past the cap are not reported. Empty input yields no findings.
pub fn analyze_text(input: &str) -> Vec<TextFinding> {
    let text = truncate_to_scan_limit(input);
    let mut findings = Vec::new();
    for detector in [
        detect_zero_width as fn(&str) -> Option<TextFinding>,
        detect_variation_selectors,
        detect_bidi_controls,
        detect_whitespace_anomaly,
        detect_homoglyphs,
    ] {
        if let Some(finding) = detector(text) {
            findings.push(finding);
        }
    }
    findings
}

/// Bytes-level entry point: validates UTF-8 and delegates to [`analyze_text`].
///
/// Non-UTF-8 buffers are not text and are handled gracefully per the
/// forensics convention (probes never fail; they report what they can
/// observe): they yield no findings. Byte-offset evidence for binary probes
/// is the domain of [`crate::forensics`].
pub fn analyze_bytes(input: &[u8]) -> Vec<TextFinding> {
    match std::str::from_utf8(input) {
        Ok(text) => analyze_text(text),
        Err(_) => Vec::new(),
    }
}

/// Truncate input to the bounded scan limit at a char boundary.
fn truncate_to_scan_limit(input: &str) -> &str {
    if input.len() <= MAX_TEXT_SCAN_BYTES {
        return input;
    }
    let mut end = MAX_TEXT_SCAN_BYTES;
    while !input.is_char_boundary(end) {
        end -= 1;
    }
    &input[..end]
}

type KindCounts = BTreeMap<&'static str, usize>;
/// A zero-width run: (char offset of first char, run length, per-kind counts).
type ZwRun = (usize, usize, KindCounts);

/// ZERO_WIDTH: U+200B..U+200D, U+2060, U+FEFF.
///
/// Reports every zero-width character offset plus counts, and applies a
/// heuristic for zero-width binary encoding: consecutive runs of at least
/// [`ZERO_WIDTH_RUN_MIN`] zero-width characters (typically ZWSP/ZWNJ as bit
/// levels) are reported as a run pattern (length, position, composition).
/// The payload is never decoded.
///
/// A leading U+FEFF is treated as a byte-order mark, not steganography.
fn detect_zero_width(text: &str) -> Option<TextFinding> {
    let mut offsets: Vec<usize> = Vec::new();
    let mut totals: KindCounts = BTreeMap::new();
    let mut runs: Vec<ZwRun> = Vec::new();
    let mut run_start: Option<(usize, KindCounts)> = None;
    let mut run_len = 0usize;

    for (char_offset, c) in text.chars().enumerate() {
        let name = if char_offset == 0 && c == '\u{FEFF}' {
            None // leading U+FEFF is a BOM, not steganographic
        } else {
            zero_width_name(c)
        };
        match name {
            Some(name) => {
                if run_start.is_none() {
                    run_start = Some((char_offset, KindCounts::new()));
                    run_len = 0;
                }
                *run_start.as_mut().unwrap().1.entry(name).or_insert(0) += 1;
                run_len += 1;
                *totals.entry(name).or_insert(0) += 1;
                offsets.push(char_offset);
            }
            None => close_zw_run(&mut runs, &mut run_start, &mut run_len),
        }
    }
    close_zw_run(&mut runs, &mut run_start, &mut run_len);

    if offsets.is_empty() {
        return None;
    }

    let total: usize = totals.values().sum();
    let kinds: Vec<String> = totals.iter().map(|(k, v)| format!("{} {}", k, v)).collect();
    let mut detail = format!(
        "zero-width characters: {} total ({})",
        total,
        kinds.join(", ")
    );
    if runs.is_empty() {
        detail.push_str("; no runs long enough to suggest bit encoding");
    } else {
        let parts: Vec<String> = runs
            .iter()
            .map(|(start, len, kinds)| {
                let composition: Vec<String> =
                    kinds.iter().map(|(k, v)| format!("{}x{}", k, v)).collect();
                format!("{} chars @{} ({})", len, start, composition.join(","))
            })
            .collect();
        detail.push_str(&format!(
            "; consecutive runs of >= {} zero-width chars suggest binary encoding (pattern only, not decoded): {}",
            ZERO_WIDTH_RUN_MIN,
            parts.join("; ")
        ));
    }

    Some(TextFinding {
        detector_id: ZERO_WIDTH,
        offsets,
        detail,
    })
}

/// Close the current zero-width run, recording it when long enough.
fn close_zw_run(
    runs: &mut Vec<ZwRun>,
    run_start: &mut Option<(usize, KindCounts)>,
    run_len: &mut usize,
) {
    if *run_len >= ZERO_WIDTH_RUN_MIN {
        if let Some((start, kinds)) = run_start.take() {
            runs.push((start, *run_len, kinds));
        }
    }
    run_start.take();
    *run_len = 0;
}

/// Name a zero-width code point, if it is one.
fn zero_width_name(c: char) -> Option<&'static str> {
    match c {
        '\u{200B}' => Some("ZWSP"),
        '\u{200C}' => Some("ZWNJ"),
        '\u{200D}' => Some("ZWJ"),
        '\u{2060}' => Some("WORD_JOINER"),
        '\u{FEFF}' => Some("ZWNBSP"),
        _ => None,
    }
}

/// VARIATION_SELECTORS: U+FE00..FE0F and U+E0100..E01EF used outside emoji
/// presentation context.
///
/// The classic smuggle appends CDP variation selectors (VS17..VS256) after an
/// emoji base to encode bits, or attaches VS16 to a plain ASCII character.
/// Heuristic (approximate emoji-base allowlist, documented limitation):
///
/// - U+E0100..E01EF (CDP-only selectors): always flagged.
/// - U+FE00..FE0F: flagged unless it is VS16 (U+FE0F) immediately after an
///   emoji base (emoji/keycap/regional-indicator/code points that legitimately
///   request emoji presentation).
/// - Dense consecutive-VS runs (>= 2 in a row) are called out in the detail.
fn detect_variation_selectors(text: &str) -> Option<TextFinding> {
    let mut offsets: Vec<usize> = Vec::new();
    let mut cdp_count = 0usize; // VS17..VS256 (U+E0100..E01EF)
    let mut non_emoji_count = 0usize; // VS1..VS16 not on an emoji base
    let mut dense_max = 0usize;
    let mut dense_cur = 0usize;
    let mut prev: Option<char> = None;

    for (char_offset, c) in text.chars().enumerate() {
        if is_variation_selector(c) {
            let legit_emoji_vs16 = c == '\u{FE0F}' && is_emoji_base(prev.unwrap_or_default());
            if !legit_emoji_vs16 {
                offsets.push(char_offset);
                if ('\u{E0100}'..='\u{E01EF}').contains(&c) {
                    cdp_count += 1;
                } else {
                    non_emoji_count += 1;
                }
            }
            dense_cur += 1;
            dense_max = dense_max.max(dense_cur);
        } else {
            dense_cur = 0;
        }
        prev = Some(c);
    }

    if offsets.is_empty() {
        return None;
    }

    let mut detail = format!(
        "variation selectors outside emoji presentation context: {} flagged (CDP VS17-256: {}, VS1-15/VS16 on non-emoji base: {})",
        offsets.len(),
        cdp_count,
        non_emoji_count
    );
    if dense_max >= 2 {
        detail.push_str(&format!(
            "; dense run of up to {} consecutive variation selectors",
            dense_max
        ));
    }

    Some(TextFinding {
        detector_id: VARIATION_SELECTORS,
        offsets,
        detail,
    })
}

fn is_variation_selector(c: char) -> bool {
    matches!(c, '\u{FE00}'..='\u{FE0F}' | '\u{E0100}'..='\u{E01EF}')
}

/// Approximate emoji-base allowlist for the VS16 presentation check.
///
/// Covers keycap bases, regional indicators, and the common emoji/symbol
/// blocks. This is intentionally approximate: a rare emoji base missing from
/// the list causes a false positive (evidence-oriented flag, not a verdict),
/// while no amount of real emoji text causes a false negative for the CDP
/// selector trick.
fn is_emoji_base(c: char) -> bool {
    let cp = c as u32;
    matches!(cp,
        0x23 | 0x2A | 0x30..=0x39                 // keycap bases: #, *, 0-9
        | 0xA9 | 0xAE                             // ©, ®
        | 0x203C | 0x2049 | 0x2122 | 0x2139       // ‼, ⁉, ™, ℹ
        | 0x2194..=0x21AA                         // arrows
        | 0x231A..=0x231B | 0x2328 | 0x23CF       // ⌚, ⌛, ⌨, ⏏
        | 0x23E9..=0x23FA                         // ⏩..⏺ misc media
        | 0x24C2                                  // Ⓜ
        | 0x25AA..=0x25FE                         // geometric shapes
        | 0x2600..=0x27BF                         // misc symbols + dingbats
        | 0x2934..=0x2935                         // ⤴, ⤵
        | 0x2B05..=0x2B07 | 0x2B1B..=0x2B1C       // arrows, squares
        | 0x2B50 | 0x2B55                         // ⭐, ⭕
        | 0x3030 | 0x303D | 0x3297 | 0x3299       // wavy dash, part alternation
        | 0x1F000..=0x1FAFF                       // all emoji blocks incl. regional indicators
    )
}

/// BIDI_CONTROLS: U+202A..U+202E and U+2066..U+2069.
///
/// Any bidi embedding/override/isolate control in source or document text is
/// the trojan-source attack class; presence alone is flagged with offsets.
fn detect_bidi_controls(text: &str) -> Option<TextFinding> {
    let mut offsets: Vec<usize> = Vec::new();
    let mut totals: KindCounts = BTreeMap::new();
    for (char_offset, c) in text.chars().enumerate() {
        if let Some(name) = bidi_control_name(c) {
            offsets.push(char_offset);
            *totals.entry(name).or_insert(0) += 1;
        }
    }
    if offsets.is_empty() {
        return None;
    }
    let kinds: Vec<String> = totals.iter().map(|(k, v)| format!("{} {}", k, v)).collect();
    let detail = format!(
        "bidi control characters: {} total ({}) — trojan-source style overrides/embeddings/isolates",
        offsets.len(),
        kinds.join(", ")
    );
    Some(TextFinding {
        detector_id: BIDI_CONTROLS,
        offsets,
        detail,
    })
}

/// Name a bidi control code point, if it is one.
fn bidi_control_name(c: char) -> Option<&'static str> {
    match c {
        '\u{202A}' => Some("LRE"),
        '\u{202B}' => Some("RLE"),
        '\u{202C}' => Some("PDF"),
        '\u{202D}' => Some("LRO"),
        '\u{202E}' => Some("RLO"),
        '\u{2066}' => Some("LRI"),
        '\u{2067}' => Some("RLI"),
        '\u{2068}' => Some("FSI"),
        '\u{2069}' => Some("PDI"),
        _ => None,
    }
}

/// WHITESPACE_ANOMALY: non-ASCII whitespace plus trailing-whitespace runs.
///
/// Two channels in one detector:
/// - Non-ASCII whitespace (U+00A0 NBSP, U+1680, U+2000..U+200A, U+3000):
///   every occurrence is reported; these are invisible in most editors and
///   carry information by position.
/// - Trailing whitespace at end of line: runs of at least
///   [`TRAILING_WS_RUN_MIN`] spaces/tabs before `\n` are the classic
///   whitespace stego channel (one binary level per line). Each offending
///   line contributes the character offset of its run start.
fn detect_whitespace_anomaly(text: &str) -> Option<TextFinding> {
    let mut offsets: Vec<usize> = Vec::new();
    let mut ws_totals: KindCounts = BTreeMap::new();
    let mut trailing_lines = 0usize;
    let mut max_trailing = 0usize;
    let mut line_start = 0usize;

    for line in text.split('\n') {
        let mut trailing_run = 0usize;
        for (ci, c) in line.chars().enumerate() {
            if let Some(name) = non_ascii_whitespace_name(c) {
                offsets.push(line_start + ci);
                *ws_totals.entry(name).or_insert(0) += 1;
                trailing_run = 0;
            } else if c == ' ' || c == '\t' {
                trailing_run += 1;
            } else {
                trailing_run = 0;
            }
        }
        if trailing_run >= TRAILING_WS_RUN_MIN {
            trailing_lines += 1;
            max_trailing = max_trailing.max(trailing_run);
            offsets.push(line_start + line.chars().count() - trailing_run);
        }
        line_start += line.chars().count() + 1; // +1 for the '\n' separator
    }

    if offsets.is_empty() {
        return None;
    }

    let mut detail = String::new();
    if !ws_totals.is_empty() {
        let total: usize = ws_totals.values().sum();
        let kinds: Vec<String> = ws_totals
            .iter()
            .map(|(k, v)| format!("{} {}", k, v))
            .collect();
        detail.push_str(&format!(
            "non-ASCII whitespace: {} total ({})",
            total,
            kinds.join(", ")
        ));
    }
    if trailing_lines > 0 {
        if !detail.is_empty() {
            detail.push_str("; ");
        }
        detail.push_str(&format!(
            "trailing whitespace runs (>= {} chars, classic per-line stego channel) on {} line(s), max run {}",
            TRAILING_WS_RUN_MIN,
            trailing_lines,
            max_trailing
        ));
    }

    Some(TextFinding {
        detector_id: WHITESPACE_ANOMALY,
        offsets,
        detail,
    })
}

/// Name a non-ASCII whitespace code point, if it is one.
fn non_ascii_whitespace_name(c: char) -> Option<&'static str> {
    match c {
        '\u{00A0}' => Some("NBSP"),
        '\u{1680}' => Some("OGHAM_SPACE"),
        '\u{2000}' => Some("EN_QUAD"),
        '\u{2001}' => Some("EM_QUAD"),
        '\u{2002}' => Some("EN_SPACE"),
        '\u{2003}' => Some("EM_SPACE"),
        '\u{2004}' => Some("THREE_PER_EM_SPACE"),
        '\u{2005}' => Some("FOUR_PER_EM_SPACE"),
        '\u{2006}' => Some("SIX_PER_EM_SPACE"),
        '\u{2007}' => Some("FIGURE_SPACE"),
        '\u{2008}' => Some("PUNCTUATION_SPACE"),
        '\u{2009}' => Some("THIN_SPACE"),
        '\u{200A}' => Some("HAIR_SPACE"),
        '\u{3000}' => Some("IDEOGRAPHIC_SPACE"),
        _ => None,
    }
}

/// HOMOGLYPH_SUSPECT: non-ASCII characters with strong ASCII confusables.
///
/// Covers the high-risk subsets: Cyrillic/Greek letters that render
/// identically to ASCII letters, and fullwidth forms U+FF01..U+FF5E that map
/// 1:1 onto ASCII. Reported as character + offset. Limitation (documented):
/// this is an approximate, hand-picked confusable set — it is not the full
/// Unicode confusables table (UTS #39), so rare lookalikes are missed and
/// identical-looking characters in legitimately non-ASCII text still flag.
fn detect_homoglyphs(text: &str) -> Option<TextFinding> {
    let mut offsets: Vec<usize> = Vec::new();
    let mut totals: KindCounts = BTreeMap::new();
    for (char_offset, c) in text.chars().enumerate() {
        if ascii_confusable(c).is_some() {
            offsets.push(char_offset);
            let script: &'static str = if ('\u{0400}'..='\u{04FF}').contains(&c) {
                "cyrillic"
            } else if ('\u{0370}'..='\u{03FF}').contains(&c) {
                "greek"
            } else {
                "fullwidth"
            };
            *totals.entry(script).or_insert(0) += 1;
        }
    }
    if offsets.is_empty() {
        return None;
    }
    let kinds: Vec<String> = totals.iter().map(|(k, v)| format!("{} {}", k, v)).collect();
    let detail = format!(
        "ASCII-confusable lookalike characters: {} total ({}) — approximate confusable set, not exhaustive (UTS #39 not implemented)",
        offsets.len(),
        kinds.join(", ")
    );
    Some(TextFinding {
        detector_id: HOMOGLYPH_SUSPECT,
        offsets,
        detail,
    })
}

/// The ASCII twin of a confusable non-ASCII character, if it has one.
fn ascii_confusable(c: char) -> Option<char> {
    let ascii = match c {
        // Cyrillic lowercase.
        '\u{0430}' => 'a', // а
        '\u{0435}' => 'e', // е
        '\u{043E}' => 'o', // о
        '\u{0440}' => 'p', // р
        '\u{0441}' => 'c', // с
        '\u{0443}' => 'y', // у
        '\u{0445}' => 'x', // х
        '\u{0456}' => 'i', // і
        // Cyrillic uppercase.
        '\u{0410}' => 'A', // А
        '\u{0412}' => 'B', // В
        '\u{0415}' => 'E', // Е
        '\u{041A}' => 'K', // К
        '\u{041C}' => 'M', // М
        '\u{041D}' => 'H', // Н
        '\u{041E}' => 'O', // О
        '\u{0420}' => 'P', // Р
        '\u{0421}' => 'C', // С
        '\u{0422}' => 'T', // Т
        '\u{0423}' => 'Y', // У
        '\u{0425}' => 'X', // Х
        // Greek lowercase.
        '\u{03B9}' => 'i', // ι
        '\u{03BA}' => 'k', // κ
        '\u{03BD}' => 'v', // ν
        '\u{03BF}' => 'o', // ο
        '\u{03C1}' => 'p', // ρ
        '\u{03C4}' => 't', // τ
        '\u{03C5}' => 'u', // υ
        // Greek uppercase.
        '\u{0391}' => 'A', // Α
        '\u{0392}' => 'B', // Β
        '\u{0395}' => 'E', // Ε
        '\u{0396}' => 'Z', // Ζ
        '\u{0397}' => 'H', // Η
        '\u{0399}' => 'I', // Ι
        '\u{039A}' => 'K', // Κ
        '\u{039C}' => 'M', // Μ
        '\u{039D}' => 'N', // Ν
        '\u{039F}' => 'O', // Ο
        '\u{03A1}' => 'P', // Ρ
        '\u{03A4}' => 'T', // Τ
        '\u{03A5}' => 'Y', // Υ
        '\u{03A7}' => 'X', // Χ
        // Fullwidth ASCII variants U+FF01..U+FF5E map back 1:1.
        '\u{FF01}'..='\u{FF5E}' => char::from_u32(c as u32 - 0xFEE0).unwrap_or(c),
        _ => return None,
    };
    Some(ascii)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ZWSP: char = '\u{200B}';

    fn finding<'a>(findings: &'a [TextFinding], id: &str) -> Option<&'a TextFinding> {
        findings.iter().find(|f| f.detector_id == id)
    }

    #[test]
    fn zero_width_positive_offsets_and_runs() {
        let findings = analyze_text("a\u{200B}b\u{200C}c");
        let f = finding(&findings, ZERO_WIDTH).expect("zero-width chars flagged");
        assert_eq!(f.offsets, vec![1, 3]);
        assert!(f.detail.contains("ZWSP 1"));
        assert!(f.detail.contains("ZWNJ 1"));

        // 16 consecutive ZWSP: reported as a bit-encodable run pattern,
        // never decoded.
        let run_text = format!("seed{}tail", ZWSP.to_string().repeat(16));
        let findings = analyze_text(&run_text);
        let f = finding(&findings, ZERO_WIDTH).unwrap();
        assert!(f.detail.contains("16 chars @4"));
        assert!(f.detail.contains("ZWSPx16"));
    }

    #[test]
    fn zero_width_bom_is_not_flagged() {
        // A leading U+FEFF is a byte-order mark; clean text must stay clean.
        assert!(finding(&analyze_text("\u{FEFF}plain text"), ZERO_WIDTH).is_none());
    }

    #[test]
    fn zero_width_clean_text_has_no_finding() {
        assert!(finding(&analyze_text("plain words only"), ZERO_WIDTH).is_none());
    }

    #[test]
    fn variation_selectors_flag_non_emoji_and_cdp_usage() {
        // CDP selector VS17 after ordinary text: always suspicious.
        let findings = analyze_text("abc\u{E0100}def");
        let f = finding(&findings, VARIATION_SELECTORS).expect("CDP VS flagged");
        assert_eq!(f.offsets, vec![3]);
        assert!(f.detail.contains("CDP VS17-256: 1"));

        // VS16 on a plain ASCII letter: suspicious.
        let findings = analyze_text("a\u{FE0F}");
        let f = finding(&findings, VARIATION_SELECTORS).expect("VS16 on ASCII flagged");
        assert_eq!(f.offsets, vec![1]);
    }

    #[test]
    fn variation_selector_vs16_on_emoji_base_is_clean() {
        // Legitimate emoji presentation: base + VS16 must NOT flag.
        assert!(finding(
            &analyze_text("\u{1F44D}\u{FE0F} thumbs up"),
            VARIATION_SELECTORS
        )
        .is_none());
        assert!(finding(&analyze_text("©\u{FE0F} 2026"), VARIATION_SELECTORS).is_none());
        // Keycap sequence: digit base + VS16 + combining enclosing keycap.
        assert!(finding(&analyze_text("1\u{FE0F}\u{20E3}"), VARIATION_SELECTORS).is_none());
    }

    #[test]
    fn bidi_controls_flagged_with_names() {
        let findings = analyze_text("if (admin) {\u{202E}");
        let f = finding(&findings, BIDI_CONTROLS).expect("RLO flagged");
        assert_eq!(f.offsets, vec![12]);
        assert!(f.detail.contains("RLO 1"));

        assert!(finding(&analyze_text("clean code"), BIDI_CONTROLS).is_none());
    }

    #[test]
    fn whitespace_anomaly_flags_non_ascii_and_trailing_runs() {
        let findings = analyze_text("hello\u{00A0}world\nfoo  \nbar\t\t\n");
        let f = finding(&findings, WHITESPACE_ANOMALY).expect("whitespace anomalies flagged");
        // NBSP at 5; trailing "  " on line 1 starts at 15; trailing "\t\t" on
        // line 2 starts at 21.
        assert_eq!(f.offsets, vec![5, 15, 21]);
        assert!(f.detail.contains("NBSP 1"));
        assert!(f.detail.contains("2 line(s)"));
    }

    #[test]
    fn whitespace_anomaly_negative_single_trailing_space_and_clean() {
        // A single trailing space is below the run threshold: not flagged.
        assert!(finding(&analyze_text("a \n"), WHITESPACE_ANOMALY).is_none());
        assert!(finding(&analyze_text("hello world\nok\n"), WHITESPACE_ANOMALY).is_none());
    }

    #[test]
    fn homoglyph_suspect_flags_confusables() {
        // "pаypаl" with Cyrillic а (U+0430) inside an ASCII word.
        let findings = analyze_text("p\u{0430}yp\u{0430}l");
        let f = finding(&findings, HOMOGLYPH_SUSPECT).expect("Cyrillic homoglyph flagged");
        assert_eq!(f.offsets, vec![1, 4]);
        assert!(f.detail.contains("cyrillic"));

        // Greek ο (U+03BF).
        let findings = analyze_text("inf\u{03BF}");
        assert_eq!(
            finding(&findings, HOMOGLYPH_SUSPECT).unwrap().offsets,
            vec![3]
        );

        // Fullwidth forms map 1:1 onto ASCII.
        let findings = analyze_text("\u{FF50}\u{FF41}\u{FF59}");
        let f = finding(&findings, HOMOGLYPH_SUSPECT).expect("fullwidth flagged");
        assert_eq!(f.offsets, vec![0, 1, 2]);
        assert!(f.detail.contains("fullwidth"));

        assert!(finding(&analyze_text("pure ascii text"), HOMOGLYPH_SUSPECT).is_none());
    }

    #[test]
    fn empty_input_yields_no_findings() {
        assert!(analyze_text("").is_empty());
    }

    #[test]
    fn bytes_entry_validates_utf8() {
        // Valid UTF-8 bytes behave exactly like analyze_text.
        assert_eq!(analyze_bytes("a\u{200B}".as_bytes()).len(), 1);
        // Invalid UTF-8: handled gracefully with no findings.
        assert!(analyze_bytes(b"\xff\xfe\x00junk").is_empty());
        assert!(analyze_bytes(&[]).is_empty());
    }

    #[test]
    fn oversize_input_is_truncated_to_scan_cap() {
        // Payload just past the cap: not scanned, not reported.
        let mut text = "x".repeat(MAX_TEXT_SCAN_BYTES);
        text.push(ZWSP);
        assert!(finding(&analyze_text(&text), ZERO_WIDTH).is_none());
        // Payload ending exactly at the cap: reported at its offset.
        // (ZWSP is 3 bytes, so pad with MAX - 3 ASCII chars.)
        let mut text = "x".repeat(MAX_TEXT_SCAN_BYTES - 3);
        text.push(ZWSP);
        let findings = analyze_text(&text);
        let f = finding(&findings, ZERO_WIDTH).unwrap();
        assert_eq!(f.offsets, vec![MAX_TEXT_SCAN_BYTES - 3]);
    }

    #[test]
    fn fully_clean_text_yields_no_findings() {
        let text = "The quick brown fox jumps over the lazy dog.\nSecond line of prose.\n";
        assert!(analyze_text(text).is_empty());
    }
}
