//! Bounded structural PDF analysis (DOC-004; plan spec 03 §Documents).
//!
//! Hand-rolled structural tokenizer with **no new dependencies**: header and
//! version probing, `%%EOF` inventory, trailer/`startxref`/xref sanity, a
//! bounded object-keyword scan (`/EmbeddedFile`, `/EmbeddedFiles`,
//! `/JavaScript`, `/JS`, `/OpenAction`, `/Launch`, `/URI`, `/AcroForm`,
//! `/Filter` chains), XMP metadata presence, and a literal-string text
//! channel that runs the [`crate::unicode_text`] detectors over extracted
//! strings. Detection only — no rendering, no JavaScript execution.
//! Invisible-text rendering heuristics (text render mode 3, off-page `Td`
//! positioning) are out of scope and skipped (see the registry calibration
//! note).
//!
//! Every step is bounds-checked against hostile input: oversized files,
//! runaway object counts, oversized literal strings, lying `/Length` claims,
//! and truncated/corrupt structure never panic — they surface as bounded
//! findings. Malformed-structure errors fold into a single consolidated
//! finding.
//!
//! Finding families (reported as [`super::ContainerFinding`] strings):
//!
//! - [`PDF_FAMILY`] — structural inventory/observations for every parseable
//!   PDF (version, object/EOF inventory, xref status, XMP/AcroForm/http(s)
//!   URI notes). Observations never set
//!   [`super::ForensicScan::detected`].
//! - [`DOC_004_FAMILY`] — concealment/anomaly evidence: embedded files,
//!   JavaScript/OpenAction/Launch actions, dangerous URI schemes, `/Crypt`
//!   or stacked filters on non-image streams, appended data after the last
//!   `%%EOF`, text-channel hits, budget rejections, and the consolidated
//!   malformed-structure finding. These are detections and do set
//!   `detected`.

use super::ooxml;
use super::ContainerFinding;
use crate::unicode_text;
use flate2::read::DeflateDecoder;
use std::io::Read as _;

/// Stable detector family ID: PDF concealment/anomaly detections (DOC-004).
pub const DOC_004_FAMILY: &str = "DOC-004";
/// Stable detector family ID: PDF structural inventory/observations.
pub const PDF_FAMILY: &str = "PDF";

/// Maximum input size accepted for PDF structural analysis; larger buffers
/// are reported as a single budget finding and skipped.
pub const PDF_MAX_FILE_BYTES: usize = 64 * 1024 * 1024;
/// Maximum number of `N 0 obj` bodies inspected in one scan; later objects
/// are reported as truncated evidence, never silently dropped.
pub const PDF_MAX_OBJECTS_SCANNED: usize = 8192;
/// Maximum decoded length of a single PDF literal/hex string.
pub const PDF_MAX_STRING_LENGTH: usize = 4096;
/// Maximum bytes of one object body inspected (the per-object dict window).
pub const PDF_MAX_OBJECT_WINDOW_BYTES: usize = 64 * 1024;
/// Total extracted-text budget for the literal-string text channel.
pub const PDF_MAX_TEXT_BYTES: usize = unicode_text::MAX_TEXT_SCAN_BYTES;
/// Maximum bytes of one stream considered for inflation/text extraction.
pub const PDF_MAX_STREAM_BYTES: usize = 8 * 1024 * 1024;
/// Maximum inflated bytes accepted for one stream.
pub const PDF_MAX_STREAM_INFLATE_BYTES: usize = 256 * 1024;
/// Maximum total inflated bytes across all streams in one scan.
pub const PDF_MAX_STREAM_INFLATE_TOTAL: usize = 1024 * 1024;
/// Maximum number of streams inflated in one scan.
pub const PDF_MAX_STREAMS_INFLATED: usize = 16;
/// Maximum number of findings emitted per PDF.
pub const PDF_MAX_FINDINGS: usize = 64;
/// Header search window: `%PDF-` must appear within the first 1024 bytes.
const HEADER_WINDOW_BYTES: usize = 1024;
/// Bound for one finding's `detail` string (bytes).
const DETAIL_MAX_BYTES: usize = 256;

/// Object keywords that mark concealment/execution channels, with the
/// evidence phrase used in the finding detail.
const SUSPICIOUS_KEYWORDS: &[(&str, &str)] = &[
    ("/EmbeddedFile", "embedded file payload"),
    ("/EmbeddedFiles", "embedded file name tree"),
    ("/JavaScript", "embedded JavaScript"),
    ("/JS", "JavaScript action payload"),
    ("/OpenAction", "auto-run action on document open"),
    ("/Launch", "external application launch"),
];

/// URI schemes treated as concealment/execution channels (DOC-004).
const DANGEROUS_URI_SCHEMES: &[&str] = &["javascript", "vbscript", "file"];
/// Common external-link schemes reported as observations, not detections.
const OBSERVED_URI_SCHEMES: &[&str] = &["http", "https", "mailto", "ftp"];

/// Run the bounded DOC-004 structural scan over a PDF-family buffer.
///
/// Never panics on hostile input. Returns findings in detector order:
/// object-keyword evidence, the structural inventory, consolidated
/// malformed-structure errors, trailing-data evidence, metadata notes, and
/// finally the literal-string text channel.
pub fn analyze_pdf(data: &[u8]) -> Vec<ContainerFinding> {
    let mut findings: Vec<ContainerFinding> = Vec::new();

    if data.len() > PDF_MAX_FILE_BYTES {
        push_finding(
            &mut findings,
            ContainerFinding {
                path: "<pdf>".to_string(),
                family: DOC_004_FAMILY.to_string(),
                detail: bound_detail(format!(
                    "pdf is {} bytes, exceeding the {PDF_MAX_FILE_BYTES}-byte scan budget; structural scan skipped",
                    data.len()
                )),
            },
        );
        return findings;
    }

    let header_at = find(data, b"%PDF-", 0).filter(|&at| at < HEADER_WINDOW_BYTES);
    let Some(header_at) = header_at else {
        push_finding(
            &mut findings,
            ContainerFinding {
                path: "<pdf>".to_string(),
                family: DOC_004_FAMILY.to_string(),
                detail: format!(
                    "no %PDF- header within the first {HEADER_WINDOW_BYTES} bytes; malformed or disguised PDF"
                ),
            },
        );
        return findings;
    };

    if header_at > 0 {
        push_finding(
            &mut findings,
            ContainerFinding {
                path: "header".to_string(),
                family: DOC_004_FAMILY.to_string(),
                detail: bound_detail(format!(
                    "junk prefix of {header_at} bytes before the %PDF- header (polyglot risk)"
                )),
            },
        );
    }
    let version = parse_pdf_version(&data[header_at..]);

    // ---- bounded object-keyword scan ----
    let mut object_findings: Vec<ContainerFinding> = Vec::new();
    let mut text_buf: Vec<u8> = Vec::new();
    let mut inflate_total = 0usize;
    let mut streams_inflated = 0usize;
    let mut objects_scanned = 0usize;
    let mut objects_truncated = false;
    let mut pos = header_at;

    while let Some(at) = find(data, b" obj", pos) {
        if objects_scanned >= PDF_MAX_OBJECTS_SCANNED {
            objects_truncated = true;
            break;
        }
        objects_scanned += 1;
        let label = object_label(data, at);
        let cap = (at + PDF_MAX_OBJECT_WINDOW_BYTES).min(data.len());
        let window_end = match find(data, b"endobj", at) {
            Some(end) if end <= cap => end,
            _ => cap,
        };
        let window = &data[at..window_end];

        // Suspicious object keywords (one combined finding per object).
        let matched: Vec<String> = SUSPICIOUS_KEYWORDS
            .iter()
            .filter(|(keyword, _)| find(window, keyword.as_bytes(), 0).is_some())
            .map(|(keyword, description)| format!("{description} ({keyword})"))
            .collect();
        if !matched.is_empty() {
            push_finding(
                &mut object_findings,
                ContainerFinding {
                    path: label.clone(),
                    family: DOC_004_FAMILY.to_string(),
                    detail: bound_detail(format!(
                        "{label}: suspicious keywords {}",
                        matched.join("; ")
                    )),
                },
            );
        }

        // Interactive forms are common in legitimate PDFs: observation only.
        if find(window, b"/AcroForm", 0).is_some() {
            push_finding(
                &mut object_findings,
                ContainerFinding {
                    path: label.clone(),
                    family: PDF_FAMILY.to_string(),
                    detail: format!("{label}: interactive form (/AcroForm) present"),
                },
            );
        }

        // URI actions: dangerous schemes are detections; ordinary external
        // links are observations.
        if find(window, b"/URI", 0).is_some() {
            if let Some(value) = extract_uri_value(window) {
                match classify_uri(&value) {
                    Some(UriClass::Dangerous(scheme)) => push_finding(
                        &mut object_findings,
                        ContainerFinding {
                            path: label.clone(),
                            family: DOC_004_FAMILY.to_string(),
                            detail: bound_detail(format!(
                                "{label}: URI action with dangerous scheme \"{scheme}:\" (value not reconstructed)"
                            )),
                        },
                    ),
                    Some(UriClass::Observed(scheme)) => push_finding(
                        &mut object_findings,
                        ContainerFinding {
                            path: label.clone(),
                            family: PDF_FAMILY.to_string(),
                            detail: bound_detail(format!(
                                "{label}: external URI link (scheme {scheme}:)"
                            )),
                        },
                    ),
                    _ => {}
                }
            }
        }

        // Lying /Length claims: the stream read is bounded regardless, but
        // the claim itself is worth recording.
        if let Some(claimed) = parse_dict_length(window) {
            if claimed > PDF_MAX_STREAM_BYTES as u64 {
                push_finding(
                    &mut object_findings,
                    ContainerFinding {
                        path: label.clone(),
                        family: DOC_004_FAMILY.to_string(),
                        detail: bound_detail(format!(
                            "{label}: stream /Length claims {claimed} bytes, exceeding the \
                             {PDF_MAX_STREAM_BYTES}-byte bounded stream window; stream not inflated"
                        )),
                    },
                );
            }
        }

        let filters = parse_filter_names(window);
        let is_image = find(window, b"/Image", 0).is_some();
        if let Some(filters) = &filters {
            let names: Vec<String> = filters.to_vec();
            if !is_image {
                if names.iter().any(|name| name == "Crypt") {
                    push_finding(
                        &mut object_findings,
                        ContainerFinding {
                            path: label.clone(),
                            family: DOC_004_FAMILY.to_string(),
                            detail: format!(
                                "{label}: non-image stream uses the /Crypt filter (encrypted content not analyzed)"
                            ),
                        },
                    );
                } else if names.len() >= 3 {
                    push_finding(
                        &mut object_findings,
                        ContainerFinding {
                            path: label.clone(),
                            family: DOC_004_FAMILY.to_string(),
                            detail: bound_detail(format!(
                                "{label}: stacked filter chain on non-image stream ({})",
                                names.join(" / ")
                            )),
                        },
                    );
                }
            }
        }

        // Literal-string text channel: dict strings plus (inflated) stream
        if !is_image && text_buf.len() < PDF_MAX_TEXT_BYTES {
            let dict_end = stream_keyword(window).unwrap_or(window.len());
            collect_strings(&window[..dict_end], &mut text_buf);
            if let Some(range) = stream_data_range(data, at, window_end) {
                let filtered = filters.as_ref().is_some_and(|f| !f.is_empty());
                let has_flate = filters
                    .as_ref()
                    .is_some_and(|f| f.iter().any(|name| name == "FlateDecode"));
                if !filtered {
                    collect_strings(&data[range], &mut text_buf);
                } else if has_flate
                    && streams_inflated < PDF_MAX_STREAMS_INFLATED
                    && inflate_total < PDF_MAX_STREAM_INFLATE_TOTAL
                {
                    let cap = PDF_MAX_STREAM_INFLATE_BYTES
                        .min(PDF_MAX_STREAM_INFLATE_TOTAL - inflate_total);
                    streams_inflated += 1;
                    let mut decoder = DeflateDecoder::new(&data[range]).take(cap as u64);
                    let mut inflated = Vec::new();
                    if decoder.read_to_end(&mut inflated).is_ok() {
                        inflate_total += inflated.len();
                        collect_strings(&inflated, &mut text_buf);
                    }
                }
            }
        }

        pos = at + 4;
    }
    if objects_truncated {
        push_finding(
            &mut object_findings,
            ContainerFinding {
                path: "<pdf>".to_string(),
                family: PDF_FAMILY.to_string(),
                detail: format!(
                    "object scan truncated at {PDF_MAX_OBJECTS_SCANNED} objects (budget); later objects not scanned"
                ),
            },
        );
    }

    // ---- EOF / trailer / xref structure ----
    let mut eof_positions: Vec<usize> = Vec::new();
    let mut eof_from = 0usize;
    while let Some(at) = find(data, b"%%EOF", eof_from) {
        if eof_positions.len() < 4096 {
            eof_positions.push(at);
        }
        eof_from = at + 5;
    }

    let mut structural_errors: Vec<String> = Vec::new();
    if eof_positions.is_empty() {
        structural_errors.push("no %%EOF marker".to_string());
    } else if let Some(&last) = eof_positions.last() {
        let after = &data[(last + 5).min(data.len())..];
        let appended = after
            .iter()
            .filter(|b| !matches!(b, b' ' | b'\t' | b'\n' | b'\r'))
            .count();
        if appended > 0 {
            push_finding(
                &mut object_findings,
                ContainerFinding {
                    path: "trailer".to_string(),
                    family: DOC_004_FAMILY.to_string(),
                    detail: bound_detail(format!(
                        "{appended} byte(s) of data after the last %%EOF (appended payload or incremental-revision residue)"
                    )),
                },
            );
        }
    }

    let trailer_present = find(data, b"trailer", header_at).is_some();
    let xref_stream_style = find(data, b"/XRef", 0).is_some();
    let trailer_status = if trailer_present {
        "present"
    } else if xref_stream_style {
        "absent (xref-stream style)"
    } else {
        "absent"
    };
    if !trailer_present && !xref_stream_style {
        structural_errors.push("no trailer dictionary".to_string());
    }

    let startxref_status;
    match find(data, b"startxref", header_at) {
        None => {
            structural_errors.push("no startxref marker".to_string());
            startxref_status = "absent";
        }
        Some(at) => match parse_startxref_value(data, at) {
            None => {
                structural_errors.push("startxref value unparsable".to_string());
                startxref_status = "invalid";
            }
            Some(offset) => {
                if offset >= data.len() {
                    structural_errors.push(format!(
                        "startxref offset {offset} is out of bounds (file is {} bytes)",
                        data.len()
                    ));
                    startxref_status = "out of bounds";
                } else {
                    let target = &data[offset..];
                    if target.starts_with(b"xref")
                        || target.first().is_some_and(|b| b.is_ascii_digit())
                    {
                        startxref_status = "ok";
                    } else {
                        structural_errors.push(format!(
                            "startxref points to byte {offset}, which is not an xref table or xref stream object"
                        ));
                        startxref_status = "mismatch";
                    }
                }
            }
        },
    }

    // ---- structural inventory (observation) ----
    push_finding(
        &mut findings,
        ContainerFinding {
            path: "<pdf>".to_string(),
            family: PDF_FAMILY.to_string(),
            detail: bound_detail(format!(
                "pdf: version {}, header at byte {header_at}, {objects_scanned} object(s) scanned, \
                 {} %%EOF marker(s), trailer {trailer_status}, startxref {startxref_status}",
                version.as_deref().unwrap_or("unknown"),
                eof_positions.len(),
            )),
        },
    );

    // Malformed-structure errors fold into a single consolidated finding.
    if !structural_errors.is_empty() {
        push_finding(
            &mut findings,
            ContainerFinding {
                path: "<pdf>".to_string(),
                family: DOC_004_FAMILY.to_string(),
                detail: bound_detail(format!("malformed pdf: {}", structural_errors.join("; "))),
            },
        );
    }

    // XMP metadata packet presence (observation).
    if find(data, b"<?xpacket", 0).is_some() {
        push_finding(
            &mut findings,
            ContainerFinding {
                path: "metadata".to_string(),
                family: PDF_FAMILY.to_string(),
                detail: "XMP metadata packet present".to_string(),
            },
        );
    }

    findings.extend(object_findings);

    // ---- literal-string text channel (DOC-002 detectors over PDF strings) ----
    if !text_buf.is_empty() {
        for finding in unicode_text::analyze_bytes(&text_buf) {
            push_finding(
                &mut findings,
                ContainerFinding {
                    path: "strings".to_string(),
                    family: DOC_004_FAMILY.to_string(),
                    detail: bound_detail(ooxml::format_text_finding(&finding)),
                },
            );
        }
    }

    findings
}

/// One object keyword's classification for URI values.
enum UriClass {
    Dangerous(String),
    Observed(String),
}

/// Classify a decoded URI value by its scheme.
fn classify_uri(value: &[u8]) -> Option<UriClass> {
    let window = &value[..value.len().min(128)];
    let text = String::from_utf8_lossy(window).to_ascii_lowercase();
    let colon = text.find(':')?;
    let scheme = text[..colon].trim().to_string();
    if scheme.is_empty()
        || !scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.')
    {
        return None;
    }
    if DANGEROUS_URI_SCHEMES.contains(&scheme.as_str()) {
        Some(UriClass::Dangerous(scheme))
    } else if OBSERVED_URI_SCHEMES.contains(&scheme.as_str()) {
        Some(UriClass::Observed(scheme))
    } else {
        None
    }
}

/// Extract the string value of a `/URI` key from a dict window, if present.
///
/// Iterates every `/URI` occurrence: `/S/URI` (the action-type name value)
/// yields no string value and the scan continues to the `/URI(…)` key.
fn extract_uri_value(window: &[u8]) -> Option<Vec<u8>> {
    let mut from = 0usize;
    loop {
        let at = find(window, b"/URI", from)?;
        let mut i = at + 4;
        while i < window.len() && matches!(window[i], b' ' | b'\n' | b'\r' | b'\t') {
            i += 1;
        }
        match window.get(i) {
            Some(b'(') => return decode_literal_string(window, i).map(|(value, _)| value),
            Some(b'<') if window.get(i + 1) != Some(&b'<') => {
                return decode_hex_string(window, i).map(|(value, _)| value);
            }
            _ => from = at + 1,
        }
    }
}

/// Parse the filter chain declared by a `/Filter` key: either a single name
/// or an array of names. Returns the names without their leading slashes.
fn parse_filter_names(window: &[u8]) -> Option<Vec<String>> {
    let at = find(window, b"/Filter", 0)?;
    let mut i = at + 7;
    while i < window.len() && matches!(window[i], b' ' | b'\n' | b'\r' | b'\t') {
        i += 1;
    }
    let mut names = Vec::new();
    match window.get(i) {
        Some(b'[') => {
            i += 1;
            while i < window.len() {
                match window[i] {
                    b']' => break,
                    b'/' => {
                        if let Some(name) = read_name(window, &mut i) {
                            names.push(name);
                        }
                    }
                    _ => i += 1,
                }
            }
        }
        Some(b'/') => {
            names.push(read_name(window, &mut i)?);
        }
        _ => return None,
    }
    Some(names)
}

/// Read one PDF name token (after its leading slash) starting at `*i`,
/// advancing `*i` past it.
fn read_name(window: &[u8], i: &mut usize) -> Option<String> {
    *i += 1;
    let start = *i;
    while *i < window.len()
        && (window[*i].is_ascii_alphanumeric() || matches!(window[*i], b'-' | b'+' | b'#'))
    {
        *i += 1;
    }
    if *i == start {
        return None;
    }
    Some(String::from_utf8_lossy(&window[start..*i]).into_owned())
}

/// Parse a direct numeric `/Length` claim (indirect `N 0 R` references are
/// ignored: the length is unverifiable without resolving the reference).
fn parse_dict_length(window: &[u8]) -> Option<u64> {
    let at = find(window, b"/Length", 0)?;
    // The keyword must end at a delimiter: "/Length1" (a distinct font key)
    // is not a /Length claim.
    if !matches!(
        window.get(at + 7),
        Some(b' ') | Some(b'\n') | Some(b'\r') | Some(b'\t')
    ) {
        return None;
    }
    let mut i = at + 7;
    while i < window.len() && matches!(window[i], b' ' | b'\n' | b'\r' | b'\t') {
        i += 1;
    }
    let start = i;
    while i < window.len() && window[i].is_ascii_digit() {
        i += 1;
    }
    if i == start || i - start > 19 {
        return None;
    }
    let value: u64 = std::str::from_utf8(&window[start..i]).ok()?.parse().ok()?;
    // An indirect reference looks like "N 0 R": generation number is always 0.
    let mut j = i;
    while j < window.len() && window[j] == b' ' {
        j += 1;
    }
    if window.get(j..j + 3) == Some(b"0 R") || window.get(j) == Some(&b'0') {
        return None;
    }
    Some(value)
}

/// Locate the `stream` keyword in an object window (it must follow an EOL).
fn stream_keyword(window: &[u8]) -> Option<usize> {
    let mut from = 0usize;
    loop {
        let at = find(window, b"stream", from)?;
        if at > 0 && matches!(window[at - 1], b'\n' | b'\r') {
            return Some(at);
        }
        from = at + 1;
    }
}

/// Resolve the raw stream-data range for the object starting at `obj_start`.
/// The stream is bounded by the next `endstream` and by
/// [`PDF_MAX_STREAM_BYTES`] — claimed `/Length` values are never trusted for
/// sizing.
fn stream_data_range(
    data: &[u8],
    obj_start: usize,
    window_end: usize,
) -> Option<std::ops::Range<usize>> {
    let keyword = find(data, b"stream", obj_start)
        .filter(|&at| at < window_end)
        .filter(|&at| at > 0 && matches!(data[at - 1], b'\n' | b'\r'))?;
    let mut start = keyword + 6;
    if data.get(start) == Some(&b'\r') {
        start += 1;
    }
    if data.get(start) == Some(&b'\n') {
        start += 1;
    }
    if start >= data.len() {
        return None;
    }
    let search_end = start.saturating_add(PDF_MAX_STREAM_BYTES).min(data.len());
    let end = find(data, b"endstream", start)
        .filter(|&at| at <= search_end)
        .unwrap_or(search_end);
    Some(start..end)
}

/// Decode a PDF literal string starting at the `(` at `start`; returns the
/// decoded bytes and the index just past the closing `)`. Unbalanced or
/// oversized strings yield `None`.
fn decode_literal_string(data: &[u8], start: usize) -> Option<(Vec<u8>, usize)> {
    let mut out = Vec::new();
    let mut depth = 1usize;
    let mut i = start + 1;
    while i < data.len() {
        if out.len() > PDF_MAX_STRING_LENGTH {
            return None;
        }
        match data[i] {
            b'\\' => {
                i += 1;
                let escape = *data.get(i)?;
                i += 1;
                match escape {
                    b'n' => out.push(b'\n'),
                    b'r' => out.push(b'\r'),
                    b't' => out.push(b'\t'),
                    b'b' => out.push(0x08),
                    b'f' => out.push(0x0C),
                    b'\n' => {}
                    b'\r' => {
                        if data.get(i) == Some(&b'\n') {
                            i += 1;
                        }
                    }
                    b'0'..=b'7' => {
                        let mut value = u32::from(escape - b'0');
                        for _ in 0..2 {
                            match data.get(i) {
                                Some(&digit @ b'0'..=b'7') => {
                                    value = value * 8 + u32::from(digit - b'0');
                                    i += 1;
                                }
                                _ => break,
                            }
                        }
                        out.push(value as u8);
                    }
                    other => out.push(other),
                }
            }
            b'(' => {
                depth += 1;
                out.push(b'(');
                i += 1;
            }
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some((out, i + 1));
                }
                out.push(b')');
                i += 1;
            }
            _ => {
                out.push(data[i]);
                i += 1;
            }
        }
    }
    None
}

/// Decode a PDF hex string starting at the `<` at `start` (dict delimiters
/// `<<` are rejected). Returns the decoded bytes and the index just past
/// the closing `>`; a dangling final nibble is zero-padded.
fn decode_hex_string(data: &[u8], start: usize) -> Option<(Vec<u8>, usize)> {
    if data.get(start + 1) == Some(&b'<') {
        return None;
    }
    let mut out = Vec::new();
    let mut pending: Option<u8> = None;
    let mut i = start + 1;
    while i < data.len() {
        match data[i] {
            b'>' => {
                if let Some(high) = pending {
                    out.push(high * 16);
                }
                return Some((out, i + 1));
            }
            digit @ (b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F') => {
                let nibble = hex_val(digit)?;
                if out.len() > PDF_MAX_STRING_LENGTH {
                    return None;
                }
                match pending.take() {
                    Some(high) => out.push(high * 16 + nibble),
                    None => pending = Some(nibble),
                }
            }
            b' ' | b'\n' | b'\r' | b'\t' => {}
            _ => return None,
        }
        i += 1;
    }
    None
}

fn hex_val(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        b'A'..=b'F' => Some(digit - b'A' + 10),
        _ => None,
    }
}

/// Walk a byte region and append every decodable literal/hex string to
/// `text` (newline-joined). Only strings that are valid UTF-8 within the
/// per-string budget are kept, so `text` stays valid UTF-8 for the
/// [`unicode_text`] detectors.
fn collect_strings(region: &[u8], text: &mut Vec<u8>) {
    let mut i = 0usize;
    while i < region.len() && text.len() < PDF_MAX_TEXT_BYTES {
        match region[i] {
            b'(' => match decode_literal_string(region, i) {
                Some((value, next)) => {
                    i = next;
                    push_text(text, &value);
                }
                None => i += 1,
            },
            b'<' if i + 1 < region.len() && region[i + 1] != b'<' => {
                match decode_hex_string(region, i) {
                    Some((value, next)) => {
                        i = next;
                        push_text(text, &value);
                    }
                    None => i += 1,
                }
            }
            _ => i += 1,
        }
    }
}

/// Append one decoded string to the bounded text buffer.
fn push_text(text: &mut Vec<u8>, value: &[u8]) {
    if value.is_empty() || value.len() > PDF_MAX_STRING_LENGTH {
        return;
    }
    if std::str::from_utf8(value).is_err() {
        return;
    }
    if text.len() >= PDF_MAX_TEXT_BYTES {
        return;
    }
    if !text.is_empty() {
        text.push(b'\n');
    }
    let room = PDF_MAX_TEXT_BYTES - text.len();
    let take = value.len().min(room);
    text.extend_from_slice(&value[..take]);
}

/// Parse the version from a buffer starting at the `%PDF-` header.
fn parse_pdf_version(data: &[u8]) -> Option<String> {
    if data.len() < 8 {
        return None;
    }
    let (major, dot, minor) = (data[5], data[6], data[7]);
    if major.is_ascii_digit() && dot == b'.' && minor.is_ascii_digit() {
        Some(format!("{}.{}", major as char, minor as char))
    } else {
        None
    }
}

/// Label an object occurrence: `object N` when the classic `N 0 obj` token
/// precedes the keyword, else a byte-offset label.
fn object_label(data: &[u8], obj_keyword: usize) -> String {
    let mut i = obj_keyword;
    while i > 0 && data[i - 1] == b' ' {
        i -= 1;
    }
    if i == 0 || data[i - 1] != b'0' {
        return format!("object@{obj_keyword}");
    }
    i -= 1;
    if i == 0 || data[i - 1] != b' ' {
        return format!("object@{obj_keyword}");
    }
    i -= 1;
    let digits_end = i;
    while i > 0 && data[i - 1].is_ascii_digit() {
        i -= 1;
    }
    if digits_end == i || digits_end - i > 10 {
        return format!("object@{obj_keyword}");
    }
    format!("object {}", String::from_utf8_lossy(&data[i..digits_end]))
}

/// Parse the integer following a `startxref` keyword.
fn parse_startxref_value(data: &[u8], keyword: usize) -> Option<usize> {
    let mut i = keyword + 9;
    while i < data.len() && matches!(data[i], b' ' | b'\n' | b'\r' | b'\t') {
        i += 1;
    }
    let start = i;
    while i < data.len() && data[i].is_ascii_digit() {
        i += 1;
    }
    if i == start || i - start > 19 {
        return None;
    }
    std::str::from_utf8(&data[start..i]).ok()?.parse().ok()
}

/// Find the first occurrence of `needle` in `data` at or after `from`.
fn find(data: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || data.len() < needle.len() {
        return None;
    }
    let last = data.len() - needle.len();
    if from > last {
        return None;
    }
    (from..=last).find(|&i| &data[i..i + needle.len()] == needle)
}

/// Push a finding unless the PDF hit [`PDF_MAX_FINDINGS`]; the cap is
/// recorded as its own finding so truncation is never silent.
fn push_finding(findings: &mut Vec<ContainerFinding>, finding: ContainerFinding) {
    if findings.len() >= PDF_MAX_FINDINGS {
        let exhausted = "finding budget exhausted; further findings suppressed";
        if findings.last().is_none_or(|last| last.detail != exhausted) {
            findings.push(ContainerFinding {
                path: "<pdf>".to_string(),
                family: PDF_FAMILY.to_string(),
                detail: exhausted.to_string(),
            });
        }
        return;
    }
    findings.push(finding);
}

/// Bound a detail string to [`DETAIL_MAX_BYTES`] bytes at a char boundary.
fn bound_detail(detail: String) -> String {
    if detail.len() <= DETAIL_MAX_BYTES {
        return detail;
    }
    let mut end = DETAIL_MAX_BYTES;
    while !detail.is_char_boundary(end) {
        end -= 1;
    }
    let mut bound = detail[..end].to_string();
    bound.push('…');
    bound
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forensics::{scan_bytes, FileFamily};
    use flate2::write::DeflateEncoder;
    use std::io::Write as _;

    /// Assemble a minimal deterministic PDF: `%PDF-1.7` header, numbered
    /// objects, a correct xref table, trailer, `startxref`, `%%EOF`.
    fn build_pdf(objects: &[&str]) -> Vec<u8> {
        let mut out: Vec<u8> = b"%PDF-1.7\n".to_vec();
        let mut offsets: Vec<usize> = Vec::new();
        for (index, body) in objects.iter().enumerate() {
            offsets.push(out.len());
            out.extend_from_slice(format!("{} 0 obj\n{body}\nendobj\n", index + 1).as_bytes());
        }
        let xref_at = out.len();
        out.extend_from_slice(format!("xref\n0 {}\n", objects.len() + 1).as_bytes());
        out.extend_from_slice(b"0000000000 65535 f \n");
        for offset in &offsets {
            out.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
        }
        out.extend_from_slice(
            format!(
                "trailer\n<</Size {} /Root 1 0 R>>\nstartxref\n{xref_at}\n%%EOF\n",
                objects.len() + 1
            )
            .as_bytes(),
        );
        out
    }

    fn clean_pdf() -> Vec<u8> {
        build_pdf(&[
            "<</Type/Catalog/Pages 2 0 R>>",
            "<</Type/Pages/Kids[3 0 R]/Count 1>>",
            "<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>",
        ])
    }

    fn doc004_findings(findings: &[ContainerFinding]) -> Vec<&ContainerFinding> {
        findings
            .iter()
            .filter(|f| f.family == DOC_004_FAMILY)
            .collect()
    }

    #[test]
    fn clean_pdf_yields_only_observations() {
        let bytes = clean_pdf();
        let findings = analyze_pdf(&bytes);
        assert!(doc004_findings(&findings).is_empty());
        let inventory = findings
            .iter()
            .find(|f| f.family == PDF_FAMILY && f.path == "<pdf>")
            .expect("inventory finding");
        assert!(
            inventory.detail.contains("version 1.7"),
            "detail: {}",
            inventory.detail
        );
        assert!(
            inventory.detail.contains("1 %%EOF marker"),
            "detail: {}",
            inventory.detail
        );
        assert!(
            inventory.detail.contains("startxref ok"),
            "detail: {}",
            inventory.detail
        );
    }

    #[test]
    fn scan_bytes_wires_pdf_family() {
        let scan = scan_bytes(&clean_pdf());
        assert_eq!(scan.file_family, FileFamily::Pdf);
        assert!(!scan.container_findings.is_empty());
        assert!(!scan.detected);
        // Plain text is unchanged by the wiring.
        assert!(scan_bytes(b"plain text buffer")
            .container_findings
            .is_empty());
    }

    #[test]
    fn no_header_yields_single_finding() {
        let findings = analyze_pdf(b"junk data");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].family, DOC_004_FAMILY);
        assert!(findings[0].detail.contains("no %PDF- header"));
    }

    #[test]
    fn javascript_and_open_action_are_flagged() {
        let bytes = build_pdf(&[
            "<</Type/Catalog/Pages 2 0 R/OpenAction<</S/JavaScript/JS(app.launch(););>>>>",
            "<</Type/Pages/Kids[3 0 R]/Count 1>>",
        ]);
        let scan_tmp = analyze_pdf(&bytes);
        let findings = doc004_findings(&scan_tmp);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].path, "object 1");
        assert!(findings[0].detail.contains("/OpenAction"));
        assert!(findings[0].detail.contains("/JavaScript"));
        assert!(findings[0].detail.contains("/JS"));
    }

    #[test]
    fn launch_action_is_flagged() {
        let bytes = build_pdf(&[
            "<</Type/Catalog/Pages 2 0 R/OpenAction<</S/Launch/F(cmd.exe)>>>>",
            "<</Type/Pages/Kids[3 0 R]/Count 1>>",
        ]);
        let scan_tmp = analyze_pdf(&bytes);
        let findings = doc004_findings(&scan_tmp);
        assert!(findings.iter().any(|f| f.detail.contains("/Launch")));
    }

    #[test]
    fn embedded_file_is_flagged() {
        let bytes = build_pdf(&[
            "<</Type/Catalog/Pages 2 0 R>>",
            "<</Type/Pages/Kids[3 0 R]/Count 1>>",
            "<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>",
            "<</Type/Filespec/F(attach.bin)/EF<</F 5 0 R>>>>",
            "<</Type/EmbeddedFile/Subtype(application#2Foctet-stream)/Length 12>>\nstream\nraw payload\nendstream",
        ]);
        let scan_tmp = analyze_pdf(&bytes);
        let findings = doc004_findings(&scan_tmp);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].path, "object 5");
        assert!(findings[0].detail.contains("/EmbeddedFile"));
    }

    #[test]
    fn trailing_data_after_last_eof_is_flagged() {
        let mut bytes = clean_pdf();
        bytes.extend_from_slice(b"\nappended payload\n");
        let scan_tmp = analyze_pdf(&bytes);
        let findings = doc004_findings(&scan_tmp);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].path, "trailer");
        assert!(findings[0].detail.contains("after the last %%EOF"));
    }

    #[test]
    fn trailing_whitespace_after_eof_is_not_flagged() {
        let mut bytes = clean_pdf();
        bytes.extend_from_slice(b"\r\n\n");
        assert!(doc004_findings(&analyze_pdf(&bytes)).is_empty());
    }

    #[test]
    fn truncated_pdf_folds_errors_into_single_finding() {
        let clean = clean_pdf();
        let truncated = &clean[..clean.len() / 2];
        let scan_tmp = analyze_pdf(truncated);
        let findings = doc004_findings(&scan_tmp);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].path, "<pdf>");
        assert!(findings[0].detail.contains("malformed pdf"));
        assert!(findings[0].detail.contains("no %%EOF marker"));
    }

    #[test]
    fn oversized_length_claim_is_flagged() {
        let bytes =
            build_pdf(&["<</Type/EmbeddedFile/Length 2147483647>>\nstream\nshort\nendstream"]);
        let scan_tmp = analyze_pdf(&bytes);
        let findings = doc004_findings(&scan_tmp);
        assert!(findings
            .iter()
            .any(|f| f.detail.contains("Length claims 2147483647")));
    }

    #[test]
    fn budget_oversized_file_is_skipped() {
        let data = vec![0u8; PDF_MAX_FILE_BYTES + 1];
        let findings = analyze_pdf(&data);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].family, DOC_004_FAMILY);
        assert!(findings[0].detail.contains("scan budget"));
    }

    #[test]
    fn flate_bomb_is_bounded() {
        // 1 MiB of 'A' compressed to a few hundred bytes, with a lying small
        // /Length and the inflated output far beyond the per-stream cap.
        let big = vec![b'A'; 1024 * 1024];
        let mut encoder = DeflateEncoder::new(Vec::new(), flate2::Compression::best());
        encoder.write_all(&big).expect("deflate write");
        let compressed = encoder.finish().expect("deflate finish");
        assert!(compressed.len() < 4096);
        let body = format!(
            "<</Type/EmbeddedFile/Filter/FlateDecode/Length {}>>\nstream\n",
            compressed.len() + 4
        );
        let mut bytes = b"%PDF-1.7\n1 0 obj\n".to_vec();
        bytes.extend_from_slice(body.as_bytes());
        bytes.extend_from_slice(&compressed);
        bytes.extend_from_slice(b"\nendstream\nendobj\n");
        bytes.extend_from_slice(b"startxref\n99999\n%%EOF\n");
        // Completes in bounded time/memory and never panics; the inflate cap
        // keeps the extracted-text budget at most PDF_MAX_STREAM_INFLATE_BYTES.
        let findings = analyze_pdf(&bytes);
        assert!(findings.len() <= PDF_MAX_FINDINGS);
    }

    #[test]
    fn crypt_and_stacked_filters_are_flagged() {
        let bytes = build_pdf(&[
            "<</Type/EmbeddedFile/Filter/Crypt>>\nstream\nx\nendstream",
            "<</Type/EmbeddedFile/Filter[/ASCII85Decode/FlateDecode/RunLengthDecode]>>\nstream\nx\nendstream",
            "<</Type/EmbeddedFile/Filter[/ASCII85Decode/FlateDecode]>>\nstream\nx\nendstream",
        ]);
        let scan_tmp = analyze_pdf(&bytes);
        let findings = doc004_findings(&scan_tmp);
        assert!(findings.iter().any(|f| f.detail.contains("/Crypt")));
        assert!(findings
            .iter()
            .any(|f| f.detail.contains("stacked filter chain")));
        // The legitimate two-filter chain is not flagged as stacked.
        assert_eq!(
            findings
                .iter()
                .filter(|f| f.detail.contains("stacked filter chain"))
                .count(),
            1
        );
    }

    #[test]
    fn image_streams_are_exempt_from_filter_suspicion() {
        let bytes = build_pdf(&[
            "<</Type/XObject/Subtype/Image/Filter[/ASCII85Decode/FlateDecode/RunLengthDecode]/Width 4>>\nstream\nx\nendstream",
        ]);
        assert!(doc004_findings(&analyze_pdf(&bytes)).is_empty());
    }

    #[test]
    fn acroform_and_xmp_are_observations() {
        let bytes = build_pdf(&[
            "<</AcroForm<</Fields[]>>>>",
            "<</Type/Metadata>>\nstream\n<?xpacket begin='' id='x'?>\nendstream",
        ]);
        let findings = analyze_pdf(&bytes);
        assert!(doc004_findings(&findings).is_empty());
        assert!(findings
            .iter()
            .any(|f| f.family == PDF_FAMILY && f.detail.contains("/AcroForm")));
        assert!(findings
            .iter()
            .any(|f| f.family == PDF_FAMILY && f.detail.contains("XMP metadata")));
    }

    #[test]
    fn missing_trailer_and_bad_startxref_are_reported() {
        // No trailer; startxref points at a non-xref offset.
        let out: Vec<u8> = b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\nstartxref\n1\n%%EOF\n".to_vec();
        let scan_tmp = analyze_pdf(&out);
        let findings = doc004_findings(&scan_tmp);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].detail.contains("no trailer dictionary"));
        assert!(findings[0].detail.contains("not an xref table"));
    }

    #[test]
    fn startxref_out_of_bounds_is_reported() {
        let out: Vec<u8> = b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\nstartxref\n99999\n%%EOF\n".to_vec();
        let scan_tmp = analyze_pdf(&out);
        let findings = doc004_findings(&scan_tmp);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].detail.contains("out of bounds"));
    }

    #[test]
    fn literal_string_zero_width_channel_fires() {
        let laced = "Hidden\u{200b}\u{200c}\u{200b}\u{200c}\u{200b}\u{200c}\u{200b}\u{200c}\u{200b}\u{200c}\u{200b}\u{200c} run";
        let bytes = build_pdf(&[&format!("<</Title({laced})>>")]);
        let scan_tmp = analyze_pdf(&bytes);
        let findings = doc004_findings(&scan_tmp);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].path, "strings");
        assert!(findings[0].detail.contains("ZERO_WIDTH"));
    }

    #[test]
    fn hex_string_channel_fires() {
        // U+202E override (E2 80 AE) encoded as a hex string in a dict,
        // preceded by an ASCII underscore: "<_ \u{202E}>".
        let bytes = build_pdf(&["<</Title<5FE280AE2020>>>"]);
        let scan_tmp = analyze_pdf(&bytes);
        let findings = doc004_findings(&scan_tmp);
        assert!(findings
            .iter()
            .any(|f| f.path == "strings" && f.detail.contains("BIDI_CONTROLS")));
    }

    #[test]
    fn hostile_mutations_never_panic() {
        let clean = clean_pdf();
        let mut mutants: Vec<Vec<u8>> = Vec::new();
        for i in (0..clean.len()).step_by(7) {
            for probe in [0x00u8, 0xFF, b'(', b')', b'<', b'>', b'\\', b'%'] {
                let mut mutant = clean.clone();
                mutant[i] = probe;
                mutants.push(mutant);
            }
        }
        for cut in (0..clean.len()).step_by(64) {
            mutants.push(clean[..cut].to_vec());
        }
        mutants.push(Vec::new());
        mutants.push(b"%PDF-".to_vec());
        mutants.push(b"%PDF-1.7\n".to_vec());
        for mutant in &mutants {
            let findings = analyze_pdf(mutant);
            assert!(findings.len() <= PDF_MAX_FINDINGS);
        }
    }

    #[test]
    fn object_scan_budget_is_enforced() {
        // More than PDF_MAX_OBJECTS_SCANNED object markers: the scan must
        // truncate with an explicit observation, not run unbounded.
        let filler = "x".repeat(64);
        let body = format!("<</Length {}/Title({filler})>>", filler.len());
        let objects: Vec<String> = (0..PDF_MAX_OBJECTS_SCANNED + 8)
            .map(|_| body.clone())
            .collect();
        let refs: Vec<&str> = objects.iter().map(|s| s.as_str()).collect();
        let bytes = build_pdf(&refs);
        let findings = analyze_pdf(&bytes);
        assert!(findings
            .iter()
            .any(|f| f.detail.contains("object scan truncated")));
    }

    #[test]
    fn junk_prefix_header_is_flagged() {
        let mut bytes = b"leading junk!!\n".to_vec();
        bytes.extend_from_slice(&clean_pdf());
        let scan_tmp = analyze_pdf(&bytes);
        let findings = doc004_findings(&scan_tmp);
        assert!(findings
            .iter()
            .any(|f| f.path == "header" && f.detail.contains("junk prefix")));
    }
}
