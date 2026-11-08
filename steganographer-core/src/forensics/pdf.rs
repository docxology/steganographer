//! Bounded lexical PDF inspection, not a renderer or a complete PDF validator.
//! Names, comments, literal/hex strings and stream bytes are kept distinct.
//! Unsupported encodings, compressed object streams and exhausted budgets are
//! explicitly incomplete; observations alone never become concealment verdicts.

use super::{incomplete, ooxml, ContainerAnalysis, ContainerFinding};
use crate::unicode_text;
use flate2::read::ZlibDecoder;
use std::borrow::Cow;
use std::io::Read as _;

pub const DOC_004_FAMILY: &str = "DOC-004";
pub const PDF_FAMILY: &str = "PDF";
pub const PDF_MAX_FILE_BYTES: usize = 64 * 1024 * 1024;
pub const PDF_MAX_OBJECTS_SCANNED: usize = 8192;
pub const PDF_MAX_STRING_LENGTH: usize = 4096;
pub const PDF_MAX_OBJECT_WINDOW_BYTES: usize = 64 * 1024;
pub const PDF_MAX_TEXT_BYTES: usize = unicode_text::MAX_TEXT_SCAN_BYTES;
pub const PDF_MAX_STREAM_BYTES: usize = 8 * 1024 * 1024;
pub const PDF_MAX_STREAM_INFLATE_BYTES: usize = 256 * 1024;
pub const PDF_MAX_STREAM_INFLATE_TOTAL: usize = 1024 * 1024;
pub const PDF_MAX_STREAMS_INFLATED: usize = 16;
pub const PDF_MAX_DECODE_INPUT_TOTAL: usize = 16 * 1024 * 1024;
pub const PDF_MAX_FINDINGS: usize = 64;
const HEADER_WINDOW_BYTES: usize = 1024;
const DETAIL_MAX_BYTES: usize = 256;
const SUSPICIOUS_KEYWORDS: &[(&[u8], &str)] = &[
    (b"EmbeddedFile", "embedded file payload (/EmbeddedFile)"),
    (b"EmbeddedFiles", "embedded file name tree (/EmbeddedFiles)"),
    (b"JavaScript", "embedded JavaScript (/JavaScript)"),
    (b"JS", "JavaScript action payload (/JS)"),
    (b"OpenAction", "auto-run action (/OpenAction)"),
    (b"Launch", "external application launch (/Launch)"),
];

fn reason(result: &mut ContainerAnalysis, code: &str) {
    incomplete(&mut result.incomplete_reasons, code);
}

fn finding(result: &mut ContainerAnalysis, path: &str, positive: bool, detail: String) {
    result.detected |= positive;
    let item = ContainerFinding {
        path: path.to_string(),
        family: (if positive { DOC_004_FAMILY } else { PDF_FAMILY }).to_string(),
        detail: bound_detail(detail),
    };
    if result.findings.len() < PDF_MAX_FINDINGS {
        result.findings.push(item);
    } else {
        reason(result, "pdf_finding_limit");
        // Keep a visible positive even if observations used all display slots.
        if !result.findings[..PDF_MAX_FINDINGS - 1]
            .iter()
            .any(|f| f.family == DOC_004_FAMILY)
        {
            if positive {
                result.findings[PDF_MAX_FINDINGS - 2] = item;
            } else if result.findings[PDF_MAX_FINDINGS - 1].family == DOC_004_FAMILY {
                result.findings[PDF_MAX_FINDINGS - 2] =
                    result.findings[PDF_MAX_FINDINGS - 1].clone();
            }
        }
        result.findings[PDF_MAX_FINDINGS - 1] = ContainerFinding {
            path: "<pdf>".to_string(),
            family: PDF_FAMILY.to_string(),
            detail: "finding budget exhausted; further findings suppressed".to_string(),
        };
    }
}

fn whitespace(b: u8) -> bool {
    matches!(b, 0 | b'\t' | b'\n' | 0x0c | b'\r' | b' ')
}

fn delimiter(b: u8) -> bool {
    whitespace(b)
        || matches!(
            b,
            b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%'
        )
}

#[derive(Debug)]
enum Token<'a> {
    Word(&'a [u8]),
    Name(Cow<'a, [u8]>),
    String(Vec<u8>, bool),
    Delimiter(u8),
    EofMarker(usize),
}

/// One forward-only lexer. Every next() either consumes input or returns None.
/// Oversized strings are consumed to their real delimiter within this slice,
/// but only a bounded prefix is retained. They are never reinterpreted as code.
struct Lexer<'a> {
    data: &'a [u8],
    pos: usize,
    malformed: bool,
    limited: bool,
}

impl<'a> Lexer<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            malformed: false,
            limited: false,
        }
    }

    fn next(&mut self) -> Option<Token<'a>> {
        while self.pos < self.data.len() {
            let start = self.pos;
            let byte = self.data[self.pos];
            self.pos += 1;
            if whitespace(byte) {
                continue;
            }
            match byte {
                b'%' => {
                    while self.pos < self.data.len()
                        && !matches!(self.data[self.pos], b'\r' | b'\n')
                    {
                        self.pos += 1;
                    }
                    let line_start = self.data[..start]
                        .iter()
                        .rposition(|b| matches!(b, b'\r' | b'\n'))
                        .map_or(0, |p| p + 1);
                    if self.data[line_start..start].iter().all(|b| whitespace(*b))
                        && self.data[start..self.pos].starts_with(b"%%EOF")
                        && self.data[start + 5..self.pos]
                            .iter()
                            .all(|b| whitespace(*b))
                    {
                        return Some(Token::EofMarker(start));
                    }
                }
                b'/' => {
                    let name_start = self.pos;
                    while self.pos < self.data.len() && !delimiter(self.data[self.pos]) {
                        self.pos += 1;
                    }
                    let raw = &self.data[name_start..self.pos];
                    if !raw.contains(&b'#') {
                        self.limited |= raw.len() > PDF_MAX_STRING_LENGTH;
                        return Some(Token::Name(Cow::Borrowed(
                            &raw[..raw.len().min(PDF_MAX_STRING_LENGTH)],
                        )));
                    }
                    let mut name = Vec::with_capacity(raw.len().min(PDF_MAX_STRING_LENGTH));
                    let mut at = 0;
                    while at < raw.len() {
                        let mut value = raw[at];
                        at += 1;
                        if value == b'#' {
                            if let Some((hi, lo)) = raw
                                .get(at..at.saturating_add(2))
                                .and_then(|p| Some((hex_val(p[0])?, hex_val(p[1])?)))
                            {
                                value = hi * 16 + lo;
                                at += 2;
                            } else {
                                self.malformed = true;
                            }
                        }
                        if name.len() < PDF_MAX_STRING_LENGTH {
                            name.push(value);
                        } else {
                            self.limited = true;
                        }
                    }
                    return Some(Token::Name(Cow::Owned(name)));
                }
                b'(' => {
                    let mut out = Vec::new();
                    let mut depth = 1usize;
                    let mut capped = false;
                    while self.pos < self.data.len() {
                        let mut value = self.data[self.pos];
                        self.pos += 1;
                        match value {
                            b'\\' => {
                                let Some(&escape) = self.data.get(self.pos) else {
                                    break;
                                };
                                self.pos += 1;
                                value = match escape {
                                    b'n' => b'\n',
                                    b'r' => b'\r',
                                    b't' => b'\t',
                                    b'b' => 8,
                                    b'f' => 12,
                                    b'\n' => continue,
                                    b'\r' => {
                                        if self.data.get(self.pos) == Some(&b'\n') {
                                            self.pos += 1;
                                        }
                                        continue;
                                    }
                                    b'0'..=b'7' => {
                                        let mut number = u16::from(escape - b'0');
                                        for _ in 0..2 {
                                            match self.data.get(self.pos) {
                                                Some(&digit @ b'0'..=b'7') => {
                                                    number = number * 8 + u16::from(digit - b'0');
                                                    self.pos += 1;
                                                }
                                                _ => break,
                                            }
                                        }
                                        number as u8
                                    }
                                    other => other,
                                };
                            }
                            b'(' => depth += 1,
                            b')' => {
                                depth -= 1;
                                if depth == 0 {
                                    return Some(Token::String(out, capped));
                                }
                            }
                            b'\r' => {
                                if self.data.get(self.pos) == Some(&b'\n') {
                                    self.pos += 1;
                                }
                                value = b'\n';
                            }
                            _ => {}
                        }
                        if out.len() < PDF_MAX_STRING_LENGTH {
                            out.push(value);
                        } else {
                            capped = true;
                        }
                    }
                    self.malformed = true;
                    return Some(Token::String(out, true));
                }
                b'<' if self.data.get(self.pos) != Some(&b'<') => {
                    let mut out = Vec::new();
                    let mut high = None;
                    let mut capped = false;
                    while self.pos < self.data.len() {
                        let byte = self.data[self.pos];
                        self.pos += 1;
                        if byte == b'>' {
                            if let Some(hi) = high {
                                if out.len() < PDF_MAX_STRING_LENGTH {
                                    out.push(hi * 16);
                                } else {
                                    capped = true;
                                }
                            }
                            return Some(Token::String(out, capped));
                        }
                        if whitespace(byte) {
                            continue;
                        }
                        if let Some(nibble) = hex_val(byte) {
                            if let Some(hi) = high.take() {
                                if out.len() < PDF_MAX_STRING_LENGTH {
                                    out.push(hi * 16 + nibble);
                                } else {
                                    capped = true;
                                }
                            } else {
                                high = Some(nibble);
                            }
                        } else {
                            self.malformed = true;
                        }
                    }
                    self.malformed = true;
                    return Some(Token::String(out, true));
                }
                b'<' | b'>' => {
                    if self.data.get(self.pos) == Some(&byte) {
                        self.pos += 1;
                    }
                    return Some(Token::Delimiter(byte));
                }
                b')' | b'[' | b']' | b'{' | b'}' => return Some(Token::Delimiter(byte)),
                _ => {
                    while self.pos < self.data.len() && !delimiter(self.data[self.pos]) {
                        self.pos += 1;
                    }
                    return Some(Token::Word(&self.data[start..self.pos]));
                }
            }
        }
        None
    }
}

struct ScanState {
    text: Vec<u8>,
    inflate_total: usize,
    streams_inflated: usize,
    decode_input: usize,
    xref_stream: bool,
}

/// Analyze bounded lexical objects, with a positive latch separate from display
/// caps. Compressed object streams are explicitly unsupported, never certified
/// clean. Stream searches are bounded BEFORE traversal.
pub fn analyze_pdf(input: &[u8]) -> ContainerAnalysis {
    let mut result = ContainerAnalysis::default();
    let data = &input[..input.len().min(PDF_MAX_FILE_BYTES)];
    if data.len() != input.len() {
        reason(&mut result, "pdf_file_byte_limit");
    }
    let header = &data[..data.len().min(HEADER_WINDOW_BYTES)];
    let Some(header_at) = find(header, b"%PDF-", 0) else {
        reason(&mut result, "pdf_header_invalid");
        finding(
            &mut result,
            "<pdf>",
            false,
            "no %PDF- header within the first 1024 bytes; malformed pdf".to_string(),
        );
        return result;
    };
    if header_at > 0 {
        finding(
            &mut result,
            "header",
            true,
            format!("junk prefix of {header_at} bytes before the %PDF- header (polyglot risk)"),
        );
    }
    let version = parse_pdf_version(&data[header_at..]);
    if version.is_none() {
        reason(&mut result, "pdf_header_invalid");
    }
    let mut state = ScanState {
        text: Vec::new(),
        inflate_total: 0,
        streams_inflated: 0,
        decode_input: 0,
        xref_stream: false,
    };
    let mut lexer = Lexer::new(data);
    let mut numbers: [Option<u64>; 2] = [None, None];
    let mut objects = 0usize;
    let mut eof_count = 0usize;
    let mut last_eof = None;
    let mut trailer = false;
    let mut startxref = None;
    let mut expect_startxref = false;
    while let Some(token) = lexer.next() {
        match &token {
            Token::Word(b"obj") if numbers[0].is_some() && numbers[1].is_some() => {
                if objects == PDF_MAX_OBJECTS_SCANNED {
                    reason(&mut result, "pdf_object_limit");
                    break;
                }
                objects += 1;
                let label = format!("object {}", numbers[0].unwrap());
                lexer.pos = scan_object(data, lexer.pos, &label, &mut state, &mut result);
                numbers = [None, None];
                continue;
            }
            Token::EofMarker(at) => {
                eof_count += 1;
                last_eof = Some(*at);
            }
            Token::Word(b"trailer") => trailer = true,
            Token::Word(b"startxref") => expect_startxref = true,
            Token::Name(name) if name.as_ref() == b"Encrypt" => {
                reason(&mut result, "pdf_encryption_unsupported")
            }
            Token::Word(word) if expect_startxref => {
                startxref = unsigned(word).and_then(|n| usize::try_from(n).ok());
                expect_startxref = false;
            }
            _ => {}
        }
        match token {
            Token::Word(word) => numbers = [numbers[1], unsigned(word)],
            _ => numbers = [None, None],
        }
    }
    if lexer.malformed {
        reason(&mut result, "pdf_lexical_error");
    }
    if lexer.limited {
        reason(&mut result, "pdf_token_limit");
    }
    let mut errors = Vec::new();
    if last_eof.is_none() {
        errors.push("no %%EOF marker".to_string());
    }
    if !trailer && !state.xref_stream {
        errors.push("no trailer dictionary".to_string());
    }
    let xref_status = match startxref {
        None => {
            errors.push("no valid startxref marker".to_string());
            "absent"
        }
        Some(at) if at >= data.len() => {
            errors.push(format!("startxref offset {at} is out of bounds"));
            "out of bounds"
        }
        Some(at) if data[at..].starts_with(b"xref") || data[at].is_ascii_digit() => "ok",
        Some(_) => {
            errors.push("startxref target mismatch".to_string());
            "mismatch"
        }
    };
    let eof_coverage_complete = !result.incomplete_reasons.iter().any(|code| {
        matches!(
            code.as_str(),
            "pdf_file_byte_limit"
                | "pdf_object_limit"
                | "pdf_object_byte_limit"
                | "pdf_object_unterminated"
                | "pdf_stream_unterminated"
                | "pdf_stream_eol_invalid"
                | "pdf_lexical_error"
        )
    });
    if let Some(last) = last_eof.filter(|_| eof_coverage_complete) {
        let appended = data[last + 5..].iter().filter(|b| !whitespace(**b)).count();
        if appended > 0 {
            finding(&mut result, "trailer", true, format!("{appended} byte(s) of data after the last %%EOF (appended payload or incremental-revision residue)"));
        }
    }
    finding(&mut result, "<pdf>", false, format!(
        "pdf: version {}, header at byte {header_at}, {objects} object(s) scanned, {eof_count} %%EOF marker(s), trailer {}, startxref {xref_status}",
        version.as_deref().unwrap_or("unknown"), if trailer { "present" } else { "absent" },
    ));
    if !errors.is_empty() {
        reason(&mut result, "pdf_structure_invalid");
        finding(
            &mut result,
            "<pdf>",
            false,
            format!("malformed pdf: {}", errors.join("; ")),
        );
    }
    if find(data, b"<?xpacket", 0).is_some() {
        finding(
            &mut result,
            "metadata",
            false,
            "XMP metadata packet present".to_string(),
        );
    }
    for text_finding in unicode_text::analyze_bytes(&state.text) {
        finding(
            &mut result,
            "strings",
            true,
            ooxml::format_text_finding(&text_finding),
        );
    }
    result
}

enum ObjectContext<'a> {
    Dictionary(Option<Cow<'a, [u8]>>),
    FilterArray,
    Array,
}

/// Consume one object window once. Stream bytes are skipped atomically and can
/// never manufacture `obj`, `endobj`, action names or EOF markers.
fn scan_object(
    data: &[u8],
    start: usize,
    label: &str,
    state: &mut ScanState,
    result: &mut ContainerAnalysis,
) -> usize {
    let end = start
        .saturating_add(PDF_MAX_OBJECT_WINDOW_BYTES)
        .min(data.len());
    let mut lexer = Lexer::new(&data[start..end]);
    let mut contexts: Vec<ObjectContext<'_>> = Vec::new();
    let mut stream_decode_unsupported = false;
    let mut filters: Vec<Cow<'_, [u8]>> = Vec::new();
    let mut image = false;
    let mut claimed_length = None;
    let mut length_numbers = 0usize;
    let mut matched = [false; SUSPICIOUS_KEYWORDS.len()];
    let mut saw_stream = false;
    let mut closed = false;
    let mut next = data.len();
    while let Some(token) = lexer.next() {
        // A dictionary name is either a key or its value, never both.
        // Composite values consume their parent's key at the opening token.
        let outer = contexts.len() == 1;
        let closing = matches!(&token, Token::Delimiter(b'>' | b']'));
        let value_key = if closing {
            None
        } else if let Some(ObjectContext::Dictionary(key)) = contexts.last_mut() {
            if key.is_some() {
                key.take()
            } else {
                if let Token::Name(name) = &token {
                    *key = Some(name.clone());
                }
                None
            }
        } else {
            None
        };
        let filter_value = outer && value_key.as_deref() == Some(b"Filter");
        let decode_parameters_value = outer && value_key.as_deref() == Some(b"DecodeParms");
        let filter_array = matches!(contexts.last(), Some(ObjectContext::FilterArray));
        match &token {
            Token::Name(name) => {
                for (index, (keyword, _)) in SUSPICIOUS_KEYWORDS.iter().enumerate() {
                    matched[index] |= name.as_ref() == *keyword;
                }
                if name.as_ref() == b"AcroForm" {
                    finding(
                        result,
                        label,
                        false,
                        format!("{label}: interactive form (/AcroForm) present"),
                    );
                }
                if name.as_ref() == b"ObjStm" {
                    reason(result, "pdf_object_stream_unsupported");
                }
                if name.as_ref() == b"Encrypt" {
                    reason(result, "pdf_encryption_unsupported");
                }
                if outer && value_key.as_deref() == Some(b"Type") && name.as_ref() == b"XRef" {
                    state.xref_stream = true;
                }
                if outer && value_key.as_deref() == Some(b"Subtype") {
                    image = name.as_ref() == b"Image";
                }
                if filter_value || filter_array {
                    if filters.len() < 64 {
                        filters.push(name.clone());
                    } else {
                        reason(result, "pdf_filter_limit");
                    }
                }
            }
            Token::String(bytes, capped) => {
                if *capped {
                    reason(result, "pdf_string_limit");
                }
                if value_key.as_deref() == Some(b"URI") {
                    if let Some((dangerous, scheme)) = classify_uri(bytes) {
                        finding(
                            result,
                            label,
                            dangerous,
                            format!(
                                "{label}: {} URI link (scheme {scheme}:)",
                                if dangerous { "dangerous" } else { "external" }
                            ),
                        );
                    }
                }
                push_text(&mut state.text, bytes, *capped, result);
            }
            Token::Delimiter(b'[') => contexts.push(if filter_value {
                ObjectContext::FilterArray
            } else {
                ObjectContext::Array
            }),
            Token::Delimiter(b'<') => contexts.push(ObjectContext::Dictionary(None)),
            Token::Delimiter(b']' | b'>') => {
                let valid = matches!(
                    (&token, contexts.pop()),
                    (
                        Token::Delimiter(b']'),
                        Some(ObjectContext::Array | ObjectContext::FilterArray)
                    ) | (
                        Token::Delimiter(b'>'),
                        Some(ObjectContext::Dictionary(None))
                    )
                );
                if !valid {
                    reason(result, "pdf_lexical_error");
                    stream_decode_unsupported = true;
                }
            }
            Token::Word(b"endobj") => {
                if !contexts.is_empty() {
                    reason(result, "pdf_lexical_error");
                }
                closed = true;
                next = start + lexer.pos;
                break;
            }
            Token::Word(b"stream") => {
                saw_stream = true;
                if !contexts.is_empty() {
                    reason(result, "pdf_lexical_error");
                    stream_decode_unsupported = true;
                }
                let keyword_end = start + lexer.pos;
                if let Some((range, resume)) =
                    stream_range(data, keyword_end, claimed_length, result)
                {
                    if !stream_decode_unsupported {
                        inspect_stream(&data[range], &filters, image, label, state, result);
                    }
                    // Only the small suffix after endstream is lexed for endobj.
                    let suffix_end = resume
                        .saturating_add(PDF_MAX_OBJECT_WINDOW_BYTES)
                        .min(data.len());
                    let mut suffix = Lexer::new(&data[resume..suffix_end]);
                    if matches!(suffix.next(), Some(Token::Word(b"endobj"))) {
                        closed = true;
                        next = resume + suffix.pos;
                    } else {
                        reason(result, "pdf_object_unterminated");
                        next = resume;
                    }
                } else {
                    next = data.len();
                }
                break;
            }
            Token::Word(word) => {
                if outer && value_key.as_deref() == Some(b"Length") {
                    claimed_length = unsigned(word);
                    length_numbers = usize::from(claimed_length.is_some());
                } else if length_numbers == 1 && unsigned(word).is_some() {
                    length_numbers = 2;
                } else if length_numbers == 2 && *word == b"R" {
                    claimed_length = None;
                    reason(result, "pdf_indirect_length");
                    length_numbers = 0;
                } else {
                    length_numbers = 0;
                }
            }
            _ => {}
        }
        if filter_value && !matches!(&token, Token::Name(_) | Token::Delimiter(b'[')) {
            reason(result, "pdf_filter_unsupported");
            stream_decode_unsupported = true;
        }
        if filter_array && !matches!(&token, Token::Name(_) | Token::Delimiter(b']')) {
            reason(result, "pdf_filter_unsupported");
            stream_decode_unsupported = true;
        }
        if value_key.as_deref() == Some(b"URI") && matches!(&token, Token::Word(_)) {
            reason(result, "pdf_uri_indirect_unsupported");
        }
        if decode_parameters_value && !matches!(&token, Token::Word(b"null")) {
            reason(result, "pdf_decode_parameters_unsupported");
            stream_decode_unsupported = true;
        }
    }
    if lexer.malformed {
        reason(result, "pdf_lexical_error");
    }
    if lexer.limited {
        reason(result, "pdf_token_limit");
    }
    if !closed {
        reason(
            result,
            if end < data.len() && !saw_stream {
                "pdf_object_byte_limit"
            } else {
                "pdf_object_unterminated"
            },
        );
    }
    let mut descriptions = Vec::new();
    for (index, (_, description)) in SUSPICIOUS_KEYWORDS.iter().enumerate() {
        if matched[index] {
            descriptions.push(*description);
        }
    }
    if !descriptions.is_empty() {
        finding(
            result,
            label,
            true,
            format!("{label}: suspicious keywords {}", descriptions.join("; ")),
        );
    }
    if !image && filters.iter().any(|name| name.as_ref() == b"Crypt") {
        finding(
            result,
            label,
            true,
            format!("{label}: non-image stream uses the /Crypt filter"),
        );
    } else if !image && filters.len() >= 3 {
        finding(
            result,
            label,
            true,
            format!("{label}: stacked filter chain on non-image stream"),
        );
    }
    next
}

/// Direct lengths are used only if their endpoint agrees with endstream. An
/// indirect/malformed length falls back to ONE bounded delimiter search, with
/// explicit ambiguity rather than pretending arbitrary stream bytes are parsed.
fn stream_range(
    data: &[u8],
    keyword_end: usize,
    claim: Option<u64>,
    result: &mut ContainerAnalysis,
) -> Option<(std::ops::Range<usize>, usize)> {
    let mut start = keyword_end;
    match data.get(start) {
        Some(b'\r') => {
            start += 1;
            if data.get(start) == Some(&b'\n') {
                start += 1;
            }
        }
        Some(b'\n') => start += 1,
        _ => {
            reason(result, "pdf_stream_eol_invalid");
            return None;
        }
    }
    if let Some(length) = claim {
        if length > PDF_MAX_STREAM_BYTES as u64 {
            reason(result, "pdf_stream_byte_limit");
        } else if let Some(end) = usize::try_from(length)
            .ok()
            .and_then(|n| start.checked_add(n))
            .filter(|end| *end <= data.len())
        {
            let mut at = end;
            if data.get(at) == Some(&b'\r') {
                at += 1;
            }
            if data.get(at) == Some(&b'\n') {
                at += 1;
            }
            if keyword_at(data, at, b"endstream") {
                return Some((start..end, at + 9));
            }
            reason(result, "pdf_stream_length_mismatch");
        } else {
            reason(result, "pdf_stream_length_mismatch");
        }
    } else {
        reason(result, "pdf_stream_length_unknown");
    }
    let end = start.saturating_add(PDF_MAX_STREAM_BYTES).min(data.len());
    let window = &data[start..end];
    let mut from = 0;
    while let Some(at) = find(window, b"endstream", from) {
        if at > 0 && matches!(window[at - 1], b'\r' | b'\n') && keyword_at(window, at, b"endstream")
        {
            let mut text_end = start + at;
            if text_end > start && data[text_end - 1] == b'\n' {
                text_end -= 1;
            }
            if text_end > start && data[text_end - 1] == b'\r' {
                text_end -= 1;
            }
            return Some((start..text_end, start + at + 9));
        }
        from = at + 9;
    }
    reason(result, "pdf_stream_unterminated");
    None
}

fn inspect_stream(
    bytes: &[u8],
    filters: &[Cow<'_, [u8]>],
    image: bool,
    _label: &str,
    state: &mut ScanState,
    result: &mut ContainerAnalysis,
) {
    if image {
        return;
    } // Pixel/font rendering is outside this lexical scope.
    if filters.is_empty() {
        collect_strings(bytes, &mut state.text, result);
        return;
    }
    if filters.len() != 1 || !matches!(filters[0].as_ref(), b"FlateDecode" | b"Fl") {
        reason(result, "pdf_filter_unsupported");
        return;
    }
    if state.streams_inflated >= PDF_MAX_STREAMS_INFLATED
        || state.inflate_total >= PDF_MAX_STREAM_INFLATE_TOTAL
    {
        reason(result, "pdf_inflate_limit");
        return;
    }
    if bytes.len() > PDF_MAX_DECODE_INPUT_TOTAL - state.decode_input {
        reason(result, "pdf_decode_input_budget");
        return;
    }
    state.decode_input += bytes.len();
    let cap = PDF_MAX_STREAM_INFLATE_BYTES.min(PDF_MAX_STREAM_INFLATE_TOTAL - state.inflate_total);
    state.streams_inflated += 1;
    let mut decoder = ZlibDecoder::new(bytes).take((cap + 1) as u64);
    let mut decoded = Vec::new();
    let decode_ok = decoder.read_to_end(&mut decoded).is_ok();
    if !decode_ok {
        reason(result, "pdf_flate_invalid");
    }
    if decoded.len() > cap {
        reason(result, "pdf_inflate_limit");
        decoded.truncate(cap);
    }
    state.inflate_total += decoded.len();
    collect_strings(&decoded, &mut state.text, result);
}

fn collect_strings(region: &[u8], text: &mut Vec<u8>, result: &mut ContainerAnalysis) {
    let mut lexer = Lexer::new(region);
    while let Some(token) = lexer.next() {
        if text.len() >= PDF_MAX_TEXT_BYTES {
            reason(result, "pdf_text_byte_limit");
            break;
        }
        if let Token::String(bytes, capped) = token {
            if capped {
                reason(result, "pdf_string_limit");
            }
            push_text(text, &bytes, capped, result);
        }
    }
    if lexer.malformed {
        reason(result, "pdf_lexical_error");
    }
    if lexer.limited {
        reason(result, "pdf_token_limit");
    }
}

fn push_text(text: &mut Vec<u8>, value: &[u8], capped: bool, result: &mut ContainerAnalysis) {
    if value.is_empty() {
        return;
    }
    let decoded;
    let value = if value.starts_with(b"\xfe\xff") || value.starts_with(b"\xff\xfe") {
        if !(value.len() - 2).is_multiple_of(2) && !capped {
            reason(result, "pdf_text_encoding_invalid");
            return;
        }
        let little = value.starts_with(b"\xff\xfe");
        let units = value[2..].as_chunks::<2>().0.iter().map(|pair| {
            if little {
                u16::from_le_bytes([pair[0], pair[1]])
            } else {
                u16::from_be_bytes([pair[0], pair[1]])
            }
        });
        let mut output = String::new();
        for ch in char::decode_utf16(units) {
            match ch {
                Ok(ch) => output.push(ch),
                Err(_) if capped => {
                    reason(result, "pdf_text_encoding_invalid");
                    break;
                }
                Err(_) => {
                    reason(result, "pdf_text_encoding_invalid");
                    return;
                }
            }
        }
        decoded = output;
        decoded.as_str()
    } else {
        match std::str::from_utf8(value) {
            Ok(value) => value,
            Err(error) if capped => {
                reason(result, "pdf_text_encoding_invalid");
                // The decoder's retained prefix can end inside a character.
                std::str::from_utf8(&value[..error.valid_up_to()]).unwrap_or("")
            }
            Err(_) => {
                reason(result, "pdf_text_encoding_unsupported");
                return;
            }
        }
    };
    if value.is_empty() {
        return;
    }
    let separator = usize::from(!text.is_empty());
    let room = PDF_MAX_TEXT_BYTES
        .saturating_sub(text.len())
        .saturating_sub(separator);
    let mut take = value.len().min(room);
    while !value.is_char_boundary(take) {
        take -= 1;
    }
    if take < value.len() {
        reason(result, "pdf_text_byte_limit");
    }
    if take == 0 {
        return;
    }
    if separator != 0 {
        text.push(b'\n');
    }
    text.extend_from_slice(&value.as_bytes()[..take]);
}

fn classify_uri(value: &[u8]) -> Option<(bool, &str)> {
    let text = std::str::from_utf8(value).ok()?.trim_start();
    let colon = text.find(':')?;
    let scheme = &text[..colon];
    if !scheme
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
    {
        return None;
    }
    for known in ["javascript", "vbscript", "file"] {
        if scheme.eq_ignore_ascii_case(known) {
            return Some((true, known));
        }
    }
    for known in ["http", "https", "mailto", "ftp"] {
        if scheme.eq_ignore_ascii_case(known) {
            return Some((false, known));
        }
    }
    None
}

fn unsigned(word: &[u8]) -> Option<u64> {
    if word.is_empty() || word.len() > 20 || !word.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(word).ok()?.parse().ok()
}

fn keyword_at(data: &[u8], at: usize, word: &[u8]) -> bool {
    data.get(at..at.saturating_add(word.len())) == Some(word)
        && data.get(at + word.len()).is_none_or(|b| delimiter(*b))
}

fn hex_val(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn parse_pdf_version(data: &[u8]) -> Option<String> {
    let version = data.get(5..8)?;
    if version[0].is_ascii_digit() && version[1] == b'.' && version[2].is_ascii_digit() {
        Some(String::from_utf8_lossy(version).into_owned())
    } else {
        None
    }
}

fn find(data: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    data.get(from..)?
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|at| at + from)
}

fn bound_detail(mut detail: String) -> String {
    if detail.len() > DETAIL_MAX_BYTES {
        let mut end = DETAIL_MAX_BYTES;
        while !detail.is_char_boundary(end) {
            end -= 1;
        }
        detail.truncate(end);
    }
    detail
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forensics::{scan_bytes, FileFamily};
    use flate2::write::ZlibEncoder;
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

    fn doc004_findings(analysis: &ContainerAnalysis) -> Vec<&ContainerFinding> {
        analysis
            .findings
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
            .findings
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
        assert_eq!(findings.findings.len(), 1);
        assert!(!findings.detected);
        assert!(!findings.incomplete_reasons.is_empty());
        assert_eq!(findings.findings[0].family, PDF_FAMILY);
        assert!(findings.findings[0].detail.contains("no %PDF- header"));
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
        assert!(!scan_tmp.detected);
        assert!(!scan_tmp.incomplete_reasons.is_empty());
        let malformed: Vec<_> = scan_tmp
            .findings
            .iter()
            .filter(|f| f.detail.starts_with("malformed pdf"))
            .collect();
        assert_eq!(malformed.len(), 1);
        assert!(malformed[0].detail.contains("no %%EOF marker"));
    }

    #[test]
    fn oversized_length_claim_is_flagged() {
        let bytes =
            build_pdf(&["<</Type/EmbeddedFile/Length 2147483647>>\nstream\nshort\nendstream"]);
        let scan_tmp = analyze_pdf(&bytes);
        assert!(scan_tmp.detected);
        assert!(scan_tmp
            .incomplete_reasons
            .iter()
            .any(|code| code == "pdf_stream_byte_limit"));
    }

    #[test]
    fn oversized_file_reports_partial_without_fabricating_detection() {
        let data = vec![0u8; PDF_MAX_FILE_BYTES + 1];
        let analysis = analyze_pdf(&data);
        assert!(!analysis.detected);
        assert!(analysis
            .incomplete_reasons
            .iter()
            .any(|code| code == "pdf_file_byte_limit"));
    }

    #[test]
    fn flate_bomb_is_bounded() {
        // Standard zlib framing; the decoded content exceeds the output cap.
        let big = vec![b'A'; 1024 * 1024];
        let mut encoder = ZlibEncoder::new(Vec::new(), flate2::Compression::best());
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
        let analysis = analyze_pdf(&bytes);
        assert!(analysis.findings.len() <= PDF_MAX_FINDINGS);
        assert!(analysis
            .incomplete_reasons
            .iter()
            .any(|code| code == "pdf_inflate_limit"));
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
            .findings
            .iter()
            .any(|f| f.family == PDF_FAMILY && f.detail.contains("/AcroForm")));
        assert!(findings
            .findings
            .iter()
            .any(|f| f.family == PDF_FAMILY && f.detail.contains("XMP metadata")));
    }

    #[test]
    fn missing_trailer_and_bad_startxref_are_reported() {
        // No trailer; startxref points at a non-xref offset.
        let out: Vec<u8> = b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\nstartxref\n1\n%%EOF\n".to_vec();
        let scan_tmp = analyze_pdf(&out);
        assert!(!scan_tmp.detected);
        assert!(scan_tmp
            .incomplete_reasons
            .iter()
            .any(|code| code == "pdf_structure_invalid"));
        assert!(scan_tmp
            .findings
            .iter()
            .any(|finding| finding.detail.contains("no trailer dictionary")));
        assert!(scan_tmp
            .findings
            .iter()
            .any(|finding| finding.detail.contains("startxref target mismatch")));
    }

    #[test]
    fn startxref_out_of_bounds_is_reported() {
        let out: Vec<u8> = b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\nstartxref\n99999\n%%EOF\n".to_vec();
        let scan_tmp = analyze_pdf(&out);
        assert!(!scan_tmp.detected);
        assert!(scan_tmp
            .incomplete_reasons
            .iter()
            .any(|code| code == "pdf_structure_invalid"));
        assert!(scan_tmp
            .findings
            .iter()
            .any(|finding| finding.detail.contains("out of bounds")));
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
            assert!(findings.findings.len() <= PDF_MAX_FINDINGS);
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
            .incomplete_reasons
            .iter()
            .any(|code| code == "pdf_object_limit"));
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
