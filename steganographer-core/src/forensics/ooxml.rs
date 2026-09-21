//! Container-aware OOXML / WordprocessingML analysis (DOC-001, DOC-002; plan
//! spec 03 §Documents) for ZIP-family inputs (docx, pptx, xlsx, generic ZIPs).
//!
//! Implements a minimal in-memory ZIP reader with **no new dependencies**:
//! end-of-central-directory (EOCD) scan, central-directory entry parsing,
//! local-header bounds checks, and `flate2` raw-deflate inflation for
//! compressed entries. Zip64, multi-disk archives, and data descriptors are
//! out of scope and rejected with typed errors rather than guessed at.
//!
//! Every parse step is bounds-checked against hostile input: entry counts,
//! name lengths, claimed sizes, and total inflate output are all capped by
//! the [`CONTAINER_*`] budget constants (mirrored in
//! [`crate::forensics::detector_registry`]). Budget violations never panic —
//! they surface as typed errors and, at the [`analyze_package`] level, as
//! DOC-001 topology findings.
//!
//! Detector families (reported as [`crate::forensics::ContainerFinding`]
//! `family` strings):
//!
//! - [`ZIP_TOPOLOGY_FAMILY`] — ZIP inventory observations for every ZIP-family
//!   input (entry counts, claimed sizes, compression methods, office family).
//!   Observations never set [`crate::forensics::ForensicScan::detected`].
//! - [`DOC_001_FAMILY`] — OOXML package anomalies: duplicate entries,
//!   encrypted entries, oversized claimed sizes, inflate-budget rejections,
//!   and embedded-media entries that claim text-like content.
//! - [`DOC_002_FAMILY`] — WordprocessingML concealment in the main part
//!   (`word/document.xml`): the Unicode/text stego channels from
//!   [`crate::unicode_text`] (zero-width, bidi, variation selectors, …) plus
//!   ASCII whitespace runs inside XML text nodes. These are detections and do
//!   set `detected`.

use std::collections::HashMap;
use std::io::Read;

use crate::forensics::ContainerFinding;
use crate::unicode_text;

/// Stable detector family ID: OOXML package inventory/topology (DOC-001).
pub const DOC_001_FAMILY: &str = "DOC-001";
/// Stable detector family ID: WordprocessingML concealment channels (DOC-002).
pub const DOC_002_FAMILY: &str = "DOC-002";
/// Stable detector family ID: generic ZIP inventory/topology observations.
pub const ZIP_TOPOLOGY_FAMILY: &str = "ZIP_TOPOLOGY";

// Container budgets — mirrored in `detector_registry()` and enforced below.
/// Maximum number of central-directory entries parsed per package.
pub const CONTAINER_MAX_ENTRIES: usize = 4096;
/// Maximum byte length of a single entry name.
pub const CONTAINER_MAX_ENTRY_NAME_BYTES: usize = 512;
/// EOCD scan window: maximum ZIP comment length (64 KiB) plus the 22-byte
/// fixed EOCD record.
pub const CONTAINER_MAX_EOCD_SCAN_BYTES: usize = 66_000;
/// Maximum inflated size accepted for one entry, regardless of its claimed
/// uncompressed size.
pub const CONTAINER_MAX_INFLATE_PER_ENTRY: usize = 4 * 1024 * 1024;
/// Maximum total inflated bytes accepted across all entries in one analysis.
pub const CONTAINER_MAX_INFLATE_TOTAL: usize = 8 * 1024 * 1024;
/// Maximum number of container findings emitted per package.
pub const CONTAINER_MAX_FINDINGS: usize = 64;
/// Bound for one finding's `detail` string (bytes).
const DETAIL_MAX_BYTES: usize = 256;
/// Minimum ASCII space/tab run inside an XML text node before it is reported
/// as a concealment channel (DOC-002). Pretty-printed XML keeps indentation
/// below this in the common case.
const XML_WS_RUN_MIN: usize = 8;

const CONTENT_TYPES: &str = "[Content_Types].xml";
const WORD_DOCUMENT: &str = "word/document.xml";
const PPT_PRESENTATION: &str = "ppt/presentation.xml";
const XL_WORKBOOK: &str = "xl/workbook.xml";
/// Path fragment marking embedded-media directories (docx/pptx/xlsx).
const MEDIA_DIR_FRAGMENT: &str = "media/";
/// Extensions that make a media-directory entry claim to be text, not media.
const TEXT_LIKE_EXTS: &[&str] = &["txt", "xml", "json", "html", "htm", "csv", "rtf"];

/// Typed rejection reasons for the in-memory ZIP reader.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OoxmlError {
    /// No EOCD record (`PK\x05\x06`) in the trailing scan window.
    #[error("ZIP end-of-central-directory record not found within the last {0} bytes")]
    EocdNotFound(usize),
    /// Central-directory offset/size exceed the input buffer.
    #[error(
        "ZIP central directory out of bounds: offset {offset}, size {size}, input {input_len}"
    )]
    CentralDirectoryOutOfBounds {
        offset: usize,
        size: usize,
        input_len: usize,
    },
    /// Claimed entry count exceeds [`CONTAINER_MAX_ENTRIES`].
    #[error("ZIP claims {claimed} entries, exceeding the {limit}-entry budget")]
    TooManyEntries { claimed: usize, limit: usize },
    /// A central-directory entry name exceeds [`CONTAINER_MAX_ENTRY_NAME_BYTES`].
    #[error("ZIP entry name at index {index} is {len} bytes, exceeding the {limit}-byte budget")]
    EntryNameTooLong {
        index: usize,
        len: usize,
        limit: usize,
    },
    /// Central directory ends mid-record (or a signature is wrong).
    #[error("ZIP central directory truncated or corrupt at byte offset {offset}")]
    CentralDirectoryCorrupt { offset: usize },
    /// The local file header for an entry is out of bounds or malformed.
    #[error("ZIP local header for entry \"{name}\" is out of bounds or corrupt")]
    LocalHeaderCorrupt { name: String },
    /// The local header name differs from the central-directory name.
    #[error("ZIP local header for entry \"{name}\" does not match the central-directory record")]
    LocalHeaderMismatch { name: String },
    /// Entry data extends past the end of the input.
    #[error(
        "ZIP entry \"{name}\" data out of bounds: offset {offset}, size {size}, input {input_len}"
    )]
    EntryDataOutOfBounds {
        name: String,
        offset: usize,
        size: usize,
        input_len: usize,
    },
    /// Entry is encrypted (general-purpose flag bit 0); never analyzed.
    #[error("ZIP entry \"{name}\" is encrypted; encrypted entries are not analyzed")]
    EncryptedEntry { name: String },
    /// Entry uses a compression method other than stored (0) or deflate (8).
    #[error("ZIP entry \"{name}\" uses unsupported compression method {method}")]
    UnsupportedCompressionMethod { name: String, method: u16 },
    /// Claimed uncompressed size exceeds [`CONTAINER_MAX_INFLATE_PER_ENTRY`].
    #[error(
        "ZIP entry \"{name}\" claims {claimed} bytes, exceeding the {limit}-byte per-entry inflate budget"
    )]
    InflateBudgetExceeded {
        name: String,
        claimed: usize,
        limit: usize,
    },
    /// Cumulative inflate output would exceed [`CONTAINER_MAX_INFLATE_TOTAL`].
    #[error(
        "ZIP analysis would inflate {inflated} bytes in total, exceeding the {limit}-byte budget"
    )]
    InflateTotalBudgetExceeded { inflated: usize, limit: usize },
    /// Actual inflated (or stored) size differs from the claimed size.
    #[error("ZIP entry \"{name}\" yields {actual} bytes, expected {claimed}")]
    InflateSizeMismatch {
        name: String,
        actual: usize,
        claimed: usize,
    },
    /// Inflation failed (corrupt deflate stream).
    #[error("ZIP entry \"{name}\" has a corrupt deflate stream")]
    InflateFailed { name: String },
}

/// One ZIP entry as recorded in the central directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZipEntry {
    name: String,
    flags: u16,
    method: u16,
    crc32: u32,
    compressed_size: usize,
    uncompressed_size: usize,
    local_header_offset: usize,
}

impl ZipEntry {
    /// Entry name (lossy UTF-8 of the raw central-directory name bytes).
    pub fn name(&self) -> &str {
        &self.name
    }
    /// General-purpose bit flags; bit 0 marks encryption.
    pub fn flags(&self) -> u16 {
        self.flags
    }
    /// Compression method (0 = stored, 8 = deflate).
    pub fn method(&self) -> u16 {
        self.method
    }
    /// Claimed compressed size in bytes.
    pub fn compressed_size(&self) -> usize {
        self.compressed_size
    }
    /// Claimed uncompressed size in bytes (hostile values are possible).
    pub fn uncompressed_size(&self) -> usize {
        self.uncompressed_size
    }
    /// Claimed CRC-32 of the uncompressed content (not verified).
    pub fn crc32(&self) -> u32 {
        self.crc32
    }
}

/// A parsed in-memory ZIP archive borrowed from its input bytes.
#[derive(Debug, Clone)]
pub struct ZipArchive<'a> {
    data: &'a [u8],
    entries: Vec<ZipEntry>,
}

impl<'a> ZipArchive<'a> {
    /// Parse the central directory of `data` (a ZIP-family buffer).
    ///
    /// All structural fields are bounds-checked; hostile values are rejected
    /// with typed [`OoxmlError`]s before any allocation that depends on them.
    pub fn parse(data: &'a [u8]) -> Result<Self, OoxmlError> {
        let eocd = find_eocd(data)?;
        let total_entries = read_u16(data, eocd + 10) as usize;
        let cd_size = read_u32(data, eocd + 12) as usize;
        let cd_offset = read_u32(data, eocd + 16) as usize;

        if total_entries > CONTAINER_MAX_ENTRIES {
            return Err(OoxmlError::TooManyEntries {
                claimed: total_entries,
                limit: CONTAINER_MAX_ENTRIES,
            });
        }
        if cd_offset
            .checked_add(cd_size)
            .is_none_or(|end| end > data.len())
        {
            return Err(OoxmlError::CentralDirectoryOutOfBounds {
                offset: cd_offset,
                size: cd_size,
                input_len: data.len(),
            });
        }

        let mut entries = Vec::new();
        let mut pos = cd_offset;
        let end = cd_offset + cd_size;
        for index in 0..total_entries {
            if pos + 46 > end || read_u32(data, pos) != 0x0201_4b50 {
                return Err(OoxmlError::CentralDirectoryCorrupt { offset: pos });
            }
            let flags = read_u16(data, pos + 8);
            let method = read_u16(data, pos + 10);
            let crc32 = read_u32(data, pos + 16);
            let compressed_size = read_u32(data, pos + 20) as usize;
            let uncompressed_size = read_u32(data, pos + 24) as usize;
            let name_len = read_u16(data, pos + 28) as usize;
            let extra_len = read_u16(data, pos + 30) as usize;
            let comment_len = read_u16(data, pos + 32) as usize;
            let local_offset = read_u32(data, pos + 42) as usize;
            let record_end = pos + 46 + name_len + extra_len + comment_len;
            if record_end > end {
                return Err(OoxmlError::CentralDirectoryCorrupt { offset: pos });
            }
            if name_len > CONTAINER_MAX_ENTRY_NAME_BYTES {
                return Err(OoxmlError::EntryNameTooLong {
                    index,
                    len: name_len,
                    limit: CONTAINER_MAX_ENTRY_NAME_BYTES,
                });
            }
            let name = String::from_utf8_lossy(&data[pos + 46..pos + 46 + name_len]).into_owned();
            entries.push(ZipEntry {
                name,
                flags,
                method,
                crc32,
                compressed_size,
                uncompressed_size,
                local_header_offset: local_offset,
            });
            pos = record_end;
        }

        Ok(ZipArchive { data, entries })
    }

    /// All parsed entries, in central-directory order.
    pub fn entries(&self) -> &[ZipEntry] {
        &self.entries
    }

    /// First entry with the given name, if present.
    pub fn find(&self, name: &str) -> Option<&ZipEntry> {
        self.entries.iter().find(|e| e.name == name)
    }

    /// Inflate/extract one entry, enforcing the per-entry and total budgets.
    ///
    /// `inflate_total` accumulates claimed output across reads in one
    /// analysis; pass `&mut 0` for one-shot reads.
    pub fn read_entry(
        &self,
        entry: &ZipEntry,
        inflate_total: &mut usize,
    ) -> Result<Vec<u8>, OoxmlError> {
        if entry.flags & 0x1 != 0 {
            return Err(OoxmlError::EncryptedEntry {
                name: entry.name.clone(),
            });
        }
        let range = self.local_data_range(entry)?;
        let raw = &self.data[range];
        match entry.method {
            0 => {
                if entry.compressed_size != entry.uncompressed_size {
                    return Err(OoxmlError::InflateSizeMismatch {
                        name: entry.name.clone(),
                        actual: entry.compressed_size,
                        claimed: entry.uncompressed_size,
                    });
                }
                *inflate_total = inflate_total.saturating_add(raw.len());
                Ok(raw.to_vec())
            }
            8 => inflate_raw(raw, &entry.name, entry.uncompressed_size, inflate_total),
            method => Err(OoxmlError::UnsupportedCompressionMethod {
                name: entry.name.clone(),
                method,
            }),
        }
    }

    /// Resolve an entry's local header and return the compressed-data range.
    fn local_data_range(&self, entry: &ZipEntry) -> Result<std::ops::Range<usize>, OoxmlError> {
        let off = entry.local_header_offset;
        let data = self.data;
        if off + 30 > data.len() || read_u32(data, off) != 0x0403_4b50 {
            return Err(OoxmlError::LocalHeaderCorrupt {
                name: entry.name.clone(),
            });
        }
        let name_len = read_u16(data, off + 26) as usize;
        let extra_len = read_u16(data, off + 28) as usize;
        let name_start = off + 30;
        let data_start = name_start + name_len + extra_len;
        if data.get(name_start..name_start + name_len) != Some(entry.name.as_bytes()) {
            return Err(OoxmlError::LocalHeaderMismatch {
                name: entry.name.clone(),
            });
        }
        let data_end = data_start + entry.compressed_size;
        if data_end > data.len() {
            return Err(OoxmlError::EntryDataOutOfBounds {
                name: entry.name.clone(),
                offset: data_start,
                size: entry.compressed_size,
                input_len: data.len(),
            });
        }
        Ok(data_start..data_end)
    }
}

fn read_u16(data: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([data[at], data[at + 1]])
}

fn read_u32(data: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]])
}
fn find_eocd(data: &[u8]) -> Result<usize, OoxmlError> {
    if data.len() < 22 {
        return Err(OoxmlError::EocdNotFound(CONTAINER_MAX_EOCD_SCAN_BYTES));
    }
    let scan_len = data.len().min(CONTAINER_MAX_EOCD_SCAN_BYTES);
    let floor = data.len() - scan_len;
    // Last start offset at which a 4-byte signature (and the fixed 22-byte
    // EOCD record beginning with it) fits the buffer.
    let mut pos = data.len() - 4;
    loop {
        if read_u32(data, pos) == 0x0605_4b50 {
            // pos + 22 <= data.len() holds because pos <= data.len() - 4 and
            // the signature match implies pos + 4 <= data.len().
            let comment_len = read_u16(data, pos + 20) as usize;
            if pos + 22 + comment_len <= data.len() {
                return Ok(pos);
            }
        }
        if pos == floor || pos == 0 {
            break;
        }
        pos -= 1;
    }
    Err(OoxmlError::EocdNotFound(CONTAINER_MAX_EOCD_SCAN_BYTES))
}

/// Inflate a raw-deflate stream with hard budget checks. The claimed size is
/// validated against the per-entry budget *before* any allocation, and the
/// read is additionally capped with `take`, so a lying (too-small) claim
/// cannot over-allocate either.
fn inflate_raw(
    raw: &[u8],
    name: &str,
    claimed: usize,
    inflate_total: &mut usize,
) -> Result<Vec<u8>, OoxmlError> {
    if claimed > CONTAINER_MAX_INFLATE_PER_ENTRY {
        return Err(OoxmlError::InflateBudgetExceeded {
            name: name.to_string(),
            claimed,
            limit: CONTAINER_MAX_INFLATE_PER_ENTRY,
        });
    }
    let new_total = *inflate_total + claimed;
    if new_total > CONTAINER_MAX_INFLATE_TOTAL {
        return Err(OoxmlError::InflateTotalBudgetExceeded {
            inflated: new_total,
            limit: CONTAINER_MAX_INFLATE_TOTAL,
        });
    }
    let mut decoder = flate2::read::DeflateDecoder::new(raw).take(claimed as u64);
    let mut out = Vec::with_capacity(claimed);
    if decoder.read_to_end(&mut out).is_err() {
        return Err(OoxmlError::InflateFailed {
            name: name.to_string(),
        });
    }
    if out.len() != claimed {
        return Err(OoxmlError::InflateSizeMismatch {
            name: name.to_string(),
            actual: out.len(),
            claimed,
        });
    }
    *inflate_total = new_total;
    Ok(out)
}

/// Run the DOC-001/DOC-002 container analysis over a ZIP-family buffer.
///
/// Never panics on hostile input: parse and read failures become DOC-001
/// evidence. Returns findings in detector order (inventory, topology
/// anomalies, then WordprocessingML concealment).
pub fn analyze_package(data: &[u8]) -> Vec<ContainerFinding> {
    let mut findings: Vec<ContainerFinding> = Vec::new();
    let archive = match ZipArchive::parse(data) {
        Ok(archive) => archive,
        Err(error) => {
            findings.push(ContainerFinding {
                path: "<package>".to_string(),
                family: DOC_001_FAMILY.to_string(),
                detail: bound_detail(format!("package rejected: {error}")),
            });
            return findings;
        }
    };

    let entries = archive.entries();
    let names: Vec<&str> = entries.iter().map(|e| e.name()).collect();
    let office_family = office_family(&names);
    let claimed_total = entries
        .iter()
        .map(|e| e.uncompressed_size)
        .fold(0usize, usize::saturating_add);
    push_finding(
        &mut findings,
        ContainerFinding {
            path: "<package>".to_string(),
            family: ZIP_TOPOLOGY_FAMILY.to_string(),
            detail: bound_detail(format!(
                "zip package: {} entries, {} bytes claimed uncompressed, methods {:?}; office family: {}",
                entries.len(),
                claimed_total,
                compression_methods(entries),
                office_family,
            )),
        },
    );

    // DOC-001 topology anomalies (observations, not concealment detections).
    let mut name_counts: HashMap<&str, usize> = HashMap::new();
    for entry in entries {
        *name_counts.entry(entry.name()).or_insert(0) += 1;
        if entry.uncompressed_size > CONTAINER_MAX_INFLATE_PER_ENTRY {
            push_finding(
                &mut findings,
                ContainerFinding {
                    path: entry.name().to_string(),
                    family: DOC_001_FAMILY.to_string(),
                    detail: bound_detail(format!(
                        "entry claims {} bytes uncompressed, exceeding the {}-byte per-entry inflate budget; content not inflated",
                        entry.uncompressed_size, CONTAINER_MAX_INFLATE_PER_ENTRY
                    )),
                },
            );
        }
    }
    for (name, count) in name_counts.iter().filter(|(_, c)| **c > 1) {
        push_finding(
            &mut findings,
            ContainerFinding {
                path: "<package>".to_string(),
                family: DOC_001_FAMILY.to_string(),
                detail: bound_detail(format!("duplicate entry name: {name} (x{count})")),
            },
        );
    }
    for entry in entries.iter().filter(|e| e.flags() & 0x1 != 0) {
        push_finding(
            &mut findings,
            ContainerFinding {
                path: entry.name().to_string(),
                family: DOC_001_FAMILY.to_string(),
                detail: "entry is encrypted (general-purpose flag bit 0); content not analyzed"
                    .to_string(),
            },
        );
    }
    for entry in entries.iter().filter(|e| is_media_name(e.name())) {
        if let Some(ext) = path_extension(entry.name()) {
            if TEXT_LIKE_EXTS
                .iter()
                .any(|candidate| ext.eq_ignore_ascii_case(candidate))
            {
                push_finding(
                    &mut findings,
                    ContainerFinding {
                        path: entry.name().to_string(),
                        family: DOC_001_FAMILY.to_string(),
                        detail: bound_detail(format!(
                            "embedded-media entry claims text-like content ({ext})"
                        )),
                    },
                );
            }
        }
    }

    // DOC-002 WordprocessingML concealment (detections).
    match office_family {
        "docx" => analyze_document_xml(&archive, &mut findings),
        "pptx" | "xlsx" => {
            push_finding(
                &mut findings,
                ContainerFinding {
                    path: "<package>".to_string(),
                    family: ZIP_TOPOLOGY_FAMILY.to_string(),
                    detail: bound_detail(format!(
                        "{office_family} package: topology-only analysis (WordprocessingML channels not scanned)"
                    )),
                },
            );
        }
        _ => {}
    }

    findings
}

/// Deep-analyze `word/document.xml`: Unicode/text stego channels plus ASCII
/// whitespace runs inside XML text nodes.
fn analyze_document_xml(archive: &ZipArchive<'_>, findings: &mut Vec<ContainerFinding>) {
    let Some(entry) = archive.find(WORD_DOCUMENT) else {
        return;
    };
    if entry.uncompressed_size > CONTAINER_MAX_INFLATE_PER_ENTRY {
        // Already reported by the topology check; do not double-report.
        return;
    }
    let mut inflate_total = 0usize;
    let xml_bytes = match archive.read_entry(entry, &mut inflate_total) {
        Ok(bytes) => bytes,
        Err(error) => {
            push_finding(
                findings,
                ContainerFinding {
                    path: WORD_DOCUMENT.to_string(),
                    family: DOC_001_FAMILY.to_string(),
                    detail: bound_detail(format!("main part rejected: {error}")),
                },
            );
            return;
        }
    };
    let Ok(xml) = std::str::from_utf8(&xml_bytes) else {
        push_finding(
            findings,
            ContainerFinding {
                path: WORD_DOCUMENT.to_string(),
                family: DOC_001_FAMILY.to_string(),
                detail: "main part is not valid UTF-8; text channels not analyzed".to_string(),
            },
        );
        return;
    };

    for finding in unicode_text::analyze_text(xml) {
        let offsets = if finding.offsets.len() > 4 {
            let head: Vec<String> = finding
                .offsets
                .iter()
                .take(4)
                .map(|o| o.to_string())
                .collect();
            format!("{}… ({} flagged)", head.join(","), finding.offsets.len())
        } else {
            finding
                .offsets
                .iter()
                .map(|o| o.to_string())
                .collect::<Vec<_>>()
                .join(",")
        };
        push_finding(
            findings,
            ContainerFinding {
                path: WORD_DOCUMENT.to_string(),
                family: DOC_002_FAMILY.to_string(),
                detail: bound_detail(format!(
                    "{}: {} (char offsets {offsets})",
                    finding.detector_id, finding.detail
                )),
            },
        );
    }

    if let Some((runs, longest, first)) = detect_xml_whitespace_runs(xml) {
        push_finding(
            findings,
            ContainerFinding {
                path: WORD_DOCUMENT.to_string(),
                family: DOC_002_FAMILY.to_string(),
                detail: bound_detail(format!(
                    "XML text-node whitespace runs: {runs} runs, longest {longest} chars, first at char offset {first}"
                )),
            },
        );
    }
}

/// Find long ASCII space/tab runs inside XML text nodes (between `>` and `<`).
///
/// Non-ASCII whitespace is intentionally excluded here: [`crate::unicode_text`]'s
/// `WHITESPACE_ANOMALY` detector already covers it.
fn detect_xml_whitespace_runs(xml: &str) -> Option<(usize, usize, usize)> {
    let mut in_text = false;
    let mut runs = 0usize;
    let mut longest = 0usize;
    let mut first: Option<usize> = None;
    let mut run = 0usize;
    let mut run_start = 0usize;
    for (i, c) in xml.char_indices() {
        match c {
            '<' | '>' => {
                if run >= XML_WS_RUN_MIN {
                    runs += 1;
                    longest = longest.max(run);
                    first.get_or_insert(run_start);
                }
                run = 0;
                in_text = c == '>';
            }
            ' ' | '\t' if in_text => {
                if run == 0 {
                    run_start = i;
                }
                run += 1;
            }
            _ => run = 0,
        }
    }
    if run >= XML_WS_RUN_MIN {
        runs += 1;
        longest = longest.max(run);
        first.get_or_insert(run_start);
    }
    first.map(|first| (runs, longest, first))
}

fn office_family(names: &[&str]) -> &'static str {
    if names.contains(&CONTENT_TYPES) && names.contains(&WORD_DOCUMENT) {
        "docx"
    } else if names.contains(&CONTENT_TYPES) && names.contains(&PPT_PRESENTATION) {
        "pptx"
    } else if names.contains(&CONTENT_TYPES) && names.contains(&XL_WORKBOOK) {
        "xlsx"
    } else {
        "none"
    }
}

fn compression_methods(entries: &[ZipEntry]) -> Vec<u16> {
    let mut methods: Vec<u16> = entries.iter().map(|e| e.method()).collect();
    methods.sort_unstable();
    methods.dedup();
    methods
}

fn path_extension(name: &str) -> Option<&str> {
    let last = name.rsplit('/').next()?;
    let dot = last.rfind('.')?;
    if dot + 1 == last.len() {
        return None;
    }
    Some(&last[dot + 1..])
}

fn is_media_name(name: &str) -> bool {
    name.contains(MEDIA_DIR_FRAGMENT)
}

/// Push a finding unless the package hit [`CONTAINER_MAX_FINDINGS`]; the cap
/// is recorded as its own finding so truncation is never silent.
fn push_finding(findings: &mut Vec<ContainerFinding>, finding: ContainerFinding) {
    if findings.len() >= CONTAINER_MAX_FINDINGS {
        let exhausted = "finding budget exhausted; further findings suppressed";
        if findings.last().is_none_or(|last| last.detail != exhausted) {
            findings.push(ContainerFinding {
                path: "<package>".to_string(),
                family: ZIP_TOPOLOGY_FAMILY.to_string(),
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
    use flate2::write::DeflateEncoder;
    use flate2::Compression;
    use std::io::Write as _;

    /// One fixture entry pending assembly.
    struct EntrySpec {
        name: String,
        method: u16,
        compressed: Vec<u8>,
        uncompressed: Vec<u8>,
        offset: usize,
        crc: u32,
    }

    /// Tiny deterministic ZIP writer for fixtures: local headers + data +
    /// central directory + EOCD. CRC-32 computed with a local table
    /// implementation (no new dependencies).
    struct ZipBuilder {
        entries: Vec<EntrySpec>,
        central_lies: HashMap<String, (Option<u32>, Option<u32>)>,
        encrypted: Vec<String>,
    }

    impl ZipBuilder {
        fn new() -> Self {
            ZipBuilder {
                entries: Vec::new(),
                central_lies: HashMap::new(),
                encrypted: Vec::new(),
            }
        }

        fn add_stored(mut self, name: &str, data: &[u8]) -> Self {
            self.entries.push(EntrySpec {
                name: name.to_string(),
                method: 0,
                compressed: data.to_vec(),
                uncompressed: data.to_vec(),
                offset: 0,
                crc: crc32(data),
            });
            self
        }

        fn add_deflated(mut self, name: &str, data: &[u8]) -> Self {
            let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(data).expect("deflate write");
            let compressed = encoder.finish().expect("deflate finish");
            self.entries.push(EntrySpec {
                name: name.to_string(),
                method: 8,
                compressed,
                uncompressed: data.to_vec(),
                offset: 0,
                crc: crc32(data),
            });
            self
        }

        /// Override central-directory sizes for an entry — fabricates hostile
        /// archives with lying sizes. `None` keeps the real size.
        fn lie_sizes(
            mut self,
            name: &str,
            compressed: Option<u32>,
            uncompressed: Option<u32>,
        ) -> Self {
            self.central_lies
                .insert(name.to_string(), (compressed, uncompressed));
            self
        }

        /// Set the general-purpose encryption flag for an entry in both the
        /// local header and the central directory (content is plain).
        fn mark_encrypted(mut self, name: &str) -> Self {
            self.encrypted.push(name.to_string());
            self
        }

        /// Unsupported compression method for an entry.
        fn mark_method(mut self, name: &str, method: u16) -> Self {
            for entry in self.entries.iter_mut() {
                if entry.name == name {
                    entry.method = method;
                }
            }
            self
        }

        fn build(mut self) -> Vec<u8> {
            let mut out: Vec<u8> = Vec::new();
            let mut central: Vec<u8> = Vec::new();
            for index in 0..self.entries.len() {
                self.entries[index].offset = out.len();
                let entry = &self.entries[index];
                let flags: u16 = if self.encrypted.contains(&entry.name) {
                    1
                } else {
                    0
                };
                out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
                out.extend_from_slice(&20u16.to_le_bytes()); // version needed
                out.extend_from_slice(&flags.to_le_bytes());
                out.extend_from_slice(&entry.method.to_le_bytes());
                out.extend_from_slice(&0u16.to_le_bytes()); // mod time
                out.extend_from_slice(&0u16.to_le_bytes()); // mod date
                out.extend_from_slice(&entry.crc.to_le_bytes());
                out.extend_from_slice(&(entry.compressed.len() as u32).to_le_bytes());
                out.extend_from_slice(&(entry.uncompressed.len() as u32).to_le_bytes());
                out.extend_from_slice(&(entry.name.len() as u16).to_le_bytes());
                out.extend_from_slice(&0u16.to_le_bytes()); // extra len
                out.extend_from_slice(entry.name.as_bytes());
                out.extend_from_slice(&entry.compressed);

                let real_sizes = (
                    entry.compressed.len() as u32,
                    entry.uncompressed.len() as u32,
                );
                let (csize, usize_) = self
                    .central_lies
                    .get(&entry.name)
                    .copied()
                    .map_or(real_sizes, |(c, u)| {
                        (c.unwrap_or(real_sizes.0), u.unwrap_or(real_sizes.1))
                    });
                central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
                central.extend_from_slice(&20u16.to_le_bytes()); // version made by
                central.extend_from_slice(&20u16.to_le_bytes()); // version needed
                central.extend_from_slice(&flags.to_le_bytes());
                central.extend_from_slice(&entry.method.to_le_bytes());
                central.extend_from_slice(&0u16.to_le_bytes()); // mod time
                central.extend_from_slice(&0u16.to_le_bytes()); // mod date
                central.extend_from_slice(&entry.crc.to_le_bytes());
                central.extend_from_slice(&csize.to_le_bytes());
                central.extend_from_slice(&usize_.to_le_bytes());
                central.extend_from_slice(&(entry.name.len() as u16).to_le_bytes());
                central.extend_from_slice(&0u16.to_le_bytes()); // extra
                central.extend_from_slice(&0u16.to_le_bytes()); // comment
                central.extend_from_slice(&0u16.to_le_bytes()); // disk start
                central.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
                central.extend_from_slice(&0u32.to_le_bytes()); // external attrs
                central.extend_from_slice(&(entry.offset as u32).to_le_bytes());
                central.extend_from_slice(entry.name.as_bytes());
            }
            let cd_offset = out.len();
            let cd_size = central.len();
            out.extend_from_slice(&central);
            out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes()); // disk
            out.extend_from_slice(&0u16.to_le_bytes()); // cd disk
            out.extend_from_slice(&(self.entries.len() as u16).to_le_bytes());
            out.extend_from_slice(&(self.entries.len() as u16).to_le_bytes());
            out.extend_from_slice(&(cd_size as u32).to_le_bytes());
            out.extend_from_slice(&(cd_offset as u32).to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes()); // comment len
            out
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

    const CONTENT_TYPES_XML: &str =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Default Extension=\"xml\" ContentType=\"application/xml\"/></Types>";

    fn document_xml(body_text: &str) -> String {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\"><w:body><w:p><w:r><w:t>{body_text}</w:t></w:r></w:p></w:body></w:document>"
        )
    }

    fn docx(document_text: &str) -> Vec<u8> {
        ZipBuilder::new()
            .add_stored(CONTENT_TYPES, CONTENT_TYPES_XML.as_bytes())
            .add_deflated(WORD_DOCUMENT, document_xml(document_text).as_bytes())
            .build()
    }

    fn findings_with_family<'a>(
        findings: &'a [ContainerFinding],
        family: &str,
    ) -> Vec<&'a ContainerFinding> {
        findings.iter().filter(|f| f.family == family).collect()
    }

    #[test]
    fn parses_stored_and_deflated_entries() {
        let bytes = ZipBuilder::new()
            .add_stored("a.txt", b"hello")
            .add_deflated("b.txt", b"deflate me deflate me deflate me")
            .build();
        let archive = ZipArchive::parse(&bytes).expect("parse");
        assert_eq!(archive.entries().len(), 2);
        assert_eq!(archive.find("a.txt").expect("stored").method(), 0);
        assert_eq!(archive.find("b.txt").expect("deflated").method(), 8);
        let mut total = 0;
        let stored = archive.read_entry(archive.find("a.txt").expect("a"), &mut total);
        assert_eq!(stored.expect("stored"), b"hello");
        let deflated = archive.read_entry(archive.find("b.txt").expect("b"), &mut total);
        assert_eq!(
            deflated.expect("deflated"),
            b"deflate me deflate me deflate me"
        );
        assert_eq!(total, 5 + 32);
    }

    #[test]
    fn empty_and_short_inputs_are_rejected_typed() {
        assert!(matches!(
            ZipArchive::parse(&[]),
            Err(OoxmlError::EocdNotFound(CONTAINER_MAX_EOCD_SCAN_BYTES))
        ));
        assert!(matches!(
            ZipArchive::parse(b"PK\x03\x04junk"),
            Err(OoxmlError::EocdNotFound(CONTAINER_MAX_EOCD_SCAN_BYTES))
        ));
    }

    #[test]
    fn trailing_comment_zip_parses() {
        let base = ZipBuilder::new().add_stored("x.txt", b"data").build();
        let comment = b"archive comment";
        // The EOCD comment-length field is the last 2 bytes of the archive.
        let mut commented = base;
        let comment_len_pos = commented.len() - 2;
        commented.extend_from_slice(comment);
        commented[comment_len_pos..comment_len_pos + 2]
            .copy_from_slice(&(comment.len() as u16).to_le_bytes());
        let archive = ZipArchive::parse(&commented).expect("parse with comment");
        assert_eq!(archive.entries().len(), 1);
    }

    #[test]
    fn encrypted_entry_is_rejected() {
        let bytes = ZipBuilder::new()
            .add_stored("secret.txt", b"plaintext")
            .mark_encrypted("secret.txt")
            .build();
        let archive = ZipArchive::parse(&bytes).expect("parse");
        let entry = archive.find("secret.txt").expect("entry");
        assert_eq!(
            archive.read_entry(entry, &mut 0),
            Err(OoxmlError::EncryptedEntry {
                name: "secret.txt".to_string()
            })
        );
        let findings = analyze_package(&bytes);
        assert!(findings
            .iter()
            .any(|f| f.family == DOC_001_FAMILY && f.path == "secret.txt"));
    }

    #[test]
    fn unsupported_method_is_rejected() {
        let bytes = ZipBuilder::new()
            .add_stored("weird.bin", b"data")
            .mark_method("weird.bin", 12)
            .build();
        let archive = ZipArchive::parse(&bytes).expect("parse");
        let entry = archive.find("weird.bin").expect("entry");
        assert!(matches!(
            archive.read_entry(entry, &mut 0),
            Err(OoxmlError::UnsupportedCompressionMethod { method: 12, .. })
        ));
    }

    #[test]
    fn oversized_claim_is_rejected_without_inflating() {
        let bytes = ZipBuilder::new()
            .add_deflated("bomb.bin", b"tiny")
            .lie_sizes("bomb.bin", None, Some(0x7FFF_FFFF))
            .build();
        let archive = ZipArchive::parse(&bytes).expect("parse");
        let entry = archive.find("bomb.bin").expect("entry");
        assert!(matches!(
            archive.read_entry(entry, &mut 0),
            Err(OoxmlError::InflateBudgetExceeded {
                claimed: 0x7FFF_FFFF,
                ..
            })
        ));
        let findings = analyze_package(&bytes);
        assert!(findings.iter().any(|f| f.family == DOC_001_FAMILY
            && f.path == "bomb.bin"
            && f.detail.contains("inflate budget")));
    }

    #[test]
    fn lying_small_claim_cannot_overallocate() {
        // Claim 16 bytes; the actual deflate stream inflates to far more.
        // The budgeted read must stay bounded (take cap) and never panic.
        let big = vec![0xABu8; 64 * 1024];
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&big).expect("deflate write");
        let compressed = encoder.finish().expect("deflate finish");
        assert!(compressed.len() < 2048);
        let bytes = ZipBuilder::new()
            .add_deflated("bomb.bin", &big)
            .lie_sizes("bomb.bin", None, Some(16))
            .build();
        let archive = ZipArchive::parse(&bytes).expect("parse");
        let entry = archive.find("bomb.bin").expect("entry");
        match archive.read_entry(entry, &mut 0) {
            Ok(data) => assert_eq!(data.len(), 16),
            Err(OoxmlError::InflateSizeMismatch { .. }) => {}
            Err(other) => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn clean_docx_produces_no_concealment_findings() {
        let bytes = docx("Hello world");
        let findings = analyze_package(&bytes);
        assert!(findings.iter().any(|f| f.family == ZIP_TOPOLOGY_FAMILY));
        assert!(findings_with_family(&findings, DOC_001_FAMILY).is_empty());
        assert!(findings_with_family(&findings, DOC_002_FAMILY).is_empty());
    }

    #[test]
    fn laced_docx_document_xml_triggers_doc_002() {
        let laced = "Hello\u{200b}\u{200c}\u{200b}\u{200c}\u{200b}\u{200c}\u{200b}\u{200c}\u{200b}\u{200c}\u{200b}\u{200c} world";
        let bytes = docx(laced);
        let findings = analyze_package(&bytes);
        let doc002 = findings_with_family(&findings, DOC_002_FAMILY);
        assert_eq!(doc002.len(), 1);
        assert!(doc002[0].detail.contains("ZERO_WIDTH"));
        assert_eq!(doc002[0].path, WORD_DOCUMENT);
    }

    #[test]
    fn whitespace_run_in_text_node_triggers_doc_002() {
        let spaced = format!("Hello{}", " ".repeat(12));
        let bytes = docx(&spaced);
        let findings = analyze_package(&bytes);
        let doc002 = findings_with_family(&findings, DOC_002_FAMILY);
        // The unicode_text WHITESPACE_ANOMALY channel and the XML text-node
        // run detector can both fire for the same run; require the
        // text-node run evidence specifically.
        assert!(doc002.iter().any(|f| f.detail.contains("whitespace runs")));
    }

    #[test]
    fn pptx_and_xlsx_get_topology_only_findings() {
        let pptx = ZipBuilder::new()
            .add_stored(CONTENT_TYPES, CONTENT_TYPES_XML.as_bytes())
            .add_stored(PPT_PRESENTATION, b"<p:presentation/>")
            .build();
        let findings = analyze_package(&pptx);
        assert!(findings.iter().any(|f| f.family == ZIP_TOPOLOGY_FAMILY
            && f.detail.contains("pptx")
            && f.detail.contains("topology-only")));

        let xlsx = ZipBuilder::new()
            .add_stored(CONTENT_TYPES, CONTENT_TYPES_XML.as_bytes())
            .add_stored(XL_WORKBOOK, b"<workbook/>")
            .build();
        let findings = analyze_package(&xlsx);
        assert!(findings.iter().any(|f| f.family == ZIP_TOPOLOGY_FAMILY
            && f.detail.contains("xlsx")
            && f.detail.contains("topology-only")));
    }

    #[test]
    fn generic_zip_gets_inventory_finding_only() {
        let bytes = ZipBuilder::new()
            .add_stored("notes/readme.txt", b"plain notes")
            .build();
        let findings = analyze_package(&bytes);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].family, ZIP_TOPOLOGY_FAMILY);
        assert!(findings[0].detail.contains("office family: none"));
    }

    #[test]
    fn media_entry_claiming_text_is_flagged() {
        let bytes = ZipBuilder::new()
            .add_stored(CONTENT_TYPES, CONTENT_TYPES_XML.as_bytes())
            .add_stored(WORD_DOCUMENT, document_xml("ok").as_bytes())
            .add_stored("word/media/image1.txt", b"not really an image")
            .build();
        let findings = analyze_package(&bytes);
        assert!(findings.iter().any(|f| f.family == DOC_001_FAMILY
            && f.path == "word/media/image1.txt"
            && f.detail.contains("text-like")));
    }

    #[test]
    fn duplicate_entries_are_reported() {
        let bytes = ZipBuilder::new()
            .add_stored("dup.bin", b"one")
            .add_stored("dup.bin", b"two")
            .build();
        let findings = analyze_package(&bytes);
        assert!(findings.iter().any(|f| f.family == DOC_001_FAMILY
            && f.detail.contains("duplicate entry name: dup.bin (x2)")));
    }

    #[test]
    fn hostile_zip_with_bogus_eocd_is_rejected_without_panic() {
        // EOCD comment length that overruns the buffer -> typed rejection.
        let mut bytes = ZipBuilder::new().add_stored("a.txt", b"x").build();
        let len = bytes.len();
        bytes[len - 2] = 0xFF;
        bytes[len - 1] = 0xFF;
        let findings = analyze_package(&bytes);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].family, DOC_001_FAMILY);
        assert!(findings[0].detail.contains("package rejected"));
    }

    #[test]
    fn truncated_central_directory_is_rejected() {
        let bytes = ZipBuilder::new().add_stored("a.txt", b"x").build();
        let truncated = &bytes[..bytes.len() - 20];
        assert!(ZipArchive::parse(truncated).is_err());
    }

    #[test]
    fn inflated_size_mismatch_is_rejected() {
        let bytes = ZipBuilder::new()
            .add_deflated("b.txt", b"deflate me deflate me deflate me")
            .lie_sizes("b.txt", None, Some(9999))
            .build();
        let archive = ZipArchive::parse(&bytes).expect("parse");
        let entry = archive.find("b.txt").expect("entry");
        assert!(matches!(
            archive.read_entry(entry, &mut 0),
            Err(OoxmlError::InflateSizeMismatch { claimed: 9999, .. })
        ));
    }

    #[test]
    fn entry_name_budget_is_enforced() {
        // A name longer than the budget must be rejected before any lossy
        // decode of oversized names.
        let long_name = "n".repeat(CONTAINER_MAX_ENTRY_NAME_BYTES + 1);
        let bytes = ZipBuilder::new().add_stored(&long_name, b"x").build();
        assert!(matches!(
            ZipArchive::parse(&bytes),
            Err(OoxmlError::EntryNameTooLong { .. })
        ));
    }
}
