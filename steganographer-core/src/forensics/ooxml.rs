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
//! - [`DOC_003_FAMILY`] — Extended-part concealment coverage (DOC-003):
//!   the Unicode/text stego channels over pptx slides/notes, xlsx
//!   sharedStrings/worksheets, and docx headers/footers; presentation.xml
//!   header/footer placeholders; and embedded-media entry anomalies. These
//!   are detections and do set `detected`.
use std::collections::BTreeMap;

use super::{ContainerAnalysis, ContainerFinding};
use crate::unicode_text;

/// Stable detector family ID: OOXML package inventory/topology (DOC-001).
pub const DOC_001_FAMILY: &str = "DOC-001";
/// Stable detector family ID: WordprocessingML concealment channels (DOC-002).
pub const DOC_002_FAMILY: &str = "DOC-002";
/// Stable detector family ID: extended OOXML part coverage (DOC-003).
pub const DOC_003_FAMILY: &str = "DOC-003";
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
/// Maximum compressed/stored input reserved across attempted entry decodes.
pub const CONTAINER_MAX_DECODE_INPUT_TOTAL: usize = 16 * 1024 * 1024;
/// Maximum attempted entry decodes, including failures and repeated ranges.
pub const CONTAINER_MAX_DECODE_ATTEMPTS: usize = 256;
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
/// Media-directory extensions that mark executable/script content (DOC-003).
const MEDIA_SUSPICIOUS_EXTS: &[&str] = &[
    "exe", "dll", "js", "vbs", "ps1", "bat", "cmd", "hta", "scr", "com", "sh", "msi", "jar", "swf",
];
/// Recognized image/audio/video extensions inside media directories (DOC-003).
const MEDIA_KNOWN_EXTS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "bmp", "tif", "tiff", "emf", "wmf", "webp", "ico", "mp3", "wav",
    "wma", "m4a", "aac", "ogg", "oga", "flac", "mp4", "m4v", "avi", "wmv", "mov", "mkv", "mpeg",
    "mpg", "webm",
];
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
    /// Compressed/stored input reservations exceed the package work budget.
    #[error("ZIP decode input would exceed the {limit}-byte budget")]
    DecodeInputBudgetExceeded { limit: usize },
    /// Too many entry decodes have been attempted.
    #[error("ZIP decode attempts exceed the {limit}-attempt budget")]
    DecodeAttemptBudgetExceeded { limit: usize },
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
    /// The archive requires an unsupported ZIP feature.
    #[error("unsupported ZIP feature: {feature}")]
    UnsupportedFeature { feature: &'static str },
    /// Entry checksum does not match the bytes read.
    #[error("ZIP entry \"{name}\" CRC-32 mismatch")]
    ChecksumMismatch { name: String },
}

/// Shared admission state for all entry reads in one analysis.
/// Reservations precede decoding and are never refunded after failures.
#[derive(Debug, Default)]
pub struct ZipReadBudget {
    output: usize,
    input: usize,
    attempts: usize,
}

impl ZipReadBudget {
    fn reserve(&mut self, entry: &ZipEntry) -> Result<(), OoxmlError> {
        let output = check_output_budget(&entry.name, entry.uncompressed_size, self.output)?;
        if self.attempts >= CONTAINER_MAX_DECODE_ATTEMPTS {
            return Err(OoxmlError::DecodeAttemptBudgetExceeded {
                limit: CONTAINER_MAX_DECODE_ATTEMPTS,
            });
        }
        let input = self
            .input
            .checked_add(entry.compressed_size)
            .filter(|&n| n <= CONTAINER_MAX_DECODE_INPUT_TOTAL)
            .ok_or(OoxmlError::DecodeInputBudgetExceeded {
                limit: CONTAINER_MAX_DECODE_INPUT_TOTAL,
            })?;
        self.output = output;
        self.input = input;
        self.attempts += 1;
        Ok(())
    }
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
    name_range: std::ops::Range<usize>,
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
    /// Claimed CRC-32 of the uncompressed content (verified on extraction).
    pub fn crc32(&self) -> u32 {
        self.crc32
    }
}

/// A parsed in-memory ZIP archive borrowed from its input bytes.
#[derive(Debug, Clone)]
pub struct ZipArchive<'a> {
    data: &'a [u8],
    entries: Vec<ZipEntry>,
    central_offset: usize,
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
        if read_u16(data, eocd + 4) != 0
            || read_u16(data, eocd + 6) != 0
            || read_u16(data, eocd + 8) as usize != total_entries
        {
            return Err(OoxmlError::UnsupportedFeature {
                feature: "multi_disk",
            });
        }
        if total_entries == u16::MAX as usize
            || cd_size == u32::MAX as usize
            || cd_offset == u32::MAX as usize
        {
            return Err(OoxmlError::UnsupportedFeature { feature: "zip64" });
        }
        if total_entries > CONTAINER_MAX_ENTRIES {
            return Err(OoxmlError::TooManyEntries {
                claimed: total_entries,
                limit: CONTAINER_MAX_ENTRIES,
            });
        }
        let end = cd_offset
            .checked_add(cd_size)
            .filter(|&end| end <= eocd)
            .ok_or(OoxmlError::CentralDirectoryOutOfBounds {
                offset: cd_offset,
                size: cd_size,
                input_len: data.len(),
            })?;
        let mut entries = Vec::new();
        let mut pos = cd_offset;
        for index in 0..total_entries {
            let fixed_end = pos
                .checked_add(46)
                .filter(|&n| n <= end)
                .ok_or(OoxmlError::CentralDirectoryCorrupt { offset: pos })?;
            if read_u32(data, pos) != 0x0201_4b50 {
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
            if read_u16(data, pos + 34) != 0 {
                return Err(OoxmlError::UnsupportedFeature {
                    feature: "multi_disk",
                });
            }
            if compressed_size == u32::MAX as usize
                || uncompressed_size == u32::MAX as usize
                || local_offset == u32::MAX as usize
            {
                return Err(OoxmlError::UnsupportedFeature { feature: "zip64" });
            }
            if flags & 8 != 0 {
                return Err(OoxmlError::UnsupportedFeature {
                    feature: "data_descriptor",
                });
            }
            let record_end = fixed_end
                .checked_add(name_len)
                .and_then(|n| n.checked_add(extra_len))
                .and_then(|n| n.checked_add(comment_len))
                .filter(|&n| n <= end)
                .ok_or(OoxmlError::CentralDirectoryCorrupt { offset: pos })?;
            if name_len > CONTAINER_MAX_ENTRY_NAME_BYTES {
                return Err(OoxmlError::EntryNameTooLong {
                    index,
                    len: name_len,
                    limit: CONTAINER_MAX_ENTRY_NAME_BYTES,
                });
            }
            let name_range = fixed_end..fixed_end + name_len;
            let name = String::from_utf8_lossy(&data[name_range.clone()]).into_owned();
            entries.push(ZipEntry {
                name,
                name_range,
                flags,
                method,
                crc32,
                compressed_size,
                uncompressed_size,
                local_header_offset: local_offset,
            });
            pos = record_end;
        }
        if pos != end {
            return Err(OoxmlError::CentralDirectoryCorrupt { offset: pos });
        }
        Ok(ZipArchive {
            data,
            entries,
            central_offset: cd_offset,
        })
    }

    /// All parsed entries, in central-directory order.
    pub fn entries(&self) -> &[ZipEntry] {
        &self.entries
    }

    /// First entry with the given name, if present.
    pub fn find(&self, name: &str) -> Option<&ZipEntry> {
        self.entries.iter().find(|e| e.name == name)
    }

    /// Extract one entry using shared output, input and attempt reservations.
    ///
    /// Reuse the same budget across every part, including duplicate/aliased
    /// entries. Use `ZipReadBudget::default()` for a fresh one-shot analysis.
    pub fn read_entry(
        &self,
        entry: &ZipEntry,
        budget: &mut ZipReadBudget,
    ) -> Result<Vec<u8>, OoxmlError> {
        if entry.flags & 0x1 != 0 {
            return Err(OoxmlError::EncryptedEntry {
                name: entry.name.clone(),
            });
        }
        budget.reserve(entry)?;
        let range = self.local_data_range(entry)?;
        let raw = &self.data[range];
        let out = match entry.method {
            0 => {
                if entry.compressed_size != entry.uncompressed_size {
                    return Err(OoxmlError::InflateSizeMismatch {
                        name: entry.name.clone(),
                        actual: entry.compressed_size,
                        claimed: entry.uncompressed_size,
                    });
                }
                raw.to_vec()
            }
            8 => inflate_raw(raw, &entry.name, entry.uncompressed_size)?,
            method => {
                return Err(OoxmlError::UnsupportedCompressionMethod {
                    name: entry.name.clone(),
                    method,
                })
            }
        };
        if crc32(&out) != entry.crc32 {
            return Err(OoxmlError::ChecksumMismatch {
                name: entry.name.clone(),
            });
        }
        Ok(out)
    }

    /// Resolve an entry's local header and return the compressed-data range.
    fn local_data_range(&self, entry: &ZipEntry) -> Result<std::ops::Range<usize>, OoxmlError> {
        let off = entry.local_header_offset;
        let data = self.data;
        let corrupt = || OoxmlError::LocalHeaderCorrupt {
            name: entry.name.clone(),
        };
        let name_start = off
            .checked_add(30)
            .filter(|&n| n <= self.central_offset)
            .ok_or_else(corrupt)?;
        if read_u32(data, off) != 0x0403_4b50 {
            return Err(corrupt());
        }
        let name_len = read_u16(data, off + 26) as usize;
        let extra_len = read_u16(data, off + 28) as usize;
        let name_end = name_start.checked_add(name_len).ok_or_else(corrupt)?;
        let data_start = name_end.checked_add(extra_len).ok_or_else(corrupt)?;
        if data_start > self.central_offset
            || data.get(name_start..name_end) != data.get(entry.name_range.clone())
            || read_u16(data, off + 6) != entry.flags
            || read_u16(data, off + 8) != entry.method
            || read_u32(data, off + 14) != entry.crc32
            || read_u32(data, off + 18) as usize != entry.compressed_size
            || read_u32(data, off + 22) as usize != entry.uncompressed_size
        {
            return Err(OoxmlError::LocalHeaderMismatch {
                name: entry.name.clone(),
            });
        }
        let data_end = data_start
            .checked_add(entry.compressed_size)
            .filter(|&n| n <= self.central_offset)
            .ok_or_else(|| OoxmlError::EntryDataOutOfBounds {
                name: entry.name.clone(),
                offset: data_start,
                size: entry.compressed_size,
                input_len: data.len(),
            })?;
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
    // Only examine candidates whose complete fixed record fits.
    let mut pos = data.len() - 22;
    let mut found = None;
    let mut fallback = None;
    loop {
        if read_u32(data, pos) == 0x0605_4b50 {
            let comment_len = read_u16(data, pos + 20) as usize;
            if pos.checked_add(22).and_then(|n| n.checked_add(comment_len)) == Some(data.len()) {
                fallback.get_or_insert(pos);
                let cd_end =
                    (read_u32(data, pos + 16) as usize)
                        .checked_add(read_u32(data, pos + 12) as usize);
                if cd_end == Some(pos) && found.replace(pos).is_some() {
                    return Err(OoxmlError::UnsupportedFeature {
                        feature: "ambiguous_eocd",
                    });
                }
            }
        }
        if pos == floor || pos == 0 {
            break;
        }
        pos -= 1;
    }
    found
        .or(fallback)
        .ok_or(OoxmlError::EocdNotFound(CONTAINER_MAX_EOCD_SCAN_BYTES))
}

/// Admit output before allocation, identically for stored and deflated data.
fn check_output_budget(name: &str, claimed: usize, total: usize) -> Result<usize, OoxmlError> {
    if claimed > CONTAINER_MAX_INFLATE_PER_ENTRY {
        return Err(OoxmlError::InflateBudgetExceeded {
            name: name.to_string(),
            claimed,
            limit: CONTAINER_MAX_INFLATE_PER_ENTRY,
        });
    }
    total
        .checked_add(claimed)
        .filter(|&n| n <= CONTAINER_MAX_INFLATE_TOTAL)
        .ok_or(OoxmlError::InflateTotalBudgetExceeded {
            inflated: total.saturating_add(claimed),
            limit: CONTAINER_MAX_INFLATE_TOTAL,
        })
}

/// Read one extra byte to distinguish a complete stream from a claimed prefix.
fn inflate_raw(raw: &[u8], name: &str, claimed: usize) -> Result<Vec<u8>, OoxmlError> {
    let limit = claimed
        .checked_add(1)
        .ok_or_else(|| OoxmlError::InflateFailed {
            name: name.to_string(),
        })?;
    let mut out = Vec::with_capacity(limit);
    let mut decoder = flate2::Decompress::new(false);
    let status = decoder
        .decompress_vec(raw, &mut out, flate2::FlushDecompress::Finish)
        .map_err(|_| OoxmlError::InflateFailed {
            name: name.to_string(),
        })?;
    if out.len() != claimed {
        return Err(OoxmlError::InflateSizeMismatch {
            name: name.to_string(),
            actual: out.len(),
            claimed,
        });
    }
    if status != flate2::Status::StreamEnd || decoder.total_in() != raw.len() as u64 {
        return Err(OoxmlError::InflateFailed {
            name: name.to_string(),
        });
    }
    Ok(out)
}

fn crc32(data: &[u8]) -> u32 {
    // Compile-time table; no per-byte heap allocation or table rebuilding.
    const TABLE: [u32; 256] = {
        let mut table = [0; 256];
        let mut i = 0;
        while i < 256 {
            let mut c = i as u32;
            let mut bit = 0;
            while bit < 8 {
                c = if c & 1 != 0 {
                    0xedb8_8320 ^ (c >> 1)
                } else {
                    c >> 1
                };
                bit += 1;
            }
            table[i] = c;
            i += 1;
        }
        table
    };
    let mut crc = u32::MAX;
    for &byte in data {
        crc = TABLE[((crc ^ byte as u32) & 255) as usize] ^ (crc >> 8);
    }
    !crc
}

/// Run the DOC-001/DOC-002/DOC-003 container analysis over a ZIP-family
/// buffer.
///
/// Never panics on hostile input: parse and read failures become DOC-001
/// evidence. Returns findings in detector order (inventory, topology
/// anomalies, then WordprocessingML concealment, then extended-part
/// coverage).
pub fn analyze_package(data: &[u8]) -> ContainerAnalysis {
    let mut findings = ContainerAnalysis::default();
    let archive = match ZipArchive::parse(data) {
        Ok(archive) => archive,
        Err(error) => {
            incomplete(&mut findings, zip_reason(&error));
            findings.findings.push(ContainerFinding {
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
    let mut name_counts: BTreeMap<&str, usize> = BTreeMap::new();
    for entry in entries {
        *name_counts.entry(entry.name()).or_insert(0) += 1;
        if entry.uncompressed_size > CONTAINER_MAX_INFLATE_PER_ENTRY {
            incomplete(&mut findings, "zip_entry_budget");
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
        incomplete(&mut findings, "zip_duplicate_name");
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
        incomplete(&mut findings, "zip_encrypted_entry");
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

    // DOC-002 WordprocessingML concealment (detections) plus DOC-003
    // extended-part coverage.
    let mut inflate_total = ZipReadBudget::default();
    match office_family {
        "docx" => {
            analyze_document_xml(&archive, &mut inflate_total, &mut findings);
            analyze_office_parts(&archive, "docx", &mut inflate_total, &mut findings);
        }
        "pptx" | "xlsx" => {
            analyze_office_parts(&archive, office_family, &mut inflate_total, &mut findings)
        }
        _ => {}
    }

    findings
}

/// Deep-analyze `word/document.xml`: Unicode/text stego channels plus ASCII
/// whitespace runs inside XML text nodes.
fn analyze_document_xml(
    archive: &ZipArchive<'_>,
    inflate_total: &mut ZipReadBudget,
    findings: &mut ContainerAnalysis,
) {
    // Scan every interpretation of duplicate main parts, within the same budget.
    for entry in archive
        .entries()
        .iter()
        .filter(|e| e.name() == WORD_DOCUMENT)
    {
        analyze_part_text(archive, entry, inflate_total, findings, DOC_002_FAMILY);
    }
}

/// Format one [`unicode_text::TextFinding`] as a bounded evidence detail:
/// "DETECTOR: detail (char offsets o1,o2,…)", offsets capped at 4 with an
/// aggregate count. Shared by the DOC-002 and DOC-003 part analyses.
pub(crate) fn format_text_finding(finding: &unicode_text::TextFinding) -> String {
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
    format!(
        "{}: {} (char offsets {offsets})",
        finding.detector_id, finding.detail
    )
}

/// DOC-003 extended-part analysis for office packages: text channels over
/// pptx slides/notes, xlsx sharedStrings/worksheets, docx headers/footers;
/// presentation.xml header/footer placeholders; and media-entry anomalies.
///
/// The read budget is shared across all parts, including failed decodes.
fn analyze_office_parts(
    archive: &ZipArchive<'_>,
    family_kind: &str,
    inflate_total: &mut ZipReadBudget,
    findings: &mut ContainerAnalysis,
) {
    for entry in archive.entries() {
        let name = entry.name();
        let is_text_part = match family_kind {
            "docx" => {
                (name.starts_with("word/header") || name.starts_with("word/footer"))
                    && name.ends_with(".xml")
            }
            "pptx" => {
                (name.starts_with("ppt/slides/slide")
                    || name.starts_with("ppt/notesSlides/notesSlide"))
                    && name.ends_with(".xml")
            }
            "xlsx" => {
                (name == "xl/sharedStrings.xml" || name.starts_with("xl/worksheets/"))
                    && name.ends_with(".xml")
            }
            _ => false,
        };
        if is_text_part {
            analyze_part_text(archive, entry, inflate_total, findings, DOC_003_FAMILY);
        }
    }
    if family_kind == "pptx" {
        analyze_presentation_placeholders(archive, inflate_total, findings);
    }
    analyze_media_entries(archive, findings);
}

/// Deep-analyze one extended XML part: Unicode/text stego channels plus XML
/// text-node whitespace runs, emitting findings under DOC-003. Read
/// failures stay DOC-001 topology evidence.
fn analyze_part_text(
    archive: &ZipArchive<'_>,
    entry: &ZipEntry,
    inflate_total: &mut ZipReadBudget,
    findings: &mut ContainerAnalysis,
    family: &str,
) {
    let path = entry.name().to_string();
    if entry.uncompressed_size > CONTAINER_MAX_INFLATE_PER_ENTRY {
        // Already reported by the DOC-001 topology check; do not
        // double-report.
        return;
    }
    let bytes = match archive.read_entry(entry, inflate_total) {
        Ok(bytes) => bytes,
        Err(error) => {
            incomplete(findings, zip_reason(&error));
            push_finding(
                findings,
                ContainerFinding {
                    path: path.clone(),
                    family: DOC_001_FAMILY.to_string(),
                    detail: bound_detail(format!("part rejected: {error}")),
                },
            );
            return;
        }
    };
    let xml = match decode_xml(&bytes) {
        Ok(xml) => xml,
        Err(reason) => {
            incomplete(findings, reason);
            push_finding(
                findings,
                ContainerFinding {
                    path,
                    family: DOC_001_FAMILY.to_string(),
                    detail: format!("XML text not analyzed: {reason}"),
                },
            );
            return;
        }
    };
    if xml.truncated {
        incomplete(findings, "xml_text_budget");
    }

    for finding in unicode_text::analyze_text(&xml.text) {
        push_finding(
            findings,
            ContainerFinding {
                path: path.clone(),
                family: family.to_string(),
                detail: bound_detail(format_text_finding(&finding)),
            },
        );
    }
    for finding in unicode_text::analyze_text(&xml.attributes) {
        push_finding(
            findings,
            ContainerFinding {
                path: path.clone(),
                family: family.to_string(),
                detail: bound_detail(format!(
                    "XML attribute values: {}",
                    format_text_finding(&finding)
                )),
            },
        );
    }
    if let Some((runs, longest, first)) = detect_xml_whitespace_runs(&xml.text) {
        push_finding(
            findings,
            ContainerFinding {
                path,
                family: family.to_string(),
                detail: bound_detail(format!(
                    "XML text-node whitespace runs: {runs} runs, longest {longest} chars, first at decoded-text char offset {first}"
                )),
            },
        );
    }
}

/// Detect header/footer placeholder markup in `ppt/presentation.xml`
/// (DOC-003): footer/header/date/slide-number placeholders are a classic
/// low-visibility text channel in presentation packages.
fn analyze_presentation_placeholders(
    archive: &ZipArchive<'_>,
    inflate_total: &mut ZipReadBudget,
    findings: &mut ContainerAnalysis,
) {
    for entry in archive
        .entries()
        .iter()
        .filter(|e| e.name() == PPT_PRESENTATION)
    {
        if entry.uncompressed_size > CONTAINER_MAX_INFLATE_PER_ENTRY {
            continue;
        }
        let bytes = match archive.read_entry(entry, inflate_total) {
            Ok(bytes) => bytes,
            Err(error) => {
                incomplete(findings, zip_reason(&error));
                push_finding(
                    findings,
                    ContainerFinding {
                        path: PPT_PRESENTATION.to_string(),
                        family: DOC_001_FAMILY.to_string(),
                        detail: bound_detail(format!("part rejected: {error}")),
                    },
                );
                continue;
            }
        };
        let xml = match decode_xml(&bytes) {
            Ok(xml) => xml,
            Err(reason) => {
                incomplete(findings, reason);
                continue;
            }
        };
        if xml.placeholder_namespace_incomplete {
            incomplete(findings, "xml_namespace_unsupported");
        }
        if xml.presentation_placeholder {
            push_finding(
            findings,
            ContainerFinding {
                path: PPT_PRESENTATION.to_string(),
                family: DOC_003_FAMILY.to_string(),
                detail: "parsed PresentationML header/footer placeholder markup present: potential hidden-text channel".to_string(),
            },
        );
        }
    }
}

/// DOC-003 media-entry anomalies across office packages: executable/script
/// extensions and unrecognized non-media extensions inside media
/// directories. Text-like extensions are already DOC-001 evidence and are
/// skipped here to avoid double-reporting.
fn analyze_media_entries(archive: &ZipArchive<'_>, findings: &mut ContainerAnalysis) {
    for entry in archive.entries().iter().filter(|e| is_media_name(e.name())) {
        let Some(ext) = path_extension(entry.name()) else {
            push_finding(
                findings,
                ContainerFinding {
                    path: entry.name().to_string(),
                    family: DOC_003_FAMILY.to_string(),
                    detail: "embedded-media entry has no file extension".to_string(),
                },
            );
            continue;
        };
        let ext_lower = ext.to_ascii_lowercase();
        if TEXT_LIKE_EXTS
            .iter()
            .any(|candidate| ext_lower == *candidate)
        {
            continue;
        }
        if MEDIA_SUSPICIOUS_EXTS
            .iter()
            .any(|candidate| ext_lower == *candidate)
        {
            push_finding(
                findings,
                ContainerFinding {
                    path: entry.name().to_string(),
                    family: DOC_003_FAMILY.to_string(),
                    detail: bound_detail(format!(
                        "embedded-media entry carries executable/script extension ({ext})"
                    )),
                },
            );
        } else if !MEDIA_KNOWN_EXTS
            .iter()
            .any(|candidate| ext_lower == *candidate)
        {
            push_finding(
                findings,
                ContainerFinding {
                    path: entry.name().to_string(),
                    family: DOC_003_FAMILY.to_string(),
                    detail: bound_detail(format!(
                        "embedded-media entry has unrecognized media extension ({ext})"
                    )),
                },
            );
        }
    }
}

struct DecodedXml {
    presentation_placeholder: bool,
    placeholder_namespace_incomplete: bool,
    text: String,
    attributes: String,
    truncated: bool,
}

/// Small bounded XML tokenizer, not a renderer. No DTD or named entity lookup.
/// Only predefined/numeric references and BOM-marked UTF-16 are supported.
fn decode_xml(bytes: &[u8]) -> Result<DecodedXml, &'static str> {
    let utf16 = bytes.starts_with(&[0xff, 0xfe]) || bytes.starts_with(&[0xfe, 0xff]);
    let source = if utf16 {
        if !bytes.len().is_multiple_of(2) {
            return Err("xml_encoding_invalid");
        }
        let little = bytes[0] == 0xff;
        let units = bytes[2..].as_chunks::<2>().0.iter().map(|b| {
            if little {
                u16::from_le_bytes([b[0], b[1]])
            } else {
                u16::from_be_bytes([b[0], b[1]])
            }
        });
        char::decode_utf16(units)
            .collect::<Result<String, _>>()
            .map_err(|_| "xml_encoding_invalid")?
    } else {
        std::str::from_utf8(bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes))
            .map_err(|_| "xml_encoding_unsupported")?
            .to_string()
    };
    if !source.chars().all(xml_character) {
        return Err("xml_character_invalid");
    }
    // XML line-ending normalization applies to source literals, not references.
    let source = if source.contains('\r') {
        let mut normalized = String::with_capacity(source.len());
        let mut chars = source.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\r' {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                normalized.push('\n');
            } else {
                normalized.push(c);
            }
        }
        normalized
    } else {
        source
    };
    let mut text = String::new();
    let mut truncated = false;
    let mut attributes = String::new();
    let mut attributes_truncated = false;
    let mut stack: Vec<&str> = Vec::new();
    // Namespace resolution is limited to the placeholder probe, not general
    // OOXML schema/relationship validation. Shadowing and default bindings apply.
    let mut namespaces: Vec<(&str, bool, usize)> = Vec::new();
    let mut presentation_placeholder = false;
    let mut placeholder_namespace_incomplete = false;
    let mut root_seen = false;
    let mut pos = 0;
    while pos < source.len() {
        let rest = &source[pos..];
        if !rest.starts_with('<') {
            let end = rest.find('<').unwrap_or(rest.len());
            let value = &rest[..end];
            if value.contains("]]>")
                || (stack.is_empty() && !value.trim_matches(xml_space).is_empty())
            {
                return Err("xml_structure_invalid");
            }
            if !stack.is_empty() {
                decode_references(value, |c| push_xml_char(&mut text, &mut truncated, c))?;
            }
            pos += end;
            continue;
        }
        if let Some(comment) = rest.strip_prefix("<!--") {
            let end = comment.find("-->").ok_or("xml_structure_invalid")?;
            if comment[..end].contains("--") || comment[..end].ends_with('-') {
                return Err("xml_structure_invalid");
            }
            pos += 4 + end + 3;
            continue;
        }
        if let Some(cdata) = rest.strip_prefix("<![CDATA[") {
            if stack.is_empty() {
                return Err("xml_structure_invalid");
            }
            let end = cdata.find("]]>").ok_or("xml_structure_invalid")?;
            for c in cdata[..end].chars() {
                push_xml_char(&mut text, &mut truncated, c);
            }
            pos += 9 + end + 3;
            continue;
        }
        if rest.starts_with("<!") {
            return Err("xml_dtd_unsupported");
        }
        if rest.starts_with("<?") {
            let end = rest.find("?>").ok_or("xml_structure_invalid")?;
            let body = &rest[2..end];
            let target_end = body.find(xml_space).unwrap_or(body.len());
            let target = &body[..target_end];
            if !xml_name(target) {
                return Err("xml_structure_invalid");
            }
            if target.eq_ignore_ascii_case("xml") {
                if pos != 0 || target != "xml" {
                    return Err("xml_structure_invalid");
                }
                let mut version_seen = false;
                let mut standalone_seen = false;
                xml_attributes(&body[target_end..], |name, value| {
                    if name == "version" {
                        if version_seen || standalone_seen {
                            return Err("xml_structure_invalid");
                        }
                        if value != "1.0" {
                            return Err("xml_version_unsupported");
                        }
                        version_seen = true;
                    } else if !version_seen || standalone_seen {
                        return Err("xml_structure_invalid");
                    }
                    if name == "encoding" {
                        let supported = if utf16 {
                            value.eq_ignore_ascii_case("UTF-16")
                                || (bytes[0] == 0xff && value.eq_ignore_ascii_case("UTF-16LE"))
                                || (bytes[0] == 0xfe && value.eq_ignore_ascii_case("UTF-16BE"))
                        } else {
                            value.eq_ignore_ascii_case("UTF-8")
                        };
                        if !supported {
                            return Err("xml_encoding_unsupported");
                        }
                    }
                    if name == "standalone" {
                        if !matches!(value, "yes" | "no") {
                            return Err("xml_structure_invalid");
                        }
                        standalone_seen = true;
                    } else if !matches!(name, "version" | "encoding") {
                        return Err("xml_structure_invalid");
                    }
                    Ok(())
                })?;
                if !version_seen {
                    return Err("xml_structure_invalid");
                }
            }
            pos += end + 2;
            continue;
        }
        let mut quote = None;
        let mut end = None;
        for (i, c) in rest[1..].char_indices() {
            match (quote, c) {
                (Some(q), c) if q == c => quote = None,
                (None, '\'' | '"') => quote = Some(c),
                (None, '>') => {
                    end = Some(i + 1);
                    break;
                }
                (None, '<') => return Err("xml_structure_invalid"),
                _ => {}
            }
        }
        let end = end.ok_or("xml_structure_invalid")?;
        let body = &rest[1..end];
        if let Some(closing) = body.strip_prefix('/') {
            let name = closing.trim_end_matches(xml_space);
            if !xml_name(name) || stack.pop() != Some(name) {
                return Err("xml_structure_invalid");
            }
            while namespaces
                .last()
                .is_some_and(|(_, _, depth)| *depth > stack.len())
            {
                namespaces.pop();
            }
        } else {
            let empty = body.ends_with('/');
            let body = if empty { &body[..body.len() - 1] } else { body };
            let name_end = body.find(xml_space).unwrap_or(body.len());
            let name = &body[..name_end];
            if !xml_name(name) {
                return Err("xml_structure_invalid");
            }
            let mut placeholder_type = false;
            xml_attributes(&body[name_end..], |attribute, value| {
                if !value.is_empty()
                    && !attributes.is_empty()
                    && attributes.len() < unicode_text::MAX_TEXT_SCAN_BYTES
                {
                    push_xml_char(&mut attributes, &mut attributes_truncated, '\n');
                }
                let namespace = if attribute == "xmlns" {
                    Some("")
                } else {
                    attribute.strip_prefix("xmlns:")
                };
                let relevant = namespace.is_some() || attribute == "type";
                let mut decoded = String::new();
                let mut capped = false;
                decode_references(value, |c| {
                    push_xml_char(&mut attributes, &mut attributes_truncated, c);
                    if relevant && !capped {
                        if decoded.len() + c.len_utf8() <= 100 {
                            decoded.push(c);
                        } else {
                            capped = true;
                        }
                    }
                })?;
                if let Some(prefix) = namespace {
                    let presentation = !capped
                        && matches!(
                            decoded.as_str(),
                            "http://schemas.openxmlformats.org/presentationml/2006/main"
                                | "http://purl.oclc.org/ooxml/presentationml/main"
                        );
                    namespaces.push((prefix, presentation, stack.len() + 1));
                }
                if attribute == "type" {
                    placeholder_type =
                        !capped && matches!(decoded.as_str(), "ftr" | "hdr" | "dt" | "sldNum");
                }
                Ok(())
            })?;
            let (prefix, local) = name.split_once(':').unwrap_or(("", name));
            if local == "hf" || (local == "ph" && placeholder_type) {
                match namespaces.iter().rev().find(|(p, _, _)| *p == prefix) {
                    Some((_, true, _)) => presentation_placeholder = true,
                    Some((_, false, _)) => {}
                    None => placeholder_namespace_incomplete = true,
                }
            }
            if stack.is_empty() {
                if root_seen {
                    return Err("xml_structure_invalid");
                }
                root_seen = true;
            }
            if !empty {
                if stack.len() == 256 {
                    return Err("xml_depth_budget");
                }
                stack.push(name);
            } else {
                while namespaces
                    .last()
                    .is_some_and(|(_, _, depth)| *depth > stack.len())
                {
                    namespaces.pop();
                }
            }
        }
        // Separate text nodes, never invent a long run across markup.
        if !text.is_empty()
            && !text.ends_with('\n')
            && text.len() < unicode_text::MAX_TEXT_SCAN_BYTES
        {
            push_xml_char(&mut text, &mut truncated, '\n');
        }
        pos += end + 1;
    }
    if !root_seen || !stack.is_empty() {
        return Err("xml_structure_invalid");
    }
    Ok(DecodedXml {
        presentation_placeholder,
        placeholder_namespace_incomplete,
        text,
        attributes,
        truncated: truncated || attributes_truncated,
    })
}

fn xml_character(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r' | '\u{20}'..='\u{d7ff}' | '\u{e000}'..='\u{fffd}' | '\u{10000}'..='\u{10ffff}')
}

fn xml_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\r' | '\n')
}

fn xml_name_start(c: char) -> bool {
    matches!(c, ':' | '_' | 'A'..='Z' | 'a'..='z' | '\u{c0}'..='\u{d6}'
        | '\u{d8}'..='\u{f6}' | '\u{f8}'..='\u{2ff}' | '\u{370}'..='\u{37d}'
        | '\u{37f}'..='\u{1fff}' | '\u{200c}'..='\u{200d}' | '\u{2070}'..='\u{218f}'
        | '\u{2c00}'..='\u{2fef}' | '\u{3001}'..='\u{d7ff}' | '\u{f900}'..='\u{fdcf}'
        | '\u{fdf0}'..='\u{fffd}' | '\u{10000}'..='\u{effff}')
}

fn xml_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next().is_some_and(xml_name_start)
        && chars.all(|c| {
            xml_name_start(c)
                || matches!(c, '-' | '.' | '0'..='9'
            | '\u{b7}' | '\u{300}'..='\u{36f}' | '\u{203f}'..='\u{2040}')
        })
}

fn xml_attributes<'a>(
    mut rest: &'a str,
    mut visit: impl FnMut(&'a str, &'a str) -> Result<(), &'static str>,
) -> Result<(), &'static str> {
    let mut names = std::collections::BTreeSet::new();
    while !rest.is_empty() {
        let trimmed = rest.trim_start_matches(xml_space);
        if trimmed.is_empty() {
            return Ok(());
        }
        if trimmed.len() == rest.len() {
            return Err("xml_structure_invalid");
        }
        let end = trimmed
            .find(|c: char| c == '=' || xml_space(c))
            .ok_or("xml_structure_invalid")?;
        let name = &trimmed[..end];
        if !xml_name(name) || !names.insert(name) {
            return Err("xml_structure_invalid");
        }
        if names.len() > 1024 {
            return Err("xml_attribute_budget");
        }
        rest = trimmed[end..].trim_start_matches(xml_space);
        rest = rest
            .strip_prefix('=')
            .ok_or("xml_structure_invalid")?
            .trim_start_matches(xml_space);
        let quote = rest.chars().next().ok_or("xml_structure_invalid")?;
        if !matches!(quote, '\'' | '"') {
            return Err("xml_structure_invalid");
        }
        rest = &rest[1..];
        let end = rest.find(quote).ok_or("xml_structure_invalid")?;
        let value = &rest[..end];
        if value.contains('<') {
            return Err("xml_structure_invalid");
        }
        visit(name, value)?;
        rest = &rest[end + 1..];
    }
    Ok(())
}

fn decode_references(value: &str, mut push: impl FnMut(char)) -> Result<(), &'static str> {
    let mut rest = value;
    while !rest.is_empty() {
        if let Some(reference) = rest.strip_prefix('&') {
            let end = reference.find(';').ok_or("xml_reference_invalid")?;
            let name = &reference[..end];
            let c = match name {
                "amp" => '&',
                "lt" => '<',
                "gt" => '>',
                "apos" => '\'',
                "quot" => '"',
                _ => {
                    let n = if let Some(hex) = name.strip_prefix("#x") {
                        if hex.is_empty() || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                            return Err("xml_reference_invalid");
                        }
                        u32::from_str_radix(hex, 16).ok()
                    } else if let Some(decimal) = name.strip_prefix('#') {
                        if decimal.is_empty() || !decimal.bytes().all(|b| b.is_ascii_digit()) {
                            return Err("xml_reference_invalid");
                        }
                        decimal.parse::<u32>().ok()
                    } else {
                        return Err("xml_entity_unsupported");
                    };
                    n.and_then(char::from_u32)
                        .filter(|&c| xml_character(c))
                        .ok_or("xml_reference_invalid")?
                }
            };
            push(c);
            rest = &reference[end + 1..];
        } else {
            let end = rest.find('&').unwrap_or(rest.len());
            for c in rest[..end].chars() {
                push(c);
            }
            rest = &rest[end..];
        }
    }
    Ok(())
}

fn push_xml_char(text: &mut String, truncated: &mut bool, c: char) {
    if *truncated {
        return;
    }
    if text.len() + c.len_utf8() <= unicode_text::MAX_TEXT_SCAN_BYTES {
        text.push(c);
    } else {
        *truncated = true;
    }
}

/// Long space/tab runs in decoded text; offsets count Unicode characters.
fn detect_xml_whitespace_runs(text: &str) -> Option<(usize, usize, usize)> {
    let mut runs = 0usize;
    let mut longest = 0usize;
    let mut first = None;
    let mut run = 0usize;
    let mut run_start = 0usize;
    for (i, c) in text.chars().chain(std::iter::once('\n')).enumerate() {
        if c == ' ' || c == '\t' {
            if run == 0 {
                run_start = i;
            }
            run += 1;
        } else {
            if run >= XML_WS_RUN_MIN {
                runs += 1;
                longest = longest.max(run);
                first.get_or_insert(run_start);
            }
            run = 0;
        }
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
fn push_finding(analysis: &mut ContainerAnalysis, finding: ContainerFinding) {
    let positive = matches!(
        finding.family.as_str(),
        DOC_002_FAMILY | DOC_003_FAMILY | "DOC-004"
    );
    analysis.detected |= positive;
    if analysis.findings.len() < CONTAINER_MAX_FINDINGS {
        analysis.findings.push(finding);
        return;
    }
    incomplete(analysis, "zip_finding_budget");
    // The sentinel replaces the last display slot; detection is already latched.
    let summary = if analysis.detected {
        "finding budget exhausted; positive concealment evidence present; further findings suppressed"
    } else {
        "finding budget exhausted; further findings suppressed"
    };
    analysis.findings[CONTAINER_MAX_FINDINGS - 1] = ContainerFinding {
        path: "<package>".to_string(),
        family: ZIP_TOPOLOGY_FAMILY.to_string(),
        detail: summary.to_string(),
    };
}

fn incomplete(analysis: &mut ContainerAnalysis, reason: &'static str) {
    if analysis.incomplete_reasons.len() < 16
        && !analysis.incomplete_reasons.iter().any(|r| r == reason)
    {
        analysis.incomplete_reasons.push(reason.to_string());
    }
}

fn zip_reason(error: &OoxmlError) -> &'static str {
    match error {
        OoxmlError::TooManyEntries { .. } => "zip_entry_count_budget",
        OoxmlError::EntryNameTooLong { .. } => "zip_name_budget",
        OoxmlError::InflateBudgetExceeded { .. } => "zip_entry_budget",
        OoxmlError::InflateTotalBudgetExceeded { .. } => "zip_total_budget",
        OoxmlError::DecodeInputBudgetExceeded { .. } => "zip_decode_input_budget",
        OoxmlError::DecodeAttemptBudgetExceeded { .. } => "zip_decode_attempt_budget",
        OoxmlError::EncryptedEntry { .. } => "zip_encrypted_entry",
        OoxmlError::UnsupportedCompressionMethod { .. } => "zip_compression_unsupported",
        OoxmlError::UnsupportedFeature {
            feature: "multi_disk",
        } => "zip_multi_disk_unsupported",
        OoxmlError::UnsupportedFeature {
            feature: "data_descriptor",
        } => "zip_descriptor_unsupported",
        OoxmlError::UnsupportedFeature { .. } => "zip_feature_unsupported",
        _ => "zip_corrupt",
    }
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
        central_lies: BTreeMap<String, (Option<u32>, Option<u32>)>,
        encrypted: Vec<String>,
    }

    impl ZipBuilder {
        fn new() -> Self {
            ZipBuilder {
                entries: Vec::new(),
                central_lies: BTreeMap::new(),
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

    const CONTENT_TYPES_XML: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Default Extension=\"xml\" ContentType=\"application/xml\"/></Types>";

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
        let mut total = ZipReadBudget::default();
        let stored = archive.read_entry(archive.find("a.txt").expect("a"), &mut total);
        assert_eq!(stored.expect("stored"), b"hello");
        let deflated = archive.read_entry(archive.find("b.txt").expect("b"), &mut total);
        assert_eq!(
            deflated.expect("deflated"),
            b"deflate me deflate me deflate me"
        );
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
            archive.read_entry(entry, &mut ZipReadBudget::default()),
            Err(OoxmlError::EncryptedEntry {
                name: "secret.txt".to_string()
            })
        );
        let findings = analyze_package(&bytes).findings;
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
            archive.read_entry(entry, &mut ZipReadBudget::default()),
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
            archive.read_entry(entry, &mut ZipReadBudget::default()),
            Err(OoxmlError::InflateBudgetExceeded {
                claimed: 0x7FFF_FFFF,
                ..
            })
        ));
        let findings = analyze_package(&bytes).findings;
        assert!(findings.iter().any(|f| f.family == DOC_001_FAMILY
            && f.path == "bomb.bin"
            && f.detail.contains("inflate budget")));
    }

    #[test]
    fn lying_small_claim_cannot_overallocate() {
        // Claim 16 bytes; the actual deflate stream inflates to far more.
        // Local/central disagreement is rejected before decompression.
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
        assert!(matches!(
            archive.read_entry(entry, &mut ZipReadBudget::default()),
            Err(OoxmlError::LocalHeaderMismatch { .. })
        ));
    }

    #[test]
    fn clean_docx_produces_no_concealment_findings() {
        let bytes = docx("Hello world");
        let findings = analyze_package(&bytes).findings;
        assert!(findings.iter().any(|f| f.family == ZIP_TOPOLOGY_FAMILY));
        assert!(findings_with_family(&findings, DOC_001_FAMILY).is_empty());
        assert!(findings_with_family(&findings, DOC_002_FAMILY).is_empty());
    }

    #[test]
    fn laced_docx_document_xml_triggers_doc_002() {
        let laced = "Hello\u{200b}\u{200c}\u{200b}\u{200c}\u{200b}\u{200c}\u{200b}\u{200c}\u{200b}\u{200c}\u{200b}\u{200c} world";
        let bytes = docx(laced);
        let findings = analyze_package(&bytes).findings;
        let doc002 = findings_with_family(&findings, DOC_002_FAMILY);
        assert_eq!(doc002.len(), 1);
        assert!(doc002[0].detail.contains("ZERO_WIDTH"));
        assert_eq!(doc002[0].path, WORD_DOCUMENT);
    }

    #[test]
    fn whitespace_run_in_text_node_triggers_doc_002() {
        let spaced = format!("Hello{}", " ".repeat(12));
        let bytes = docx(&spaced);
        let findings = analyze_package(&bytes).findings;
        let doc002 = findings_with_family(&findings, DOC_002_FAMILY);
        // The unicode_text WHITESPACE_ANOMALY channel and the XML text-node
        // run detector can both fire for the same run; require the
        // text-node run evidence specifically.
        assert!(doc002.iter().any(|f| f.detail.contains("whitespace runs")));
    }

    /// Minimal pptx fixture: content types, presentation, one slide and one
    /// notes slide with the given text bodies.
    fn pptx(slide_text: &str, notes_text: Option<&str>, presentation: Option<&str>) -> Vec<u8> {
        let mut builder = ZipBuilder::new()
            .add_stored(CONTENT_TYPES, CONTENT_TYPES_XML.as_bytes())
            .add_stored(
                PPT_PRESENTATION,
                presentation.unwrap_or("<p:presentation/>").as_bytes(),
            )
            .add_stored(
                "ppt/slides/slide1.xml",
                format!("<p:sld><p:cSld><p:spTree><p:sp><p:txBody><a:p><a:t>{slide_text}</a:t></a:p></p:txBody></p:sp></p:spTree></p:cSld></p:sld>").as_bytes(),
            );
        if let Some(notes) = notes_text {
            builder = builder.add_stored(
                "ppt/notesSlides/notesSlide1.xml",
                format!("<p:notes><a:p><a:t>{notes}</a:t></a:p></p:notes>").as_bytes(),
            );
        }
        builder.build()
    }

    /// Minimal xlsx fixture: content types, workbook, sharedStrings, one
    /// worksheet with the given text body.
    fn xlsx(shared_text: &str, sheet_text: &str) -> Vec<u8> {
        ZipBuilder::new()
            .add_stored(CONTENT_TYPES, CONTENT_TYPES_XML.as_bytes())
            .add_stored(XL_WORKBOOK, b"<workbook/>")
            .add_stored(
                "xl/sharedStrings.xml",
                format!("<sst><si><t>{shared_text}</t></si></sst>").as_bytes(),
            )
            .add_stored(
                "xl/worksheets/sheet1.xml",
                format!("<worksheet><is><t>{sheet_text}</t></is></worksheet>").as_bytes(),
            )
            .build()
    }

    #[test]
    fn clean_pptx_and_xlsx_produce_no_extended_findings() {
        let findings = analyze_package(&pptx("Hello", None, None)).findings;
        assert!(findings_with_family(&findings, DOC_003_FAMILY).is_empty());
        assert!(findings_with_family(&findings, DOC_002_FAMILY).is_empty());

        let findings = analyze_package(&xlsx("Shared text", "Sheet text")).findings;
        assert!(findings_with_family(&findings, DOC_003_FAMILY).is_empty());
        assert!(findings_with_family(&findings, DOC_002_FAMILY).is_empty());
    }

    #[test]
    fn laced_pptx_slide_triggers_doc_003() {
        let laced = "Hello\u{200b}\u{200c}\u{200b}\u{200c}\u{200b}\u{200c}\u{200b}\u{200c}\u{200b}\u{200c}\u{200b}\u{200c} world";
        let findings = analyze_package(&pptx(laced, None, None)).findings;
        let doc003 = findings_with_family(&findings, DOC_003_FAMILY);
        assert_eq!(doc003.len(), 1);
        assert!(doc003[0].detail.contains("ZERO_WIDTH"));
        assert_eq!(doc003[0].path, "ppt/slides/slide1.xml");
    }

    #[test]
    fn laced_pptx_notes_trigger_doc_003() {
        let laced = "Note\u{200b}\u{200c}\u{200b}\u{200c}\u{200b}\u{200c}\u{200b}\u{200c}\u{200b}\u{200c}\u{200b}\u{200c} text";
        let findings = analyze_package(&pptx("Clean", Some(laced), None)).findings;
        let doc003 = findings_with_family(&findings, DOC_003_FAMILY);
        assert_eq!(doc003.len(), 1);
        assert_eq!(doc003[0].path, "ppt/notesSlides/notesSlide1.xml");
    }

    #[test]
    fn presentation_placeholder_markup_is_reported() {
        let presentation = "<p:presentation xmlns:p=\"http://schemas.openxmlformats.org/presentationml/2006/main\"><p:hf ftr=\"1\" sldNum=\"1\"/></p:presentation>";
        let findings = analyze_package(&pptx("Clean", None, Some(presentation))).findings;
        let doc003 = findings_with_family(&findings, DOC_003_FAMILY);
        assert_eq!(doc003.len(), 1);
        assert_eq!(doc003[0].path, PPT_PRESENTATION);
        assert!(doc003[0].detail.contains("placeholder"));
    }

    #[test]
    fn laced_xlsx_shared_strings_trigger_doc_003() {
        let laced = "Shared\u{200b}\u{200c}\u{200b}\u{200c}\u{200b}\u{200c}\u{200b}\u{200c}\u{200b}\u{200c}\u{200b}\u{200c} text";
        let findings = analyze_package(&xlsx(laced, "Clean")).findings;
        let doc003 = findings_with_family(&findings, DOC_003_FAMILY);
        assert_eq!(doc003.len(), 1);
        assert!(doc003[0].detail.contains("ZERO_WIDTH"));
        assert_eq!(doc003[0].path, "xl/sharedStrings.xml");
    }

    #[test]
    fn laced_xlsx_sheet_triggers_doc_003() {
        let laced = "Cell\u{200b}\u{200c}\u{200b}\u{200c}\u{200b}\u{200c}\u{200b}\u{200c}\u{200b}\u{200c}\u{200b}\u{200c} text";
        let findings = analyze_package(&xlsx("Clean", laced)).findings;
        let doc003 = findings_with_family(&findings, DOC_003_FAMILY);
        assert_eq!(doc003.len(), 1);
        assert_eq!(doc003[0].path, "xl/worksheets/sheet1.xml");
    }

    #[test]
    fn laced_docx_header_triggers_doc_003() {
        let laced = "Header\u{200b}\u{200c}\u{200b}\u{200c}\u{200b}\u{200c}\u{200b}\u{200c}\u{200b}\u{200c}\u{200b}\u{200c} text";
        let bytes = ZipBuilder::new()
            .add_stored(CONTENT_TYPES, CONTENT_TYPES_XML.as_bytes())
            .add_stored(WORD_DOCUMENT, document_xml("Clean body").as_bytes())
            .add_stored(
                "word/header1.xml",
                format!("<w:hdr><w:p><w:r><w:t>{laced}</w:t></w:r></w:p></w:hdr>").as_bytes(),
            )
            .build();
        let findings = analyze_package(&bytes).findings;
        let doc003 = findings_with_family(&findings, DOC_003_FAMILY);
        assert_eq!(doc003.len(), 1);
        assert!(doc003[0].detail.contains("ZERO_WIDTH"));
        assert_eq!(doc003[0].path, "word/header1.xml");
        // The clean main part stays quiet on DOC-002.
        assert!(findings_with_family(&findings, DOC_002_FAMILY).is_empty());
    }

    #[test]
    fn media_entry_with_executable_extension_is_flagged() {
        let bytes = ZipBuilder::new()
            .add_stored(CONTENT_TYPES, CONTENT_TYPES_XML.as_bytes())
            .add_stored(WORD_DOCUMENT, document_xml("ok").as_bytes())
            .add_stored("word/media/dropper.exe", b"MZ binary")
            .build();
        let findings = analyze_package(&bytes).findings;
        assert!(findings.iter().any(|f| f.family == DOC_003_FAMILY
            && f.path == "word/media/dropper.exe"
            && f.detail.contains("executable/script extension")));
    }

    #[test]
    fn media_entry_with_unknown_extension_is_flagged() {
        let bytes = ZipBuilder::new()
            .add_stored(CONTENT_TYPES, CONTENT_TYPES_XML.as_bytes())
            .add_stored(PPT_PRESENTATION, b"<p:presentation/>")
            .add_stored("ppt/media/blob.dat", b"opaque bytes")
            .build();
        let findings = analyze_package(&bytes).findings;
        assert!(findings.iter().any(|f| f.family == DOC_003_FAMILY
            && f.path == "ppt/media/blob.dat"
            && f.detail.contains("unrecognized media extension")));
    }

    #[test]
    fn oversized_slide_claim_is_skipped_without_panic() {
        // A slide claiming a huge uncompressed size is DOC-001 evidence and
        // must not be inflated by the extended-part pass.
        let bytes = ZipBuilder::new()
            .add_stored(CONTENT_TYPES, CONTENT_TYPES_XML.as_bytes())
            .add_stored(PPT_PRESENTATION, b"<p:presentation/>")
            .add_deflated("ppt/slides/slide1.xml", b"tiny")
            .lie_sizes("ppt/slides/slide1.xml", None, Some(0x7FFF_FFFF))
            .build();
        let findings = analyze_package(&bytes).findings;
        assert!(findings.iter().any(|f| f.family == DOC_001_FAMILY
            && f.path == "ppt/slides/slide1.xml"
            && f.detail.contains("inflate budget")));
        assert!(findings_with_family(&findings, DOC_003_FAMILY).is_empty());
    }

    #[test]
    fn generic_zip_gets_inventory_finding_only() {
        let bytes = ZipBuilder::new()
            .add_stored("notes/readme.txt", b"plain notes")
            .build();
        let findings = analyze_package(&bytes).findings;
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
        let findings = analyze_package(&bytes).findings;
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
        let findings = analyze_package(&bytes).findings;
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
        let findings = analyze_package(&bytes).findings;
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
            archive.read_entry(entry, &mut ZipReadBudget::default()),
            Err(OoxmlError::LocalHeaderMismatch { .. })
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
    #[test]
    fn eocd_signatures_in_comments_are_data_not_headers() {
        // Exact valid 26-byte crash reproducer from F01.
        let mut exact = b"PK\x05\x06".to_vec();
        exact.extend_from_slice(&[0; 16]);
        exact.extend_from_slice(b"\x04\x00PK\x05\x06");
        assert_eq!(exact.len(), 26);
        assert!(ZipArchive::parse(&exact).unwrap().entries().is_empty());
        let result = analyze_package(&exact);
        assert!(!result.detected);
        assert!(result.incomplete_reasons.is_empty());
        assert!(!crate::forensics::scan_bytes(&exact).detected);
        for trailing in 0..21 {
            let mut bytes = ZipBuilder::new().build();
            bytes[20..22].copy_from_slice(&((4 + trailing) as u16).to_le_bytes());
            bytes.extend_from_slice(b"PK\x05\x06");
            bytes.extend(std::iter::repeat_n(0, trailing));
            assert!(ZipArchive::parse(&bytes).is_ok());
        }
    }

    #[test]
    fn split_and_descriptor_archives_are_typed_unsupported() {
        let mut bytes = ZipBuilder::new().build();
        bytes[4..6].copy_from_slice(&1u16.to_le_bytes());
        bytes[6..8].copy_from_slice(&1u16.to_le_bytes());
        assert!(matches!(
            ZipArchive::parse(&bytes),
            Err(OoxmlError::UnsupportedFeature {
                feature: "multi_disk"
            })
        ));
        assert_eq!(
            analyze_package(&bytes).incomplete_reasons,
            ["zip_multi_disk_unsupported"]
        );
        let mut bytes = ZipBuilder::new().add_stored("x", b"x").build();
        let cd = read_u32(&bytes, bytes.len() - 6) as usize;
        bytes[cd + 8..cd + 10].copy_from_slice(&8u16.to_le_bytes());
        assert!(matches!(
            ZipArchive::parse(&bytes),
            Err(OoxmlError::UnsupportedFeature {
                feature: "data_descriptor"
            })
        ));
    }

    #[test]
    fn huge_local_offsets_and_local_central_disagreements_reject() {
        let base = ZipBuilder::new().add_stored("x", b"data").build();
        let cd = read_u32(&base, base.len() - 6) as usize;
        let mut huge = base.clone();
        huge[cd + 42..cd + 46].copy_from_slice(&0xffff_fff0u32.to_le_bytes());
        let archive = ZipArchive::parse(&huge).unwrap();
        assert!(matches!(
            archive.read_entry(&archive.entries()[0], &mut ZipReadBudget::default()),
            Err(OoxmlError::LocalHeaderCorrupt { .. })
        ));
        for field in [6, 8, 14, 18, 22, 30] {
            let mut bytes = base.clone();
            bytes[field] ^= 1;
            let archive = ZipArchive::parse(&bytes).unwrap();
            assert!(matches!(
                archive.read_entry(&archive.entries()[0], &mut ZipReadBudget::default()),
                Err(OoxmlError::LocalHeaderMismatch { .. })
            ));
        }
        let mut bytes = base;
        bytes[31] ^= 1; // content corruption, not header corruption
        let archive = ZipArchive::parse(&bytes).unwrap();
        assert!(matches!(
            archive.read_entry(&archive.entries()[0], &mut ZipReadBudget::default()),
            Err(OoxmlError::ChecksumMismatch { .. })
        ));
    }

    #[test]
    fn deflate_requires_exact_size_and_stream_completion_even_for_zero_claim() {
        for claimed in [0, 16] {
            let mut bytes = ZipBuilder::new()
                .add_deflated("x", &[b'A'; 65536])
                .lie_sizes("x", None, Some(claimed))
                .build();
            // Make local and central agree: the decompressor must reject the lie.
            bytes[22..26].copy_from_slice(&claimed.to_le_bytes());
            let archive = ZipArchive::parse(&bytes).unwrap();
            assert!(matches!(
                archive.read_entry(&archive.entries()[0], &mut ZipReadBudget::default()),
                Err(OoxmlError::InflateSizeMismatch { .. })
            ));
        }
        assert!(matches!(
            inflate_raw(&[], "x", 0),
            Err(OoxmlError::InflateFailed { .. })
        ));
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(b"complete").unwrap();
        let raw = encoder.finish().unwrap();
        assert_eq!(inflate_raw(&raw, "x", 8).unwrap(), b"complete");
        assert!(inflate_raw(&raw[..raw.len() - 1], "x", 8).is_err());
        let mut extra = raw;
        extra.push(0);
        assert!(inflate_raw(&extra, "x", 8).is_err());
    }

    #[test]
    fn stored_and_deflated_entry_and_total_budgets_match() {
        let data = vec![b'A'; CONTAINER_MAX_INFLATE_PER_ENTRY + 1];
        for deflated in [false, true] {
            let builder = ZipBuilder::new();
            let bytes = if deflated {
                builder.add_deflated("x", &data)
            } else {
                builder.add_stored("x", &data)
            }
            .build();
            let archive = ZipArchive::parse(&bytes).unwrap();
            assert!(matches!(
                archive.read_entry(&archive.entries()[0], &mut ZipReadBudget::default()),
                Err(OoxmlError::InflateBudgetExceeded { .. })
            ));
            let data = &data[..CONTAINER_MAX_INFLATE_PER_ENTRY];
            let mut builder = ZipBuilder::new();
            for name in ["x", "y", "z"] {
                builder = if deflated {
                    builder.add_deflated(name, data)
                } else {
                    builder.add_stored(name, data)
                };
            }
            let bytes = builder.build();
            let archive = ZipArchive::parse(&bytes).unwrap();
            let mut total = ZipReadBudget::default();
            for entry in &archive.entries()[..2] {
                archive.read_entry(entry, &mut total).unwrap();
            }
            assert!(matches!(
                archive.read_entry(&archive.entries()[2], &mut total),
                Err(OoxmlError::InflateTotalBudgetExceeded { .. })
            ));
            assert_eq!(total.output, CONTAINER_MAX_INFLATE_TOTAL);
            let mut overflowing_total = ZipReadBudget {
                output: usize::MAX,
                ..Default::default()
            };
            assert!(matches!(
                archive.read_entry(&archive.entries()[0], &mut overflowing_total),
                Err(OoxmlError::InflateTotalBudgetExceeded { .. })
            ));
        }
    }

    #[test]
    fn main_and_extended_parts_share_the_package_budget() {
        let xml = format!("<r>{}</r>", "x".repeat(CONTAINER_MAX_INFLATE_PER_ENTRY - 7));
        for deflated in [false, true] {
            let mut builder =
                ZipBuilder::new().add_stored(CONTENT_TYPES, CONTENT_TYPES_XML.as_bytes());
            for name in [WORD_DOCUMENT, "word/header1.xml", "word/footer1.xml"] {
                builder = if deflated {
                    builder.add_deflated(name, xml.as_bytes())
                } else {
                    builder.add_stored(name, xml.as_bytes())
                };
            }
            let result = analyze_package(&builder.build());
            assert!(result
                .incomplete_reasons
                .iter()
                .any(|r| r == "zip_total_budget"));
            assert!(result
                .incomplete_reasons
                .iter()
                .any(|r| r == "xml_text_budget"));
            assert!(!result.detected);
        }
    }

    #[test]
    fn xml_literal_reference_cdata_and_utf16_channels_agree() {
        for body in [
            "A\u{200b}B",
            "A&#x200B;B",
            "A&#8203;B",
            "<![CDATA[A\u{200b}B]]>",
        ] {
            let result = analyze_package(&docx(body));
            assert!(result.detected);
            assert!(result.incomplete_reasons.is_empty());
            assert!(result.findings.iter().any(|f| f.family == DOC_002_FAMILY
                && f.detail.contains("ZERO_WIDTH")
                && f.detail.contains("offsets 1")));
        }
        for little in [false, true] {
            let xml = "<?xml version=\"1.0\" encoding=\"UTF-16\"?><r>A&#x200B;B</r>";
            let mut bytes = if little {
                vec![0xff, 0xfe]
            } else {
                vec![0xfe, 0xff]
            };
            for unit in xml.encode_utf16() {
                bytes.extend_from_slice(&if little {
                    unit.to_le_bytes()
                } else {
                    unit.to_be_bytes()
                });
            }
            let package = ZipBuilder::new()
                .add_stored(CONTENT_TYPES, CONTENT_TYPES_XML.as_bytes())
                .add_stored(WORD_DOCUMENT, &bytes)
                .build();
            let result = analyze_package(&package);
            assert!(result.detected);
            assert!(result.incomplete_reasons.is_empty());
        }
        for body in ["A&amp;B", "A&lt;B", "A&gt;B", "A&apos;B", "A&quot;B"] {
            assert!(!analyze_package(&docx(body)).detected);
        }
    }

    #[test]
    fn xml_spaces_offsets_and_unsupported_syntax_are_honest() {
        for body in ["é        B", "é        "] {
            let result = analyze_package(&docx(body));
            assert!(result
                .findings
                .iter()
                .any(|f| f.detail.contains("whitespace runs") && f.detail.contains("offset 1")));
        }
        for (xml, reason) in [
            (
                "<!DOCTYPE r [<!ENTITY x SYSTEM 'file:///secret'>]><r>&x;</r>",
                "xml_dtd_unsupported",
            ),
            ("<r>&undefined;</r>", "xml_entity_unsupported"),
            ("<r>&#xD800;</r>", "xml_reference_invalid"),
            ("<r><s></r>", "xml_structure_invalid"),
            (
                "<?xml version='1.0' encoding='ISO-8859-1'?><r/>",
                "xml_encoding_unsupported",
            ),
        ] {
            let package = ZipBuilder::new()
                .add_stored(CONTENT_TYPES, CONTENT_TYPES_XML.as_bytes())
                .add_stored(WORD_DOCUMENT, xml.as_bytes())
                .build();
            let result = analyze_package(&package);
            assert!(!result.detected);
            assert!(result.incomplete_reasons.iter().any(|r| r == reason));
        }
    }

    #[test]
    fn duplicate_main_parts_are_all_examined_and_positive_survives_finding_cap() {
        let duplicate = ZipBuilder::new()
            .add_stored(CONTENT_TYPES, CONTENT_TYPES_XML.as_bytes())
            .add_stored(WORD_DOCUMENT, b"<r>clean</r>")
            .add_stored(WORD_DOCUMENT, "<r>A\u{200b}B</r>".as_bytes())
            .build();
        let result = analyze_package(&duplicate);
        assert!(result.detected);
        assert!(result
            .incomplete_reasons
            .iter()
            .any(|r| r == "zip_duplicate_name"));
        for observations in [62, 63, 64, 65] {
            let mut builder = ZipBuilder::new()
                .add_stored(CONTENT_TYPES, CONTENT_TYPES_XML.as_bytes())
                .add_deflated(WORD_DOCUMENT, "<r>A\u{200b}B</r>".as_bytes());
            for i in 0..observations {
                builder = builder.add_stored(&format!("word/media/{i}.txt"), b"");
            }
            let result = analyze_package(&builder.build());
            assert!(result.detected);
            assert!(result.findings.len() <= CONTAINER_MAX_FINDINGS);
            if observations >= 63 {
                assert!(result
                    .incomplete_reasons
                    .iter()
                    .any(|r| r == "zip_finding_budget"));
                assert!(result.findings.last().unwrap().detail.contains("positive"));
            }
        }
    }
    #[test]
    fn attribute_references_preserve_existing_unicode_channel_coverage() {
        for value in ["A\u{200b}B", "A&#x200B;B", "A&#8203;B"] {
            let xml = format!("<r hidden='{value}'>visible</r>");
            let package = ZipBuilder::new()
                .add_stored(CONTENT_TYPES, CONTENT_TYPES_XML.as_bytes())
                .add_stored(WORD_DOCUMENT, xml.as_bytes())
                .build();
            let result = analyze_package(&package);
            assert!(result.detected);
            assert!(result.incomplete_reasons.is_empty());
            assert!(result
                .findings
                .iter()
                .any(|f| f.detail.contains("XML attribute values")
                    && f.detail.contains("ZERO_WIDTH")));
        }
    }

    #[test]
    fn corrupt_read_attempts_consume_the_shared_output_reservation() {
        let data = vec![b'x'; CONTAINER_MAX_INFLATE_PER_ENTRY];
        let mut bytes = ZipBuilder::new().add_stored("x", &data).build();
        bytes[31] ^= 1;
        let archive = ZipArchive::parse(&bytes).unwrap();
        let mut total = ZipReadBudget::default();
        for _ in 0..2 {
            assert!(matches!(
                archive.read_entry(&archive.entries()[0], &mut total),
                Err(OoxmlError::ChecksumMismatch { .. })
            ));
        }
        assert!(matches!(
            archive.read_entry(&archive.entries()[0], &mut total),
            Err(OoxmlError::InflateTotalBudgetExceeded { .. })
        ));
    }
    #[test]
    fn complete_fake_eocd_in_a_comment_cannot_erase_the_real_document() {
        let mut bytes = docx("A\u{200b}B");
        let end = bytes.len();
        bytes[end - 2..end].copy_from_slice(&22u16.to_le_bytes());
        bytes.extend_from_slice(b"PK\x05\x06");
        bytes.extend_from_slice(&[0; 18]);
        let result = analyze_package(&bytes);
        assert!(result.detected);
        assert!(result.incomplete_reasons.is_empty());
    }

    #[test]
    fn exact_decoded_text_cap_is_complete_but_a_later_character_is_partial() {
        for extra in [0, 1] {
            let text = "x".repeat(unicode_text::MAX_TEXT_SCAN_BYTES + extra);
            let result = analyze_package(&docx(&text));
            assert!(!result.detected);
            assert_eq!(
                result
                    .incomplete_reasons
                    .iter()
                    .any(|r| r == "xml_text_budget"),
                extra != 0
            );
        }
    }

    fn aliased_empty_document(raw: &[u8], copies: usize) -> Vec<u8> {
        let mut builder = ZipBuilder::new()
            .add_stored(CONTENT_TYPES, CONTENT_TYPES_XML.as_bytes())
            .add_deflated(WORD_DOCUMENT, b"");
        builder.entries[1].compressed = raw.to_vec();
        let mut bytes = builder.build();
        let eocd = bytes.len() - 22;
        let central = read_u32(&bytes, eocd + 16) as usize;
        let record_start = central + 46 + CONTENT_TYPES.len();
        let record = bytes[record_start..eocd].to_vec();
        let extra = record.repeat(copies - 1);
        let size = read_u32(&bytes, eocd + 12) + extra.len() as u32;
        bytes.splice(eocd..eocd, extra);
        let eocd = bytes.len() - 22;
        bytes[eocd + 8..eocd + 10].copy_from_slice(&((copies + 1) as u16).to_le_bytes());
        bytes[eocd + 10..eocd + 12].copy_from_slice(&((copies + 1) as u16).to_le_bytes());
        bytes[eocd + 12..eocd + 16].copy_from_slice(&size.to_le_bytes());
        bytes
    }

    #[test]
    fn aliased_zero_output_streams_reserve_compressed_input_before_each_decode() {
        // Byte-aligned empty stored DEFLATE blocks: valid, nontrivial input,
        // exactly zero output. All central records reference one local range.
        let mut raw = [0, 0, 0, 255, 255].repeat(209_715);
        let last = raw.len() - 5;
        raw[last] = 1;
        let copies = CONTAINER_MAX_DECODE_INPUT_TOTAL / raw.len();
        let bytes = aliased_empty_document(&raw, copies + 1);
        let archive = ZipArchive::parse(&bytes).unwrap();
        let mut budget = ZipReadBudget::default();
        for entry in &archive.entries()[1..=copies] {
            assert_eq!(archive.read_entry(entry, &mut budget).unwrap(), b"");
        }
        assert_eq!(budget.output, 0);
        assert_eq!(budget.input, copies * raw.len());
        assert_eq!(budget.attempts, copies);
        assert!(matches!(
            archive.read_entry(&archive.entries()[copies + 1], &mut budget),
            Err(OoxmlError::DecodeInputBudgetExceeded { .. })
        ));
        assert_eq!(budget.attempts, copies);
        let result = analyze_package(&bytes);
        assert!(result
            .incomplete_reasons
            .iter()
            .any(|r| r == "zip_decode_input_budget"));
        assert!(!result.detected);
        assert!(crate::forensics::scan_bytes(&bytes).incomplete);
    }

    #[test]
    fn decode_attempt_budget_includes_zero_output_and_corrupt_aliases() {
        for raw in [&[3, 0][..], &[255][..]] {
            let bytes = aliased_empty_document(raw, CONTAINER_MAX_DECODE_ATTEMPTS + 1);
            let archive = ZipArchive::parse(&bytes).unwrap();
            let mut budget = ZipReadBudget::default();
            for entry in &archive.entries()[1..=CONTAINER_MAX_DECODE_ATTEMPTS] {
                let decoded = archive.read_entry(entry, &mut budget);
                if raw == b"\x03\x00" {
                    assert!(decoded.unwrap().is_empty());
                } else {
                    assert!(matches!(decoded, Err(OoxmlError::InflateFailed { .. })));
                }
            }
            assert_eq!(budget.output, 0);
            assert_eq!(budget.input, raw.len() * CONTAINER_MAX_DECODE_ATTEMPTS);
            assert_eq!(budget.attempts, CONTAINER_MAX_DECODE_ATTEMPTS);
            assert!(matches!(
                archive.read_entry(archive.entries().last().unwrap(), &mut budget),
                Err(OoxmlError::DecodeAttemptBudgetExceeded { .. })
            ));
            let result = analyze_package(&bytes);
            assert!(result
                .incomplete_reasons
                .iter()
                .any(|r| r == "zip_decode_attempt_budget"));
        }
    }

    #[test]
    fn input_reservation_exact_boundary_and_oversized_first_attempt() {
        let bytes = aliased_empty_document(&[255], 1);
        let archive = ZipArchive::parse(&bytes).unwrap();
        let entry = &archive.entries()[1];
        let mut budget = ZipReadBudget {
            input: CONTAINER_MAX_DECODE_INPUT_TOTAL - 1,
            ..Default::default()
        };
        assert!(matches!(
            archive.read_entry(entry, &mut budget),
            Err(OoxmlError::InflateFailed { .. })
        ));
        assert_eq!(budget.input, CONTAINER_MAX_DECODE_INPUT_TOTAL);
        assert!(matches!(
            archive.read_entry(entry, &mut budget),
            Err(OoxmlError::DecodeInputBudgetExceeded { .. })
        ));
        let mut oversized = entry.clone();
        oversized.compressed_size = CONTAINER_MAX_DECODE_INPUT_TOTAL + 1;
        let mut budget = ZipReadBudget::default();
        assert!(matches!(
            archive.read_entry(&oversized, &mut budget),
            Err(OoxmlError::DecodeInputBudgetExceeded { .. })
        ));
        assert_eq!(budget.attempts, 0);
    }

    #[test]
    fn presentation_placeholders_follow_elements_attributes_and_namespace_scope() {
        const NS: &str = "http://schemas.openxmlformats.org/presentationml/2006/main";
        for marker in [
            "<q:ph type='ftr'/>",
            "<q:ph other='x' type = 'h&#100;r'/>",
            "<q:ph type=\"dt\"/>",
            "<q:ph type='sldNum'/>",
            "<q:hf/>",
            "<hf xmlns='http://schemas.openxmlformats.org/presentationml/2006/main'/>",
            "<s:hf xmlns:s='http://purl.oclc.org/ooxml/presentationml/main'/>",
            "<q:ph type='ftr' xmlns:q='http://schemas.openxmlformats.org/presentationml/2006/main'/>",
        ] {
            let xml = format!("<q:presentation xmlns:q='{NS}'>{marker}</q:presentation>");
            let result = analyze_package(&pptx("Clean", None, Some(&xml)));
            assert!(result.findings.iter().any(|f| f.path == PPT_PRESENTATION && f.family == DOC_003_FAMILY), "{marker}: {:?}", result);
            assert!(result.incomplete_reasons.is_empty(), "{marker}: {:?}", result);
        }
        for marker in [
            "<!-- <q:hf ftr='1'/> -->",
            "<![CDATA[<q:ph type='ftr'/>]]>",
            "<q:ph type='body'/>",
            "<q:ph q:type='ftr'/>",
            "<q:hf xmlns:q='urn:not-presentation'/>",
            "<other xmlns:q='urn:not-presentation'><q:hf/></other>",
            "<q:ph type='ftr extra'/>",
            "<x:hf xmlns:x='urn:foreign'/>",
        ] {
            let xml = format!("<q:presentation xmlns:q='{NS}'>{marker}</q:presentation>");
            let result = analyze_package(&pptx("Clean", None, Some(&xml)));
            assert!(!result.detected, "{marker}: {:?}", result);
            assert!(
                result.incomplete_reasons.is_empty(),
                "{marker}: {:?}",
                result
            );
        }
        let xml = format!(
            "<q:presentation xmlns:q='{NS}'><x xmlns:q='urn:foreign'/><q:hf/></q:presentation>"
        );
        assert!(analyze_package(&pptx("Clean", None, Some(&xml))).detected);
        let xml = format!("<q:presentation xmlns:q='{NS}'><q:hf></q:presentation>");
        let result = analyze_package(&pptx("Clean", None, Some(&xml)));
        assert!(!result.detected);
        assert!(result
            .incomplete_reasons
            .iter()
            .any(|r| r == "xml_structure_invalid"));
        let result = analyze_package(&pptx(
            "Clean",
            None,
            Some("<p:presentation><p:hf/></p:presentation>"),
        ));
        assert!(!result.detected);
        assert!(result
            .incomplete_reasons
            .iter()
            .any(|r| r == "xml_namespace_unsupported"));
    }

    #[test]
    fn duplicate_presentations_and_utf16_placeholders_are_examined() {
        let xml = "<p:presentation xmlns:p='http://schemas.openxmlformats.org/presentationml/2006/main'><p:ph type='ftr'/></p:presentation>";
        let mut utf16 = vec![255, 254];
        for unit in xml.encode_utf16() {
            utf16.extend_from_slice(&unit.to_le_bytes());
        }
        let bytes = ZipBuilder::new()
            .add_stored(CONTENT_TYPES, CONTENT_TYPES_XML.as_bytes())
            .add_stored(PPT_PRESENTATION, b"<presentation/>")
            .add_deflated(PPT_PRESENTATION, &utf16)
            .build();
        let result = analyze_package(&bytes);
        assert!(result.detected);
        assert!(result
            .incomplete_reasons
            .iter()
            .any(|reason| reason == "zip_duplicate_name"));
        assert!(result
            .findings
            .iter()
            .any(|f| f.path == PPT_PRESENTATION && f.family == DOC_003_FAMILY));
    }

    #[test]
    fn decode_attempt_exhaustion_preserves_earlier_positive_and_shared_coverage() {
        let mut builder = ZipBuilder::new()
            .add_stored(CONTENT_TYPES, CONTENT_TYPES_XML.as_bytes())
            .add_deflated(WORD_DOCUMENT, document_xml("A\u{200b}B").as_bytes());
        for _ in 0..CONTAINER_MAX_DECODE_ATTEMPTS {
            builder = builder.add_deflated("word/header1.xml", b"<r/>");
        }
        let result = analyze_package(&builder.build());
        assert!(result.detected);
        assert!(result
            .incomplete_reasons
            .iter()
            .any(|r| r == "zip_decode_attempt_budget"));
    }
}
