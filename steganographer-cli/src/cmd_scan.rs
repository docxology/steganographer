//! `steganographer scan` — bounded forensic scan of files and directories.
//!
//! Runs the structural detectors in [`steganographer_core::forensics`] plus the
//! statistical detectors in [`steganographer_core::steganalysis`] over one file
//! or a directory tree, and emits deterministic machine-readable findings.

use std::io::Read;
use std::path::Path;

use serde::Serialize;
use steganographer_core::forensics;

/// One scanned file's forensic verdict.
#[derive(Debug, Serialize)]
struct ScanFinding {
    file: String,
    size: usize,
    /// `true` when only the first `max_bytes` bytes were examined.
    truncated: bool,
    detected: bool,
    entropy: f64,
    file_family: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    embedded_magic: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    magic_offsets: Vec<usize>,
    statistical_detected: bool,
    statistical_confidence: f64,
    message: String,
}

/// Aggregate totals for the run.
#[derive(Debug, Serialize)]
struct ScanSummary {
    files_scanned: usize,
    findings: usize,
    errors: usize,
}

impl ScanFinding {
    fn from_scan(path: &Path, size: usize, truncated: bool, scan: forensics::ForensicScan) -> Self {
        let magic_offsets = scan.magic_matches.iter().map(|m| m.offset).collect();
        ScanFinding {
            file: path.display().to_string(),
            size,
            truncated,
            detected: scan.detected,
            entropy: scan.entropy,
            file_family: scan.file_family.as_str().to_string(),
            embedded_magic: scan.embedded_magic.map(|m| m.as_str().to_string()),
            magic_offsets,
            statistical_detected: scan.statistical.detected,
            statistical_confidence: scan.statistical.confidence,
            message: scan.message,
        }
    }
}

/// Read at most `max_bytes` from a file, reporting the true size and whether
/// the buffer was truncated.
fn read_bounded(path: &Path, max_bytes: usize) -> std::io::Result<(Vec<u8>, usize, bool)> {
    let file = std::fs::File::open(path)?;
    let total = file.metadata()?.len() as usize;
    let mut reader = file.take(max_bytes as u64);
    let mut data = Vec::with_capacity(max_bytes.min(total));
    reader.read_to_end(&mut data)?;
    let truncated = total > data.len();
    Ok((data, total, truncated))
}

fn scan_one(path: &Path, max_bytes: usize) -> anyhow::Result<ScanFinding> {
    let (data, size, truncated) = read_bounded(path, max_bytes)?;
    let scan = forensics::scan_bytes(&data);
    Ok(ScanFinding::from_scan(path, size, truncated, scan))
}

#[allow(clippy::too_many_arguments)] // internal CLI orchestration entry
/// Bounded, non-following directory walk.
fn walk(
    dir: &Path,
    depth: u32,
    max_depth: u32,
    max_files: usize,
    max_bytes: usize,
    files_scanned: &mut usize,
    findings: &mut Vec<ScanFinding>,
    errors: &mut Vec<String>,
) {
    if depth > max_depth || *files_scanned >= max_files {
        return;
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) => {
            errors.push(format!("{}: {error}", dir.display()));
            return;
        }
    };
    for entry in entries.flatten() {
        if *files_scanned >= max_files {
            return;
        }
        let path = entry.path();
        // `file_type` does not follow symlinks, so links and special files are
        // skipped rather than opened.
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(_) => continue,
        };
        if file_type.is_dir() {
            walk(
                &path,
                depth + 1,
                max_depth,
                max_files,
                max_bytes,
                files_scanned,
                findings,
                errors,
            );
        } else if file_type.is_file() {
            *files_scanned += 1;
            match scan_one(&path, max_bytes) {
                Ok(finding) => {
                    if finding.detected {
                        findings.push(finding);
                    }
                }
                Err(error) => errors.push(format!("{}: {error}", path.display())),
            }
        }
    }
}

/// Run the scan and return the process exit code: `0` clean, `1` findings.
///
/// Errors during the scan are collected into the report and do not abort the
/// run; only argument/usage errors return `Err`.
pub fn run(
    input: &str,
    max_depth: u32,
    max_files: usize,
    max_bytes: usize,
    format: &str,
) -> anyhow::Result<i32> {
    let path = Path::new(input);
    let metadata = std::fs::metadata(path)
        .map_err(|error| anyhow::anyhow!("cannot access '{input}': {error}"))?;

    let mut findings: Vec<ScanFinding> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    let mut files_scanned = 0usize;

    if metadata.is_file() {
        files_scanned = 1;
        match scan_one(path, max_bytes) {
            Ok(finding) => {
                if finding.detected {
                    findings.push(finding);
                }
            }
            Err(error) => errors.push(format!("{input}: {error}")),
        }
    } else if metadata.is_dir() {
        walk(
            path,
            0,
            max_depth,
            max_files,
            max_bytes,
            &mut files_scanned,
            &mut findings,
            &mut errors,
        );
    } else {
        anyhow::bail!("'{input}' is not a regular file or directory");
    }

    emit(format, &findings, &errors, files_scanned)?;
    Ok(if findings.is_empty() { 0 } else { 1 })
}

fn emit(
    format: &str,
    findings: &[ScanFinding],
    errors: &[String],
    files_scanned: usize,
) -> anyhow::Result<()> {
    let summary = ScanSummary {
        files_scanned,
        findings: findings.len(),
        errors: errors.len(),
    };
    match format {
        "jsonl" => {
            for finding in findings {
                println!("{}", serde_json::to_string(finding)?);
            }
            for error in errors {
                println!(
                    "{}",
                    serde_json::json!({ "type": "error", "message": error })
                );
            }
            eprintln!("{}", serde_json::to_string(&summary)?);
        }
        "json" => {
            let output = serde_json::json!({
                "findings": findings,
                "summary": summary,
                "errors": errors,
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        }
        _ => {
            for finding in findings {
                println!(
                    "{}: {} (family={}, entropy={:.2}, statistical_confidence={:.2})",
                    finding.file,
                    finding.message,
                    finding.file_family,
                    finding.entropy,
                    finding.statistical_confidence
                );
            }
            for error in errors {
                eprintln!("error: {error}");
            }
            println!(
                "Scanned {} file(s), {} finding(s), {} error(s)",
                summary.files_scanned, summary.findings, summary.errors
            );
        }
    }
    Ok(())
}
