//! `steganographer scan` — bounded forensic scan of files and directories.
//!
//! Runs the structural detectors in [`steganographer_core::forensics`] plus the
//! statistical detectors in [`steganographer_core::steganalysis`] over one file
//! or a directory tree, and emits deterministic machine-readable findings.

use std::io::Read;
use std::path::Path;

use serde::Serialize;
use steganographer_core::config::ProfileConfig;
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
    #[serde(skip_serializing_if = "Vec::is_empty")]
    text_findings: Vec<TextFindingReport>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    container_findings: Vec<ContainerFindingReport>,
    statistical_detected: bool,
}

/// Aggregate totals for the run.
#[derive(Debug, Serialize)]
struct ScanSummary {
    files_scanned: usize,
    findings: usize,
    errors: usize,
}

impl ScanFinding {
    fn from_scan(
        path: &Path,
        size: usize,
        truncated: bool,
        scan: forensics::ForensicScan,
        detectors: &ScanDetectors,
    ) -> Self {
        let magic_offsets = if detectors.magic {
            scan.magic_matches.iter().map(|m| m.offset).collect()
        } else {
            Vec::new()
        };
        let embedded_magic = if detectors.magic {
            scan.embedded_magic.map(|m| m.as_str().to_string())
        } else {
            None
        };
        let text_findings: Vec<TextFindingReport> = scan
            .text_findings
            .iter()
            .filter(|finding| detectors.allows_text(finding.detector_id))
            .map(TextFindingReport::from_finding)
            .collect();
        let container_findings: Vec<ContainerFindingReport> = scan
            .container_findings
            .iter()
            .map(|finding| ContainerFindingReport {
                path: finding.path.to_string(),
                family: finding.family.to_string(),
                detail: finding.detail.to_string(),
            })
            .collect();
        let statistical_detected = scan.statistical.detected && detectors.statistical;
        // The profile's detector set filters which findings are reported;
        // detection and the exit-1 policy follow the filtered report.
        // Container findings have no detector knob and always contribute.
        let detected = statistical_detected
            || embedded_magic.is_some()
            || !text_findings.is_empty()
            || !container_findings.is_empty();
        ScanFinding {
            file: path.display().to_string(),
            size,
            truncated,
            detected,
            entropy: scan.entropy,
            file_family: scan.file_family.as_str().to_string(),
            embedded_magic,
            magic_offsets,
            text_findings,
            container_findings,
            statistical_detected,
        }
    }
}

/// One FOR-005 unicode/text detector's evidence, serialized into scan
/// findings. Offsets are character offsets into the scanned text, matching
/// the core detector contract.
#[derive(Debug, Serialize)]
struct TextFindingReport {
    detector_id: &'static str,
    offsets: Vec<usize>,
    detail: String,
}

impl TextFindingReport {
    fn from_finding(finding: &steganographer_core::unicode_text::TextFinding) -> Self {
        TextFindingReport {
            detector_id: finding.detector_id,
            offsets: finding.offsets.clone(),
            detail: finding.detail.clone(),
        }
    }
}

/// One container-level forensic finding, mapped from the core
/// `forensics::ContainerFinding` contract (`path`, `family`, `detail`).
#[derive(Debug, Serialize)]
struct ContainerFindingReport {
    path: String,
    family: String,
    detail: String,
}

/// Active scan detector selection: which findings a scan reports. Derived
/// from an optional config profile's `scan.detectors` set; the default
/// reports every detector.
#[derive(Debug, Clone)]
struct ScanDetectors {
    /// Report statistical detector results (`statistical`).
    statistical: bool,
    /// Report embedded-magic probes (`magic`).
    magic: bool,
    /// Text detector IDs to report; `None` reports every FOR-005 detector.
    text: Option<Vec<String>>,
}

impl ScanDetectors {
    /// Every detector enabled.
    fn all() -> Self {
        ScanDetectors {
            statistical: true,
            magic: true,
            text: None,
        }
    }

    /// Build the selection from a profile's `scan.detectors` set. The config
    /// layer validates IDs against `SCAN_DETECTORS`; IDs outside the two
    /// scanner groups select text detectors.
    fn from_profile(profile: &ProfileConfig) -> Self {
        let mut detectors = ScanDetectors::all();
        if let Some(scan) = &profile.scan {
            if let Some(selected) = &scan.detectors {
                detectors.statistical = selected.iter().any(|id| id == "statistical");
                detectors.magic = selected.iter().any(|id| id == "magic");
                detectors.text = Some(
                    selected
                        .iter()
                        .filter(|id| id.as_str() != "statistical" && id.as_str() != "magic")
                        .cloned()
                        .collect(),
                );
            }
        }
        detectors
    }

    /// Whether a text finding with this detector ID is reported.
    fn allows_text(&self, detector_id: &str) -> bool {
        self.text
            .as_ref()
            .is_none_or(|ids| ids.iter().any(|id| id == detector_id))
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

fn scan_one(
    path: &Path,
    max_bytes: usize,
    detectors: &ScanDetectors,
) -> anyhow::Result<ScanFinding> {
    let (data, size, truncated) = read_bounded(path, max_bytes)?;
    let scan = forensics::scan_bytes(&data);
    Ok(ScanFinding::from_scan(
        path, size, truncated, scan, detectors,
    ))
}

#[allow(clippy::too_many_arguments)] // internal CLI orchestration entry
/// Bounded, non-following directory walk.
fn walk(
    dir: &Path,
    depth: u32,
    max_depth: u32,
    max_files: usize,
    max_bytes: usize,
    detectors: &ScanDetectors,
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
                detectors,
                files_scanned,
                findings,
                errors,
            );
        } else if file_type.is_file() {
            *files_scanned += 1;
            match scan_one(&path, max_bytes, detectors) {
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

/// Whether `path` is a symlink (`symlink_metadata` does not follow links).
fn is_symlink(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_symlink())
        .unwrap_or(false)
}

/// Enforce the scan symlink policy: the top-level input is rejected when it
/// is a symlink, keeping the top level consistent with the documented
/// "symlinks are never followed" directory recursion, unless
/// `follow_input_symlink` is set.
pub fn check_input_symlink(path: &Path, follow_input_symlink: bool) -> Result<(), String> {
    if !follow_input_symlink && is_symlink(path) {
        return Err(format!(
            "'{}' is a symlink; symlinks are never followed by scan \
             (pass --follow-input-symlink to scan the link target anyway)",
            path.display()
        ));
    }
    Ok(())
}

/// Run the scan and return the process exit code: `0` clean, `1` findings.
///
/// Errors during the scan are collected into the report and do not abort the
/// run; only argument/usage errors return `Err`. A symlinked input is
/// rejected unless `follow_input_symlink` is set. `profile` (resolved from
/// the config's `[profiles]` table by the caller) selects the reported
/// detector set.
pub fn run(
    input: &str,
    max_depth: u32,
    max_files: usize,
    max_bytes: usize,
    format: &str,
    follow_input_symlink: bool,
    profile: Option<&ProfileConfig>,
) -> anyhow::Result<i32> {
    let path = Path::new(input);
    check_input_symlink(path, follow_input_symlink).map_err(anyhow::Error::msg)?;
    let metadata = std::fs::metadata(path)
        .map_err(|error| anyhow::anyhow!("cannot access '{input}': {error}"))?;

    let detectors = profile
        .map(ScanDetectors::from_profile)
        .unwrap_or_else(ScanDetectors::all);

    let mut findings: Vec<ScanFinding> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    let mut files_scanned = 0usize;

    if metadata.is_file() {
        files_scanned = 1;
        match scan_one(path, max_bytes, &detectors) {
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
            &detectors,
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
                print!(
                    "{} (family={}, entropy={:.2}, statistical_detected={}",
                    finding.file,
                    finding.file_family,
                    finding.entropy,
                    finding.statistical_detected
                );
                if !finding.text_findings.is_empty() {
                    let ids: Vec<&str> = finding
                        .text_findings
                        .iter()
                        .map(|tf| tf.detector_id)
                        .collect();
                    print!(", text_detectors={})", ids.join(", "));
                } else {
                    print!(")");
                }
                println!();
                for container in &finding.container_findings {
                    println!(
                        "  container: {} ({}): {}",
                        container.path, container.family, container.detail
                    );
                }
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

#[cfg(test)]
mod tests {
    use super::*;
    use steganographer_core::config::ScanProfileConfig;
    use steganographer_core::unicode_text::HOMOGLYPH_SUSPECT;

    fn profile_with_detectors(ids: &[&str]) -> ProfileConfig {
        ProfileConfig {
            limits: None,
            scan: Some(ScanProfileConfig {
                detectors: Some(ids.iter().map(|id| id.to_string()).collect()),
            }),
        }
    }

    #[test]
    fn symlink_input_rejected_unless_follow_flag() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.txt");
        std::fs::write(&target, b"hello").unwrap();
        let link = dir.path().join("link.txt");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let error = check_input_symlink(&link, false).unwrap_err();
        assert!(error.contains("symlink"));

        // With the override flag the link is accepted, and run() follows the
        // link target (clean file, exit 0).
        assert!(check_input_symlink(&link, true).is_ok());
        let code = run(link.to_str().unwrap(), 8, 100, 1024, "json", true, None).unwrap();
        assert_eq!(code, 0);

        // run() enforces the same policy for direct callers.
        let error = run(link.to_str().unwrap(), 8, 100, 1024, "plain", false, None)
            .unwrap_err()
            .to_string();
        assert!(error.contains("symlink"));
    }

    #[test]
    fn regular_input_accepted_without_flag() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("plain.txt");
        std::fs::write(&file, b"hello").unwrap();
        assert!(check_input_symlink(&file, false).is_ok());
        let code = run(file.to_str().unwrap(), 8, 100, 1024, "json", false, None).unwrap();
        assert_eq!(code, 0);
    }

    #[test]
    fn profile_without_scan_block_reports_everything() {
        let profile = ProfileConfig {
            limits: None,
            scan: None,
        };
        let detectors = ScanDetectors::from_profile(&profile);
        assert!(detectors.statistical);
        assert!(detectors.magic);
        assert!(detectors.text.is_none());
    }

    #[test]
    fn profile_detector_set_filters_reported_findings() {
        // Cyrillic 'а' inside an ASCII word is a homoglyph suspect.
        let scan = forensics::scan_bytes("p\u{0430}ypal".as_bytes());
        assert!(!scan.text_findings.is_empty());

        // No profile: everything reported.
        let full = ScanFinding::from_scan(
            Path::new("f.txt"),
            8,
            false,
            scan.clone(),
            &ScanDetectors::all(),
        );
        assert!(full.detected);
        assert!(!full.text_findings.is_empty());

        // Profile limited to the statistical group: text findings suppressed
        // and detection follows the filtered report.
        let filtered = ScanFinding::from_scan(
            Path::new("f.txt"),
            8,
            false,
            scan.clone(),
            &ScanDetectors::from_profile(&profile_with_detectors(&["statistical"])),
        );
        assert!(filtered.text_findings.is_empty());
        assert!(!filtered.detected);

        // Profile keeping only the homoglyph detector: the finding survives.
        let kept = ScanFinding::from_scan(
            Path::new("f.txt"),
            8,
            false,
            scan,
            &ScanDetectors::from_profile(&profile_with_detectors(&[HOMOGLYPH_SUSPECT])),
        );
        assert!(kept.detected);
        assert_eq!(kept.text_findings.len(), 1);
        assert_eq!(kept.text_findings[0].detector_id, HOMOGLYPH_SUSPECT);
    }
}
