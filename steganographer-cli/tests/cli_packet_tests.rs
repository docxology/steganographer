//! Integration tests for the generic packet CLI contract.
//!
//! Covers: JSON purity of `encode --format json` (single document, no
//! serialized key material), the multi-frame `input` field, the `extract`
//! subcommand (SUR-002), the spread-spectrum legacy round-trip through the
//! core differential-pair embedder, unknown `--hash-algorithm` rejection,
//! and the scan surface for the FOR-005 unicode text detectors.

use std::path::PathBuf;
use std::process::Command;

/// Path to the built CLI binary.
fn cli_binary() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir.parent().unwrap();
    workspace_root
        .join("target")
        .join("debug")
        .join("steganographer")
}

/// Path to the workspace root (for finding config/example.toml).
fn config_path() -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("config")
        .join("example.toml")
        .to_string_lossy()
        .to_string()
}

/// Helper: run the CLI with given arguments, return (exit_code, stdout, stderr).
fn run_cli(args: &[&str]) -> (i32, String, String) {
    let bin = cli_binary();
    let output = Command::new(&bin)
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("Failed to execute {:?}: {error}", bin));
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

/// Parse the whole stdout as exactly one `steganographer.cli/v1` envelope
/// document, returning the command payload inside `result`.
fn parse_single_json(stdout: &str) -> serde_json::Value {
    let document: serde_json::Value = serde_json::from_str(stdout).unwrap_or_else(|error| {
        panic!("stdout is not a single pure JSON document ({error}): {stdout}")
    });
    assert_eq!(
        document["schema"], "steganographer.cli/v1",
        "missing cli/v1 envelope schema: {stdout}"
    );
    document["result"].clone()
}

/// Create a raw RGB test frame (640x480, 3 bytes/pixel).
fn create_test_rgb(path: &std::path::Path) {
    let width = 640u32;
    let height = 480u32;
    let bpp = 3usize;
    let data: Vec<u8> = (0..(width as usize * height as usize * bpp))
        .map(|i| (i % 251) as u8)
        .collect();
    std::fs::write(path, &data).expect("Failed to write test RGB file");
}

// ═══════════════════════════════════════════════════════════════════════════
// JSON purity: packet encode with encryption
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_packet_encode_encrypt_json_is_pure_document() {
    let tmp = tempfile::tempdir().unwrap();
    let input = tmp.path().join("input.rgb");
    let carrier = tmp.path().join("packet.rgb");
    create_test_rgb(&input);

    let (code, stdout, stderr) = run_cli(&[
        "--config",
        &config_path(),
        "encode",
        "--input",
        input.to_str().unwrap(),
        "--output",
        carrier.to_str().unwrap(),
        "--stego-type",
        "lsb_video",
        "--bits",
        "1",
        "--payload-text",
        "encrypt me in json mode",
        "--encrypt",
        "--format",
        "json",
    ]);
    assert_eq!(
        code, 0,
        "packet encode failed: stdout={stdout}, stderr={stderr}"
    );

    // Exactly one JSON document, and it is the generic packet report.
    let result = parse_single_json(&stdout);
    assert_eq!(result["protocol"], "1.0-alpha");
    assert_eq!(result["encrypted"], true);

    // A freshly generated 32-byte key must never appear on stdout in JSON
    // mode (the generator hints on stderr instead).
    assert!(
        !stdout.contains("Generated random encryption key"),
        "generated-key prose leaked into JSON stdout: {stdout}"
    );
    assert!(
        stderr.contains("encryption key"),
        "plain-mode key hint missing from stderr: {stderr}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// No secret serialization: legacy EncodeResult in --format json
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_legacy_encode_json_never_serializes_secret_keys() {
    let tmp = tempfile::tempdir().unwrap();
    let input = tmp.path().join("input.rgb");
    let output = tmp.path().join("output.rgb");
    create_test_rgb(&input);

    let key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let (code, stdout, stderr) = run_cli(&[
        "--config",
        &config_path(),
        "encode",
        "--input",
        input.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
        "--stego-type",
        "lsb_video",
        "--encrypt",
        "--encryption-key",
        key_hex,
        "--format",
        "json",
    ]);
    assert_eq!(
        code, 0,
        "legacy encode failed: stdout={stdout}, stderr={stderr}"
    );

    let result = parse_single_json(&stdout);
    assert!(
        result.get("encryption_key_hex").is_none(),
        "encryption key serialized into JSON: {result}"
    );
    assert!(
        result.get("embedding_key_hex").is_none(),
        "embedding key serialized into JSON: {result}"
    );
    assert_eq!(result["encrypted"], true);

    // Plain mode still hands the key to the user.
    let plain_output = tmp.path().join("output-plain.rgb");
    let (code, plain_stdout, stderr) = run_cli(&[
        "--config",
        &config_path(),
        "encode",
        "--input",
        input.to_str().unwrap(),
        "--output",
        plain_output.to_str().unwrap(),
        "--stego-type",
        "lsb_video",
        "--encrypt",
        "--encryption-key",
        key_hex,
    ]);
    assert_eq!(code, 0, "plain encode failed: {stderr}");
    assert!(
        plain_stdout.contains(key_hex),
        "plain mode must print the encryption key: {plain_stdout}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Multi-frame spreading reports the real input path
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_multi_frame_json_input_reports_real_input() {
    let tmp = tempfile::tempdir().unwrap();
    let input = tmp.path().join("input.rgb");
    let output = tmp.path().join("output.rgb");
    create_test_rgb(&input);

    let (code, stdout, stderr) = run_cli(&[
        "--config",
        &config_path(),
        "encode",
        "--input",
        input.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
        "--stego-type",
        "lsb_video",
        "--spread",
        "2",
        "--format",
        "json",
    ]);
    assert_eq!(
        code, 0,
        "multi-frame encode failed: stdout={stdout}, stderr={stderr}"
    );

    let result = parse_single_json(&stdout);
    assert_eq!(
        result["input"],
        input.to_str().unwrap(),
        "multi-frame JSON must report the real input path: {result}"
    );
    assert_eq!(result["spread"], 2);
    // Shard naming appends `_{i:03}` to the full output filename (legacy
    // behavior pinned here).
    assert!(tmp.path().join("output.rgb_001").exists());
    assert!(tmp.path().join("output.rgb_002").exists());
}

// ═══════════════════════════════════════════════════════════════════════════
// Unknown --hash-algorithm is rejected, not silently defaulted
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_hash_algorithm_unknown_is_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let input = tmp.path().join("input.rgb");
    let output = tmp.path().join("output.rgb");
    create_test_rgb(&input);

    let (code, _stdout, stderr) = run_cli(&[
        "--config",
        &config_path(),
        "encode",
        "--input",
        input.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
        "--stego-type",
        "lsb_video",
        "--hash-algorithm",
        "md5",
    ]);
    assert_ne!(code, 0, "unknown hash algorithm must not silently encode");
    assert!(
        stderr.contains("hash algorithm"),
        "error must name the hash algorithm: {stderr}"
    );
    assert!(!output.exists());
}

// ═══════════════════════════════════════════════════════════════════════════
// extract: roundtrip, overwrite refusal, --force, directory refusal
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_extract_roundtrip_overwrite_and_directory_refusals() {
    let tmp = tempfile::tempdir().unwrap();
    let input = tmp.path().join("input.rgb");
    let carrier = tmp.path().join("packet.rgb");
    let payload_file = tmp.path().join("payload.bin");
    let extracted = tmp.path().join("extracted.bin");
    create_test_rgb(&input);
    let payload: Vec<u8> = (0..1024).map(|value| (value % 251) as u8).collect();
    std::fs::write(&payload_file, &payload).unwrap();

    let (code, stdout, stderr) = run_cli(&[
        "--config",
        &config_path(),
        "encode",
        "--input",
        input.to_str().unwrap(),
        "--output",
        carrier.to_str().unwrap(),
        "--stego-type",
        "lsb_video",
        "--bits",
        "2",
        "--payload-file",
        payload_file.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "encode failed: stdout={stdout}, stderr={stderr}");

    // Roundtrip with an explicit strength.
    let (code, stdout, stderr) = run_cli(&[
        "--config",
        &config_path(),
        "extract",
        "--input",
        carrier.to_str().unwrap(),
        "--output",
        extracted.to_str().unwrap(),
        "--bits",
        "2",
    ]);
    assert_eq!(code, 0, "extract failed: stdout={stdout}, stderr={stderr}");
    assert_eq!(std::fs::read(&extracted).unwrap(), payload);
    // Saved-digest report: byte count, packet kind, BLAKE3 digest.
    assert!(
        stdout.contains("1024 bytes"),
        "byte count missing: {stdout}"
    );
    assert!(
        stdout.contains("kind: file"),
        "packet kind missing: {stdout}"
    );
    let digest = blake3::hash(&payload).to_string();
    assert!(
        stdout.contains(&digest),
        "BLAKE3 digest missing from extract report: {stdout}"
    );

    // Overwrite refusal without --force.
    let (code, _, stderr) = run_cli(&[
        "--config",
        &config_path(),
        "extract",
        "--input",
        carrier.to_str().unwrap(),
        "--output",
        extracted.to_str().unwrap(),
        "--bits",
        "2",
    ]);
    assert_ne!(code, 0, "overwrite without --force must fail");
    assert!(stderr.contains("--force"), "refusal message: {stderr}");

    // --force replaces the output.
    let (code, _, stderr) = run_cli(&[
        "--config",
        &config_path(),
        "extract",
        "--input",
        carrier.to_str().unwrap(),
        "--output",
        extracted.to_str().unwrap(),
        "--bits",
        "2",
        "--force",
    ]);
    assert_eq!(code, 0, "extract --force failed: {stderr}");
    assert_eq!(std::fs::read(&extracted).unwrap(), payload);

    // Refusal to extract onto a directory.
    let dir = tmp.path().join("adir");
    std::fs::create_dir(&dir).unwrap();
    let (code, _, stderr) = run_cli(&[
        "--config",
        &config_path(),
        "extract",
        "--input",
        carrier.to_str().unwrap(),
        "--output",
        dir.to_str().unwrap(),
    ]);
    assert_ne!(code, 0, "extract onto directory must fail");
    assert!(stderr.contains("directory"), "directory refusal: {stderr}");
}

// ═══════════════════════════════════════════════════════════════════════════
// Spread-spectrum legacy roundtrip through the core differential embedder
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_spread_spectrum_video_encode_verify_roundtrip() {
    let tmp = tempfile::tempdir().unwrap();
    let input = tmp.path().join("input.rgb");
    let output = tmp.path().join("output.rgb");
    let key_prefix = tmp.path().join("test_key");

    // 64 pixels per payload bit; the 109-byte signature needs 904 bits.
    create_test_rgb(&input);

    run_cli(&["keygen", "--output", key_prefix.to_str().unwrap()]);
    let key_path = format!("{}.key", key_prefix.display());
    let pub_path = format!("{}.pub", key_prefix.display());
    let pub_key = std::fs::read_to_string(&pub_path)
        .unwrap()
        .trim()
        .to_string();

    let embed_key = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

    let (code, stdout, stderr) = run_cli(&[
        "--config",
        &config_path(),
        "encode",
        "--input",
        input.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
        "--stego-type",
        "spread_spectrum_video",
        "--signing-key",
        &key_path,
        "--embedding-key",
        embed_key,
    ]);
    assert_eq!(
        code, 0,
        "spread-spectrum encode failed: stdout={stdout}, stderr={stderr}"
    );

    let (code, stdout, stderr) = run_cli(&[
        "--config",
        &config_path(),
        "verify",
        "--input",
        output.to_str().unwrap(),
        "--public-key",
        &pub_key,
        "--stego-type",
        "spread_spectrum_video",
        "--embedding-key",
        embed_key,
        "--format",
        "json",
    ]);
    assert_eq!(
        code, 0,
        "spread-spectrum verify failed: stdout={stdout}, stderr={stderr}"
    );
    let result = parse_single_json(&stdout);
    assert_eq!(result["found"], true, "signature not found: {stdout}");
    assert_eq!(result["status"], "valid", "signature not valid: {stdout}");
}

// ═══════════════════════════════════════════════════════════════════════════
// Scan surfaces the FOR-005 unicode text detectors
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_scan_surfaces_unicode_text_findings() {
    let tmp = tempfile::tempdir().unwrap();
    let text_file = tmp.path().join("stego.txt");

    // A zero-width run of 16 ZWSP characters is the classic binary channel.
    let mut content = String::from("innocent paragraph\n");
    content.push_str("payload line");
    for _ in 0..16 {
        content.push('\u{200B}');
    }
    content.push('\n');
    std::fs::write(&text_file, content.as_bytes()).unwrap();

    let (code, stdout, stderr) = run_cli(&[
        "--config",
        &config_path(),
        "scan",
        "--input",
        text_file.to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert_eq!(
        code, 4,
        "text stego must meet the findings threshold (exit 4): stdout={stdout}, stderr={stderr}"
    );

    let result = parse_single_json(&stdout);
    let findings = result["findings"].as_array().expect("findings array");
    assert_eq!(findings.len(), 1, "one finding expected: {result}");
    let text_findings = findings[0]["text_findings"]
        .as_array()
        .expect("text_findings array");
    let ids: Vec<&str> = text_findings
        .iter()
        .filter_map(|tf| tf["detector_id"].as_str())
        .collect();
    assert!(
        ids.contains(&"ZERO_WIDTH"),
        "ZERO_WIDTH detector must fire: {text_findings:?}"
    );
    // Character offsets must be reported as evidence.
    assert!(
        text_findings.iter().all(|tf| {
            tf["offsets"]
                .as_array()
                .map(|o| !o.is_empty())
                .unwrap_or(false)
        }),
        "offsets must be reported: {text_findings:?}"
    );

    // Plain mode names the detectors too.
    let (code, plain_stdout, _) = run_cli(&[
        "--config",
        &config_path(),
        "scan",
        "--input",
        text_file.to_str().unwrap(),
    ]);
    assert_eq!(code, 4, "findings must meet the threshold (exit 4)");
    assert!(
        plain_stdout.contains("ZERO_WIDTH"),
        "plain scan must name text detectors: {plain_stdout}"
    );
}
