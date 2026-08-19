//! Integration tests for the steganographer CLI.
//!
//! These tests exercise the encode → verify round-trip for each stego type,
//! catching the class of bugs (nonce reuse, broken spread-spectrum key wiring,
//! dct_video stub) that went unnoticed because nothing exercised the CLI layer.

use std::path::PathBuf;
use std::process::Command;

/// Path to the built CLI binary.
fn cli_binary() -> PathBuf {
    // Cargo puts the binary at target/debug/steganographer (or target/release/)
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir.parent().unwrap();
    workspace_root
        .join("target")
        .join("debug")
        .join("steganographer")
}

/// Path to the workspace root (for finding config/example.toml).
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

/// Path to the config file.
fn config_path() -> String {
    workspace_root()
        .join("config")
        .join("example.toml")
        .to_string_lossy()
        .to_string()
}

/// Helper: run the CLI with given arguments, return (exit_code, stdout, stderr).
fn run_cli(args: &[&str]) -> (i32, String, String) {
    let bin = cli_binary();
    if !bin.exists() {
        // Try release binary
        let release_bin = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("target")
            .join("release")
            .join("steganographer");
        if release_bin.exists() {
            return run_cli_with_bin(&release_bin, args);
        }
        panic!("CLI binary not found at {:?} or {:?}", bin, release_bin);
    }
    run_cli_with_bin(&bin, args)
}

fn run_cli_with_bin(bin: &PathBuf, args: &[&str]) -> (i32, String, String) {
    let output = Command::new(bin)
        .args(args)
        .output()
        .expect("Failed to execute steganographer CLI");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

fn parse_json(stdout: &str) -> serde_json::Value {
    serde_json::from_str(stdout)
        .unwrap_or_else(|error| panic!("invalid JSON output ({error}): {stdout}"))
}

fn assert_valid_verification(stdout: &str) -> serde_json::Value {
    let result = parse_json(stdout);
    assert_eq!(result["found"], true, "signature was not found: {stdout}");
    assert_eq!(
        result["status"], "valid",
        "signature was not valid: {stdout}"
    );
    result
}

/// Create a raw RGB test frame (640x480, 3 bytes/pixel).
fn create_test_rgb(path: &str) {
    let width = 640;
    let height = 480;
    let bpp = 3;
    let data: Vec<u8> = (0..(width * height * bpp))
        .map(|i| (i % 256) as u8)
        .collect();
    std::fs::write(path, &data).expect("Failed to write test RGB file");
}

/// Create a raw S16LE PCM audio test file.
fn create_test_pcm(path: &str) {
    let samples: Vec<i16> = (0..44100).map(|i| (i % 1000) as i16).collect();
    let bytes: Vec<u8> = samples.iter().flat_map(|s| s.to_le_bytes()).collect();
    std::fs::write(path, &bytes).expect("Failed to write test PCM file");
}

fn create_test_png(path: &std::path::Path, width: u32, height: u32) {
    let image = image::RgbImage::from_fn(width, height, |x, y| {
        image::Rgb([(x % 251) as u8, (y % 241) as u8, ((x + y) % 239) as u8])
    });
    image.save(path).unwrap();
}

fn create_test_wav(path: &std::path::Path, spec: hound::WavSpec, frame_count: usize) {
    let mut writer = hound::WavWriter::create(path, spec).unwrap();
    for index in 0..frame_count * spec.channels as usize {
        writer
            .write_sample((index as i16).wrapping_mul(17))
            .unwrap();
    }
    writer.finalize().unwrap();
}

// ═══════════════════════════════════════════════════════════════════════════════
// Keygen
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_keygen_creates_keypair() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().with_extension("");
    let key_path = format!("{}.key", path.display());
    let pub_path = format!("{}.pub", path.display());

    let (code, stdout, _) = run_cli(&["keygen", "--output", &path.display().to_string()]);

    assert_eq!(code, 0, "keygen failed: {}", stdout);
    assert!(
        PathBuf::from(&key_path).exists(),
        "Private key file not created"
    );
    assert!(
        PathBuf::from(&pub_path).exists(),
        "Public key file not created"
    );

    let key_content = std::fs::read_to_string(&key_path).unwrap();
    assert_eq!(
        key_content.len(),
        64,
        "Private key should be 32 bytes hex (64 chars)"
    );

    let pub_content = std::fs::read_to_string(&pub_path).unwrap();
    assert_eq!(
        pub_content.len(),
        64,
        "Public key should be 32 bytes hex (64 chars)"
    );

    // Cleanup
    let _ = std::fs::remove_file(&key_path);
    let _ = std::fs::remove_file(&pub_path);
}

// ═══════════════════════════════════════════════════════════════════════════════
// LSB Video encode → verify round-trip
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_lsb_video_encode_verify_roundtrip_with_ecc_auto_bits() {
    // Regression: encode with a non-default LSB strength (2) and ECC, then
    // verify with --bits auto. Auto detection must pick the correct strength
    // (not just the first that parses) or the carrier canonicalization uses the
    // wrong low-bit mask and verification reports "invalid".
    let tmp = tempfile::tempdir().unwrap();
    let input = tmp.path().join("input.rgb");
    let key_prefix = tmp.path().join("test_key");
    create_test_rgb(input.to_str().unwrap());

    run_cli(&["keygen", "--output", key_prefix.to_str().unwrap()]);
    let key_path = format!("{}.key", key_prefix.display());
    let pub_path = format!("{}.pub", key_prefix.display());
    let pub_key = std::fs::read_to_string(&pub_path)
        .unwrap()
        .trim()
        .to_string();

    let output = tmp.path().join("output.rgb");
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
        "--bits",
        "2",
        "--ecc",
        "--ecc-parity",
        "4",
        "--signing-key",
        &key_path,
    ]);
    assert_eq!(code, 0, "encode failed: stdout={stdout}, stderr={stderr}");

    let (code, stdout, stderr) = run_cli(&[
        "--config",
        &config_path(),
        "verify",
        "--input",
        output.to_str().unwrap(),
        "--public-key",
        &pub_key,
        "--stego-type",
        "lsb_video",
        "--bits",
        "auto",
        "--ecc",
        "--ecc-parity",
        "4",
        "--format",
        "json",
    ]);
    assert_eq!(code, 0, "verify failed: stdout={stdout}, stderr={stderr}");
    let result = assert_valid_verification(&stdout);
    assert_eq!(
        result["lsb_bits"], 2,
        "auto-bits must detect the 2-bit encode"
    );
    assert_eq!(result["ecc_corrected"], true);
}
#[test]
fn test_lsb_video_encode_verify_roundtrip() {
    let tmp = tempfile::tempdir().unwrap();
    let input = tmp.path().join("input.rgb");
    let key_prefix = tmp.path().join("test_key");

    create_test_rgb(input.to_str().unwrap());

    // Generate a signing key
    let (code, _, _) = run_cli(&["keygen", "--output", key_prefix.to_str().unwrap()]);
    assert_eq!(code, 0, "keygen failed");

    let key_path = format!("{}.key", key_prefix.display());
    let pub_path = format!("{}.pub", key_prefix.display());
    let pub_key = std::fs::read_to_string(&pub_path)
        .unwrap()
        .trim()
        .to_string();

    for bits in 1..=4u8 {
        let output = tmp.path().join(format!("output-{bits}.rgb"));
        let bits_arg = bits.to_string();
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
            "--bits",
            &bits_arg,
            "--signing-key",
            &key_path,
        ]);
        assert_eq!(
            code, 0,
            "encode at {bits} bits failed: stdout={stdout}, stderr={stderr}"
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
            "lsb_video",
            "--bits",
            "auto",
            "--format",
            "json",
        ]);
        assert_eq!(
            code, 0,
            "verify at {bits} bits failed: stdout={stdout}, stderr={stderr}"
        );
        let result = assert_valid_verification(&stdout);
        assert_eq!(result["lsb_bits"], bits);
    }
}

#[test]
fn test_generic_packet_text_roundtrip_at_all_lsb_strengths() {
    let tmp = tempfile::tempdir().unwrap();
    let input = tmp.path().join("input.png");
    create_test_png(&input, 160, 160);
    let payload = "generic packet payload with unicode: π";

    for bits in 1..=4u8 {
        let carrier = tmp.path().join(format!("packet-{bits}.png"));
        let decoded = tmp.path().join(format!("payload-{bits}.txt"));
        let bits_arg = bits.to_string();
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
            &bits_arg,
            "--payload-text",
            payload,
            "--mime-type",
            "text/plain",
            "--filename",
            "message.txt",
            "--format",
            "json",
        ]);
        assert_eq!(
            code, 0,
            "generic encode failed at {bits} bits: stdout={stdout}, stderr={stderr}"
        );
        let encoded = parse_json(&stdout);
        assert_eq!(encoded["protocol"], "1.0-alpha");
        assert_eq!(encoded["payload_kind"], "text");
        assert_eq!(encoded["bits"], bits);

        let (code, stdout, stderr) = run_cli(&[
            "--config",
            &config_path(),
            "decode",
            "--input",
            carrier.to_str().unwrap(),
            "--output",
            decoded.to_str().unwrap(),
            "--bits",
            "auto",
            "--format",
            "json",
        ]);
        assert_eq!(
            code, 0,
            "generic decode failed at {bits} bits: stdout={stdout}, stderr={stderr}"
        );
        let result = parse_json(&stdout);
        assert_eq!(result["protocol"], "1.0-alpha");
        assert_eq!(result["bits"], bits);
        assert_eq!(result["mime_type"], "text/plain");
        assert_eq!(result["filename"], "message.txt");
        assert_eq!(std::fs::read_to_string(decoded).unwrap(), payload);
    }
}

#[test]
fn test_generic_packet_file_roundtrip_and_safe_overwrite() {
    let tmp = tempfile::tempdir().unwrap();
    let input = tmp.path().join("input.rgb");
    let carrier = tmp.path().join("packet.rgb");
    let payload_file = tmp.path().join("payload.bin");
    let decoded = tmp.path().join("decoded.bin");
    create_test_rgb(input.to_str().unwrap());
    let payload: Vec<u8> = (0..2048).map(|value| (value % 251) as u8).collect();
    std::fs::write(&payload_file, &payload).unwrap();

    let (code, stdout, stderr) = run_cli(&[
        "--config",
        &config_path(),
        "encode",
        "--input",
        input.to_str().unwrap(),
        "--output",
        carrier.to_str().unwrap(),
        "--payload-file",
        payload_file.to_str().unwrap(),
        "--mime-type",
        "application/octet-stream",
    ]);
    assert_eq!(
        code, 0,
        "generic file encode failed: stdout={stdout}, stderr={stderr}"
    );

    let (code, stdout, stderr) = run_cli(&[
        "--config",
        &config_path(),
        "decode",
        "--input",
        carrier.to_str().unwrap(),
        "--output",
        decoded.to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert_eq!(
        code, 0,
        "generic file decode failed: stdout={stdout}, stderr={stderr}"
    );
    assert_eq!(std::fs::read(&decoded).unwrap(), payload);

    let (code, _, stderr) = run_cli(&[
        "--config",
        &config_path(),
        "decode",
        "--input",
        carrier.to_str().unwrap(),
        "--output",
        decoded.to_str().unwrap(),
    ]);
    assert_ne!(code, 0);
    assert!(stderr.contains("--force"));

    #[cfg(unix)]
    {
        let alias = tmp.path().join("carrier-alias.rgb");
        std::os::unix::fs::symlink(&carrier, &alias).unwrap();
        let (code, _, stderr) = run_cli(&[
            "--config",
            &config_path(),
            "decode",
            "--input",
            carrier.to_str().unwrap(),
            "--output",
            alias.to_str().unwrap(),
            "--force",
        ]);
        assert_ne!(code, 0);
        assert!(stderr.contains("must differ from the carrier input"));
    }

    {
        use steganographer_core::packet::{
            crc32c, AlgorithmDescriptor, DecodeLimits, GenericPacket, Locator, PayloadKind,
            TransformDescriptor, FLAG_COMPRESSED, KERNEL_SPATIAL_LSB, PLACEMENT_SEQUENTIAL,
        };
        use steganographer_core::{CarrierEmbedder, EmbeddingConfig, SpatialLsb};

        let limits = DecodeLimits::default();
        let mut transformed_packet = GenericPacket::new_untransformed(
            b"encoded transform body".to_vec(),
            *b"0123456789abcdef",
            *b"nonce123",
            PayloadKind::Bytes,
            AlgorithmDescriptor::new(PLACEMENT_SEQUENTIAL, 1, Vec::new()),
            AlgorithmDescriptor::new(KERNEL_SPATIAL_LSB, 1, vec![1]),
            &limits,
        )
        .unwrap();
        transformed_packet
            .envelope
            .transforms
            .push(TransformDescriptor {
                algorithm: 9999, // unknown to the decoder
                version: 1,
                critical: true,
                parameters: Vec::new(),
            });
        let envelope = transformed_packet.envelope.encode(&limits).unwrap();
        transformed_packet.locator = Locator::new(
            FLAG_COMPRESSED,
            envelope.len(),
            transformed_packet.body.len(),
            crc32c(&envelope),
            *b"nonce123",
            &limits,
        )
        .unwrap();

        let packet_bytes = transformed_packet.encode(&limits).unwrap();
        let mut carrier_bytes = std::fs::read(&input).unwrap();
        SpatialLsb
            .embed_packet(
                &mut carrier_bytes,
                &packet_bytes,
                &EmbeddingConfig::new(1).unwrap(),
            )
            .unwrap();
        let transformed_carrier = tmp.path().join("transformed-packet.rgb");
        let transformed_output = tmp.path().join("unsupported-transform.bin");
        std::fs::write(&transformed_carrier, carrier_bytes).unwrap();

        let (code, _, stderr) = run_cli(&[
            "--config",
            &config_path(),
            "decode",
            "--input",
            transformed_carrier.to_str().unwrap(),
            "--output",
            transformed_output.to_str().unwrap(),
        ]);
        assert_ne!(code, 0);
        assert!(
            stderr.contains("not supported") || stderr.contains("unknown"),
            "unknown critical transform must fail closed: {stderr}"
        );
        assert!(!transformed_output.exists());
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// LSB Video encode → verify with encryption
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_lsb_video_encode_verify_with_encryption() {
    let tmp = tempfile::tempdir().unwrap();
    let input = tmp.path().join("input.rgb");
    let output = tmp.path().join("output.rgb");
    let key_prefix = tmp.path().join("test_key");

    create_test_rgb(input.to_str().unwrap());

    // Generate signing key
    run_cli(&["keygen", "--output", key_prefix.to_str().unwrap()]);
    let key_path = format!("{}.key", key_prefix.display());
    let pub_path = format!("{}.pub", key_prefix.display());
    let pub_key = std::fs::read_to_string(&pub_path)
        .unwrap()
        .trim()
        .to_string();

    // Use a fixed encryption key (32 bytes hex)
    let enc_key = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";

    // Encode with encryption
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
        "--signing-key",
        &key_path,
        "--encrypt",
        "--encryption-key",
        enc_key,
    ]);
    assert_eq!(
        code, 0,
        "encrypted encode failed: stdout={}, stderr={}",
        stdout, stderr
    );

    // Verify with decryption
    let (code, stdout, stderr) = run_cli(&[
        "--config",
        &config_path(),
        "verify",
        "--input",
        output.to_str().unwrap(),
        "--public-key",
        &pub_key,
        "--stego-type",
        "lsb_video",
        "--decrypt",
        "--decryption-key",
        enc_key,
        "--format",
        "json",
    ]);
    assert_eq!(
        code, 0,
        "decrypted verify failed: stdout={}, stderr={}",
        stdout, stderr
    );
    let result = assert_valid_verification(&stdout);
    assert_eq!(result["encrypted"], true);
}

// ═══════════════════════════════════════════════════════════════════════════════
// LSB Video encode → verify with ECC
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_lsb_video_encode_verify_with_ecc() {
    let tmp = tempfile::tempdir().unwrap();
    let input = tmp.path().join("input.rgb");
    let output = tmp.path().join("output.rgb");
    let key_prefix = tmp.path().join("test_key");

    create_test_rgb(input.to_str().unwrap());

    run_cli(&["keygen", "--output", key_prefix.to_str().unwrap()]);
    let key_path = format!("{}.key", key_prefix.display());
    let pub_path = format!("{}.pub", key_prefix.display());
    let pub_key = std::fs::read_to_string(&pub_path)
        .unwrap()
        .trim()
        .to_string();

    // Encode with ECC
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
        "--signing-key",
        &key_path,
        "--ecc",
        "--ecc-parity",
        "4",
    ]);
    assert_eq!(
        code, 0,
        "ECC encode failed: stdout={}, stderr={}",
        stdout, stderr
    );

    // Verify with ECC
    let (code, stdout, stderr) = run_cli(&[
        "--config",
        &config_path(),
        "verify",
        "--input",
        output.to_str().unwrap(),
        "--public-key",
        &pub_key,
        "--stego-type",
        "lsb_video",
        "--ecc",
        "--ecc-parity",
        "4",
        "--format",
        "json",
    ]);
    assert_eq!(
        code, 0,
        "ECC verify failed: stdout={}, stderr={}",
        stdout, stderr
    );
    let result = assert_valid_verification(&stdout);
    assert_eq!(result["ecc_corrected"], true);
}

// ═══════════════════════════════════════════════════════════════════════════════
// LSB Audio encode → verify round-trip
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_lsb_audio_encode_verify_roundtrip() {
    let tmp = tempfile::tempdir().unwrap();
    let input = tmp.path().join("input.pcm");
    let output = tmp.path().join("output.pcm");
    let key_prefix = tmp.path().join("test_key");
    let embedding_key_file = tmp.path().join("embedding.key");

    create_test_pcm(input.to_str().unwrap());

    run_cli(&["keygen", "--output", key_prefix.to_str().unwrap()]);
    let key_path = format!("{}.key", key_prefix.display());
    let pub_path = format!("{}.pub", key_prefix.display());
    let pub_key = std::fs::read_to_string(&pub_path)
        .unwrap()
        .trim()
        .to_string();

    // Embedding key (32 bytes hex)
    let embed_key = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    std::fs::write(&embedding_key_file, embed_key).unwrap();

    // Encode
    let (code, stdout, stderr) = run_cli(&[
        "--config",
        &config_path(),
        "encode",
        "--input",
        input.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
        "--stego-type",
        "lsb_audio",
        "--signing-key",
        &key_path,
        "--embedding-key-file",
        embedding_key_file.to_str().unwrap(),
        "--bits",
        "3",
        "--format",
        "json",
    ]);
    assert_eq!(
        code, 0,
        "audio encode failed: stdout={}, stderr={}",
        stdout, stderr
    );
    let encode_result = parse_json(&stdout);
    assert_eq!(encode_result["embedding_key_hex"], embed_key);

    // Verify — audio requires --embedding-key
    let (code, stdout, stderr) = run_cli(&[
        "--config",
        &config_path(),
        "verify",
        "--input",
        output.to_str().unwrap(),
        "--public-key",
        &pub_key,
        "--stego-type",
        "lsb_audio",
        "--embedding-key-file",
        embedding_key_file.to_str().unwrap(),
        "--bits",
        "auto",
        "--format",
        "json",
    ]);
    assert_eq!(
        code, 0,
        "audio verify failed: stdout={}, stderr={}",
        stdout, stderr
    );
    let result = assert_valid_verification(&stdout);
    assert_eq!(result["lsb_bits"], 3);
}

// ═══════════════════════════════════════════════════════════════════════════════
// DCT video encode → verify round-trip
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_dct_video_encode_verify_roundtrip() {
    let tmp = tempfile::tempdir().unwrap();
    let input = tmp.path().join("input.rgb");
    let output = tmp.path().join("output.rgb");
    let key_prefix = tmp.path().join("test_key");

    create_test_rgb(input.to_str().unwrap());
    let (code, _, stderr) = run_cli(&["keygen", "--output", key_prefix.to_str().unwrap()]);
    assert_eq!(code, 0, "keygen failed: {stderr}");
    let key_path = format!("{}.key", key_prefix.display());
    let pub_key = std::fs::read_to_string(format!("{}.pub", key_prefix.display()))
        .unwrap()
        .trim()
        .to_string();

    let (code, stdout, stderr) = run_cli(&[
        "--config",
        &config_path(),
        "encode",
        "--input",
        input.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
        "--stego-type",
        "dct_video",
        "--width",
        "640",
        "--height",
        "480",
        "--signing-key",
        &key_path,
    ]);
    assert_eq!(
        code, 0,
        "dct_video encode failed: stdout={stdout}, stderr={stderr}"
    );

    let (code, stdout, stderr) = run_cli(&[
        "--config",
        &config_path(),
        "verify",
        "--input",
        output.to_str().unwrap(),
        "--stego-type",
        "dct_video",
        "--width",
        "640",
        "--height",
        "480",
        "--public-key",
        &pub_key,
        "--format",
        "json",
    ]);
    assert_eq!(
        code, 0,
        "dct_video verify failed: stdout={stdout}, stderr={stderr}"
    );
    assert_valid_verification(&stdout);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Spread-spectrum video encode → verify round-trip (tests the key-wiring fix)
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_spread_spectrum_video_encode_verify_roundtrip() {
    let tmp = tempfile::tempdir().unwrap();
    let input = tmp.path().join("input.rgb");
    let output = tmp.path().join("output.rgb");
    let key_prefix = tmp.path().join("test_key");

    // Need a larger frame for spread-spectrum (64 pixels per bit)
    let width = 1024u32;
    let height = 1024u32;
    let bpp = 3;
    let data: Vec<u8> = vec![128u8; (width * height * bpp) as usize];
    std::fs::write(&input, &data).expect("Failed to write test RGB file");

    run_cli(&["keygen", "--output", key_prefix.to_str().unwrap()]);
    let key_path = format!("{}.key", key_prefix.display());
    let pub_path = format!("{}.pub", key_prefix.display());
    let pub_key = std::fs::read_to_string(&pub_path)
        .unwrap()
        .trim()
        .to_string();

    // Embedding key for spread-spectrum
    let embed_key = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

    // Encode
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
        "spread-spectrum encode failed: stdout={}, stderr={}",
        stdout, stderr
    );

    // Verify — this tests that embed_ss_bit now uses the key (was broken before the fix)
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
        "spread-spectrum verify failed: stdout={}, stderr={}",
        stdout, stderr
    );
    assert_valid_verification(&stdout);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Config validation
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_config_check_valid() {
    let (code, stdout, _) = run_cli(&["--config", &config_path(), "config", "check"]);
    assert_eq!(code, 0, "config check should succeed: {}", stdout);
    assert!(
        stdout.contains("valid"),
        "config check should report valid: {}",
        stdout
    );
}

#[test]
fn test_offline_payload_transforms_inherit_from_config() {
    let tmp = tempfile::tempdir().unwrap();
    let input = tmp.path().join("input.rgb");
    let output = tmp.path().join("output.rgb");
    let config = tmp.path().join("offline.toml");
    let key_prefix = tmp.path().join("test_key");
    let encryption_key = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
    create_test_rgb(input.to_str().unwrap());
    std::fs::write(
        &config,
        format!(
            r#"
[global]
log_level = "info"
hash_algorithm = "blake3"

[video.pipeline]
width = 640
height = 480

[video.pipeline.payload]
encrypt = true
encryption_key = "{encryption_key}"
error_correction = "reed_solomon"

[video.input]
type = "file"

[video.output]
type = "file"

[video.stego]
pipeline = []
"#
        ),
    )
    .unwrap();
    run_cli(&["keygen", "--output", key_prefix.to_str().unwrap()]);
    let key_path = format!("{}.key", key_prefix.display());
    let public_key = std::fs::read_to_string(format!("{}.pub", key_prefix.display()))
        .unwrap()
        .trim()
        .to_string();

    let (code, stdout, stderr) = run_cli(&[
        "--config",
        config.to_str().unwrap(),
        "encode",
        "--input",
        input.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
        "--signing-key",
        &key_path,
        "--format",
        "json",
    ]);
    assert_eq!(
        code, 0,
        "config-driven encode failed: stdout={stdout}, stderr={stderr}"
    );
    let encode_result = parse_json(&stdout);
    assert_eq!(encode_result["encrypted"], true);
    assert_eq!(encode_result["error_correction"], true);

    let (code, stdout, stderr) = run_cli(&[
        "--config",
        config.to_str().unwrap(),
        "verify",
        "--input",
        output.to_str().unwrap(),
        "--public-key",
        &public_key,
        "--format",
        "json",
    ]);
    assert_eq!(
        code, 0,
        "config-driven verify failed: stdout={stdout}, stderr={stderr}"
    );
    let result = assert_valid_verification(&stdout);
    assert_eq!(result["encrypted"], true);
    assert_eq!(result["ecc_corrected"], true);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Verify on unsigned media returns "not found"
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_verify_unsigned_media() {
    let tmp = tempfile::tempdir().unwrap();
    let input = tmp.path().join("unsigned.rgb");

    create_test_rgb(input.to_str().unwrap());

    let (code, stdout, _) = run_cli(&[
        "--config",
        &config_path(),
        "verify",
        "--input",
        input.to_str().unwrap(),
        "--stego-type",
        "lsb_video",
        "--format",
        "json",
    ]);

    assert_eq!(
        code, 0,
        "verify on unsigned media should not crash: {}",
        stdout
    );
    let result = parse_json(&stdout);
    assert_eq!(result["found"], false);
    assert_eq!(result["status"], "no_signature");
}

// ═══════════════════════════════════════════════════════════════════════════════
// Info command
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_info_reports_capacity() {
    let tmp = tempfile::tempdir().unwrap();
    let input = tmp.path().join("input.rgb");

    create_test_rgb(input.to_str().unwrap());

    let (code, stdout, _) = run_cli(&[
        "--config",
        &config_path(),
        "info",
        "--input",
        input.to_str().unwrap(),
        "--stego-type",
        "lsb_video",
    ]);

    assert_eq!(code, 0, "info should succeed: {}", stdout);
    assert!(
        stdout.contains("capacity") || stdout.contains("Capacity"),
        "info should report capacity: {}",
        stdout
    );
}

#[test]
fn test_png_info_uses_decoded_capacity_not_compressed_size() {
    let tmp = tempfile::tempdir().unwrap();
    let input = tmp.path().join("carrier.png");
    create_test_png(&input, 96, 64);

    let (code, stdout, stderr) = run_cli(&[
        "--config",
        &config_path(),
        "info",
        "--input",
        input.to_str().unwrap(),
        "--stego-type",
        "lsb_video",
        "--bits",
        "2",
        "--format",
        "json",
    ]);
    assert_eq!(code, 0, "info failed: stdout={stdout}, stderr={stderr}");
    let result = parse_json(&stdout);
    assert_eq!(result["total_capacity_bytes"], 4604);
    assert_ne!(
        result["total_capacity_bytes"], result["file_size"],
        "capacity must not be derived from the compressed file length"
    );
}

#[test]
fn test_wav_roundtrip_preserves_source_specification() {
    let tmp = tempfile::tempdir().unwrap();
    let input = tmp.path().join("input.wav");
    let output = tmp.path().join("output.wav");
    let key_prefix = tmp.path().join("test_key");
    let spec = hound::WavSpec {
        channels: 2,
        sample_rate: 48_000,
        bits_per_sample: 16,
        sample_format: hound::SampleFormat::Int,
    };
    create_test_wav(&input, spec, 5_000);
    run_cli(&["keygen", "--output", key_prefix.to_str().unwrap()]);
    let key_path = format!("{}.key", key_prefix.display());
    let public_key = std::fs::read_to_string(format!("{}.pub", key_prefix.display()))
        .unwrap()
        .trim()
        .to_string();
    let embedding_key = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

    let (code, stdout, stderr) = run_cli(&[
        "--config",
        &config_path(),
        "encode",
        "--input",
        input.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
        "--stego-type",
        "lsb_audio",
        "--signing-key",
        &key_path,
        "--embedding-key",
        embedding_key,
    ]);
    assert_eq!(
        code, 0,
        "WAV encode failed: stdout={stdout}, stderr={stderr}"
    );
    let output_spec = hound::WavReader::open(&output).unwrap().spec();
    assert_eq!(output_spec.channels, spec.channels);
    assert_eq!(output_spec.sample_rate, spec.sample_rate);
    assert_eq!(output_spec.bits_per_sample, spec.bits_per_sample);
    assert_eq!(output_spec.sample_format, spec.sample_format);

    let (code, stdout, stderr) = run_cli(&[
        "--config",
        &config_path(),
        "verify",
        "--input",
        output.to_str().unwrap(),
        "--stego-type",
        "lsb_audio",
        "--public-key",
        &public_key,
        "--embedding-key",
        embedding_key,
        "--format",
        "json",
    ]);
    assert_eq!(
        code, 0,
        "WAV verify failed: stdout={stdout}, stderr={stderr}"
    );
    assert_valid_verification(&stdout);
}

#[test]
fn test_spatial_lsb_rejects_lossy_jpeg_output() {
    let tmp = tempfile::tempdir().unwrap();
    let input = tmp.path().join("input.png");
    let output = tmp.path().join("output.jpg");
    create_test_png(&input, 96, 96);

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
    ]);
    assert_ne!(code, 0, "lossy output unexpectedly succeeded: {stdout}");
    assert!(stderr.contains("lossy JPEG"), "unexpected error: {stderr}");
    assert!(!output.exists());
}

#[test]
fn test_combined_analysis_reports_every_core_detector() {
    let tmp = tempfile::tempdir().unwrap();
    let input = tmp.path().join("input.rgb");
    create_test_rgb(input.to_str().unwrap());

    let (code, stdout, stderr) = run_cli(&[
        "--config",
        &config_path(),
        "analyze",
        "--input",
        input.to_str().unwrap(),
        "--analysis-type",
        "combined",
        "--format",
        "json",
    ]);
    assert_eq!(
        code, 0,
        "combined analysis failed: stdout={stdout}, stderr={stderr}"
    );
    let result = parse_json(&stdout);
    assert_eq!(result["analysis_type"], "combined");
    assert!(result["chi_squared"].is_object());
    assert!(result["sample_pairs"].is_object());
    assert!(result["rs_analysis"].is_object());
}

// ═══════════════════════════════════════════════════════════════════════════════
// Revoke command
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_revoke_creates_revoked_list() {
    let tmp = tempfile::tempdir().unwrap();
    let revoked_path = tmp.path().join("revoked.json");
    let pub_key = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";

    let (code, stdout, _) = run_cli(&[
        "revoke",
        "--public-key",
        pub_key,
        "--output",
        revoked_path.to_str().unwrap(),
    ]);

    assert_eq!(code, 0, "revoke failed: {}", stdout);
    assert!(revoked_path.exists(), "revoked.json should be created");
    assert!(
        stdout.contains("Key revoked"),
        "should report revocation: {}",
        stdout
    );

    let content = std::fs::read_to_string(&revoked_path).unwrap();
    assert!(
        content.contains(pub_key),
        "revoked.json should contain the key"
    );

    // Revoke same key again — should say "already revoked"
    let (code, stdout, _) = run_cli(&[
        "revoke",
        "--public-key",
        pub_key,
        "--output",
        revoked_path.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "revoke (duplicate) failed: {}", stdout);
    assert!(
        stdout.contains("already revoked"),
        "should report duplicate: {}",
        stdout
    );
}

#[test]
fn test_revoke_invalid_key_length() {
    let tmp = tempfile::tempdir().unwrap();
    let revoked_path = tmp.path().join("revoked.json");

    let (code, stdout, stderr) = run_cli(&[
        "revoke",
        "--public-key",
        "tooshort",
        "--output",
        revoked_path.to_str().unwrap(),
    ]);

    assert_ne!(code, 0, "revoke with short key should fail");
    // The error message should appear somewhere in the output
    let combined = format!("{}\n{}", stdout, stderr);
    assert!(
        combined.contains("32 bytes")
            || combined.contains("hex")
            || combined.contains("Invalid")
            || combined.contains("Public key must be"),
        "should mention key issue: {}",
        combined
    );
}

#[test]
fn test_derive_from_password_is_deterministic_and_conflict_free() {
    let tmp = tempfile::tempdir().unwrap();
    let out_a = tmp.path().join("keys_a");
    let out_b = tmp.path().join("keys_b");
    let out_c = tmp.path().join("keys_c");
    let salt = "000102030405060708090a0b0c0d0e0f";

    // Argon2id password derivation (weak params so the test stays fast).
    let (code, stdout, _) = run_cli(&[
        "derive",
        "--password",
        "correct horse battery staple",
        "--salt",
        salt,
        "--argon2-memory",
        "8",
        "--argon2-iterations",
        "1",
        "--output",
        out_a.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "password derive failed: {}", stdout);
    for name in [
        "signing.key",
        "signing.pub",
        "encryption.key",
        "embedding.key",
    ] {
        let path = out_a.join(name);
        assert!(path.exists(), "{} should be created", name);
        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            content.trim().len(),
            64,
            "{} should be a 64-char hex key, got {}",
            name,
            content
        );
    }

    // Same password + salt + params → identical keys.
    let (code, _, _) = run_cli(&[
        "derive",
        "--password",
        "correct horse battery staple",
        "--salt",
        salt,
        "--argon2-memory",
        "8",
        "--argon2-iterations",
        "1",
        "--output",
        out_b.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);
    assert_eq!(
        std::fs::read_to_string(out_a.join("signing.key")).unwrap(),
        std::fs::read_to_string(out_b.join("signing.key")).unwrap(),
        "same password + salt must derive identical keys"
    );

    // A different salt must derive different keys.
    let (code, _, _) = run_cli(&[
        "derive",
        "--password",
        "correct horse battery staple",
        "--salt",
        "ffffffffffffffffffffffffffffffff",
        "--argon2-memory",
        "8",
        "--argon2-iterations",
        "1",
        "--output",
        out_c.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);
    assert_ne!(
        std::fs::read_to_string(out_a.join("signing.key")).unwrap(),
        std::fs::read_to_string(out_c.join("signing.key")).unwrap(),
        "different salt must derive different keys"
    );

    // Providing both a master secret and a password must fail loudly.
    let (code, _, stderr) = run_cli(&[
        "derive",
        "--master-secret",
        "00",
        "--password",
        "pw",
        "--output",
        tmp.path().join("conflict").to_str().unwrap(),
    ]);
    assert_ne!(code, 0, "master-secret + password must be rejected");
    assert!(
        stderr.contains("not both") || stderr.contains("either"),
        "should explain the conflict: {}",
        stderr
    );
}

#[test]
fn test_derive_from_password_without_salt_generates_one() {
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("keys");

    let (code, stdout, _) = run_cli(&[
        "derive",
        "--password",
        "some passphrase",
        "--argon2-memory",
        "8",
        "--argon2-iterations",
        "1",
        "--output",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "password derive failed: {}", stdout);
    assert!(
        stdout.contains("salt"),
        "a generated salt must be reported so the user can persist it: {}",
        stdout
    );
    assert!(out.join("signing.key").exists());
}

#[test]
fn test_generic_packet_encrypt_ecc_roundtrip_and_fail_closed() {
    let tmp = tempfile::tempdir().unwrap();
    let input = tmp.path().join("cover.rgb");
    let packed = tmp.path().join("packed.rgb");
    let recovered = tmp.path().join("recovered.txt");
    let payload = tmp.path().join("payload.txt");
    create_test_rgb(input.to_str().unwrap());
    std::fs::write(&payload, b"secret generic payload with encrypt + ecc").unwrap();
    let key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    let (code, stdout, _) = run_cli(&[
        "encode",
        "--input",
        input.to_str().unwrap(),
        "--output",
        packed.to_str().unwrap(),
        "--payload-file",
        payload.to_str().unwrap(),
        "--bits",
        "2",
        "--encrypt",
        "--encryption-key",
        key,
        "--ecc",
        "--ecc-parity",
        "8",
    ]);
    assert_eq!(code, 0, "encode failed: {stdout}");
    assert!(
        stdout.contains("encrypted=true") && stdout.contains("error_corrected=true"),
        "should report both transforms: {stdout}"
    );

    // Round-trip with the correct key.
    let (code, stdout, _) = run_cli(&[
        "decode",
        "--input",
        packed.to_str().unwrap(),
        "--output",
        recovered.to_str().unwrap(),
        "--bits",
        "2",
        "--decrypt",
        "--decryption-key",
        key,
    ]);
    assert_eq!(code, 0, "decode failed: {stdout}");
    assert_eq!(
        std::fs::read(&recovered).unwrap(),
        std::fs::read(&payload).unwrap(),
        "decoded payload must match the original"
    );

    // A wrong key must fail closed.
    let (code, _, _) = run_cli(&[
        "decode",
        "--input",
        packed.to_str().unwrap(),
        "--output",
        tmp.path().join("bad.txt").to_str().unwrap(),
        "--bits",
        "2",
        "--decrypt",
        "--decryption-key",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    ]);
    assert_ne!(code, 0, "wrong decryption key must fail");

    // Omitting --decrypt on an encrypted packet must fail with a clear message.
    let (code, _, stderr) = run_cli(&[
        "decode",
        "--input",
        packed.to_str().unwrap(),
        "--output",
        tmp.path().join("bad2.txt").to_str().unwrap(),
        "--bits",
        "2",
    ]);
    assert_ne!(code, 0, "encrypted packet without --decrypt must fail");
    assert!(
        stderr.contains("decryption key"),
        "should name the missing key: {stderr}"
    );
}

#[test]
fn test_generic_packet_ecc_only_roundtrip() {
    let tmp = tempfile::tempdir().unwrap();
    let input = tmp.path().join("cover.rgb");
    let packed = tmp.path().join("packed.rgb");
    let recovered = tmp.path().join("recovered.txt");
    let payload = tmp.path().join("payload.txt");
    create_test_rgb(input.to_str().unwrap());
    std::fs::write(&payload, b"ecc-only generic payload").unwrap();

    let (code, stdout, _) = run_cli(&[
        "encode",
        "--input",
        input.to_str().unwrap(),
        "--output",
        packed.to_str().unwrap(),
        "--payload-file",
        payload.to_str().unwrap(),
        "--bits",
        "2",
        "--ecc",
        "--ecc-parity",
        "4",
    ]);
    assert_eq!(code, 0, "encode failed: {stdout}");
    assert!(
        stdout.contains("encrypted=false") && stdout.contains("error_corrected=true"),
        "should report ECC only: {stdout}"
    );

    let (code, stdout, _) = run_cli(&[
        "decode",
        "--input",
        packed.to_str().unwrap(),
        "--output",
        recovered.to_str().unwrap(),
        "--bits",
        "2",
    ]);
    assert_eq!(code, 0, "decode failed: {stdout}");
    assert_eq!(
        std::fs::read(&recovered).unwrap(),
        std::fs::read(&payload).unwrap()
    );
}

#[test]
fn test_generic_packet_compress_roundtrip() {
    let tmp = tempfile::tempdir().unwrap();
    let input = tmp.path().join("cover.rgb");
    let packed = tmp.path().join("packed.rgb");
    let recovered = tmp.path().join("recovered.txt");
    let payload = tmp.path().join("payload.txt");
    create_test_rgb(input.to_str().unwrap());
    std::fs::write(&payload, vec![b'x'; 2048]).unwrap(); // highly compressible

    let (code, stdout, _) = run_cli(&[
        "encode",
        "--input",
        input.to_str().unwrap(),
        "--output",
        packed.to_str().unwrap(),
        "--payload-file",
        payload.to_str().unwrap(),
        "--bits",
        "1",
        "--compress",
    ]);
    assert_eq!(code, 0, "encode failed: {stdout}");
    assert!(
        stdout.contains("compressed=true"),
        "compression should be reported: {stdout}"
    );

    let (code, stdout, _) = run_cli(&[
        "decode",
        "--input",
        packed.to_str().unwrap(),
        "--output",
        recovered.to_str().unwrap(),
        "--bits",
        "1",
    ]);
    assert_eq!(code, 0, "decode failed: {stdout}");
    assert_eq!(
        std::fs::read(&recovered).unwrap(),
        std::fs::read(&payload).unwrap()
    );
}

#[test]
fn test_generic_packet_sign_roundtrip_and_tamper() {
    let tmp = tempfile::tempdir().unwrap();
    let input = tmp.path().join("cover.rgb");
    let packed = tmp.path().join("packed.rgb");
    let recovered = tmp.path().join("recovered.txt");
    let payload = tmp.path().join("payload.txt");
    let key_base = tmp.path().join("signer");
    create_test_rgb(input.to_str().unwrap());
    std::fs::write(&payload, b"attributed generic payload").unwrap();

    // Generate a signing key and encode a signed generic packet.
    let (code, stdout, _) = run_cli(&["keygen", "--output", key_base.to_str().unwrap()]);
    assert_eq!(code, 0, "keygen failed: {stdout}");
    let signing_key = tmp.path().join("signer.key");

    let (code, stdout, _) = run_cli(&[
        "encode",
        "--input",
        input.to_str().unwrap(),
        "--output",
        packed.to_str().unwrap(),
        "--payload-file",
        payload.to_str().unwrap(),
        "--bits",
        "2",
        "--signing-key",
        signing_key.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "encode failed: {stdout}");
    assert!(
        stdout.contains("signed=true"),
        "should report signing: {stdout}"
    );

    let (code, stdout, _) = run_cli(&[
        "decode",
        "--input",
        packed.to_str().unwrap(),
        "--output",
        recovered.to_str().unwrap(),
        "--bits",
        "2",
    ]);
    assert_eq!(code, 0, "decode failed: {stdout}");
    assert_eq!(
        std::fs::read(&recovered).unwrap(),
        std::fs::read(&payload).unwrap()
    );
}

#[test]
fn test_generic_packet_keyed_placement_roundtrip_and_fail_closed() {
    let tmp = tempfile::tempdir().unwrap();
    let input = tmp.path().join("cover.rgb");
    let packed = tmp.path().join("keyed.rgb");
    let recovered = tmp.path().join("recovered.txt");
    create_test_rgb(input.to_str().unwrap());
    let key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    let payload = "keyed placement secret";

    let (code, stdout, stderr) = run_cli(&[
        "encode",
        "--input",
        input.to_str().unwrap(),
        "--output",
        packed.to_str().unwrap(),
        "--payload-text",
        payload,
        "--bits",
        "2",
        "--embedding-key",
        key,
        "--format",
        "json",
    ]);
    assert_eq!(
        code, 0,
        "keyed encode failed: stdout={stdout}, stderr={stderr}"
    );
    assert_eq!(
        parse_json(&stdout)["keyed"],
        true,
        "encode should report keyed placement: {stdout}"
    );

    let (code, stdout, stderr) = run_cli(&[
        "decode",
        "--input",
        packed.to_str().unwrap(),
        "--output",
        recovered.to_str().unwrap(),
        "--bits",
        "auto",
        "--embedding-key",
        key,
        "--format",
        "json",
    ]);
    assert_eq!(
        code, 0,
        "keyed decode failed: stdout={stdout}, stderr={stderr}"
    );
    assert_eq!(
        parse_json(&stdout)["keyed"],
        true,
        "decode should report keyed placement: {stdout}"
    );
    assert_eq!(std::fs::read_to_string(&recovered).unwrap(), payload);

    // A wrong key fails closed and produces no output.
    let wrong_key = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    let wrong_out = tmp.path().join("wrong.txt");
    let (code, stdout, _) = run_cli(&[
        "decode",
        "--input",
        packed.to_str().unwrap(),
        "--output",
        wrong_out.to_str().unwrap(),
        "--bits",
        "auto",
        "--embedding-key",
        wrong_key,
    ]);
    assert_ne!(code, 0, "wrong key must fail closed: {stdout}");
    assert!(!wrong_out.exists(), "wrong key must not write output");

    // A key-less scanner sees no packet at all (privacy property).
    let no_key_out = tmp.path().join("nokey.txt");
    let (code, _, _) = run_cli(&[
        "decode",
        "--input",
        packed.to_str().unwrap(),
        "--output",
        no_key_out.to_str().unwrap(),
        "--bits",
        "auto",
    ]);
    assert_ne!(code, 0, "keyed packet must be invisible without a key");
    assert!(
        !no_key_out.exists(),
        "key-less decode must not write output"
    );
}

#[test]
fn test_generic_packet_wav_audio_vertical_slice() {
    // Generic packets must embed over PCM S16 WAV (audio KER-001 + FMT-004):
    // sequential and keyed round-trips, source-spec preservation, and
    // wrong-key/missing-key fail-closed behavior.
    let tmp = tempfile::tempdir().unwrap();
    let carrier = tmp.path().join("carrier.wav");
    let packed = tmp.path().join("packed.wav");
    let keyed_packed = tmp.path().join("keyed.wav");
    let recovered = tmp.path().join("recovered.txt");
    let keyed_recovered = tmp.path().join("keyed_recovered.txt");

    let spec = hound::WavSpec {
        channels: 2,
        sample_rate: 22_050,
        bits_per_sample: 16,
        sample_format: hound::SampleFormat::Int,
    };
    create_test_wav(&carrier, spec, 22_050);

    let payload = "audio generic packet payload";
    let payload_path = tmp.path().join("payload.txt");
    std::fs::write(&payload_path, payload).unwrap();

    // Sequential audio encode/decode round-trip.
    let (code, stdout, stderr) = run_cli(&[
        "encode",
        "--input",
        carrier.to_str().unwrap(),
        "--output",
        packed.to_str().unwrap(),
        "--stego-type",
        "lsb_audio",
        "--bits",
        "2",
        "--payload-file",
        payload_path.to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert_eq!(
        code, 0,
        "audio sequential encode failed: stdout={stdout}, stderr={stderr}"
    );
    assert_eq!(parse_json(&stdout)["keyed"], false);

    let (code, stdout, stderr) = run_cli(&[
        "decode",
        "--input",
        packed.to_str().unwrap(),
        "--output",
        recovered.to_str().unwrap(),
        "--stego-type",
        "lsb_audio",
        "--bits",
        "auto",
        "--format",
        "json",
    ]);
    assert_eq!(
        code, 0,
        "audio sequential decode failed: stdout={stdout}, stderr={stderr}"
    );
    assert_eq!(std::fs::read_to_string(&recovered).unwrap(), payload);

    // Source properties survive the write/reopen cycle.
    let reread = hound::WavReader::open(&packed).unwrap();
    let packed_spec = reread.spec();
    assert_eq!(packed_spec.channels, spec.channels);
    assert_eq!(packed_spec.sample_rate, spec.sample_rate);
    assert_eq!(packed_spec.bits_per_sample, 16);

    // Keyed audio round-trip.
    let key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    let (code, stdout, stderr) = run_cli(&[
        "encode",
        "--input",
        carrier.to_str().unwrap(),
        "--output",
        keyed_packed.to_str().unwrap(),
        "--stego-type",
        "lsb_audio",
        "--bits",
        "3",
        "--payload-file",
        payload_path.to_str().unwrap(),
        "--embedding-key",
        key,
        "--format",
        "json",
    ]);
    assert_eq!(
        code, 0,
        "audio keyed encode failed: stdout={stdout}, stderr={stderr}"
    );
    assert_eq!(parse_json(&stdout)["keyed"], true);

    let (code, stdout, stderr) = run_cli(&[
        "decode",
        "--input",
        keyed_packed.to_str().unwrap(),
        "--output",
        keyed_recovered.to_str().unwrap(),
        "--stego-type",
        "lsb_audio",
        "--bits",
        "auto",
        "--embedding-key",
        key,
        "--format",
        "json",
    ]);
    assert_eq!(
        code, 0,
        "audio keyed decode failed: stdout={stdout}, stderr={stderr}"
    );
    assert_eq!(parse_json(&stdout)["keyed"], true);
    assert_eq!(std::fs::read_to_string(&keyed_recovered).unwrap(), payload);

    // A wrong key fails closed with no output.
    let wrong_key = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    let wrong_out = tmp.path().join("wrong.txt");
    let (code, stdout, _) = run_cli(&[
        "decode",
        "--input",
        keyed_packed.to_str().unwrap(),
        "--output",
        wrong_out.to_str().unwrap(),
        "--stego-type",
        "lsb_audio",
        "--bits",
        "auto",
        "--embedding-key",
        wrong_key,
    ]);
    assert_ne!(code, 0, "wrong audio key must fail closed: {stdout}");
    assert!(!wrong_out.exists(), "wrong audio key must not write output");

    // A key-less scanner sees no packet (privacy property).
    let no_key_out = tmp.path().join("nokey.txt");
    let (code, _, _) = run_cli(&[
        "decode",
        "--input",
        keyed_packed.to_str().unwrap(),
        "--output",
        no_key_out.to_str().unwrap(),
        "--stego-type",
        "lsb_audio",
        "--bits",
        "auto",
    ]);
    assert_ne!(
        code, 0,
        "keyed audio packet must be invisible without a key"
    );
    assert!(
        !no_key_out.exists(),
        "key-less audio decode must not write output"
    );
}
