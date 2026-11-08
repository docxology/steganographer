//! Consumer-visible capacity, precedence, media naming and local-state contracts.
use std::path::Path;
use std::process::{Command, Output};

fn command(dir: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_steganographer"));
    command
        .current_dir(dir)
        .args(["--quiet", "--config", "config.toml"]);
    command
}
fn setup() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("config.toml"), "[global]\n").unwrap();
    dir
}
fn run(dir: &Path, args: &[&str]) -> Output {
    command(dir).args(args).output().unwrap()
}
fn result(output: &Output) -> serde_json::Value {
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["schema"], "steganographer.cli/v1");
    envelope["result"].clone()
}
fn keygen(dir: &Path, name: &str) -> String {
    result(&run(dir, &["keygen", "--output", name, "--format", "json"]))["public_key"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[test]
fn capacity_matches_exact_encode_boundary_for_rgb_pcm_and_signatures() {
    let dir = setup();
    let root = dir.path();
    keygen(root, "signer");
    let units = 24_576usize;
    for audio in [false, true] {
        let kernel = if audio { "lsb_audio" } else { "lsb_video" };
        let input = if audio { "input.pcm" } else { "input.rgb" };
        std::fs::write(
            root.join(input),
            vec![0x68; units * if audio { 2 } else { 1 }],
        )
        .unwrap();
        for bits in 1..=4 {
            for signed in [false, true] {
                let bit_text = bits.to_string();
                let mut args = vec![
                    "capacity",
                    "--carrier-units",
                    "24576",
                    "--stego-type",
                    kernel,
                    "--bits",
                    &bit_text,
                    "--filename",
                    "payload.bin",
                    "--mime-type",
                    "application/octet-stream",
                    "--format",
                    "json",
                ];
                if signed {
                    args.extend(["--signing-key", "signer.key"]);
                }
                let cap = result(&run(root, &args));
                assert_eq!(cap["signed"], signed);
                assert_eq!(cap["carrier_units"], units);
                assert_eq!(cap["filename"], "payload.bin");
                let maximum = cap["max_payload_bytes"].as_u64().unwrap() as usize;
                let overhead = cap["packet_overhead_bytes"].as_u64().unwrap() as usize;
                assert_eq!(maximum + overhead, units * bits / 8);
                std::fs::write(root.join("payload"), vec![0x42; maximum]).unwrap();
                let output = format!(
                    "out-{audio}-{bits}-{signed}.{}",
                    if audio { "pcm" } else { "rgb" }
                );
                let mut encode = vec![
                    "encode",
                    "--input",
                    input,
                    "--output",
                    &output,
                    "--stego-type",
                    kernel,
                    "--bits",
                    &bit_text,
                    "--payload-file",
                    "payload",
                    "--filename",
                    "payload.bin",
                    "--mime-type",
                    "application/octet-stream",
                    "--format",
                    "json",
                ];
                if signed {
                    encode.extend(["--signing-key", "signer.key"]);
                }
                let encoded = result(&run(root, &encode));
                assert_eq!(encoded["packet_bytes"], cap["max_packet_bytes"]);
                assert_eq!(encoded["payload_bytes"], cap["max_payload_bytes"]);
                std::fs::remove_file(root.join(&output)).unwrap();
                std::fs::write(root.join("payload"), vec![0x42; maximum + 1]).unwrap();
                assert!(!run(root, &encode).status.success());
                assert!(!root.join(&output).exists());
                let mut actual = vec![
                    "capacity",
                    "--input",
                    input,
                    "--stego-type",
                    kernel,
                    "--bits",
                    &bit_text,
                    "--filename",
                    "payload.bin",
                    "--mime-type",
                    "application/octet-stream",
                    "--format",
                    "json",
                ];
                if signed {
                    actual.extend(["--signing-key", "signer.key"]);
                }
                assert_eq!(result(&run(root, &actual)), cap);
            }
        }
    }
}

#[test]
fn auto_verification_does_not_promote_a_length_only_false_candidate() {
    let dir = setup();
    let root = dir.path();
    let mut carrier = vec![0x68u8; 96 * 96 * 3];
    // A plausible legacy length prefix, followed by one byte which cannot
    // parse as a signature payload. This is not authenticated evidence.
    for (index, shift) in (0..32).rev().enumerate() {
        carrier[index] |= ((8u32 >> shift) & 1) as u8;
    }
    std::fs::write(root.join("false.rgb"), carrier).unwrap();
    let output = run(
        root,
        &["verify", "--input", "false.rgb", "--format", "json"],
    );
    assert_eq!(output.status.code(), Some(3));
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(envelope["result"].is_null());
}

#[test]
fn capacity_uses_core_variable_width_length_framing() {
    let dir = setup();
    let root = dir.path();
    std::fs::write(root.join("input.rgb"), vec![0x68; 600_000]).unwrap();
    let mut overheads = Vec::new();
    for maximum in [255usize, 256, 65_535, 65_536] {
        std::fs::write(
            root.join("config.toml"),
            format!("[global]\n[limits]\nmax_original_len = {maximum}\n"),
        )
        .unwrap();
        let cap = result(&run(
            root,
            &[
                "capacity",
                "--carrier-units",
                "600000",
                "--filename",
                "payload.bin",
                "--format",
                "json",
            ],
        ));
        assert_eq!(cap["max_payload_bytes"], maximum);
        std::fs::write(root.join("payload"), vec![0x42; maximum]).unwrap();
        let output = format!("out-{maximum}.rgb");
        let encoded = result(&run(
            root,
            &[
                "encode",
                "--input",
                "input.rgb",
                "--output",
                &output,
                "--payload-file",
                "payload",
                "--filename",
                "payload.bin",
                "--format",
                "json",
            ],
        ));
        assert_eq!(encoded["packet_bytes"], cap["max_packet_bytes"]);
        overheads.push(cap["packet_overhead_bytes"].as_u64().unwrap());
    }
    assert_eq!(overheads[1], overheads[0] + 1);
    assert_eq!(overheads[2], overheads[1]);
    assert_eq!(overheads[3], overheads[2] + 1);
}

#[test]
fn capacity_refuses_missing_framing_and_obeys_metadata_and_config_limits() {
    let dir = setup();
    let root = dir.path();
    let tiny = run(
        root,
        &["capacity", "--carrier-units", "1", "--format", "json"],
    );
    assert_eq!(tiny.status.code(), Some(1));
    let envelope: serde_json::Value = serde_json::from_slice(&tiny.stdout).unwrap();
    assert!(envelope["result"].is_null());
    for metadata in ["../escape", "bad/name"] {
        assert_eq!(
            run(
                root,
                &[
                    "capacity",
                    "--carrier-units",
                    "24000",
                    "--filename",
                    metadata,
                    "--format",
                    "json"
                ]
            )
            .status
            .code(),
            Some(1)
        );
    }
    std::fs::write(
        root.join("config.toml"),
        "[global]\n[limits]\nmax_original_len = 17\nmax_body_len = 19\nmax_packet_len = 4096\n",
    )
    .unwrap();
    let cap = result(&run(
        root,
        &["capacity", "--carrier-units", "24000", "--format", "json"],
    ));
    assert_eq!(cap["max_payload_bytes"], 17);
}

#[test]
fn suffixed_png_and_wav_use_the_same_default_representation_everywhere() {
    let dir = setup();
    let root = dir.path();
    image::RgbImage::from_pixel(64, 64, image::Rgb([120, 130, 140]))
        .save(root.join("input.png"))
        .unwrap();
    let spec = hound::WavSpec {
        channels: 1,
        sample_rate: 8000,
        bits_per_sample: 16,
        sample_format: hound::SampleFormat::Int,
    };
    let mut wav = hound::WavWriter::create(root.join("input.wav"), spec).unwrap();
    for _ in 0..12000 {
        wav.write_sample(1234i16).unwrap();
    }
    wav.finalize().unwrap();
    for (input, output, kernel) in [
        ("input.png", "out.png_001", "lsb_video"),
        ("input.wav", "out.wav_001", "lsb_audio"),
    ] {
        result(&run(
            root,
            &[
                "encode",
                "--input",
                input,
                "--output",
                output,
                "--stego-type",
                kernel,
                "--payload-text",
                "suffix round trip",
                "--format",
                "json",
            ],
        ));
        result(&run(
            root,
            &[
                "extract",
                "--input",
                output,
                "--output",
                "payload.txt",
                "--format",
                "json",
            ],
        ));
        assert_eq!(
            std::fs::read(root.join("payload.txt")).unwrap(),
            b"suffix round trip"
        );
        std::fs::remove_file(root.join("payload.txt")).unwrap();
    }
}

#[test]
fn explicit_spread_one_overrides_config_for_encode_and_verify() {
    let dir = setup();
    let root = dir.path();
    std::fs::write(root.join("config.toml"), "[global]\n[video.input]\ntype='file'\n[video.output]\ntype='file'\n[video.stego]\npipeline=[]\n[video.pipeline.payload]\nmulti_frame_spread = 2\n").unwrap();
    std::fs::write(root.join("input.rgb"), vec![0x68; 96 * 96 * 3]).unwrap();
    let public = keygen(root, "signer");
    for (name, spread) in [
        ("omitted.rgb", None),
        ("one.rgb", Some("1")),
        ("two.rgb", Some("2")),
    ] {
        let mut args = vec![
            "encode",
            "--input",
            "input.rgb",
            "--output",
            name,
            "--signing-key",
            "signer.key",
            "--format",
            "json",
        ];
        if let Some(spread) = spread {
            args.extend(["--spread", spread]);
        }
        result(&run(root, &args));
        assert_eq!(root.join(name).exists(), spread == Some("1"));
        assert_eq!(
            root.join(format!("{name}_001")).exists(),
            spread != Some("1")
        );
        let mut verify = vec![
            "verify",
            "--input",
            name,
            "--public-key",
            &public,
            "--format",
            "json",
        ];
        if let Some(spread) = spread {
            verify.extend(["--spread", spread]);
        }
        assert_eq!(result(&run(root, &verify))["status"], "valid");
    }
}

#[test]
fn auto_invalid_verification_retains_parsed_untrusted_evidence() {
    let dir = setup();
    let root = dir.path();
    let public = keygen(root, "signer");
    let wrong = keygen(root, "other");
    std::fs::write(root.join("input.rgb"), vec![0x68; 96 * 96 * 3]).unwrap();
    result(&run(
        root,
        &[
            "encode",
            "--input",
            "input.rgb",
            "--output",
            "signed.rgb",
            "--signing-key",
            "signer.key",
            "--format",
            "json",
        ],
    ));
    assert_eq!(
        result(&run(
            root,
            &[
                "verify",
                "--input",
                "signed.rgb",
                "--public-key",
                &public,
                "--format",
                "json"
            ]
        ))["status"],
        "valid"
    );
    let mut reports = Vec::new();
    for bits in ["auto", "1"] {
        let output = run(
            root,
            &[
                "verify",
                "--input",
                "signed.rgb",
                "--public-key",
                &wrong,
                "--bits",
                bits,
                "--format",
                "json",
            ],
        );
        assert_eq!(output.status.code(), Some(3));
        let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(envelope["result"]["status"], "invalid");
        assert_eq!(envelope["result"]["found"], true);
        reports.push(envelope["result"].clone());
    }
    assert_eq!(reports[0], reports[1]);
}

#[test]
fn concurrent_revocations_hold_a_stable_companion_lock_and_merge() {
    let dir = setup();
    let root = dir.path();
    let lock_path = root.join("revoked.json.lock");
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .unwrap();
    lock.lock().unwrap();
    let keys: Vec<String> = (1..=12).map(|n| format!("{n:064x}")).collect();
    let mut children: Vec<_> = keys
        .iter()
        .map(|key| {
            command(root)
                .args([
                    "revoke",
                    "--public-key",
                    key,
                    "--output",
                    "revoked.json",
                    "--format",
                    "json",
                ])
                .stdout(std::process::Stdio::null())
                .spawn()
                .unwrap()
        })
        .collect();
    std::thread::sleep(std::time::Duration::from_millis(150));
    for child in &mut children {
        assert!(
            child.try_wait().unwrap().is_none(),
            "revoke ignored companion lock"
        );
    }
    assert!(!root.join("revoked.json").exists());
    lock.unlock().unwrap();
    for mut child in children {
        assert!(child.wait().unwrap().success());
    }
    let registry: steganographer_core::revocation::RevocationList =
        serde_json::from_slice(&std::fs::read(root.join("revoked.json")).unwrap()).unwrap();
    for key in &keys {
        let bytes = steganographer_core::crypto::decode_hex_array::<32>(key).unwrap();
        assert!(registry.is_revoked(&bytes));
    }
    assert!(lock_path.exists());
}

#[cfg(unix)]
#[test]
fn recursive_scan_never_follows_links_but_top_level_opt_in_works() {
    use std::os::unix::fs::symlink;
    let dir = setup();
    let root = dir.path();
    std::fs::create_dir(root.join("tree")).unwrap();
    std::fs::write(root.join("tree/clean.txt"), b"ordinary visible text").unwrap();
    std::fs::write(root.join("outside.txt"), b"ordinary other text").unwrap();
    symlink(root.join("outside.txt"), root.join("tree/link.txt")).unwrap();
    symlink(root.join("tree"), root.join("tree/loop")).unwrap();
    let scan = run(root, &["scan", "--input", "tree", "--format", "json"]);
    let report: serde_json::Value = serde_json::from_slice(&scan.stdout).unwrap();
    assert_eq!(report["result"]["summary"]["files_scanned"], 1);
    assert_eq!(
        run(
            root,
            &["scan", "--input", "tree/link.txt", "--format", "json"]
        )
        .status
        .code(),
        Some(1)
    );
    let followed = run(
        root,
        &[
            "scan",
            "--input",
            "tree/link.txt",
            "--follow-input-symlink",
            "--format",
            "json",
        ],
    );
    let report: serde_json::Value = serde_json::from_slice(&followed.stdout).unwrap();
    assert_eq!(report["result"]["summary"]["files_scanned"], 1);
}

#[test]
fn unavailable_statistical_observations_are_inconclusive() {
    let dir = setup();
    let root = dir.path();
    for bytes in [Vec::new(), vec![0; 16]] {
        std::fs::write(root.join("carrier"), bytes).unwrap();
        for method in ["chi_squared", "sample_pairs", "rs", "combined"] {
            let output = run(
                root,
                &[
                    "analyze",
                    "--input",
                    "carrier",
                    "--analysis-type",
                    method,
                    "--format",
                    "json",
                ],
            );
            assert_eq!(
                output.status.code(),
                Some(5),
                "{method}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(report["status"], "partial");
            assert_eq!(report["result"]["available"], false);
        }
    }
    std::fs::write(root.join("carrier"), [0, 1].repeat(16)).unwrap();
    let output = run(
        root,
        &[
            "analyze",
            "--input",
            "carrier",
            "--analysis-type",
            "combined",
            "--format",
            "json",
        ],
    );
    let report = result(&output);
    assert_eq!(report["available"], true);
    assert_eq!(report["chi_squared"]["available"], false);
    assert_eq!(report["sample_pairs"]["available"], true);
}

#[cfg(unix)]
#[test]
fn scan_depth_cutoff_does_not_open_excluded_directories() {
    use std::os::unix::fs::PermissionsExt;
    let dir = setup();
    let root = dir.path();
    let excluded = root.join("tree/excluded");
    std::fs::create_dir_all(&excluded).unwrap();
    std::fs::write(root.join("tree/clean.txt"), b"ordinary visible text").unwrap();
    std::fs::set_permissions(&excluded, std::fs::Permissions::from_mode(0o000)).unwrap();
    let output = run(
        root,
        &[
            "scan",
            "--input",
            "tree",
            "--max-depth",
            "0",
            "--format",
            "json",
        ],
    );
    std::fs::set_permissions(&excluded, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(
        output.status.code(),
        Some(5),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["result"]["summary"]["files_scanned"], 1);
    assert_eq!(report["result"]["summary"]["errors"], 0);
}
