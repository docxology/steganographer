//! Public pre-signed fixtures contain no private key material. The legacy
//! fixture's valid_revoked result proves mathematical validity and policy denial.

use serde_json::Value;
use std::path::Path;
use std::process::Command;
use steganographer_core::crypto::{encode_hex, Signer};

const COMPROMISED: &str = "d2a05f7c69249dbfba5408dd8c35551317b04bfcc6f793c5e76221778c61d552";

fn run(directory: &Path, args: &[&str]) -> (i32, Value) {
    let output = Command::new(env!("CARGO_BIN_EXE_steganographer"))
        .current_dir(directory)
        .args(args)
        .args(["--format", "json"])
        .output()
        .unwrap();
    let document = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "invalid JSON: {error}; stdout={}; stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    (output.status.code().unwrap(), document)
}

#[test]
fn compromised_legacy_signature_is_valid_but_never_authorized() {
    let temporary = tempfile::tempdir().unwrap();
    std::fs::write(
        temporary.path().join("legacy.rgb"),
        include_bytes!("../testdata/revocation/legacy.rgb"),
    )
    .unwrap();
    let arguments = [
        "verify",
        "--input",
        "legacy.rgb",
        "--input-format",
        "raw_rgb",
        "--width",
        "64",
        "--height",
        "16",
        "--bits",
        "1",
        "--public-key",
        COMPROMISED,
    ];
    let (code, document) = run(temporary.path(), &arguments);
    assert_eq!(code, 3, "{document}");
    assert_eq!(document["result"]["status"], "valid_revoked");
    assert_eq!(document["errors"][0]["code"], "verification_failed");

    // An explicitly selected default-named missing file is not an optional default.
    let mut explicit = arguments.to_vec();
    explicit.extend(["--revoked-list", "keys/revoked.json"]);
    let (code, document) = run(temporary.path(), &explicit);
    assert_eq!(code, 1, "{document}");
    assert_eq!(document["errors"][0]["code"], "usage_error");
}

#[test]
fn compromised_packet_rejection_preserves_existing_payload_with_or_without_a_pin() {
    let temporary = tempfile::tempdir().unwrap();
    std::fs::write(
        temporary.path().join("packet.rgb"),
        include_bytes!("../testdata/revocation/packet.rgb"),
    )
    .unwrap();
    std::fs::write(temporary.path().join("empty.json"), "[]").unwrap();
    std::fs::write(
        temporary.path().join("payload.bin"),
        b"must survive failed authentication",
    )
    .unwrap();
    for command in ["decode", "extract"] {
        // Unpinned recovery must still reject the packet's compromised identity.
        let arguments = [
            command,
            "--input",
            "packet.rgb",
            "--input-format",
            "raw_rgb",
            "--output",
            "payload.bin",
            "--force",
        ];
        let (code, document) = run(temporary.path(), &arguments);
        assert_eq!(code, 3, "{document}");
        assert_eq!(document["errors"][0]["code"], "verification_failed");
        assert_eq!(
            std::fs::read(temporary.path().join("payload.bin")).unwrap(),
            b"must survive failed authentication"
        );

        // Neither an explicit pin nor an empty local registry restores that identity.
        let mut pinned = arguments.to_vec();
        pinned.extend([
            "--trusted-signer",
            COMPROMISED,
            "--revoked-list",
            "empty.json",
        ]);
        let (code, document) = run(temporary.path(), &pinned);
        assert_eq!(code, 3, "{document}");
        assert_eq!(document["errors"][0]["code"], "verification_failed");
        assert_eq!(
            std::fs::read(temporary.path().join("payload.bin")).unwrap(),
            b"must survive failed authentication"
        );
    }
}

#[test]
fn additional_registry_revocation_is_case_insensitive_idempotent_and_enforced() {
    let temporary = tempfile::tempdir().unwrap();
    let directory = temporary.path();
    // Deliberately public, deterministic test seed, unrelated to the incident key.
    let signer = Signer::from_bytes(&[0x42; 32]);
    let public = encode_hex(signer.verifying_key().as_bytes());
    std::fs::write(directory.join("signing.key"), encode_hex(&[0x42; 32])).unwrap();
    std::fs::write(directory.join("cover.rgb"), vec![0x80; 64 * 64 * 3]).unwrap();
    let (code, document) = run(
        directory,
        &[
            "encode",
            "--input",
            "cover.rgb",
            "--input-format",
            "raw_rgb",
            "--width",
            "64",
            "--height",
            "64",
            "--output",
            "packet.rgb",
            "--payload-text",
            "registry-controlled payload",
            "--signing-key",
            "signing.key",
        ],
    );
    assert_eq!(code, 0, "{document}");
    let decode = [
        "decode",
        "--input",
        "packet.rgb",
        "--input-format",
        "raw_rgb",
        "--output",
        "payload.bin",
        "--trusted-signer",
        &public,
        "--force",
    ];
    let (code, document) = run(directory, &decode);
    assert_eq!(code, 0, "{document}");
    assert_eq!(document["result"]["signer_trusted"], true);
    assert_eq!(
        std::fs::read(directory.join("payload.bin")).unwrap(),
        b"registry-controlled payload"
    );

    let (code, document) = run(
        directory,
        &[
            "revoke",
            "--public-key",
            &public.to_uppercase(),
            "--output",
            "revoked.json",
        ],
    );
    assert_eq!(code, 0, "{document}");
    assert_eq!(document["result"]["already_revoked"], false);
    let (code, document) = run(
        directory,
        &[
            "revoke",
            "--public-key",
            &public,
            "--output",
            "revoked.json",
        ],
    );
    assert_eq!(code, 0, "{document}");
    assert_eq!(document["result"]["already_revoked"], true);
    assert_eq!(
        serde_json::from_slice::<Value>(&std::fs::read(directory.join("revoked.json")).unwrap())
            .unwrap(),
        serde_json::json!([public])
    );

    let mut revoked = decode.to_vec();
    revoked.extend(["--revoked-list", "revoked.json"]);
    let (code, document) = run(directory, &revoked);
    assert_eq!(code, 3, "{document}");
    assert_eq!(document["errors"][0]["code"], "verification_failed");
    assert_eq!(
        std::fs::read(directory.join("payload.bin")).unwrap(),
        b"registry-controlled payload"
    );

    // Malformed explicit policy is an input error, never an empty registry.
    std::fs::write(directory.join("revoked.json"), "[\"not-a-key\"]").unwrap();
    let (code, document) = run(directory, &revoked);
    assert_eq!(code, 1, "{document}");
    assert_eq!(document["errors"][0]["code"], "usage_error");
    assert_eq!(
        std::fs::read(directory.join("payload.bin")).unwrap(),
        b"registry-controlled payload"
    );
}
