#![no_main]

use libfuzzer_sys::fuzz_target;
use steganographer_core::forensics::{
    analyze_package, analyze_pdf, scan_bytes, CONTAINER_MAX_FINDINGS,
};

fuzz_target!(|data: &[u8]| {
    // Keep campaign work bounded even when a caller overrides -max_len.
    if data.len() > 64 * 1024 {
        return;
    }
    let _ = scan_bytes(data);
    let package = analyze_package(data);
    assert!(package.findings.len() <= CONTAINER_MAX_FINDINGS);
    let pdf = analyze_pdf(data);
    assert!(pdf.findings.len() <= CONTAINER_MAX_FINDINGS);
});
