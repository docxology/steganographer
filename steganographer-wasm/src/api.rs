//! Plain-Rust API surface for the wasm facade.
//!
//! These functions are always compiled (native and wasm32) and are the target
//! of the `#[cfg(target_arch = "wasm32")]` `bindings` module in `lib.rs`.
//! They wrap `steganographer-core` kernels over raw byte buffers:
//!
//! - packet framing: encode/decode of untransformed generic packets
//! - carriers: capacity + LSB embed/extract over raw RGB8 byte carriers and
//!   interleaved little-endian 16-bit PCM samples
//! - forensics: structural/statistical scan plus Unicode/text analysis
//! - decode limits: JSON config surface over [`DecodeLimits`]
//!
//! Reports are returned as `serde_json::Value` so the wasm bindings can pass
//! them to JavaScript as strings without any additional schema.

use serde_json::{json, Value};
use steganographer_core::carrier::{
    AudioSpatialLsb, CarrierDescriptor, CarrierEmbedder, CarrierError, CarrierExtractor,
    EmbedReport, EmbeddingConfig, ExtractReport, SpatialLsb,
};
use steganographer_core::packet::{
    AlgorithmDescriptor, DecodeLimits, DigestAlgorithm, GenericPacket, PayloadKind,
    KERNEL_SPATIAL_LSB, PLACEMENT_SEQUENTIAL,
};
use steganographer_core::unicode_text;
use steganographer_core::wasm_inspector;

// ─── Decode limits ──────────────────────────────────────────────────────────

/// The default [`DecodeLimits`] as a JSON object, one key per field. Pass a
/// subset of these keys (via [`decode_limits_from_json`]) to override
/// individual limits while keeping the defaults for the rest.
pub fn decode_limits_default() -> Value {
    let d = DecodeLimits::default();
    json!({
        "max_envelope_len": d.max_envelope_len,
        "max_body_len": d.max_body_len,
        "max_packet_len": d.max_packet_len,
        "max_field_len": d.max_field_len,
        "max_fields": d.max_fields,
        "max_transforms": d.max_transforms,
        "max_extensions": d.max_extensions,
        "max_filename_len": d.max_filename_len,
        "max_mime_len": d.max_mime_len,
        "max_original_len": d.max_original_len,
        "max_nesting_depth": d.max_nesting_depth,
        "max_aggregate_nested_bytes": d.max_aggregate_nested_bytes,
    })
}

/// Parse a JSON object into [`DecodeLimits`]. `None`/`null` yields the
/// defaults; every present key must be one of the fields reported by
/// [`decode_limits_default`] (unknown keys are rejected so typos fail loudly).
pub fn decode_limits_from_json(limits: Option<&Value>) -> Result<DecodeLimits, String> {
    let Some(value) = limits.filter(|v| !v.is_null()) else {
        return Ok(DecodeLimits::default());
    };
    let object = value
        .as_object()
        .ok_or("limits must be a JSON object (or null)")?;
    let mut out = DecodeLimits::default();
    for (key, raw) in object {
        let number = raw
            .as_u64()
            .ok_or_else(|| format!("limits.{key} must be a non-negative integer"))?;
        let field = match key.as_str() {
            "max_envelope_len" => &mut out.max_envelope_len,
            "max_body_len" => &mut out.max_body_len,
            "max_packet_len" => &mut out.max_packet_len,
            "max_field_len" => &mut out.max_field_len,
            "max_fields" => &mut out.max_fields,
            "max_transforms" => &mut out.max_transforms,
            "max_extensions" => &mut out.max_extensions,
            "max_filename_len" => &mut out.max_filename_len,
            "max_mime_len" => &mut out.max_mime_len,
            "max_original_len" => &mut out.max_original_len,
            "max_nesting_depth" => &mut out.max_nesting_depth,
            "max_aggregate_nested_bytes" => &mut out.max_aggregate_nested_bytes,
            other => return Err(format!("unknown limits field '{other}'")),
        };
        *field = usize::try_from(number)
            .map_err(|_| format!("limits.{key} does not fit the platform usize"))?;
    }
    Ok(out)
}

// ─── Packet framing ─────────────────────────────────────────────────────────

/// Encode an untransformed generic packet from a payload.
///
/// `packet_id` must be 16 bytes and `nonce` 8 bytes (they seed the public
/// locator). `payload_kind` is one of the protocol-v1 kinds: `1` bytes,
/// `2` text, `3` file, `4` frame attestation, `5` manifest.
///
/// `bits_per_unit` is the LSB strength the packet is intended to be embedded
/// with; it is recorded in the kernel descriptor (`KERNEL_SPATIAL_LSB`,
/// parameters `[bits_per_unit]`) so the carrier embedder accepts the packet.
pub fn packet_encode(
    payload: Vec<u8>,
    payload_kind: u16,
    packet_id: Vec<u8>,
    nonce: Vec<u8>,
    bits_per_unit: u8,
    limits: Option<DecodeLimits>,
) -> Result<Vec<u8>, String> {
    let limits = limits.unwrap_or_default();
    let packet_id_len = packet_id.len();
    let packet_id: [u8; 16] = packet_id
        .try_into()
        .map_err(|_| format!("packet_id must be exactly 16 bytes, got {packet_id_len}"))?;
    let nonce_len = nonce.len();
    let nonce: [u8; 8] = nonce
        .try_into()
        .map_err(|_| format!("nonce must be exactly 8 bytes, got {nonce_len}"))?;
    let kind = PayloadKind::try_from(payload_kind).map_err(|e| e.to_string())?;
    let packet = GenericPacket::new_untransformed(
        payload,
        packet_id,
        nonce,
        kind,
        AlgorithmDescriptor::new(PLACEMENT_SEQUENTIAL, 1, Vec::new()),
        AlgorithmDescriptor::new(KERNEL_SPATIAL_LSB, 1, vec![bits_per_unit]),
        &limits,
    )
    .map_err(|e| e.to_string())?;
    packet.encode(&limits).map_err(|e| e.to_string())
}

/// Decode a generic packet and return its public metadata plus body as JSON.
pub fn packet_decode(packet: Vec<u8>, limits: Option<DecodeLimits>) -> Result<Value, String> {
    let limits = limits.unwrap_or_default();
    let decoded = GenericPacket::decode(&packet, &limits).map_err(|e| e.to_string())?;
    Ok(packet_report(&decoded))
}

// ─── Carrier capacity ───────────────────────────────────────────────────────

/// Capacity of a raw RGB8 byte carrier (one carrier unit per byte).
pub fn capacity_rgb(carrier: &[u8], bits_per_unit: u8) -> Result<Value, String> {
    let report = SpatialLsb
        .capacity(
            &CarrierDescriptor::rgb8(carrier.len()),
            &config(bits_per_unit)?,
        )
        .map_err(|e| e.to_string())?;
    Ok(capacity_value(
        "rgb8",
        carrier.len(),
        bits_per_unit,
        &report,
    ))
}

/// Capacity of an interleaved little-endian 16-bit PCM carrier (one carrier
/// unit per sample, i.e. two bytes).
pub fn capacity_pcm_s16le(carrier: &[u8], bits_per_unit: u8) -> Result<Value, String> {
    ensure_even_byte_len(carrier.len())?;
    let report = AudioSpatialLsb
        .capacity(
            &CarrierDescriptor::pcm_s16le(carrier.len() / 2),
            &config(bits_per_unit)?,
        )
        .map_err(|e| e.to_string())?;
    Ok(capacity_value(
        "pcm_s16le",
        carrier.len(),
        bits_per_unit,
        &report,
    ))
}

// ─── Carrier embed/extract ──────────────────────────────────────────────────

/// Embed encoded packet bytes into a raw RGB8 carrier (sequential spatial LSB).
///
/// Returns the modified carrier plus the embed report. The packet must have
/// been encoded with the same `bits_per_unit` (its kernel descriptor records
/// it) and must fit the capacity reported by [`capacity_rgb`].
pub fn embed_rgb(
    mut carrier: Vec<u8>,
    packet: &[u8],
    bits_per_unit: u8,
) -> Result<(Vec<u8>, EmbedReport), String> {
    let report = SpatialLsb
        .embed_packet(&mut carrier, packet, &config(bits_per_unit)?)
        .map_err(|e| e.to_string())?;
    Ok((carrier, report))
}

/// Embed encoded packet bytes into an interleaved S16LE PCM carrier.
///
/// Only the low byte of each sample is touched, so the sample's upper bits are
/// never modified; the carrier length must be a multiple of 2 bytes.
pub fn embed_pcm_s16le(
    mut carrier: Vec<u8>,
    packet: &[u8],
    bits_per_unit: u8,
) -> Result<(Vec<u8>, EmbedReport), String> {
    ensure_even_byte_len(carrier.len())?;
    let report = AudioSpatialLsb
        .embed_packet(&mut carrier, packet, &config(bits_per_unit)?)
        .map_err(|e| e.to_string())?;
    Ok((carrier, report))
}

/// Extract a generic packet from a raw RGB8 carrier, returning its public
/// metadata plus body as JSON (same shape as [`packet_decode`]) and the
/// carrier-consumption numbers.
pub fn extract_rgb(
    carrier: &[u8],
    bits_per_unit: u8,
    limits: Option<DecodeLimits>,
) -> Result<Value, String> {
    let limits = limits.unwrap_or_default();
    let report = SpatialLsb
        .extract_packet(carrier, &config(bits_per_unit)?, &limits)
        .map_err(|e| e.to_string())?;
    Ok(extract_value(report))
}

/// Extract a generic packet from an interleaved S16LE PCM carrier.
pub fn extract_pcm_s16le(
    carrier: &[u8],
    bits_per_unit: u8,
    limits: Option<DecodeLimits>,
) -> Result<Value, String> {
    ensure_even_byte_len(carrier.len())?;
    let limits = limits.unwrap_or_default();
    let report = AudioSpatialLsb
        .extract_packet(carrier, &config(bits_per_unit)?, &limits)
        .map_err(|e| e.to_string())?;
    Ok(extract_value(report))
}

// ─── Forensics ──────────────────────────────────────────────────────────────

/// Run the structural/statistical forensic scan over raw bytes (core
/// `forensics::scan_bytes`, exposed through the zero-I/O `wasm_inspector`
/// facade) and append the Unicode/text findings.
pub fn forensic_scan(data: &[u8]) -> Value {
    let mut report = serde_json::to_value(wasm_inspector::inspect_bytes(data))
        .expect("WasmInspectionReport serializes");
    report["text_findings"] = text_findings_json(&unicode_text::analyze_bytes(data));
    report
}

/// Run the Unicode/text steganography detectors over raw bytes
/// (non-UTF-8 input yields no findings, per the core convention).
pub fn text_analyze_bytes(data: &[u8]) -> Value {
    text_findings_json(&unicode_text::analyze_bytes(data))
}

/// Run the Unicode/text steganography detectors over a string.
pub fn text_analyze_text(text: &str) -> Value {
    text_findings_json(&unicode_text::analyze_text(text))
}

// ─── Helpers ────────────────────────────────────────────────────────────────

fn config(bits_per_unit: u8) -> Result<EmbeddingConfig, String> {
    EmbeddingConfig::new(bits_per_unit).map_err(|e: CarrierError| e.to_string())
}

fn ensure_even_byte_len(byte_len: usize) -> Result<(), String> {
    if !byte_len.is_multiple_of(2) {
        return Err(format!(
            "carrier byte length {byte_len} is not a multiple of the 2-byte unit size"
        ));
    }
    Ok(())
}

fn capacity_value(
    kind: &str,
    byte_len: usize,
    bits_per_unit: u8,
    report: &steganographer_core::carrier::CapacityReport,
) -> Value {
    json!({
        "kind": kind,
        "byte_len": byte_len,
        "bits_per_unit": bits_per_unit,
        "usable_units": report.usable_units,
        "available_bits": report.available_bits,
        "max_packet_bytes": report.max_packet_bytes,
    })
}

fn digest_name(algorithm: DigestAlgorithm) -> &'static str {
    match algorithm {
        DigestAlgorithm::Blake3 => "blake3",
        DigestAlgorithm::Sha256 => "sha256",
        DigestAlgorithm::Sha3_256 => "sha3-256",
    }
}

fn payload_kind_name(kind: PayloadKind) -> &'static str {
    match kind {
        PayloadKind::Bytes => "bytes",
        PayloadKind::Text => "text",
        PayloadKind::File => "file",
        PayloadKind::FrameAttestation => "frame_attestation",
        PayloadKind::Manifest => "manifest",
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn descriptor_value(descriptor: &AlgorithmDescriptor) -> Value {
    json!({
        "algorithm": descriptor.algorithm,
        "version": descriptor.version,
        "parameters": descriptor.parameters,
    })
}

/// Public metadata + body of a decoded generic packet, as JSON.
fn packet_report(packet: &GenericPacket) -> Value {
    json!({
        "packet_id": hex(&packet.envelope.packet_id),
        "payload_kind": packet.envelope.payload_kind as u16,
        "payload_kind_name": payload_kind_name(packet.envelope.payload_kind),
        "original_len": packet.envelope.original_len,
        "digest": {
            "algorithm": digest_name(packet.envelope.content_digest.algorithm),
            "hex": hex(&packet.envelope.content_digest.bytes),
        },
        "body": packet.body,
        "body_len": packet.body.len(),
        "mime_type": packet.envelope.mime_type,
        "filename": packet.envelope.filename,
        "created_at_unix": packet.envelope.created_at_unix,
        "parent_id": packet.envelope.parent_id.as_ref().map(|id| hex(id)),
        "transforms": packet.envelope.transforms.iter().map(|t| json!({
            "algorithm": t.algorithm,
            "version": t.version,
            "parameters": t.parameters,
            "critical": t.critical,
        })).collect::<Vec<_>>(),
        "placement": descriptor_value(&packet.envelope.placement),
        "kernel": descriptor_value(&packet.envelope.kernel),
        "extensions": packet.envelope.extensions.iter().map(|f| json!({
            "id": f.id,
            "value_hex": hex(&f.value),
        })).collect::<Vec<_>>(),
        "locator": {
            "flags": packet.locator.flags,
            "nonce_hex": hex(&packet.locator.nonce),
            "packet_len": packet.encoded_len().unwrap_or(0),
        },
    })
}

/// Extract report mapped into the same JSON shape as [`packet_report`],
/// plus the carrier-consumption numbers.
fn extract_value(report: ExtractReport) -> Value {
    let mut value = packet_report(&report.packet);
    value["consumed_units"] = json!(report.consumed_units);
    value["bits_per_unit"] = json!(report.bits_per_unit);
    value
}

fn text_findings_json(findings: &[unicode_text::TextFinding]) -> Value {
    Value::Array(
        findings
            .iter()
            .map(|f| {
                json!({
                    "detector_id": f.detector_id,
                    "offsets": f.offsets,
                    "detail": f.detail,
                })
            })
            .collect(),
    )
}
