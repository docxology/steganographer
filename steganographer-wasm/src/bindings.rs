//! `#[wasm_bindgen]` exports over [`crate::api`].
//!
//! Signatures use `Vec<u8>` (maps to JS `Uint8Array`), `u16`/`u8`, and
//! `Option<String>` for the JSON decode-limits override (`null` = defaults).
//! Every report-returning export serializes the `serde_json::Value` report to
//! a string. Errors are returned as `Err(String)` messages.

use wasm_bindgen::prelude::*;

use crate::api;

fn limits(
    json: Option<String>,
) -> Result<Option<steganographer_core::packet::DecodeLimits>, String> {
    match json {
        None => Ok(None),
        Some(text) => {
            let value: serde_json::Value =
                serde_json::from_str(&text).map_err(|e| format!("invalid limits JSON: {e}"))?;
            Ok(Some(api::decode_limits_from_json(Some(&value))?))
        }
    }
}

fn to_string(result: Result<serde_json::Value, String>) -> Result<String, String> {
    result.map(|value| value.to_string())
}

fn to_string_now(value: serde_json::Value) -> String {
    value.to_string()
}

#[wasm_bindgen]
pub fn decode_limits_default() -> String {
    to_string_now(api::decode_limits_default())
}

// ─── Packet framing ─────────────────────────────────────────────────────────

#[wasm_bindgen]
pub fn packet_encode(
    payload: Vec<u8>,
    payload_kind: u16,
    packet_id: Vec<u8>,
    nonce: Vec<u8>,
    bits_per_unit: u8,
    limits_json: Option<String>,
) -> Result<Vec<u8>, String> {
    api::packet_encode(
        payload,
        payload_kind,
        packet_id,
        nonce,
        bits_per_unit,
        limits(limits_json)?,
    )
}

#[wasm_bindgen]
pub fn packet_decode(packet: Vec<u8>, limits_json: Option<String>) -> Result<String, String> {
    to_string(api::packet_decode(packet, limits(limits_json)?))
}

// ─── Carriers ───────────────────────────────────────────────────────────────

#[wasm_bindgen]
pub fn capacity_rgb(carrier: Vec<u8>, bits_per_unit: u8) -> Result<String, String> {
    to_string(api::capacity_rgb(&carrier, bits_per_unit))
}

#[wasm_bindgen]
pub fn capacity_pcm_s16le(carrier: Vec<u8>, bits_per_unit: u8) -> Result<String, String> {
    to_string(api::capacity_pcm_s16le(&carrier, bits_per_unit))
}

#[wasm_bindgen]
pub fn embed_rgb(carrier: Vec<u8>, packet: Vec<u8>, bits_per_unit: u8) -> Result<String, String> {
    let (carrier, report) = api::embed_rgb(carrier, &packet, bits_per_unit)?;
    Ok(to_string_now(serde_json::json!({
        "carrier": carrier,
        "report": {
            "packet_bytes": report.packet_bytes,
            "modified_units": report.modified_units,
            "remaining_capacity_bytes": report.remaining_capacity_bytes,
        },
    })))
}

#[wasm_bindgen]
pub fn embed_pcm_s16le(
    carrier: Vec<u8>,
    packet: Vec<u8>,
    bits_per_unit: u8,
) -> Result<String, String> {
    let (carrier, report) = api::embed_pcm_s16le(carrier, &packet, bits_per_unit)?;
    Ok(to_string_now(serde_json::json!({
        "carrier": carrier,
        "report": {
            "packet_bytes": report.packet_bytes,
            "modified_units": report.modified_units,
            "remaining_capacity_bytes": report.remaining_capacity_bytes,
        },
    })))
}

#[wasm_bindgen]
pub fn extract_rgb(
    carrier: Vec<u8>,
    bits_per_unit: u8,
    limits_json: Option<String>,
) -> Result<String, String> {
    to_string(api::extract_rgb(
        &carrier,
        bits_per_unit,
        limits(limits_json)?,
    ))
}

#[wasm_bindgen]
pub fn extract_pcm_s16le(
    carrier: Vec<u8>,
    bits_per_unit: u8,
    limits_json: Option<String>,
) -> Result<String, String> {
    to_string(api::extract_pcm_s16le(
        &carrier,
        bits_per_unit,
        limits(limits_json)?,
    ))
}

// ─── Forensics ──────────────────────────────────────────────────────────────

#[wasm_bindgen]
pub fn forensic_scan(data: Vec<u8>) -> String {
    to_string_now(api::forensic_scan(&data))
}

#[wasm_bindgen]
pub fn text_analyze_bytes(data: Vec<u8>) -> String {
    to_string_now(api::text_analyze_bytes(&data))
}

#[wasm_bindgen]
pub fn text_analyze_text(text: String) -> String {
    to_string_now(api::text_analyze_text(&text))
}
