//! `#[wasm_bindgen]` exports over [`crate::api`].
//!
//! Byte buffers use `Vec<u8>` (JS `Uint8Array`); numeric controls cross as
//! `f64` so finite integer/range validation precedes u8/u16 narrowing.
//! `Option<String>` carries JSON decode limits (`null` = defaults).
//! Reports are JSON strings; packet reports identify their lossless schema
//! and encode protocol u64 metadata as decimal strings. Errors throw strings.

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
    payload_kind: f64,
    packet_id: Vec<u8>,
    nonce: Vec<u8>,
    bits_per_unit: f64,
    limits_json: Option<String>,
) -> Result<Vec<u8>, String> {
    api::packet_encode(
        payload,
        api::js_payload_kind(payload_kind)?,
        packet_id,
        nonce,
        api::js_bits_per_unit(bits_per_unit)?,
        limits(limits_json)?,
    )
}

#[wasm_bindgen]
pub fn packet_decode(packet: Vec<u8>, limits_json: Option<String>) -> Result<String, String> {
    to_string(api::packet_decode(packet, limits(limits_json)?))
}

// ─── Carriers ───────────────────────────────────────────────────────────────

#[wasm_bindgen]
pub fn capacity_rgb(carrier: Vec<u8>, bits_per_unit: f64) -> Result<String, String> {
    to_string(api::capacity_rgb(
        &carrier,
        api::js_bits_per_unit(bits_per_unit)?,
    ))
}

#[wasm_bindgen]
pub fn capacity_pcm_s16le(carrier: Vec<u8>, bits_per_unit: f64) -> Result<String, String> {
    to_string(api::capacity_pcm_s16le(
        &carrier,
        api::js_bits_per_unit(bits_per_unit)?,
    ))
}

#[wasm_bindgen]
pub fn embed_rgb(carrier: Vec<u8>, packet: Vec<u8>, bits_per_unit: f64) -> Result<String, String> {
    let (carrier, report) =
        api::embed_rgb(carrier, &packet, api::js_bits_per_unit(bits_per_unit)?)?;
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
    bits_per_unit: f64,
) -> Result<String, String> {
    let (carrier, report) =
        api::embed_pcm_s16le(carrier, &packet, api::js_bits_per_unit(bits_per_unit)?)?;
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
    bits_per_unit: f64,
    limits_json: Option<String>,
) -> Result<String, String> {
    to_string(api::extract_rgb(
        &carrier,
        api::js_bits_per_unit(bits_per_unit)?,
        limits(limits_json)?,
    ))
}

#[wasm_bindgen]
pub fn extract_pcm_s16le(
    carrier: Vec<u8>,
    bits_per_unit: f64,
    limits_json: Option<String>,
) -> Result<String, String> {
    to_string(api::extract_pcm_s16le(
        &carrier,
        api::js_bits_per_unit(bits_per_unit)?,
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
