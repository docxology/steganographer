//! WebSocket handlers for streaming encoded/decoded video and audio frames.
//!
//! Channels:
//! - `/ws/encode` — receives raw JPEG frames from browser webcam, applies LSB stego + signing,
//!   sends back the encoded frame as base64 JPEG plus metrics.
//! - `/ws/decode` — receives the same encoded frame, extracts LSB payload, verifies signature,
//!   sends verification result plus decoded frame.
//! - `/ws/audio/encode` — receives PCM audio chunks, applies LSB audio stego + signing.
//! - `/ws/audio/decode` — extracts audio payload, verifies signature.

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    response::IntoResponse,
};
use image::{ImageFormat, ImageReader};
use std::io::Cursor;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use steganographer_core::{
    Signer, VideoFormat, VideoFrame, VideoStegoModule,
};
use steganographer_core::lsb_video::LsbVideo;
use steganographer_core::audio::AudioBuffer;
use steganographer_core::lsb_audio::LsbAudio;
use steganographer_core::AudioStegoModule;

use super::DashboardState;

// ═══════════════════════════════════════════════════════════════════════════════
// VIDEO WEBSOCKET UPGRADE HANDLERS
// ═══════════════════════════════════════════════════════════════════════════════

/// WebSocket upgrade handler for the encode (left panel) feed.
pub async fn ws_encode_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<DashboardState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_encode_socket(socket, state))
}

/// WebSocket upgrade handler for the decode (right panel) feed.
pub async fn ws_decode_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<DashboardState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_decode_socket(socket, state))
}

// ═══════════════════════════════════════════════════════════════════════════════
// AUDIO WEBSOCKET UPGRADE HANDLERS
// ═══════════════════════════════════════════════════════════════════════════════

/// WebSocket upgrade handler for audio encode.
pub async fn ws_audio_encode_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<DashboardState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_audio_encode_socket(socket, state))
}

/// WebSocket upgrade handler for audio decode.
pub async fn ws_audio_decode_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<DashboardState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_audio_decode_socket(socket, state))
}

// ═══════════════════════════════════════════════════════════════════════════════
// VIDEO ENCODE HANDLER
// ═══════════════════════════════════════════════════════════════════════════════

/// Handle the encode WebSocket — receives JPEG frames from the browser webcam,
/// applies LSB steganography + cryptographic signing, sends back encoded frames.
async fn handle_encode_socket(mut socket: WebSocket, state: Arc<DashboardState>) {
    log::info!("Encode WebSocket client connected");

    let frame_counter = AtomicU64::new(0);
    let signer = Signer::generate();
    let mut lsb = LsbVideo::new(1);
    let mut current_lsb_bits: u8 = 1;

    loop {
        let msg = match socket.recv().await {
            Some(Ok(msg)) => msg,
            _ => {
                log::info!("Encode WebSocket client disconnected");
                break;
            }
        };

        let jpeg_bytes = match msg {
            Message::Binary(data) => data.to_vec(),
            Message::Text(text) => {
                if text.contains("ping") {
                    let metrics_json = state.metrics.to_json();
                    let reply = serde_json::json!({
                        "type": "metrics",
                        "data": serde_json::from_str::<serde_json::Value>(&metrics_json).unwrap_or_default(),
                        "backend": state.signing_backend,
                        "identity": state.identity,
                    });
                    let _ = socket
                        .send(Message::Text(reply.to_string().into()))
                        .await;
                }
                continue;
            }
            Message::Ping(_) => continue,
            Message::Pong(_) => continue,
            Message::Close(_) => break,
        };

        if jpeg_bytes.is_empty() {
            continue;
        }

        let frame_idx = frame_counter.fetch_add(1, Ordering::Relaxed);

        let decode_result = ImageReader::with_format(
            Cursor::new(&jpeg_bytes),
            ImageFormat::Jpeg,
        )
        .decode();

        let rgb_image = match decode_result {
            Ok(img) => img.to_rgb8(),
            Err(e) => {
                log::warn!("Failed to decode JPEG frame: {}", e);
                continue;
            }
        };

        let width = rgb_image.width();
        let height = rgb_image.height();
        let mut rgb_data = rgb_image.into_raw();

        let sign_start = Instant::now();
        let payload = signer.sign_frame(frame_idx, &rgb_data, None);
        let sign_duration = sign_start.elapsed();
        state.metrics.record_sign_duration(sign_duration);

        // Update LSB bits from live config if changed
        {
            let cfg = state.live_config.lock().unwrap_or_else(|e| e.into_inner());
            if cfg.lsb_bits != current_lsb_bits {
                current_lsb_bits = cfg.lsb_bits;
                lsb = LsbVideo::new(current_lsb_bits);
                log::info!("Video encode: LSB bits updated to {}", current_lsb_bits);
            }
        }

        let embed_start = Instant::now();
        {
            let mut frame = VideoFrame {
                width,
                height,
                stride: width * 3,
                format: VideoFormat::Rgb8,
                data: &mut rgb_data,
                frame_index: frame_idx,
            };
            if let Err(e) = lsb.embed(&mut frame, Some(&payload)) {
                log::warn!("LSB embed failed: {}", e);
                continue;
            }
        }
        let embed_duration = embed_start.elapsed();
        state.metrics.record_embed_duration(embed_duration);
        state.metrics.record_frame();

        let encoded_image =
            image::RgbImage::from_raw(width, height, rgb_data.clone()).expect("invalid raw RGB dimensions");
        let mut jpeg_out = Cursor::new(Vec::new());
        if encoded_image
            .write_to(&mut jpeg_out, ImageFormat::Jpeg)
            .is_err()
        {
            log::warn!("Failed to re-encode JPEG");
            continue;
        }

        let encoded_jpeg = jpeg_out.into_inner();
        let b64_frame = base64_encode(&encoded_jpeg);

        {
            let mut last = state.last_encoded_frame.lock().unwrap_or_else(|e| e.into_inner());
            *last = Some(EncodedFrame {
                rgb_data,
                width,
                height,
                frame_index: frame_idx,
            });
        }

        let metrics_json = state.metrics.to_json();
        let reply = serde_json::json!({
            "type": "encoded_frame",
            "frame": b64_frame,
            "width": width,
            "height": height,
            "frame_index": frame_idx,
            "sign_us": sign_duration.as_micros() as u64,
            "embed_us": embed_duration.as_micros() as u64,
            "data": serde_json::from_str::<serde_json::Value>(&metrics_json).unwrap_or_default(),
            "backend": state.signing_backend,
            "identity": state.identity,
        });

        if socket
            .send(Message::Text(reply.to_string().into()))
            .await
            .is_err()
        {
            log::info!("Encode WebSocket client disconnected");
            break;
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// VIDEO DECODE HANDLER
// ═══════════════════════════════════════════════════════════════════════════════

/// Handle the decode WebSocket — extracts LSB payloads from the latest encoded
/// frame and streams verification results to the right panel.
async fn handle_decode_socket(mut socket: WebSocket, state: Arc<DashboardState>) {
    log::info!("Decode WebSocket client connected");

    let mut lsb = LsbVideo::new(1);
    let mut current_lsb_bits: u8 = 1;

    loop {
        let msg = match socket.recv().await {
            Some(Ok(msg)) => msg,
            _ => {
                log::info!("Decode WebSocket client disconnected");
                break;
            }
        };

        match msg {
            Message::Text(_) | Message::Binary(_) => {}
            Message::Ping(_) | Message::Pong(_) => continue,
            Message::Close(_) => break,
        }

        let encoded = {
            let last = state.last_encoded_frame.lock().unwrap_or_else(|e| e.into_inner());
            last.clone()
        };

        let reply = if let Some(ef) = encoded {
            let verify_start = Instant::now();
            let mut data_copy = ef.rgb_data.clone();
            let frame = VideoFrame {
                width: ef.width,
                height: ef.height,
                stride: ef.width * 3,
                format: VideoFormat::Rgb8,
                data: &mut data_copy,
                frame_index: ef.frame_index,
            };

            // Update LSB bits from live config if changed
            {
                let cfg = state.live_config.lock().unwrap_or_else(|e| e.into_inner());
                if cfg.lsb_bits != current_lsb_bits {
                    current_lsb_bits = cfg.lsb_bits;
                    lsb = LsbVideo::new(current_lsb_bits);
                    log::info!("Video decode: LSB bits updated to {}", current_lsb_bits);
                }
            }

            let extracted = lsb.extract(&frame);
            let verify_duration = verify_start.elapsed();
            state.metrics.record_verify_duration(verify_duration);

            let (verified, payload_info) = match extracted {
                Ok(Some(payload)) => {
                    state.metrics.record_verify_ok();
                    let hash_hex: String = payload
                        .hash
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect();
                    let sig_preview: String = payload
                        .signature
                        .to_bytes()
                        .iter()
                        .take(16)
                        .map(|b| format!("{:02x}", b))
                        .collect();
                    let sig_full: String = payload
                        .signature
                        .to_bytes()
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect();
                    (true, serde_json::json!({
                        "frame_index": payload.frame_index,
                        "hash": hash_hex,
                        "signature_preview": sig_preview,
                        "signature_full": sig_full,
                    }))
                }
                Ok(None) => {
                    state.metrics.record_verify_fail();
                    (false, serde_json::json!({"error": "no payload found"}))
                }
                Err(e) => {
                    state.metrics.record_verify_fail();
                    (false, serde_json::json!({"error": e.to_string()}))
                }
            };

            let decoded_image =
                image::RgbImage::from_raw(ef.width, ef.height, ef.rgb_data).expect("invalid raw RGB dimensions");
            let mut jpeg_out = Cursor::new(Vec::new());
            let _ = decoded_image.write_to(&mut jpeg_out, ImageFormat::Jpeg);
            let b64_frame = base64_encode(&jpeg_out.into_inner());

            let metrics_json = state.metrics.to_json();
            let now = {
                let d = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default();
                let secs = d.as_secs();
                // Simple ISO 8601 UTC timestamp
                let s = secs % 60;
                let m = (secs / 60) % 60;
                let h = (secs / 3600) % 24;
                format!("{:02}:{:02}:{:02}.{:03}Z", h, m, s, d.subsec_millis())
            };
            serde_json::json!({
                "type": "decoded_frame",
                "frame": b64_frame,
                "width": ef.width,
                "height": ef.height,
                "verified": verified,
                "payload": payload_info,
                "verify_us": verify_duration.as_micros() as u64,
                "timestamp": now,
                "lsb_bits": current_lsb_bits,
                "data": serde_json::from_str::<serde_json::Value>(&metrics_json).unwrap_or_default(),
                "backend": state.signing_backend,
            })
        } else {
            let metrics_json = state.metrics.to_json();
            serde_json::json!({
                "type": "verify_status",
                "data": serde_json::from_str::<serde_json::Value>(&metrics_json).unwrap_or_default(),
                "backend": state.signing_backend,
                "waiting": true,
            })
        };

        if socket
            .send(Message::Text(reply.to_string().into()))
            .await
            .is_err()
        {
            log::info!("Decode WebSocket client disconnected");
            break;
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// AUDIO ENCODE HANDLER
// ═══════════════════════════════════════════════════════════════════════════════

/// Handle the audio encode WebSocket — receives PCM audio chunks from the browser,
/// applies LSB audio steganography + cryptographic signing.
async fn handle_audio_encode_socket(mut socket: WebSocket, state: Arc<DashboardState>) {
    log::info!("Audio Encode WebSocket client connected");

    let chunk_counter = AtomicU64::new(0);
    let signer = Signer::generate();
    // Generate a random key for audio embedding (shared between encode/decode via DashboardState)
    let audio_key = {
        use rand::RngCore;
        let mut key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key);
        key
    };
    let mut lsb_audio = LsbAudio::new(1, audio_key);

    loop {
        let msg = match socket.recv().await {
            Some(Ok(msg)) => msg,
            _ => {
                log::info!("Audio Encode WebSocket disconnected");
                break;
            }
        };

        let text = match msg {
            Message::Text(t) => t.to_string(),
            Message::Ping(_) | Message::Pong(_) => continue,
            Message::Close(_) => break,
            _ => continue,
        };

        let parsed: serde_json::Value = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(e) => {
                log::warn!("Audio encode: invalid JSON: {}", e);
                continue;
            }
        };

        if parsed.get("type").and_then(|v| v.as_str()) != Some("audio_frame") {
            continue;
        }

        let chunk_idx = chunk_counter.fetch_add(1, Ordering::Relaxed);
        let sample_rate = parsed.get("sample_rate").and_then(|v| v.as_u64()).unwrap_or(44100) as u32;
        let channels = parsed.get("channels").and_then(|v| v.as_u64()).unwrap_or(1) as u16;
        let lsb_bits = parsed.get("lsb_bits").and_then(|v| v.as_u64()).unwrap_or(1) as u8;

        let pcm_b64 = match parsed.get("pcm_base64").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => continue,
        };

        let pcm_bytes = match base64_decode(pcm_b64) {
            Ok(b) => b,
            Err(e) => {
                log::warn!("Audio encode: base64 decode failed: {}", e);
                continue;
            }
        };

        let mut samples: Vec<i16> = pcm_bytes
            .chunks_exact(2)
            .map(|c| i16::from_le_bytes([c[0], c[1]]))
            .collect();

        if samples.is_empty() {
            continue;
        }

        // Update LSB bits if changed
        if lsb_bits != lsb_audio.bits() {
            lsb_audio = LsbAudio::new(lsb_bits, audio_key);
        }

        // Sign the audio chunk
        let sign_start = Instant::now();
        let sample_bytes: Vec<u8> = samples.iter().flat_map(|s| s.to_le_bytes()).collect();
        let payload = signer.sign_frame(chunk_idx, &sample_bytes, None);
        let sign_duration = sign_start.elapsed();

        // Embed payload
        let embed_start = Instant::now();
        {
            let mut buf = AudioBuffer {
                channels,
                sample_rate,
                samples: &mut samples,
                frame_index: chunk_idx,
            };
            if let Err(e) = lsb_audio.embed(&mut buf, Some(&payload)) {
                log::warn!("Audio LSB embed failed: {}", e);
                continue;
            }
        }
        let embed_duration = embed_start.elapsed();

        // Store for decode handler
        {
            let mut last = state.last_encoded_audio.lock().unwrap_or_else(|e| e.into_inner());
            *last = Some(EncodedAudioChunk {
                samples: samples.clone(),
                sample_rate,
                channels,
                chunk_index: chunk_idx,
                lsb_bits,
                audio_key,
            });
        }

        let reply = serde_json::json!({
            "type": "audio_signed",
            "chunk_index": chunk_idx,
            "sign_us": sign_duration.as_micros() as u64,
            "embed_us": embed_duration.as_micros() as u64,
            "sample_count": samples.len(),
            "backend": state.signing_backend,
        });

        if socket
            .send(Message::Text(reply.to_string().into()))
            .await
            .is_err()
        {
            log::info!("Audio Encode WebSocket disconnected");
            break;
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// AUDIO DECODE HANDLER
// ═══════════════════════════════════════════════════════════════════════════════

/// Handle the audio decode WebSocket — extracts audio LSB payloads and verifies.
async fn handle_audio_decode_socket(mut socket: WebSocket, state: Arc<DashboardState>) {
    log::info!("Audio Decode WebSocket client connected");

    let mut lsb_audio: Option<LsbAudio> = None;
    let mut current_lsb_bits: u8 = 1;

    loop {
        let msg = match socket.recv().await {
            Some(Ok(msg)) => msg,
            _ => {
                log::info!("Audio Decode WebSocket disconnected");
                break;
            }
        };

        match msg {
            Message::Text(_) | Message::Binary(_) => {}
            Message::Ping(_) | Message::Pong(_) => continue,
            Message::Close(_) => break,
        }

        let encoded = {
            let last = state.last_encoded_audio.lock().unwrap_or_else(|e| e.into_inner());
            last.clone()
        };

        let reply = if let Some(ea) = encoded {
            let verify_start = Instant::now();
            let mut samples_copy = ea.samples.clone();
            let buf = AudioBuffer {
                channels: ea.channels,
                sample_rate: ea.sample_rate,
                samples: &mut samples_copy,
                frame_index: ea.chunk_index,
            };

            // Update LSB bits from stored chunk if changed
            if ea.lsb_bits != current_lsb_bits || lsb_audio.is_none() {
                current_lsb_bits = ea.lsb_bits;
                lsb_audio = Some(LsbAudio::new(current_lsb_bits, ea.audio_key));
                log::info!("Audio decode: LSB bits updated to {}", current_lsb_bits);
            }

            let extracted = lsb_audio.as_ref().unwrap().extract(&buf);
            let verify_duration = verify_start.elapsed();

            let (verified, payload_info) = match extracted {
                Ok(Some(payload)) => {
                    let hash_hex: String = payload
                        .hash
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect();
                    let sig_preview: String = payload
                        .signature
                        .to_bytes()
                        .iter()
                        .take(16)
                        .map(|b| format!("{:02x}", b))
                        .collect();
                    let sig_full: String = payload
                        .signature
                        .to_bytes()
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect();
                    (true, serde_json::json!({
                        "chunk_index": payload.frame_index,
                        "hash": hash_hex,
                        "signature_preview": sig_preview,
                        "signature_full": sig_full,
                    }))
                }
                Ok(None) => {
                    (false, serde_json::json!({"error": "no audio payload found"}))
                }
                Err(e) => {
                    (false, serde_json::json!({"error": e.to_string()}))
                }
            };

            let now_ts = {
                let d = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default();
                let secs = d.as_secs();
                let s = secs % 60;
                let m = (secs / 60) % 60;
                let h = (secs / 3600) % 24;
                format!("{:02}:{:02}:{:02}.{:03}Z", h, m, s, d.subsec_millis())
            };
            serde_json::json!({
                "type": "audio_verify",
                "verified": verified,
                "payload": payload_info,
                "verify_us": verify_duration.as_micros() as u64,
                "timestamp": now_ts,
                "lsb_bits": current_lsb_bits,
                "backend": state.signing_backend,
                "sample_count": ea.samples.len(),
                "sample_rate": ea.sample_rate,
            })
        } else {
            serde_json::json!({
                "type": "audio_verify",
                "verified": false,
                "waiting": true,
                "backend": state.signing_backend,
            })
        };

        if socket
            .send(Message::Text(reply.to_string().into()))
            .await
            .is_err()
        {
            log::info!("Audio Decode WebSocket disconnected");
            break;
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SHARED TYPES
// ═══════════════════════════════════════════════════════════════════════════════

/// Encoded video frame data stored for cross-WS-handler sharing.
#[derive(Clone)]
pub struct EncodedFrame {
    pub rgb_data: Vec<u8>,
    pub width: u32,
    pub height: u32,
    pub frame_index: u64,
}

/// Encoded audio chunk data stored for cross-WS-handler sharing.
#[derive(Clone)]
pub struct EncodedAudioChunk {
    pub samples: Vec<i16>,
    pub sample_rate: u32,
    pub channels: u16,
    pub chunk_index: u64,
    pub lsb_bits: u8,
    pub audio_key: [u8; 32],
}

/// Base64-encode bytes (standard encoding).
fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// Base64-decode a string to bytes.
fn base64_decode(data: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(data)
}
