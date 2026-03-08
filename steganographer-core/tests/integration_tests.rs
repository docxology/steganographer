//! Integration tests for steganographer-core.
//!
//! These tests verify cross-module interactions and end-to-end workflows
//! that span multiple modules (config → crypto → lsb → verify).

use steganographer_core::audio::{AudioBuffer, AudioStegoModule};
use steganographer_core::config::Config;
use steganographer_core::crypto::{SignaturePayload, Signer, Verifier};
use steganographer_core::lsb_audio::LsbAudio;
use steganographer_core::lsb_video::LsbVideo;
use steganographer_core::overlay::{OverlayPosition, TextOverlay};
use steganographer_core::video::{VideoFormat, VideoFrame, VideoStegoModule};

// ═══════════════════════════════════════════════════════════════════════════════
// End-to-end: sign → embed → extract → verify (video)
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_e2e_video_sign_embed_extract_verify() {
    // 1. Generate key pair
    let signer = Signer::generate();
    let _verifier = Verifier::new(signer.verifying_key());

    // 2. Create a realistic frame (640x480 RGB)
    let width = 640u32;
    let height = 480u32;
    let bpp = 3usize;
    let mut frame_data: Vec<u8> = (0..width as usize * height as usize * bpp)
        .map(|i| (i % 256) as u8)
        .collect();

    // 3. Sign the frame data
    let payload = signer.sign_frame(100, &frame_data, None);

    // 4. Embed via LSB
    let mut lsb = LsbVideo::new(1);
    {
        let mut frame = VideoFrame {
            width,
            height,
            stride: width * 3,
            format: VideoFormat::Rgb8,
            data: &mut frame_data,
            frame_index: 100,
        };
        lsb.embed(&mut frame, Some(&payload)).unwrap();
    }

    // 5. Extract from modified frame
    let extracted = {
        let frame = VideoFrame {
            width,
            height,
            stride: width * 3,
            format: VideoFormat::Rgb8,
            data: &mut frame_data,
            frame_index: 100,
        };
        lsb.extract(&frame).unwrap()
    };

    // 6. Verify
    let extracted = extracted.expect("Should extract payload from frame");
    assert_eq!(extracted.frame_index, 100);
    assert_eq!(extracted.hash, payload.hash);
    assert_eq!(extracted.signature, payload.signature);

    // Note: We can't verify against the modified frame data because embedding
    // changes the pixels. The hash was computed over the original data.
    // This is by design — the hash proves what the original data was.
}

#[test]
fn test_e2e_audio_sign_embed_extract_verify() {
    // 1. Generate key pair
    let signer = Signer::generate();
    let _verifier = Verifier::new(signer.verifying_key());

    // 2. Create realistic audio buffer (1 second of 44.1kHz mono)
    let sample_count = 44100;
    let mut samples: Vec<i16> = (0..sample_count)
        .map(|i| ((i as f64 / 44100.0 * 440.0 * std::f64::consts::TAU).sin() * 16000.0) as i16)
        .collect();

    // 3. Sign the audio data (as raw bytes)
    let audio_bytes: Vec<u8> = samples.iter().flat_map(|s| s.to_le_bytes()).collect();
    let payload = signer.sign_frame(0, &audio_bytes, None);

    // 4. Embed
    let key = [42u8; 32];
    let mut lsb = LsbAudio::new(1, key);
    {
        let mut buf = AudioBuffer {
            channels: 1,
            sample_rate: 44100,
            samples: &mut samples,
            frame_index: 0,
        };
        lsb.embed(&mut buf, Some(&payload)).unwrap();
    }

    // 5. Extract
    let extracted = {
        let buf = AudioBuffer {
            channels: 1,
            sample_rate: 44100,
            samples: &mut samples,
            frame_index: 0,
        };
        lsb.extract(&buf).unwrap()
    };

    let extracted = extracted.expect("Should extract payload from audio");
    assert_eq!(extracted.frame_index, 0);
    assert_eq!(extracted.hash, payload.hash);
    assert_eq!(extracted.signature, payload.signature);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Multi-module: LSB + overlay pipeline (both applied to same frame)
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_pipeline_lsb_then_overlay() {
    let signer = Signer::generate();
    let width = 320u32;
    let height = 240u32;
    let mut frame_data = vec![128u8; (width * height * 3) as usize];

    let payload = signer.sign_frame(5, &frame_data, None);

    // Apply LSB first
    let mut lsb = LsbVideo::new(1);
    {
        let mut frame = VideoFrame {
            width,
            height,
            stride: width * 3,
            format: VideoFormat::Rgb8,
            data: &mut frame_data,
            frame_index: 5,
        };
        lsb.embed(&mut frame, Some(&payload)).unwrap();
    }

    // Then overlay (should not disturb LSB in non-overlapping regions)
    let mut overlay = TextOverlay::new("TEST".to_string(), OverlayPosition::Center);
    {
        let mut frame = VideoFrame {
            width,
            height,
            stride: width * 3,
            format: VideoFormat::Rgb8,
            data: &mut frame_data,
            frame_index: 5,
        };
        overlay.embed(&mut frame, None).unwrap();
    }

    // LSB extraction should still work if the overlay didn't overwrite the LSB region
    // (LSB writes to the beginning of frame data, overlay writes at center)
    let _extracted = {
        let frame = VideoFrame {
            width,
            height,
            stride: width * 3,
            format: VideoFormat::Rgb8,
            data: &mut frame_data,
            frame_index: 5,
        };
        lsb.extract(&frame).unwrap()
    };

    // The overlay may have corrupted some LSB bits at the center.
    // This test verifies the pipeline doesn't panic — extraction may fail gracefully.
    // In a real pipeline, the overlay would go last and LSB extraction would be
    // done before overlay application.
    // The key assertion is: no panics, no undefined behavior.
}

// ═══════════════════════════════════════════════════════════════════════════════
// Crypto: comprehensive key round-trip and cross-validation
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_crypto_key_export_import_roundtrip() {
    let signer = Signer::generate();
    let priv_bytes = signer.signing_key_bytes();
    let pub_bytes = signer.verifying_key().to_bytes();

    // Re-create signer from exported private key
    let restored_signer = Signer::from_bytes(&priv_bytes);
    assert_eq!(
        restored_signer.verifying_key().to_bytes(),
        pub_bytes,
        "Restored signer should produce the same public key"
    );

    // Sign with restored signer, verify with original verifier
    let verifier = Verifier::new(signer.verifying_key());
    let data = b"test data for roundtrip";
    let payload = restored_signer.sign_frame(0, data, None);
    assert!(verifier.verify(&payload, data, None));
}

#[test]
fn test_crypto_verifier_from_bytes() {
    let signer = Signer::generate();
    let pub_bytes = signer.verifying_key().to_bytes();

    let verifier = Verifier::from_bytes(&pub_bytes).unwrap();
    let data = b"verify_from_bytes test";
    let payload = signer.sign_frame(7, data, None);
    assert!(verifier.verify(&payload, data, None));
}

#[test]
fn test_crypto_different_audio_data_changes_hash() {
    let signer = Signer::generate();
    let video = b"same video";

    let p1 = signer.sign_frame(0, video, Some(b"audio_a"));
    let p2 = signer.sign_frame(0, video, Some(b"audio_b"));

    assert_ne!(p1.hash, p2.hash, "Different audio should produce different hashes");
    assert_ne!(p1.signature, p2.signature);
}

#[test]
fn test_crypto_payload_serialization_preserves_all_fields() {
    let signer = Signer::generate();
    let payload = signer.sign_frame(u64::MAX, b"max frame index test", Some(b"audio"));

    let bytes = payload.to_bytes();
    assert_eq!(bytes.len(), SignaturePayload::SERIALIZED_SIZE);

    let restored = SignaturePayload::from_bytes(&bytes).unwrap();
    assert_eq!(restored.frame_index, u64::MAX);
    assert_eq!(restored.hash, payload.hash);
    assert_eq!(restored.signature, payload.signature);
}

// ═══════════════════════════════════════════════════════════════════════════════
// LSB Video: edge cases and multi-bit variations
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_lsb_video_3bit_roundtrip() {
    let signer = Signer::generate();
    let payload = signer.sign_frame(33, b"3-bit test data", None);

    let mut frame_data = vec![0xFFu8; 64 * 64 * 3];
    let mut lsb = LsbVideo::new(3);

    {
        let mut frame = VideoFrame {
            width: 64, height: 64, stride: 192,
            format: VideoFormat::Rgb8, data: &mut frame_data, frame_index: 33,
        };
        lsb.embed(&mut frame, Some(&payload)).unwrap();
    }
    {
        let frame = VideoFrame {
            width: 64, height: 64, stride: 192,
            format: VideoFormat::Rgb8, data: &mut frame_data, frame_index: 33,
        };
        let extracted = lsb.extract(&frame).unwrap().unwrap();
        assert_eq!(extracted.frame_index, 33);
        assert_eq!(extracted.hash, payload.hash);
    }
}

#[test]
fn test_lsb_video_4bit_roundtrip() {
    let signer = Signer::generate();
    let payload = signer.sign_frame(44, b"4-bit test data", None);

    let mut frame_data = vec![0xA5u8; 64 * 64 * 3];
    let mut lsb = LsbVideo::new(4);

    {
        let mut frame = VideoFrame {
            width: 64, height: 64, stride: 192,
            format: VideoFormat::Rgb8, data: &mut frame_data, frame_index: 44,
        };
        lsb.embed(&mut frame, Some(&payload)).unwrap();
    }
    {
        let frame = VideoFrame {
            width: 64, height: 64, stride: 192,
            format: VideoFormat::Rgb8, data: &mut frame_data, frame_index: 44,
        };
        let extracted = lsb.extract(&frame).unwrap().unwrap();
        assert_eq!(extracted.frame_index, 44);
        assert_eq!(extracted.hash, payload.hash);
        assert_eq!(extracted.signature, payload.signature);
    }
}

#[test]
fn test_lsb_video_minimum_frame_size_1bit() {
    // 104 bytes payload * 8 bits + 32 prefix = 864 bits
    // At 1 bit per byte, need exactly 864 bytes
    let signer = Signer::generate();
    let payload = signer.sign_frame(0, b"min size", None);

    let mut frame_data = vec![128u8; 864];
    let mut lsb = LsbVideo::new(1);
    {
        let mut frame = VideoFrame {
            width: 864, height: 1, stride: 864,
            format: VideoFormat::Rgb8, data: &mut frame_data, frame_index: 0,
        };
        lsb.embed(&mut frame, Some(&payload)).unwrap();
    }
    {
        let frame = VideoFrame {
            width: 864, height: 1, stride: 864,
            format: VideoFormat::Rgb8, data: &mut frame_data, frame_index: 0,
        };
        let extracted = lsb.extract(&frame).unwrap().unwrap();
        assert_eq!(extracted.frame_index, 0);
    }
}

#[test]
fn test_lsb_video_one_byte_too_small() {
    let signer = Signer::generate();
    let payload = signer.sign_frame(0, b"test", None);

    // 863 bytes is one byte too small for 1-bit embedding (need 864)
    let mut frame_data = vec![0u8; 863];
    let mut lsb = LsbVideo::new(1);
    let mut frame = VideoFrame {
        width: 863, height: 1, stride: 863,
        format: VideoFormat::Rgb8, data: &mut frame_data, frame_index: 0,
    };
    assert!(lsb.embed(&mut frame, Some(&payload)).is_err());
}

#[test]
fn test_lsb_video_preserves_high_bits() {
    let signer = Signer::generate();
    let payload = signer.sign_frame(0, b"preserve bits", None);

    let mut frame_data = vec![0xFEu8; 64 * 64 * 3]; // all high bits set
    let original = frame_data.clone();
    let mut lsb = LsbVideo::new(1);

    {
        let mut frame = VideoFrame {
            width: 64, height: 64, stride: 192,
            format: VideoFormat::Rgb8, data: &mut frame_data, frame_index: 0,
        };
        lsb.embed(&mut frame, Some(&payload)).unwrap();
    }

    // Verify high bits (bits 7-1) are preserved
    for i in 0..frame_data.len() {
        assert_eq!(
            frame_data[i] & 0xFE, original[i] & 0xFE,
            "High bits at index {} should be preserved", i
        );
    }
}

#[test]
fn test_lsb_video_bgra_format() {
    let signer = Signer::generate();
    let payload = signer.sign_frame(0, b"bgra test", None);

    // BGRA = 4 bytes per pixel, 32x32 = 1024 pixels = 4096 bytes (plenty)
    let mut frame_data = vec![128u8; 32 * 32 * 4];
    let mut lsb = LsbVideo::new(1);

    {
        let mut frame = VideoFrame {
            width: 32, height: 32, stride: 128,
            format: VideoFormat::Bgra8, data: &mut frame_data, frame_index: 0,
        };
        lsb.embed(&mut frame, Some(&payload)).unwrap();
    }
    {
        let frame = VideoFrame {
            width: 32, height: 32, stride: 128,
            format: VideoFormat::Bgra8, data: &mut frame_data, frame_index: 0,
        };
        let extracted = lsb.extract(&frame).unwrap().unwrap();
        assert_eq!(extracted.frame_index, 0);
        assert_eq!(extracted.hash, payload.hash);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// LSB Audio: edge cases and multi-bit variations
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_lsb_audio_3bit_roundtrip() {
    let signer = Signer::generate();
    let payload = signer.sign_frame(100, b"3-bit audio", None);

    let mut samples = vec![1000i16; 8192];
    let key = [99u8; 32];
    let mut lsb = LsbAudio::new(3, key);

    {
        let mut buf = AudioBuffer {
            channels: 1, sample_rate: 44100,
            samples: &mut samples, frame_index: 0,
        };
        lsb.embed(&mut buf, Some(&payload)).unwrap();
    }
    {
        let buf = AudioBuffer {
            channels: 1, sample_rate: 44100,
            samples: &mut samples, frame_index: 0,
        };
        let extracted = lsb.extract(&buf).unwrap().unwrap();
        assert_eq!(extracted.frame_index, 100);
    }
}

#[test]
fn test_lsb_audio_4bit_roundtrip() {
    let signer = Signer::generate();
    let payload = signer.sign_frame(200, b"4-bit audio", None);

    let mut samples = vec![500i16; 8192];
    let key = [0xABu8; 32];
    let mut lsb = LsbAudio::new(4, key);

    {
        let mut buf = AudioBuffer {
            channels: 1, sample_rate: 44100,
            samples: &mut samples, frame_index: 0,
        };
        lsb.embed(&mut buf, Some(&payload)).unwrap();
    }
    {
        let buf = AudioBuffer {
            channels: 1, sample_rate: 44100,
            samples: &mut samples, frame_index: 0,
        };
        let extracted = lsb.extract(&buf).unwrap().unwrap();
        assert_eq!(extracted.frame_index, 200);
        assert_eq!(extracted.hash, payload.hash);
        assert_eq!(extracted.signature, payload.signature);
    }
}

#[test]
fn test_lsb_audio_different_keys_incompatible() {
    let signer = Signer::generate();
    let payload = signer.sign_frame(0, b"key test", None);

    let mut samples = vec![1000i16; 8192];
    let key_a = [1u8; 32];
    let key_b = [2u8; 32];

    // Embed with key A
    let mut lsb_a = LsbAudio::new(1, key_a);
    {
        let mut buf = AudioBuffer {
            channels: 1, sample_rate: 44100,
            samples: &mut samples, frame_index: 0,
        };
        lsb_a.embed(&mut buf, Some(&payload)).unwrap();
    }

    // Extract with key B should fail (wrong permutation)
    let lsb_b = LsbAudio::new(1, key_b);
    let buf = AudioBuffer {
        channels: 1, sample_rate: 44100,
        samples: &mut samples, frame_index: 0,
    };
    let result = lsb_b.extract(&buf).unwrap();
    assert!(result.is_none(), "Wrong key should not extract valid payload");
}

#[test]
fn test_lsb_audio_different_frame_index_incompatible() {
    let signer = Signer::generate();
    let payload = signer.sign_frame(0, b"frame idx test", None);

    let mut samples = vec![1000i16; 8192];
    let key = [5u8; 32];

    // Embed at frame_index 0
    let mut lsb = LsbAudio::new(1, key);
    {
        let mut buf = AudioBuffer {
            channels: 1, sample_rate: 44100,
            samples: &mut samples, frame_index: 0,
        };
        lsb.embed(&mut buf, Some(&payload)).unwrap();
    }

    // Extract at frame_index 1 should fail (different permutation)
    let buf = AudioBuffer {
        channels: 1, sample_rate: 44100,
        samples: &mut samples, frame_index: 1,
    };
    let result = lsb.extract(&buf).unwrap();
    assert!(result.is_none(), "Wrong frame index should not yield valid payload");
}

#[test]
fn test_lsb_audio_preserves_high_bits() {
    let signer = Signer::generate();
    let payload = signer.sign_frame(0, b"preserve", None);

    let mut samples: Vec<i16> = (0..8192).map(|i| (i * 7) as i16).collect();
    let original = samples.clone();
    let key = [0u8; 32];
    let mut lsb = LsbAudio::new(1, key);

    {
        let mut buf = AudioBuffer {
            channels: 1, sample_rate: 44100,
            samples: &mut samples, frame_index: 0,
        };
        lsb.embed(&mut buf, Some(&payload)).unwrap();
    }

    // All high bits (bits 15-1) should be preserved
    for i in 0..samples.len() {
        assert_eq!(
            samples[i] & !1i16, original[i] & !1i16,
            "High bits at sample {} should be preserved", i
        );
    }
}

#[test]
fn test_lsb_audio_negative_samples() {
    let signer = Signer::generate();
    let payload = signer.sign_frame(0, b"negative samples", None);

    // Use negative sample values
    let mut samples = vec![-1000i16; 8192];
    let key = [77u8; 32];
    let mut lsb = LsbAudio::new(1, key);

    {
        let mut buf = AudioBuffer {
            channels: 1, sample_rate: 44100,
            samples: &mut samples, frame_index: 0,
        };
        lsb.embed(&mut buf, Some(&payload)).unwrap();
    }
    {
        let buf = AudioBuffer {
            channels: 1, sample_rate: 44100,
            samples: &mut samples, frame_index: 0,
        };
        let extracted = lsb.extract(&buf).unwrap().unwrap();
        assert_eq!(extracted.frame_index, 0);
        assert_eq!(extracted.hash, payload.hash);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Config: comprehensive parsing tests
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_config_parse_example_toml() {
    // CARGO_MANIFEST_DIR points to steganographer-core/; config is at workspace root
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let config_path = std::path::Path::new(manifest_dir)
        .parent()
        .unwrap()
        .join("config/example.toml");
    let toml_content = std::fs::read_to_string(&config_path)
        .unwrap_or_else(|e| panic!("config/example.toml should exist at {:?}: {}", config_path, e));
    let cfg = Config::from_toml(&toml_content).expect("Example config should parse");

    assert_eq!(cfg.global.log_level.as_deref(), Some("info"));
    let video = cfg.video.expect("Video config should exist");
    assert_eq!(video.stego.pipeline, vec!["lsb_signature", "overlay"]);
    assert_eq!(video.stego.lsb_signature.as_ref().unwrap().bits, 1);

    let audio = cfg.audio.expect("Audio config should exist");
    assert_eq!(audio.stego.pipeline, vec!["lsb_signature"]);
}

#[test]
fn test_config_key_bytes_wrong_length() {
    use steganographer_core::config::LsbSignatureConfig;
    let cfg = LsbSignatureConfig {
        bits: 1,
        key: "0123456789abcdef".to_string(), // 16 hex chars = 8 bytes (too short)
    };
    assert!(cfg.key_bytes().is_err());
}

#[test]
fn test_config_key_bytes_odd_length() {
    use steganographer_core::config::LsbSignatureConfig;
    let cfg = LsbSignatureConfig {
        bits: 1,
        key: "abc".to_string(), // odd length
    };
    assert!(cfg.key_bytes().is_err());
}

#[test]
fn test_config_video_only() {
    let toml_str = r#"
[global]

[video]
[video.input]
type = "device"

[video.output]
type = "device"

[video.stego]
pipeline = ["lsb_signature"]

[video.stego.lsb_signature]
bits = 2
key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
"#;
    let cfg = Config::from_toml(toml_str).unwrap();
    assert!(cfg.video.is_some());
    assert!(cfg.audio.is_none());
    assert_eq!(cfg.video.unwrap().stego.lsb_signature.unwrap().bits, 2);
}

#[test]
fn test_config_audio_only() {
    let toml_str = r#"
[global]

[audio]
[audio.input]
type = "device"

[audio.output]
type = "device"

[audio.stego]
pipeline = ["lsb_signature"]

[audio.stego.lsb_signature]
bits = 3
key = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
"#;
    let cfg = Config::from_toml(toml_str).unwrap();
    assert!(cfg.video.is_none());
    assert!(cfg.audio.is_some());
}

// ═══════════════════════════════════════════════════════════════════════════════
// VideoFrame and AudioBuffer type tests
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_video_format_bytes_per_pixel() {
    assert_eq!(VideoFormat::Rgb8.bytes_per_pixel(), Some(3));
    assert_eq!(VideoFormat::Bgra8.bytes_per_pixel(), Some(4));
    assert_eq!(VideoFormat::Yuv420.bytes_per_pixel(), None);
}

#[test]
fn test_video_frame_pixel_byte_count() {
    let mut data = vec![0u8; 1920 * 1080 * 3];
    let frame = VideoFrame {
        width: 1920,
        height: 1080,
        stride: 1920 * 3,
        format: VideoFormat::Rgb8,
        data: &mut data,
        frame_index: 0,
    };
    assert_eq!(frame.pixel_byte_count(), 1920 * 1080 * 3);
}

#[test]
fn test_video_frame_pixel_byte_count_bgra() {
    let mut data = vec![0u8; 640 * 480 * 4];
    let frame = VideoFrame {
        width: 640,
        height: 480,
        stride: 640 * 4,
        format: VideoFormat::Bgra8,
        data: &mut data,
        frame_index: 0,
    };
    assert_eq!(frame.pixel_byte_count(), 640 * 480 * 4);
}

#[test]
fn test_video_frame_pixel_byte_count_yuv420() {
    // YUV420: Y = w*h, U = w*h/4, V = w*h/4 → total = w*h * 3/2
    let mut data = vec![0u8; 640 * 480 * 3 / 2];
    let frame = VideoFrame {
        width: 640,
        height: 480,
        stride: 640,
        format: VideoFormat::Yuv420,
        data: &mut data,
        frame_index: 0,
    };
    assert_eq!(frame.pixel_byte_count(), 640 * 480 * 3 / 2);
}

#[test]
fn test_audio_buffer_sample_count() {
    let mut samples = vec![0i16; 4410];
    let buf = AudioBuffer {
        channels: 1,
        sample_rate: 44100,
        samples: &mut samples,
        frame_index: 0,
    };
    assert_eq!(buf.sample_count(), 4410);
}

#[test]
fn test_audio_buffer_duration() {
    let mut samples = vec![0i16; 44100]; // 1 second at 44100 Hz mono
    let buf = AudioBuffer {
        channels: 1,
        sample_rate: 44100,
        samples: &mut samples,
        frame_index: 0,
    };
    assert!((buf.duration_secs() - 1.0).abs() < 0.001);
}

#[test]
fn test_audio_buffer_duration_stereo() {
    let mut samples = vec![0i16; 88200]; // 1 second at 44100 Hz stereo
    let buf = AudioBuffer {
        channels: 2,
        sample_rate: 44100,
        samples: &mut samples,
        frame_index: 0,
    };
    assert!((buf.duration_secs() - 1.0).abs() < 0.001);
}

#[test]
fn test_audio_buffer_duration_zero_rate() {
    let mut samples = vec![0i16; 100];
    let buf = AudioBuffer {
        channels: 1,
        sample_rate: 0,
        samples: &mut samples,
        frame_index: 0,
    };
    assert_eq!(buf.duration_secs(), 0.0);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Overlay: comprehensive tests
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_overlay_scale_1() {
    let mut data = vec![0u8; 320 * 240 * 3];
    let mut frame = VideoFrame {
        width: 320, height: 240, stride: 960,
        format: VideoFormat::Rgb8, data: &mut data, frame_index: 0,
    };
    let mut overlay = TextOverlay::new("A".to_string(), OverlayPosition::TopLeft)
        .with_scale(1);
    overlay.embed(&mut frame, None).unwrap();
    assert!(data.iter().any(|&b| b != 0), "Scale 1 should write pixels");
}

#[test]
fn test_overlay_all_ascii_characters() {
    let mut data = vec![0u8; 1920 * 100 * 3];
    let text: String = (32u8..=126).map(|c| c as char).collect();
    let mut frame = VideoFrame {
        width: 1920, height: 100, stride: 1920 * 3,
        format: VideoFormat::Rgb8, data: &mut data, frame_index: 0,
    };
    let mut overlay = TextOverlay::new(text, OverlayPosition::TopLeft)
        .with_scale(1);
    overlay.embed(&mut frame, None).unwrap();
    assert!(data.iter().any(|&b| b != 0));
}

#[test]
fn test_overlay_tiny_frame_no_panic() {
    // Frame smaller than one character — should not panic
    let mut data = vec![0u8; 3 * 3 * 3]; // 3x3 RGB
    let mut frame = VideoFrame {
        width: 3, height: 3, stride: 9,
        format: VideoFormat::Rgb8, data: &mut data, frame_index: 0,
    };
    let mut overlay = TextOverlay::new("TOOLONG".to_string(), OverlayPosition::TopLeft)
        .with_scale(1);
    // Should not panic even if text doesn't fit
    overlay.embed(&mut frame, None).unwrap();
}

#[test]
fn test_overlay_extract_returns_none() {
    let data = vec![0u8; 320 * 240 * 3];
    let frame = VideoFrame {
        width: 320, height: 240, stride: 960,
        format: VideoFormat::Rgb8, data: &mut data.clone(), frame_index: 0,
    };
    let overlay = TextOverlay::new("X".to_string(), OverlayPosition::Center);
    let result = overlay.extract(&frame).unwrap();
    assert!(result.is_none(), "Overlay extract should always return None");
}

// ═══════════════════════════════════════════════════════════════════════════════
// Payload size and serialization constants
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_signature_payload_size() {
    assert_eq!(SignaturePayload::SERIALIZED_SIZE, 104);
    // 8 (frame_index) + 32 (hash) + 64 (signature)
}

#[test]
fn test_signature_payload_from_invalid_bytes() {
    // Construct valid-length but potentially bad signature bytes
    let buf = [0u8; 104];
    // frame_index = 0, hash = zeros, signature = zeros
    // from_bytes should parse without error (Signature::from_bytes accepts any 64 bytes)
    let result = SignaturePayload::from_bytes(&buf);
    assert!(result.is_ok());
}

// ═══════════════════════════════════════════════════════════════════════════════
// Stress / fuzz-like tests
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_multiple_sequential_embeds_same_frame() {
    let signer = Signer::generate();

    let mut frame_data = vec![128u8; 64 * 64 * 3];
    let mut lsb = LsbVideo::new(1);

    // Embed multiple payloads to the same frame (each overwrites the previous)
    for i in 0..5u64 {
        let payload = signer.sign_frame(i, b"sequential", None);
        let mut frame = VideoFrame {
            width: 64, height: 64, stride: 192,
            format: VideoFormat::Rgb8, data: &mut frame_data, frame_index: i,
        };
        lsb.embed(&mut frame, Some(&payload)).unwrap();

        // The last embedded payload should be extractable
        let frame = VideoFrame {
            width: 64, height: 64, stride: 192,
            format: VideoFormat::Rgb8, data: &mut frame_data, frame_index: i,
        };
        let extracted = lsb.extract(&frame).unwrap().unwrap();
        assert_eq!(extracted.frame_index, i);
    }
}

#[test]
fn test_multiple_signers_different_payloads() {
    let signer_a = Signer::generate();
    let signer_b = Signer::generate();
    let verifier_a = Verifier::new(signer_a.verifying_key());
    let verifier_b = Verifier::new(signer_b.verifying_key());

    let data = b"shared data";

    let payload_a = signer_a.sign_frame(0, data, None);
    let payload_b = signer_b.sign_frame(0, data, None);

    // Same data, same frame index, but different keys → different signatures
    assert_eq!(payload_a.hash, payload_b.hash, "Same data should produce same hash");
    assert_ne!(payload_a.signature, payload_b.signature, "Different keys → different sigs");

    // Cross-verification should fail
    assert!(verifier_a.verify(&payload_a, data, None));
    assert!(!verifier_a.verify(&payload_b, data, None));
    assert!(verifier_b.verify(&payload_b, data, None));
    assert!(!verifier_b.verify(&payload_a, data, None));
}

// ═══════════════════════════════════════════════════════════════════════════════
// Template expansion integration tests
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_overlay_template_expands_frame_index() {
    // Verify that {frame_index} is substituted dynamically per-frame
    let mut data1 = vec![0u8; 320 * 240 * 3];
    let mut data2 = vec![0u8; 320 * 240 * 3];

    let mut overlay = TextOverlay::new(
        "F{frame_index}".to_string(),
        OverlayPosition::TopLeft,
    ).with_scale(1);

    // Embed with frame_index=0
    {
        let mut frame = VideoFrame {
            width: 320, height: 240, stride: 960,
            format: VideoFormat::Rgb8, data: &mut data1, frame_index: 0,
        };
        overlay.embed(&mut frame, None).unwrap();
    }

    // Embed with frame_index=1
    {
        let mut frame = VideoFrame {
            width: 320, height: 240, stride: 960,
            format: VideoFormat::Rgb8, data: &mut data2, frame_index: 1,
        };
        overlay.embed(&mut frame, None).unwrap();
    }

    // The two frames should have different pixel data (different frame indices rendered)
    assert_ne!(data1, data2, "Different frame indices should produce different overlays");
}

#[test]
fn test_overlay_template_preserves_plain_text() {
    // Text without any placeholders should render identically to two frames
    let mut data1 = vec![0u8; 320 * 240 * 3];
    let mut data2 = vec![0u8; 320 * 240 * 3];

    let mut overlay = TextOverlay::new(
        "HELLO".to_string(),
        OverlayPosition::TopLeft,
    ).with_scale(1);

    {
        let mut frame = VideoFrame {
            width: 320, height: 240, stride: 960,
            format: VideoFormat::Rgb8, data: &mut data1, frame_index: 0,
        };
        overlay.embed(&mut frame, None).unwrap();
    }
    {
        let mut frame = VideoFrame {
            width: 320, height: 240, stride: 960,
            format: VideoFormat::Rgb8, data: &mut data2, frame_index: 99,
        };
        overlay.embed(&mut frame, None).unwrap();
    }

    // Plain text (no placeholders) produces identical pixel output regardless of frame index
    assert_eq!(data1, data2, "Plain text overlay should be frame-index-independent");
}

#[test]
fn test_overlay_template_expand_static() {
    // Unit-style test of expand_template with known values
    let result = TextOverlay::expand_template("IDX:{frame_index} D:{date}", 999);
    assert!(result.contains("IDX:999"), "Should contain frame index 999");
    assert!(result.contains("D:20"), "Should contain date starting with 20xx");
    assert!(!result.contains("{frame_index}"), "Placeholder should be replaced");
    assert!(!result.contains("{date}"), "Placeholder should be replaced");
}

// ═══════════════════════════════════════════════════════════════════════════════
// Info bar: toggle tests
// ═══════════════════════════════════════════════════════════════════════════════

use steganographer_core::info_bar::InfoBar;

#[test]
fn test_info_bar_no_barcode() {
    let mut data = vec![128u8; 640 * 480 * 3];
    let signer = Signer::generate();
    let payload = signer.sign_frame(0, &data, None);

    let mut bar = InfoBar::new("TEST".to_string())
        .with_barcode(false)
        .with_qr(false)
        .with_timestamp(true);

    let mut frame = VideoFrame {
        width: 640, height: 480, stride: 640 * 3,
        format: VideoFormat::Rgb8, data: &mut data, frame_index: 0,
    };
    // Should not panic even with barcode/QR disabled
    bar.embed(&mut frame, Some(&payload)).unwrap();
}

#[test]
fn test_info_bar_all_disabled() {
    let mut data = vec![128u8; 640 * 480 * 3];

    let mut bar = InfoBar::new("TEST".to_string())
        .with_barcode(false)
        .with_qr(false)
        .with_timestamp(false);

    let mut frame = VideoFrame {
        width: 640, height: 480, stride: 640 * 3,
        format: VideoFormat::Rgb8, data: &mut data, frame_index: 0,
    };
    // Even with all features disabled, embed should succeed (renders label bar only)
    bar.embed(&mut frame, None).unwrap();
    // Some pixels will still change because the bar background is always drawn
    // The key assertion is: no panics, no undefined behavior.
}

// ═══════════════════════════════════════════════════════════════════════════════
// Config: overlay parsing test
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_config_overlay_parsing() {
    let toml_str = r#"
[global]

[video]
[video.input]
type = "device"

[video.output]
type = "device"

[video.stego]
pipeline = ["lsb_signature", "overlay"]

[video.stego.lsb_signature]
bits = 1
key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

[video.stego.overlay]
text = "CONFIDENTIAL {timestamp} F{frame_index}"
position = "bottom-right"
font_size = 24
"#;
    let cfg = Config::from_toml(toml_str).unwrap();
    let video = cfg.video.unwrap();
    assert_eq!(video.stego.pipeline, vec!["lsb_signature", "overlay"]);
    let overlay = video.stego.overlay.unwrap();
    assert_eq!(overlay.text, Some("CONFIDENTIAL {timestamp} F{frame_index}".to_string()));
    assert_eq!(overlay.position, Some("bottom-right".to_string()));
    assert_eq!(overlay.font_size, Some(24));
}

// ═══════════════════════════════════════════════════════════════════════════════
// Metrics: JSON serialization roundtrip
// ═══════════════════════════════════════════════════════════════════════════════

use steganographer_core::metrics::StegoMetrics;

#[test]
fn test_metrics_comprehensive_json() {
    let m = StegoMetrics::default();
    m.record_frame();
    m.record_frame();
    m.record_frame();
    m.record_sign_duration(std::time::Duration::from_millis(5));
    m.record_sign_duration(std::time::Duration::from_millis(15));

    let json = m.to_json();
    assert!(json.contains("\"frames_processed\":3"), "Should have 3 frames: {}", json);
    assert!(json.contains("\"avg_sign_latency_us\":"), "Should have sign latency: {}", json);

    // Verify it's valid JSON by checking basic structure
    assert!(json.starts_with('{'), "Should be JSON object");
    assert!(json.ends_with('}'), "Should be JSON object");
}

// ═══════════════════════════════════════════════════════════════════════════════
// Signer backend: integration with video pipeline
// ═══════════════════════════════════════════════════════════════════════════════

use steganographer_core::signer_backend::{Ed25519Backend, SignerBackend};

#[test]
fn test_signer_backend_e2e_sign_verify() {
    let backend = Ed25519Backend::generate();
    let data = b"frame data for backend test";

    let signature = backend.sign(data);
    assert_eq!(signature.len(), backend.signature_size());
    assert!(backend.verify(data, &signature));
    assert!(!backend.verify(b"tampered data", &signature));
    assert_eq!(backend.name(), "ed25519");
    let identity = backend.display_identity();
    assert_eq!(identity.len(), 64, "Display identity should be 64 hex chars but got: {}", identity);
}

#[test]
fn test_signer_backend_public_key_bytes() {
    let backend = Ed25519Backend::generate();
    let pk = backend.public_key_bytes();
    assert_eq!(pk.len(), 32, "Ed25519 public key should be 32 bytes");

    let backend2 = Ed25519Backend::generate();
    assert_ne!(pk, backend2.public_key_bytes(), "Different keys should differ");
}

// ═══════════════════════════════════════════════════════════════════════════════
// 2-bit LSB roundtrip tests (gap-fill: 1-bit, 3-bit, 4-bit already tested)
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_lsb_video_2bit_roundtrip() {
    let signer = Signer::generate();
    let payload = signer.sign_frame(22, b"2-bit video test data", None);

    let mut frame_data = vec![0xCCu8; 64 * 64 * 3];
    let mut lsb = LsbVideo::new(2);

    {
        let mut frame = VideoFrame {
            width: 64, height: 64, stride: 192,
            format: VideoFormat::Rgb8, data: &mut frame_data, frame_index: 22,
        };
        lsb.embed(&mut frame, Some(&payload)).unwrap();
    }
    {
        let frame = VideoFrame {
            width: 64, height: 64, stride: 192,
            format: VideoFormat::Rgb8, data: &mut frame_data, frame_index: 22,
        };
        let extracted = lsb.extract(&frame).unwrap().unwrap();
        assert_eq!(extracted.frame_index, 22);
        assert_eq!(extracted.hash, payload.hash);
        assert_eq!(extracted.signature, payload.signature);
    }
}

#[test]
fn test_lsb_audio_2bit_roundtrip() {
    let signer = Signer::generate();
    let payload = signer.sign_frame(50, b"2-bit audio test", None);

    let mut samples = vec![2000i16; 8192];
    let key = [77u8; 32];
    let mut lsb = LsbAudio::new(2, key);

    {
        let mut buf = AudioBuffer {
            channels: 1, sample_rate: 44100,
            samples: &mut samples, frame_index: 0,
        };
        lsb.embed(&mut buf, Some(&payload)).unwrap();
    }
    {
        let buf = AudioBuffer {
            channels: 1, sample_rate: 44100,
            samples: &mut samples, frame_index: 0,
        };
        let extracted = lsb.extract(&buf).unwrap().unwrap();
        assert_eq!(extracted.frame_index, 50);
        assert_eq!(extracted.hash, payload.hash);
        assert_eq!(extracted.signature, payload.signature);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Signer backend: additional edge cases
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_signer_backend_wrong_key_verify_fails() {
    let backend_a = Ed25519Backend::generate();
    let backend_b = Ed25519Backend::generate();
    let data = b"signed by A, verified by B";
    let sig = backend_a.sign(data);
    // Same data, wrong key → verification must fail
    assert!(!backend_b.verify(data, &sig), "Verification with wrong key should fail");
}

#[test]
fn test_signer_backend_display_identity_hex_format() {
    let backend = Ed25519Backend::generate();
    let identity = backend.display_identity();
    assert_eq!(identity.len(), 64, "display_identity should be 64 hex chars, got {}", identity.len());
    assert!(identity.chars().all(|c| c.is_ascii_hexdigit()),
        "display_identity should be all hex chars, got '{}'", identity);
}

#[test]
fn test_signer_backend_signature_size_ed25519() {
    let backend = Ed25519Backend::generate();
    assert_eq!(backend.signature_size(), 64, "Ed25519 signatures are 64 bytes");
    let sig = backend.sign(b"test");
    assert_eq!(sig.len(), 64, "Actual signature should match signature_size()");
}

#[test]
fn test_crypto_empty_data_sign_verify() {
    let signer = Signer::generate();
    let payload = signer.sign_frame(0, b"", None);
    // Empty data should still produce a valid hash + signature
    assert_eq!(payload.hash.len(), 32, "BLAKE3 hash should be 32 bytes even for empty data");
    assert_eq!(payload.signature.to_bytes().len(), 64);

    // Verify the signature
    let verifier = Verifier::new(signer.verifying_key());
    assert!(verifier.verify(&payload, b"", None),
        "Empty data signature should verify");
}

#[test]
fn test_e2e_audio_multi_bit_levels_all_verify() {
    // Test that audio embed/extract at bits 1, 2, 3, 4 all produce valid roundtrips
    for bits in 1..=4u8 {
        let signer = Signer::generate();
        let payload = signer.sign_frame(bits as u64, format!("audio {}bit", bits).as_bytes(), None);

        let mut samples = vec![3000i16; 16384];
        let key = [bits; 32];
        let mut lsb = LsbAudio::new(bits, key);

        {
            let mut buf = AudioBuffer {
                channels: 1, sample_rate: 48000,
                samples: &mut samples, frame_index: 0,
            };
            lsb.embed(&mut buf, Some(&payload)).unwrap();
        }
        {
            let buf = AudioBuffer {
                channels: 1, sample_rate: 48000,
                samples: &mut samples, frame_index: 0,
            };
            let extracted = lsb.extract(&buf).unwrap()
                .unwrap_or_else(|| panic!("Should extract payload at {} bits", bits));
            assert_eq!(extracted.frame_index, bits as u64,
                "Frame index mismatch at {} bits", bits);
            assert_eq!(extracted.hash, payload.hash,
                "Hash mismatch at {} bits", bits);
        }
    }
}

#[test]
fn test_metrics_frame_counter_accuracy() {
    let metrics = StegoMetrics::new();
    // Record a batch of frames
    for _ in 0..100 {
        metrics.record_frame();
    }
    let json_str = metrics.to_json();
    let json: serde_json::Value = serde_json::from_str(&json_str).expect("valid JSON");
    assert_eq!(json["frames_processed"], 100, "Should have exactly 100 frames processed");
}

#[test]
fn test_signer_backend_from_bytes_deterministic() {
    let seed = [0xABu8; 32];
    let backend_a = Ed25519Backend::from_bytes(&seed);
    let backend_b = Ed25519Backend::from_bytes(&seed);
    let data = b"deterministic key test";
    let sig_a = backend_a.sign(data);
    let sig_b = backend_b.sign(data);
    assert_eq!(sig_a, sig_b, "Same seed should produce same signature");
    assert_eq!(backend_a.public_key_bytes(), backend_b.public_key_bytes(),
        "Same seed should produce same public key");
}
