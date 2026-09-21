//! Feature-gated tests for the learned watermarker.
//!
//! These run only under `--features learned`; the default-feature test count
//! is unaffected. All tests are deterministic, localhost-only, and require no
//! network, ffmpeg, or webcam (real-H264 coverage lives in
//! `tests/h264_learned.rs` and is optional/probing).

use super::*;

/// Deterministic synthetic cover: smooth gradient plus sinusoidal texture.
fn cover_frame(width: u32, height: u32, seed: u64) -> Vec<u8> {
    let mut data = vec![0u8; (width * height * 3) as usize];
    for y in 0..height as usize {
        for x in 0..width as usize {
            let i = (y * width as usize + x) * 3;
            let g = (40.0
                + 60.0 * (x as f64 / width as f64)
                + 40.0 * ((x as f64 * 0.05 + seed as f64).sin())
                + 30.0 * ((y as f64 * 0.07 + seed as f64 * 0.3).cos()))
                as usize;
            data[i] = (g / 2).clamp(0, 255) as u8;
            data[i + 1] = g.clamp(0, 255) as u8;
            data[i + 2] = (255 - g).clamp(0, 255) as u8;
        }
    }
    data
}

/// Frame header for packed RGB8 with the given stride.
fn rgb_frame(width: u32, height: u32, data: &mut [u8]) -> VideoFrame<'_> {
    VideoFrame {
        width,
        height,
        stride: width * 3,
        format: VideoFormat::Rgb8,
        data,
        frame_index: 0,
    }
}

fn apply_gaussian(frame: &mut VideoFrame, sigma: f64, seed: u64) {
    use rand::{Rng, SeedableRng};
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
    for px in frame.data.chunks_exact_mut(3) {
        for c in px.iter_mut() {
            // Box-Muller with two uniforms, deterministic per pixel.
            let u1: f64 = rng.r#gen::<f64>().max(1e-9);
            let u2: f64 = rng.r#gen();
            let z = (-2.0 * u1.ln()).sqrt() * (std::f64::consts::TAU * u2).cos();
            *c = (*c as f64 + sigma * z).round().clamp(0.0, 255.0) as u8;
        }
    }
}

/// In-repo acceptance analog of H.264 CRF 28: quantize each 8×8 block's DCT
/// coefficients to the simulated step table, then re-synthesize pixels.
fn apply_sim_quantization(frame: &mut VideoFrame) {
    let stride = frame.stride as usize;
    let (bx_n, by_n) = block_grid(frame.width, frame.height);
    let mut block = [0u8; 64];
    for by in 0..by_n {
        for bx in 0..bx_n {
            read_block(frame.data, stride, 3, 1, bx * 8, by * 8, &mut block);
            let mut coeffs = dct_2d(&block);
            for z in 1..64 {
                let step = sim_quant_step(z);
                coeffs[ZIGZAG[z]] = (coeffs[ZIGZAG[z]] / step).round() * step;
            }
            let restored = idct_2d(&coeffs);
            write_block(frame.data, stride, 3, 1, bx * 8, by * 8, &restored);
        }
    }
}

/// Circularly shift frame content by (dx, dy), both multiples of 8.
fn circular_shift(frame: &mut VideoFrame, dx: usize, dy: usize) {
    let w = frame.width as usize;
    let h = frame.height as usize;
    let stride = frame.stride as usize;
    let orig = frame.data.to_vec();
    for y in 0..h {
        for x in 0..w {
            let sx = (x + dx) % w;
            let sy = (y + dy) % h;
            let dst = y * stride + x * 3;
            let src = sy * stride + sx * 3;
            frame.data[dst..dst + 3].copy_from_slice(&orig[src..src + 3]);
        }
    }
}

fn psnr(orig: &[u8], stego: &[u8]) -> f64 {
    let mse: f64 = orig
        .iter()
        .zip(stego.iter())
        .map(|(a, b)| (*a as f64 - *b as f64).powi(2))
        .sum::<f64>()
        / orig.len() as f64;
    if mse == 0.0 {
        return f64::INFINITY;
    }
    10.0 * (255.0_f64 * 255.0 / mse).log10()
}

#[test]
fn built_in_weights_checksum_valid() {
    let wm = LearnedWatermarker::built_in().expect("built-in weights valid");
    assert_eq!(wm.config().bits, 64);
    assert_eq!(wm.config().redundancy, 32);
}

#[test]
fn clean_roundtrip_ber_zero() {
    let wm = LearnedWatermarker::built_in().unwrap();
    let payload = 0x0123_4567_89AB_CDEFu64;
    let mut data = cover_frame(640, 480, 1);
    let orig = data.clone();
    let mut frame = rgb_frame(640, 480, &mut data);
    wm.embed(&mut frame, payload).unwrap();
    let (got, conf) = wm.extract(&frame).expect("extract");
    assert_eq!(got, payload, "clean roundtrip must be lossless");
    assert!(conf > 0.5);
    // PSNR must stay >= 30 dB on 640x480.
    let p = psnr(&orig, frame.data);
    assert!(p >= 30.0, "PSNR {} dB below 30 dB gate", p);
}

#[test]
fn embed_is_deterministic() {
    let wm = LearnedWatermarker::built_in().unwrap();
    let payload = 42u64;
    let mut a = cover_frame(640, 480, 7);
    let mut b = cover_frame(640, 480, 7);
    let mut fa = rgb_frame(640, 480, &mut a);
    let mut fb = rgb_frame(640, 480, &mut b);
    wm.embed(&mut fa, payload).unwrap();
    wm.embed(&mut fb, payload).unwrap();
    assert_eq!(
        fa.data, fb.data,
        "same input must produce identical frame bytes"
    );
}

#[test]
fn gaussian_sigma4_ber_under_2pct() {
    let wm = LearnedWatermarker::built_in().unwrap();
    let payload = 0xDEAD_BEEF_CAFE_0101u64;
    let mut wrong = 0u64;
    for case in 0..8u64 {
        let mut data = cover_frame(640, 480, 100 + case);
        let mut frame = rgb_frame(640, 480, &mut data);
        wm.embed(&mut frame, payload).unwrap();
        apply_gaussian(&mut frame, 4.0, 200 + case);
        let (got, _) = wm.extract(&frame).unwrap();
        wrong += u64::from((got ^ payload).count_ones());
    }
    let ber = wrong as f64 / (64.0 * 8.0);
    assert!(ber < 0.02, "gaussian sigma=4 BER {} >= 2%", ber);
}

#[test]
fn sim_quantization_crf28_ber_under_5pct() {
    let wm = LearnedWatermarker::built_in().unwrap();
    let payload = 0x5555_5555_AAAA_AAAAu64;
    let mut wrong = 0u64;
    for case in 0..8u64 {
        let mut data = cover_frame(640, 480, 300 + case);
        let mut frame = rgb_frame(640, 480, &mut data);
        wm.embed(&mut frame, payload).unwrap();
        apply_sim_quantization(&mut frame);
        let (got, _) = wm.extract(&frame).unwrap();
        wrong += u64::from((got ^ payload).count_ones());
    }
    let ber = wrong as f64 / (64.0 * 8.0);
    assert!(ber < 0.05, "CRF28-sim quantization BER {} >= 5%", ber);
}

#[test]
fn block_aligned_shift_ber_under_10pct() {
    let wm = LearnedWatermarker::built_in().unwrap();
    let payload = 0x0F0F_0F0F_3636_3636u64;
    let shifts = [(8usize, 0usize), (0, 8), (16, 8), (8, 16), (16, 16)];
    let mut wrong = 0u64;
    for (i, (dx, dy)) in shifts.iter().enumerate() {
        let mut data = cover_frame(640, 480, 400 + i as u64);
        let mut frame = rgb_frame(640, 480, &mut data);
        wm.embed(&mut frame, payload).unwrap();
        circular_shift(&mut frame, *dx, *dy);
        let (got, _) = wm.extract(&frame).unwrap();
        wrong += u64::from((got ^ payload).count_ones());
    }
    let ber = wrong as f64 / (64.0 * shifts.len() as f64);
    assert!(ber < 0.10, "block-aligned shift BER {} >= 10%", ber);
}

#[test]
fn embed_extract_640x480_under_50ms() {
    let wm = LearnedWatermarker::built_in().unwrap();
    let mut data = cover_frame(640, 480, 9);
    let mut frame = rgb_frame(640, 480, &mut data);
    let t0 = std::time::Instant::now();
    wm.embed(&mut frame, 0xABCD_1234_5678_90EFu64).unwrap();
    let t1 = std::time::Instant::now();
    let _ = wm.extract(&frame).unwrap();
    let t2 = std::time::Instant::now();
    let embed_ms = (t1 - t0).as_secs_f64() * 1000.0;
    let extract_ms = (t2 - t1).as_secs_f64() * 1000.0;
    // The 50 ms budget is a release-build gate (verified by the trainer at
    // ~20 ms); debug builds assert only a coarse sanity bound and print.
    if cfg!(debug_assertions) {
        println!(
            "640x480 embed {:.1} ms + extract {:.1} ms (debug build; release budget 50 ms)",
            embed_ms, extract_ms
        );
        assert!(embed_ms + extract_ms < 5000.0, "debug embed+extract >= 5 s");
    } else {
        assert!(
            embed_ms + extract_ms < 50.0,
            "embed+extract {} ms >= 50 ms (embed {}, extract {})",
            embed_ms + extract_ms,
            embed_ms,
            extract_ms
        );
    }
}

#[test]
fn mlp_matches_or_beats_majority_on_corrupted_frames() {
    let wm = LearnedWatermarker::built_in().unwrap();
    let mut mlp_wrong = 0u64;
    let mut maj_wrong = 0u64;
    for case in 0..4u64 {
        let payload = 0x1234_5678_9ABC_DEF0u64 + case * 0x0101_0101_0101_0101;
        let mut data = cover_frame(640, 480, 500 + case);
        let mut frame = rgb_frame(640, 480, &mut data);
        wm.embed(&mut frame, payload).unwrap();
        apply_sim_quantization(&mut frame);
        let (m, _) = wm.extract(&frame).unwrap();
        let (j, _) = wm.majority_extract(&frame).unwrap();
        mlp_wrong += u64::from((m ^ payload).count_ones());
        maj_wrong += u64::from((j ^ payload).count_ones());
    }
    assert!(
        mlp_wrong <= maj_wrong,
        "MLP ({} wrong bits) worse than majority ({} wrong bits)",
        mlp_wrong,
        maj_wrong
    );
}
