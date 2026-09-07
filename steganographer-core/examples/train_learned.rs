//! Trains the learned watermarker's MLP and writes `src/learned/weights.bin`.
//!
//! Deterministic: fixed master seed, synthetic covers only, no network, no
//! external datasets. Re-running reproduces the committed weights
//! byte-for-byte on the same platform.
//!
//! ```bash
//! cargo run --release -p steganographer-core --features learned \
//!   --example train_learned
//! ```

#![cfg(feature = "learned")]

use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};
use steganographer_core::learned::{LearnedConfig, LearnedModel, LearnedWatermarker};
use steganographer_core::video::{VideoFormat, VideoFrame};

use ndarray::{Array1, Zip};
use sha2::Digest;

/// Master seed for everything (covers, augmentation, eval, init).
const MASTER_SEED: u64 = 0x4C45_4152_4E45_4400; // "LEARNED\0"

/// Training/eval patch size: 384×384 = 48×48 = 2304 blocks ≥ 64×32 slots.
const PATCH: u32 = 384;

/// Training samples.
const SAMPLES: usize = 192;

/// Epochs.
const EPOCHS: usize = 25;

/// Eval patches per corruption.
const EVAL: usize = 256;

/// Model input width per bit.
const FEATS: usize = 128;

/// Augmentation kinds.
const AUGS: [&str; 6] = [
    "gauss2",
    "gauss4",
    "gauss8",
    "salt1",
    "quant28",
    "blur+shift",
];

/// Synthetic cover of arbitrary size: smooth gradient + sinusoidal curves +
/// smoothed value noise. Seeded PRNG only — no downloads, no datasets.
fn cover(seed: u64, width: u32, height: u32) -> Vec<u8> {
    let mut rng = StdRng::seed_from_u64(seed);
    let grid_n = 7usize;
    let mut grid = vec![0.0f64; grid_n * grid_n];
    for g in grid.iter_mut() {
        *g = rng.r#gen::<f64>();
    }
    let phase: f64 = rng.r#gen::<f64>() * std::f64::consts::TAU;
    let freq: f64 = 0.03 + rng.r#gen::<f64>() * 0.05;
    let mut data = vec![0u8; (width * height * 3) as usize];
    for y in 0..height as usize {
        for x in 0..width as usize {
            let fx = x as f64 / grid_n as f64;
            let fy = y as f64 / grid_n as f64;
            let x0 = fx.floor() as usize % (grid_n - 1);
            let y0 = fy.floor() as usize % (grid_n - 1);
            let smooth = |t: f64| t * t * (3.0 - 2.0 * t);
            let (sx, sy) = (smooth(fx - fx.floor()), smooth(fy - fy.floor()));
            let noise = grid[y0 * grid_n + x0] * (1.0 - sx) * (1.0 - sy)
                + grid[y0 * grid_n + x0 + 1] * sx * (1.0 - sy)
                + grid[(y0 + 1) * grid_n + x0] * (1.0 - sx) * sy
                + grid[(y0 + 1) * grid_n + x0 + 1] * sx * sy;
            let grad = 90.0 + 70.0 * (x + y) as f64 / (width + height) as f64;
            let curve = 30.0 * ((x as f64 * freq + phase).sin() * (y as f64 * freq).cos());
            let g = (grad + curve + 50.0 * noise).clamp(0.0, 255.0);
            let i = (y * width as usize + x) * 3;
            data[i] = (g * 0.6).clamp(0.0, 255.0) as u8;
            data[i + 1] = g as u8;
            data[i + 2] = (255.0 - g).clamp(0.0, 255.0) as u8;
        }
    }
    data
}

fn rgb_frame<'a>(data: &'a mut [u8], width: u32, height: u32) -> VideoFrame<'a> {
    VideoFrame {
        width,
        height,
        stride: width * 3,
        format: VideoFormat::Rgb8,
        data,
        frame_index: 0,
    }
}

/// Simulated CRF28-scale quantization of the green channel's block DCTs.
fn quantize_frame(frame: &mut VideoFrame) {
    let stride = frame.stride as usize;
    let (bx_n, by_n) = (frame.width as usize / 8, frame.height as usize / 8);
    let mut block = [0u8; 64];
    for by in 0..by_n {
        for bx in 0..bx_n {
            read_block(frame.data, stride, bx * 8, by * 8, &mut block);
            let mut coeffs = dct_2d(&block);
            for z in 1..64 {
                let step = steganographer_core::learned::sim_quant_step(z);
                coeffs[zigzag_linear(z)] = (coeffs[zigzag_linear(z)] / step).round() * step;
            }
            let restored = idct_2d(&coeffs);
            write_block(frame.data, stride, bx * 8, by * 8, &restored);
        }
    }
}

/// One augmentation applied in place.
fn augment(frame: &mut VideoFrame, kind: usize, seed: u64) {
    match kind {
        0..=2 => {
            let sigma = [2.0f64, 4.0, 8.0][kind];
            let mut rng = StdRng::seed_from_u64(seed);
            for px in frame.data.chunks_exact_mut(3) {
                for c in px.iter_mut() {
                    let u1: f64 = rng.r#gen::<f64>().max(1e-9);
                    let u2: f64 = rng.r#gen();
                    let z = (-2.0 * u1.ln()).sqrt() * (std::f64::consts::TAU * u2).cos();
                    *c = (*c as f64 + sigma * z).round().clamp(0.0, 255.0) as u8;
                }
            }
        }
        3 => {
            let mut rng = StdRng::seed_from_u64(seed);
            for px in frame.data.chunks_exact_mut(3) {
                if rng.r#gen::<f64>() < 0.01 {
                    let v = if rng.r#gen::<bool>() { 255u8 } else { 0u8 };
                    px[0] = v;
                    px[1] = v;
                    px[2] = v;
                }
            }
        }
        4 => quantize_frame(frame),
        5 => {
            blur2x(frame);
            let mut rng = StdRng::seed_from_u64(seed);
            let dx = 8 * rng.r#gen::<u32>().clamp(0, 2) as usize;
            let dy = 8 * rng.r#gen::<u32>().clamp(0, 2) as usize;
            shift_frame(frame, dx, dy);
        }
        _ => unreachable!(),
    }
}

/// 2× box downscale + bilinear upscale (mild blur).
fn blur2x(frame: &mut VideoFrame) {
    let w = frame.width as usize;
    let h = frame.height as usize;
    let stride = frame.stride as usize;
    let orig = frame.data.to_vec();
    let (sw, sh) = (w / 2, h / 2);
    let mut small = vec![0u8; sw * sh * 3];
    for y in 0..sh {
        for x in 0..sw {
            for c in 0..3 {
                let s = (2 * y) * stride + (2 * x) * 3 + c;
                let v = orig[s] as u32
                    + orig[s + 3] as u32
                    + orig[s + stride] as u32
                    + orig[s + stride + 3] as u32;
                small[(y * sw + x) * 3 + c] = (v / 4) as u8;
            }
        }
    }
    for y in 0..h {
        for x in 0..w {
            let fx = x as f64 / 2.0;
            let fy = y as f64 / 2.0;
            let x0 = (fx.floor() as usize).min(sw - 1);
            let y0 = (fy.floor() as usize).min(sh - 1);
            let x1 = (x0 + 1).min(sw - 1);
            let y1 = (y0 + 1).min(sh - 1);
            let tx = fx - fx.floor();
            let ty = fy - fy.floor();
            for c in 0..3 {
                let p = |yy: usize, xx: usize| small[(yy * sw + xx) * 3 + c] as f64;
                let v = p(y0, x0) * (1.0 - tx) * (1.0 - ty)
                    + p(y0, x1) * tx * (1.0 - ty)
                    + p(y1, x0) * (1.0 - tx) * ty
                    + p(y1, x1) * tx * ty;
                frame.data[y * stride + x * 3 + c] = v.round().clamp(0.0, 255.0) as u8;
            }
        }
    }
}

/// Circular content shift by (dx, dy), multiples of 8.
fn shift_frame(frame: &mut VideoFrame, dx: usize, dy: usize) {
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

// --- DCT helpers (mirroring the module's private machinery) ---

fn cos_basis(n: usize, k: usize) -> f64 {
    let factor = if n == 0 { 1.0 / 2.0_f64.sqrt() } else { 1.0 };
    factor * (std::f64::consts::PI * (2.0 * k as f64 + 1.0) * n as f64 / 16.0).cos()
}

fn dct_2d(block: &[u8; 64]) -> [f64; 64] {
    let mut centered = [0.0f64; 64];
    for i in 0..64 {
        centered[i] = block[i] as f64 - 128.0;
    }
    let mut temp = [0.0f64; 64];
    for i in 0..8 {
        for n in 0..8 {
            let mut sum = 0.0;
            for k in 0..8 {
                sum += centered[i * 8 + k] * cos_basis(n, k);
            }
            temp[i * 8 + n] = sum / 2.0;
        }
    }
    let mut result = [0.0f64; 64];
    for j in 0..8 {
        for n in 0..8 {
            let mut sum = 0.0;
            for k in 0..8 {
                sum += temp[k * 8 + j] * cos_basis(n, k);
            }
            result[n * 8 + j] = sum / 2.0;
        }
    }
    result
}

fn idct_2d(coeffs: &[f64; 64]) -> [u8; 64] {
    let mut temp = [0.0f64; 64];
    for j in 0..8 {
        for k in 0..8 {
            let mut sum = 0.0;
            for n in 0..8 {
                sum += coeffs[n * 8 + j] * cos_basis(n, k);
            }
            temp[k * 8 + j] = sum / 2.0;
        }
    }
    let mut result = [0u8; 64];
    for i in 0..8 {
        for k in 0..8 {
            let mut sum = 0.0;
            for n in 0..8 {
                sum += temp[i * 8 + n] * cos_basis(n, k);
            }
            result[i * 8 + k] = (sum / 2.0 + 128.0).round().clamp(0.0, 255.0) as u8;
        }
    }
    result
}

const ZIGZAG: [usize; 64] = [
    0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5, 12, 19, 26, 33, 40, 48, 41, 34, 27, 20,
    13, 6, 7, 14, 21, 28, 35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51, 58, 59,
    52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63,
];

fn zigzag_linear(z: usize) -> usize {
    ZIGZAG[z.min(63)]
}

fn read_block(data: &[u8], stride: usize, bx: usize, by: usize, out: &mut [u8; 64]) {
    for i in 0..8 {
        for j in 0..8 {
            out[i * 8 + j] = data[(by + i) * stride + (bx + j) * 3 + 1];
        }
    }
}

fn write_block(data: &mut [u8], stride: usize, bx: usize, by: usize, block: &[u8; 64]) {
    for i in 0..8 {
        for j in 0..8 {
            data[(by + i) * stride + (bx + j) * 3 + 1] = block[i * 8 + j];
        }
    }
}

// --- Hand-rolled Adam optimizer over the flat parameter vector ---

struct Adam {
    m: Array1<f32>,
    v: Array1<f32>,
    t: u32,
    lr: f32,
}

impl Adam {
    fn new(n: usize, lr: f32) -> Self {
        Self {
            m: Array1::zeros(n),
            v: Array1::zeros(n),
            t: 0,
            lr,
        }
    }

    fn step(&mut self, params: &mut Array1<f32>, grad: &Array1<f32>) {
        self.t += 1;
        let (b1, b2, eps) = (0.9f32, 0.999f32, 1e-8f32);
        let bc1 = 1.0 - b1.powi(self.t as i32);
        let bc2 = 1.0 - b2.powi(self.t as i32);
        Zip::from(&mut *self.m)
            .and(&mut *self.v)
            .and(grad)
            .and(&mut *params)
            .for_each(|m, v, g, p| {
                *m = b1 * *m + (1.0 - b1) * g;
                *v = b2 * *v + (1.0 - b2) * *g * *g;
                *p -= self.lr * (*m / bc1) / ((*v / bc2).sqrt() + eps);
            });
    }
}

/// Forward pass over the flat parameter vector (trainer-side mirror of
/// `LearnedModel::forward`, kept separate so gradients can be derived).
fn forward_flat(p: &[f32], x: &[f32]) -> ([f32; 32], [f32; 32], f32) {
    let (n_in, n_h) = (FEATS, 32);
    let w1 = &p[0..n_in * n_h];
    let b1 = &p[n_in * n_h..n_in * n_h + n_h];
    let w2 = &p[n_in * n_h + n_h..n_in * n_h + 2 * n_h];
    let b2 = p[n_in * n_h + 2 * n_h];
    let mut pre = [0.0f32; 32];
    let mut act = [0.0f32; 32];
    for h in 0..n_h {
        let mut acc = b1[h];
        for (i, f) in x.iter().enumerate() {
            acc += f * w1[h * n_in + i];
        }
        pre[h] = acc;
        act[h] = acc.tanh();
    }
    let mut logit = b2;
    for h in 0..n_h {
        logit += act[h] * w2[h];
    }
    (pre, act, logit)
}

/// Accumulate BCE-with-logits gradient for one (features, label) pair.
fn backward_one(p: &[f32], x: &[f32], label: f32, grad: &mut [f32]) -> f64 {
    let (n_in, n_h) = (FEATS, 32);
    let w2 = &p[n_in * n_h + n_h..n_in * n_h + 2 * n_h];
    let (_, act, logit) = forward_flat(p, x);
    let label = label as f64;
    let sig = (1.0 / (1.0 + (-logit as f64).exp())).clamp(1e-7, 1.0 - 1e-7);
    let loss = -(label * sig.ln() + (1.0 - label) * (1.0 - sig).ln());
    let dlogit = ((sig - label).clamp(-1.0, 1.0)) as f32;
    // Output layer.
    for h in 0..n_h {
        grad[n_in * n_h + n_h + h] += dlogit * act[h];
    }
    grad[n_in * n_h + 2 * n_h] += dlogit;
    // Hidden layer.
    for h in 0..n_h {
        let dpre = dlogit * w2[h] * (1.0 - act[h] * act[h]);
        for (i, f) in x.iter().enumerate() {
            grad[h * n_in + i] += dpre * f;
        }
        grad[n_in * n_h + h] += dpre;
    }
    loss
}

fn psnr(orig: &[u8], stego: &[u8]) -> f64 {
    let mse = orig
        .iter()
        .zip(stego.iter())
        .map(|(a, b)| (*a as f64 - *b as f64).powi(2))
        .sum::<f64>()
        / orig.len() as f64;
    if mse == 0.0 {
        return f64::INFINITY;
    }
    10.0 * (255.0 * 255.0 / mse).log10()
}

fn main() {
    println!(
        "=== learned watermarker trainer (master seed {:#x}) ===",
        MASTER_SEED
    );
    println!(
        "config: bits=64 redundancy=32 strength=16.0 seed={:#x}",
        LearnedConfig::default().seed
    );

    // Embed with the FIXED chip schedule (weights are irrelevant for embedding).
    let embedder = LearnedWatermarker::with_model(LearnedConfig::default(), LearnedModel::zeroed());

    // --- Training dataset ---
    println!(
        "embedding {} training covers ({}x{})...",
        SAMPLES, PATCH, PATCH
    );
    let mut payloads = Vec::with_capacity(SAMPLES);
    let mut embedded: Vec<Vec<u8>> = Vec::with_capacity(SAMPLES);
    {
        let mut rng = StdRng::seed_from_u64(MASTER_SEED);
        for s in 0..SAMPLES {
            payloads.push(rng.r#gen::<u64>());
            let mut data = cover(MASTER_SEED + 1000 + s as u64, PATCH, PATCH);
            let mut frame = rgb_frame(&mut data, PATCH, PATCH);
            embedder.embed(&mut frame, payloads[s]).unwrap();
            embedded.push(data);
        }
    }

    // --- Precompute augmented training features (fixed per-(sample, kind)
    // seeds; the augmentation set is generated once and reused every epoch) ---
    println!("precomputing {} augmented views...", SAMPLES * AUGS.len());
    let mut train_feats: Vec<Vec<f32>> = Vec::with_capacity(SAMPLES * AUGS.len());
    let mut train_labels: Vec<u64> = Vec::with_capacity(SAMPLES * AUGS.len());
    for s in 0..SAMPLES {
        for kind in 0..AUGS.len() {
            let aseed = MASTER_SEED
                ^ (s as u64).wrapping_mul(0x85EB_CA6B)
                ^ (kind as u64).wrapping_mul(0xC2B2_AE35);
            let mut data = embedded[s].clone();
            {
                let mut frame = rgb_frame(&mut data, PATCH, PATCH);
                augment(&mut frame, kind, aseed);
            }
            let feats = embedder
                .bit_features(&rgb_frame(&mut data, PATCH, PATCH))
                .unwrap();
            train_feats.push(feats);
            train_labels.push(payloads[s]);
        }
    }

    // --- Deterministic init + Adam ---
    let mut init_rng = StdRng::seed_from_u64(MASTER_SEED ^ INIT_SALT);
    let mut params = Array1::<f32>::zeros(LearnedModel::param_count());
    for v in params.iter_mut() {
        *v = (init_rng.r#gen::<f64>() - 0.5) as f32 * 0.02;
    }
    let mut opt = Adam::new(LearnedModel::param_count(), 1e-3);

    let bits_per_epoch = (SAMPLES * AUGS.len() * 64) as f64;
    println!(
        "training: {} epochs over {} views x 64 bits",
        EPOCHS,
        SAMPLES * AUGS.len()
    );
    for epoch in 0..EPOCHS {
        // Deterministic view order per epoch.
        let mut order_rng = StdRng::seed_from_u64(MASTER_SEED ^ (epoch as u64 + 1));
        let mut idx: Vec<usize> = (0..train_feats.len()).collect();
        idx.shuffle(&mut order_rng);
        let mut max_loss = 0.0f64;
        let mut bad = 0usize;
        let mut total_loss = 0.0f64;
        let p_snapshot: Vec<f32> = params.to_vec();
        for &v_i in idx.iter() {
            let mut grad = vec![0.0f32; LearnedModel::param_count()];
            let feats = &train_feats[v_i];
            for b in 0..64 {
                let x = &feats[b * FEATS..(b + 1) * FEATS];
                let l = backward_one(
                    &p_snapshot,
                    x,
                    ((train_labels[v_i] >> (63 - b)) & 1) as f32,
                    &mut grad,
                );
                if l.is_finite() {
                    total_loss += l;
                    max_loss = max_loss.max(l);
                } else {
                    bad += 1;
                }
            }
            // Normalize gradient over the 64 bit losses of this view.
            let g = Array1::from(grad.iter().map(|v| v / 64.0).collect::<Vec<f32>>());
            opt.step(&mut params, &g);
        }
        if (epoch + 1) % 5 == 0 || epoch == 0 {
            println!(
                "  epoch {:3}: mean BCE {:.6} max {:.3} bad {}",
                epoch + 1,
                total_loss / bits_per_epoch,
                max_loss,
                bad
            );
        }
    }
    let model = LearnedModel::from_flat(&params.to_vec()).unwrap();
    let decoder = LearnedWatermarker::with_model(LearnedConfig::default(), model.clone());

    // --- Evaluation: fresh patches, MLP vs majority ---
    println!("\nevaluating on {} fresh patches per corruption...", EVAL);
    println!(
        "{:<14} {:>10} {:>10} {:>+10}",
        "corruption", "BER(mlp)", "BER(maj)", "mlp-maj"
    );
    for (name, kind) in [
        ("clean", 255usize),
        ("gauss2", 0),
        ("gauss4", 1),
        ("gauss8", 2),
        ("salt1", 3),
        ("quant28", 4),
        ("blur+shift", 5),
    ] {
        let mut mlp_wrong = 0u64;
        let mut maj_wrong = 0u64;
        for e in 0..EVAL {
            let payload = StdRng::seed_from_u64(MASTER_SEED + 9000 + e as u64).r#gen();
            let mut data = cover(MASTER_SEED + 7000 + e as u64, PATCH, PATCH);
            {
                let mut frame = rgb_frame(&mut data, PATCH, PATCH);
                embedder.embed(&mut frame, payload).unwrap();
                if kind != 255 {
                    augment(&mut frame, kind, MASTER_SEED + 8000 + e as u64);
                }
            }
            let feats = decoder
                .bit_features(&rgb_frame(&mut data, PATCH, PATCH))
                .unwrap();
            let resp = decoder
                .slot_responses(&rgb_frame(&mut data, PATCH, PATCH))
                .unwrap();
            let mut got = 0u64;
            for b in 0..64 {
                if model.forward(&feats[b * FEATS..(b + 1) * FEATS]) > 0.0 {
                    got |= 1 << (63 - b);
                }
            }
            mlp_wrong += u64::from((got ^ payload).count_ones());
            let mut mj = 0u64;
            for b in 0..64 {
                let mut votes = 0i32;
                for c in 0..32 {
                    votes += if resp[b * 32 + c] >= 0.0 { 1 } else { -1 };
                }
                if votes > 0 {
                    mj |= 1 << (63 - b);
                }
            }
            maj_wrong += u64::from((mj ^ payload).count_ones());
        }
        let n = (64 * EVAL) as f64;
        println!(
            "{:<14} {:>10.5} {:>10.5} {:>+10.5}",
            name,
            mlp_wrong as f64 / n,
            maj_wrong as f64 / n,
            mlp_wrong as f64 / n - maj_wrong as f64 / n
        );
    }

    // --- PSNR + timing at production resolutions ---
    for (w, h) in [(640u32, 480u32), (1280u32, 720u32)] {
        let mut data = cover(MASTER_SEED + 31337 + (w as u64) * 7919, w, h);
        let orig = data.clone();
        let mut frame = rgb_frame(&mut data, w, h);
        let t0 = std::time::Instant::now();
        embedder
            .embed(&mut frame, 0x0123_4567_89AB_CDEFu64)
            .unwrap();
        let t1 = std::time::Instant::now();
        let got = decoder.extract(&frame).unwrap().0;
        let t2 = std::time::Instant::now();
        println!(
            "{}x{}: embed {:.1} ms, extract {:.1} ms, PSNR {:.2} dB, roundtrip {}",
            w,
            h,
            (t1 - t0).as_secs_f64() * 1000.0,
            (t2 - t1).as_secs_f64() * 1000.0,
            psnr(&orig, frame.data),
            if got == 0x0123_4567_89AB_CDEFu64 {
                "OK"
            } else {
                "FAILED"
            }
        );
    }

    // --- Write weights ---
    let bytes: Vec<u8> = model
        .to_flat()
        .iter()
        .flat_map(|v| v.to_le_bytes())
        .collect();
    let digest = blake3::hash(&bytes);
    let sha = sha2::Sha256::digest(&bytes);
    let mut file = Vec::with_capacity(13 + bytes.len() + 32);
    file.extend_from_slice(b"LWM1");
    file.push(1u8);
    file.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    file.extend_from_slice(&bytes);
    file.extend_from_slice(digest.as_bytes());
    let out_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/learned/weights.bin");
    std::fs::write(&out_path, &file).expect("write weights.bin");
    println!("\nweights: {} bytes -> {}", file.len(), out_path.display());
    println!("  blake3: {}", digest);
    println!("  sha256: {:x}", sha);
}

/// Deterministic RNG alias for readability.
use rand::rngs::StdRng;

/// Marker constant mixed into the init seed (arbitrary, documented value).
const INIT_SALT: u64 = 0x0B7E_11E8_53D4_F1A5;
