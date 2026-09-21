//! Learned watermarking: trained-MLP DCT-chip decoding (opt-in `learned` feature).
//!
//! This module embeds a 64-bit payload into the mid-frequency coefficients of
//! 8×8 block DCTs (the same domain as [`crate::dct_video`]) using a keyed,
//! BLAKE3-derived chip schedule, and decodes it with a tiny trained MLP
//! (128 → 32 → 1) instead of a hard threshold. A plain majority-vote baseline
//! over the redundant slots is also provided for comparison.
//!
//! ## Design
//!
//! 1. The frame is divided into 8×8 blocks; `bits × redundancy` slots (64 × 32
//!    = 2048 by default) are assigned to distinct blocks via a seeded
//!    Fisher–Yates shuffle, so every bit is carried by `redundancy`
//!    spread-out blocks.
//! 2. Each slot spreads one bit over 6 mid-frequency coefficients with
//!    ±`strength` chips; coefficient choice and chip signs are derived
//!    deterministically from BLAKE3 of `(seed, bit, copy)`.
//! 3. The decoder gathers the redundant slots' chip responses per bit, builds
//!    a 128-dimensional feature vector (4 statistics per slot, pooled when
//!    `redundancy ≠ 32`), and feeds it through the trained MLP. It also tries
//!    a small set of block-aligned candidate shifts and keeps the alignment
//!    with the strongest mean chip response, which makes the decode robust to
//!    block-aligned (multiples-of-8) content shifts within the frame.
//!
//! ## What is trained vs fixed
//!
//! *Trained* (committed in `weights.bin`): the 4161 MLP parameters
//! (`W1 128×32`, `b1 32`, `W2 32`, `b2 1`). Everything else — the carrier,
//! schedule, chip count, feature definition, and alignment search — is fixed
//! algorithm code. The committed weights are THE artifact: tests pass without
//! re-running the trainer.
//!
//! ## Reproducible retraining
//!
//! ```bash
//! cargo run --release -p steganographer-core --features learned \
//!   --example train_learned
//! ```
//! The trainer is fully deterministic: fixed master seed `0x4C4541524E4544`
//! ("LEARNED") drives cover synthesis, embedding, augmentation, evaluation,
//! and weight initialization, so re-running it reproduces `weights.bin`
//! byte-for-byte on the same platform.
//!
//! ## Honest limits
//!
//! The model is intentionally tiny and trained on synthetic covers only.
//! Scaling to production robustness (real footage, H.264/H.265 at varied CRF,
//! scaling/rotation) requires the full training run — dataset licensing and
//! model budget are owner-gated and out of scope here. See
//! `docs/algorithms.md` ("Learned watermarking") for the measured BER table.

use crate::video::{VideoFormat, VideoFrame};

/// Block size for DCT processing (8×8, as in JPEG).
const BLOCK: usize = 8;

/// Zigzag scan order mapping zigzag index → row-major linear index.
const ZIGZAG: [usize; 64] = [
    0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5, 12, 19, 26, 33, 40, 48, 41, 34, 27, 20,
    13, 6, 7, 14, 21, 28, 35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51, 58, 59,
    52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63,
];

/// Mid-frequency coefficient pool (zigzag indices 8..=40, DC and low/high
/// frequencies excluded). Chips are placed inside this band.
const MID_POOL: [usize; 33] = {
    let mut pool = [0usize; 33];
    let mut i = 0;
    while i < 33 {
        pool[i] = ZIGZAG[8 + i];
        i += 1;
    }
    pool
};

/// Number of coefficients (chips) per slot.
const CHIPS: usize = 6;

/// Per-slot feature count fed to the model (pooled across slots to 128 inputs).
const SLOT_FEATURES: usize = 4;

/// Model input width (`SLOT_FEATURES × DEFAULT_REDUNDANCY`).
const MODEL_INPUT: usize = 128;

/// Model hidden width.
const HIDDEN: usize = 32;

/// Weights file magic: `LWM1`.
const MAGIC: &[u8; 4] = b"LWM1";

/// Weights file format version.
const VERSION: u8 = 1;

/// Number of model parameters: 128×32 + 32 + 32 + 1.
const PARAM_COUNT: usize = MODEL_INPUT * HIDDEN + HIDDEN + HIDDEN + 1;

/// Configuration for the learned watermarker.
#[derive(Debug, Clone)]
pub struct LearnedConfig {
    /// Payload width in bits. Default 64 (the model decodes a `u64`).
    pub bits: u8,
    /// Independent per-bit copies (slots). Default 32; the shipped model was
    /// trained at 32 and other values are feature-pooled to the model input.
    pub redundancy: u16,
    /// Chip magnitude added to each mid-frequency DCT coefficient.
    /// Default 16.0: embed energy clears the CRF28-scale quantization step
    /// (≈27 for mid frequencies in the simulated table) while keeping
    /// 640×480 PSNR ≈ 32 dB.
    pub strength: f32,
    /// Master seed for the keyed schedule. Default `0x4C4541524E4544`.
    pub seed: u64,
}

impl Default for LearnedConfig {
    fn default() -> Self {
        Self {
            bits: 64,
            redundancy: 32,
            strength: 16.0,
            seed: 0x004C_4541_524E_4544,
        }
    }
}

/// Precomputed DCT basis value: `cos(pi (2k+1) n / 16)` with DC normalization.
fn cos_basis(n: usize, k: usize) -> f64 {
    let factor = if n == 0 { 1.0 / 2.0_f64.sqrt() } else { 1.0 };
    factor * (std::f64::consts::PI * (2.0 * k as f64 + 1.0) * n as f64 / 16.0).cos()
}

/// Forward 2D DCT of an 8×8 block (row-major), mirroring `dct_video.rs`.
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

/// Inverse 2D DCT of 64 coefficients, clamped to valid `u8` pixels.
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
            let val = (sum / 2.0 + 128.0).round();
            result[i * 8 + k] = val.clamp(0.0, 255.0) as u8;
        }
    }
    result
}

/// Derive a 64-bit value from BLAKE3 of a domain-separated byte string.
fn hash_u64(parts: &[&[u8]]) -> u64 {
    let mut hasher = blake3::Hasher::new();
    for p in parts {
        hasher.update(&(p.len() as u32).to_le_bytes());
        hasher.update(p);
    }
    let out = hasher.finalize();
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&out.as_bytes()[0..8]);
    u64::from_le_bytes(bytes)
}

/// Deterministic chip schedule for one slot: 6 distinct mid-frequency linear
/// coefficient indices and ±1 signs, derived from BLAKE3 of
/// `("lwm-chip", seed, bit, copy)`.
fn slot_chip(seed: u64, bit: usize, copy: usize) -> ([usize; CHIPS], [f32; CHIPS]) {
    let mut coeffs = [0usize; CHIPS];
    let mut signs = [0.0f32; CHIPS];
    let mut chosen = [false; 64];
    let mut used = 0;
    let mut round: u64 = 0;
    while used < CHIPS {
        let h = hash_u64(&[
            b"lwm-chip",
            &seed.to_le_bytes(),
            &(bit as u64).to_le_bytes(),
            &(copy as u64).to_le_bytes(),
            &round.to_le_bytes(),
        ]);
        for word in 0..4 {
            if used >= CHIPS {
                break;
            }
            let idx = MID_POOL[((h >> (word * 16)) & 0x1f) as usize % MID_POOL.len()];
            if !chosen[idx] {
                chosen[idx] = true;
                coeffs[used] = idx;
                signs[used] = if (h >> (60 + word)) & 1 == 0 {
                    1.0
                } else {
                    -1.0
                };
                used += 1;
            }
        }
        round += 1;
    }
    (coeffs, signs)
}

/// Deterministic block ordering: a seeded Fisher–Yates shuffle of all block
/// linear indices. Slot `j` is assigned to block `order[j]`.
fn block_order(seed: u64, blocks_x: usize, blocks_y: usize) -> Vec<usize> {
    use rand::seq::SliceRandom;
    use rand::SeedableRng;
    let dims_hash = hash_u64(&[
        b"lwm-dims",
        &seed.to_le_bytes(),
        &(blocks_x as u64).to_le_bytes(),
        &(blocks_y as u64).to_le_bytes(),
    ]);
    let mut rng = rand::rngs::StdRng::seed_from_u64(dims_hash);
    let mut order: Vec<usize> = (0..blocks_x * blocks_y).collect();
    order.shuffle(&mut rng);
    order
}

/// Trained MLP model (128 → 32 → 1, tanh hidden activation).
///
/// Parameter layout (little-endian f32): `W1[128×32]`, `b1[32]`, `W2[32]`, `b2[1]`.
#[derive(Debug, Clone)]
pub struct LearnedModel {
    w1: Vec<f32>,
    b1: [f32; HIDDEN],
    w2: [f32; HIDDEN],
    b2: f32,
}

impl LearnedModel {
    /// Zero-initialized model (used by the trainer before optimization).
    pub fn zeroed() -> Self {
        Self {
            w1: vec![0.0; MODEL_INPUT * HIDDEN],
            b1: [0.0; HIDDEN],
            w2: [0.0; HIDDEN],
            b2: 0.0,
        }
    }

    /// Build from a flat little-endian f32 parameter vector.
    pub fn from_flat(flat: &[f32]) -> anyhow::Result<Self> {
        if flat.len() != PARAM_COUNT {
            anyhow::bail!(
                "flat params must have {} entries, got {}",
                PARAM_COUNT,
                flat.len()
            );
        }
        let mut it = flat.iter().copied();
        let w1: Vec<f32> = it.by_ref().take(MODEL_INPUT * HIDDEN).collect();
        let mut b1 = [0.0f32; HIDDEN];
        for slot in b1.iter_mut() {
            *slot = it.next().expect("length checked");
        }
        let mut w2 = [0.0f32; HIDDEN];
        for slot in w2.iter_mut() {
            *slot = it.next().expect("length checked");
        }
        Ok(Self {
            w1,
            b1,
            w2,
            b2: it.next().expect("length checked"),
        })
    }

    /// Flat little-endian f32 parameter vector (w1, b1, w2, b2).
    pub fn to_flat(&self) -> Vec<f32> {
        let mut out = Vec::with_capacity(PARAM_COUNT);
        out.extend_from_slice(&self.w1);
        out.extend_from_slice(&self.b1);
        out.extend_from_slice(&self.w2);
        out.push(self.b2);
        out
    }

    /// Accessor for the hidden-layer weight matrix row-major (W1).
    pub fn w1(&self) -> &[f32] {
        &self.w1
    }

    /// Hidden bias vector (b1).
    pub fn b1(&self) -> &[f32] {
        &self.b1
    }

    /// Output weight vector (W2).
    pub fn w2(&self) -> &[f32] {
        &self.w2
    }

    /// Output bias (b2).
    pub fn b2(&self) -> f32 {
        self.b2
    }

    /// Total parameter count (4161).
    pub const fn param_count() -> usize {
        PARAM_COUNT
    }

    /// Serialize parameters to little-endian f32 bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PARAM_COUNT * 4);
        for v in self.w1.iter().chain(self.b1.iter()).chain(self.w2.iter()) {
            out.extend_from_slice(&v.to_le_bytes());
        }
        out.extend_from_slice(&self.b2.to_le_bytes());
        out
    }

    /// Parse parameters from little-endian f32 bytes (exact length required).
    pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() != PARAM_COUNT * 4 {
            anyhow::bail!(
                "learned model payload must be {} bytes, got {}",
                PARAM_COUNT * 4,
                bytes.len()
            );
        }
        let mut vals = Vec::with_capacity(PARAM_COUNT);
        for chunk in bytes.chunks_exact(4) {
            vals.push(f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
        }
        let mut it = vals.into_iter();
        let w1: Vec<f32> = it.by_ref().take(MODEL_INPUT * HIDDEN).collect();
        let mut b1 = [0.0f32; HIDDEN];
        for slot in b1.iter_mut() {
            *slot = it.next().expect("length checked");
        }
        let mut w2 = [0.0f32; HIDDEN];
        for slot in w2.iter_mut() {
            *slot = it.next().expect("length checked");
        }
        let b2 = it.next().expect("length checked");
        Ok(Self { w1, b1, w2, b2 })
    }

    /// Forward pass: returns the logit for one bit's feature vector.
    pub fn forward(&self, features: &[f32]) -> f32 {
        debug_assert_eq!(features.len(), MODEL_INPUT);
        let mut logit = self.b2;
        for h in 0..HIDDEN {
            let mut acc = self.b1[h];
            let col = &self.w1[h * MODEL_INPUT..(h + 1) * MODEL_INPUT];

            for (f, w) in features.iter().zip(col.iter()) {
                acc += f * w;
            }
            logit += acc.tanh() * self.w2[h];
        }
        logit
    }

    /// Sigmoid confidence for a logit.
    pub fn confidence(logit: f32) -> f32 {
        1.0 / (1.0 + (-logit).exp())
    }
}

/// Learned watermarker: embeds/extracts a 64-bit payload with the trained model.
///
/// All calls are pure CPU and deterministic given the committed weights.
pub struct LearnedWatermarker {
    config: LearnedConfig,
    model: LearnedModel,
}

impl LearnedWatermarker {
    /// Load the committed trained weights (`weights.bin`) with the default
    /// configuration, validating magic, version, length, and BLAKE3 checksum.
    pub fn built_in() -> anyhow::Result<Self> {
        Self::with_config(LearnedConfig::default())
    }

    /// Load the committed trained weights with a custom configuration.
    ///
    /// `bits` must be 64 (the model decodes a `u64` payload).
    pub fn with_config(config: LearnedConfig) -> anyhow::Result<Self> {
        if config.bits != 64 {
            anyhow::bail!(
                "learned watermarker supports a 64-bit payload, got {}",
                config.bits
            );
        }
        let raw = include_bytes!("weights.bin");
        let model = parse_weights(raw)?;
        Ok(Self { config, model })
    }

    /// The loaded configuration.
    pub fn config(&self) -> &LearnedConfig {
        &self.config
    }

    /// The loaded model (training/tools path).
    pub fn model(&self) -> &LearnedModel {
        &self.model
    }

    /// Build a watermarker from an explicit model (training/tools path;
    /// the committed-weights path is [`Self::built_in`]).
    pub fn with_model(config: LearnedConfig, model: LearnedModel) -> Self {
        Self { config, model }
    }

    /// Number of slots required for one embedding (bits × redundancy).
    fn slot_count(&self) -> usize {
        self.config.bits as usize * self.config.redundancy as usize
    }

    /// Embed `payload` into a frame (RGB8 or BGRA8; YUV420 unsupported).
    ///
    /// Chips are added to the green channel's mid-frequency DCT coefficients
    /// of the scheduled blocks. Deterministic: the same frame bytes and
    /// payload always produce identical output bytes.
    pub fn embed(&self, frame: &mut VideoFrame, payload: u64) -> anyhow::Result<()> {
        let bpp = match frame.format {
            VideoFormat::Rgb8 => 3usize,
            VideoFormat::Bgra8 => 4usize,
            VideoFormat::Yuv420 => {
                anyhow::bail!("learned watermarker does not support YUV420 planar format");
            }
        };
        let (blocks_x, blocks_y) = block_grid(frame.width, frame.height);
        let slots = self.slot_count();
        if blocks_x * blocks_y < slots {
            anyhow::bail!(
                "frame too small for learned embedding: need {} blocks ({} bits x {} redundancy), have {} ({}x{})",
                slots,
                self.config.bits,
                self.config.redundancy,
                blocks_x * blocks_y,
                blocks_x,
                blocks_y
            );
        }
        let order = block_order(self.config.seed, blocks_x, blocks_y);
        let stride = frame.stride as usize;
        let channel = 1; // green: least visible, matches dct_video default
        for (slot, &block_lin) in order.iter().enumerate().take(slots) {
            let bit = slot / self.config.redundancy as usize;
            let copy = slot % self.config.redundancy as usize;
            let bit_val = (payload >> (63 - bit)) & 1; // MSB-first, matches text payloads
            let (coefs, signs) = slot_chip(self.config.seed, bit, copy);
            let bx = (block_lin % blocks_x) * BLOCK;
            let by = (block_lin / blocks_x) * BLOCK;
            let mut block = [0u8; 64];
            read_block(frame.data, stride, bpp, channel, bx, by, &mut block);
            let mut coeffs = dct_2d(&block);
            for (c, s) in coefs.iter().zip(signs.iter()) {
                let dir = if bit_val == 1 { 1.0 } else { -1.0 };
                coeffs[*c] += (*s * dir * self.config.strength) as f64;
            }
            let restored = idct_2d(&coeffs);
            write_block(frame.data, stride, bpp, channel, bx, by, &restored);
        }
        log::debug!(
            "learned embed: payload {:#018x} into {} slots, strength {} (frame {})",
            payload,
            slots,
            self.config.strength,
            frame.frame_index
        );
        Ok(())
    }

    /// Extract the payload from a frame.
    ///
    /// Returns `Some((payload, confidence))` where confidence is the mean
    /// sigmoid output over the 64 bit decisions, or `None` for unsupported
    /// formats / frames too small to carry the payload.
    pub fn extract(&self, frame: &VideoFrame) -> Option<(u64, f32)> {
        let bpp = match frame.format {
            VideoFormat::Rgb8 => 3usize,
            VideoFormat::Bgra8 => 4usize,
            VideoFormat::Yuv420 => return None,
        };
        let (blocks_x, blocks_y) = block_grid(frame.width, frame.height);
        if blocks_x * blocks_y < self.slot_count() {
            return None;
        }
        let (features, _) = self.best_alignment_features(frame, bpp, blocks_x, blocks_y);
        Some(self.decode(&features))
    }

    /// Majority-vote baseline decode: each bit is the majority sign of its
    /// slots' raw chip responses. Used for trainer/eval comparison.
    pub fn majority_extract(&self, frame: &VideoFrame) -> Option<(u64, f32)> {
        let bpp = match frame.format {
            VideoFormat::Rgb8 => 3usize,
            VideoFormat::Bgra8 => 4usize,
            VideoFormat::Yuv420 => return None,
        };
        let (blocks_x, blocks_y) = block_grid(frame.width, frame.height);
        if blocks_x * blocks_y < self.slot_count() {
            return None;
        }
        let (features, _) = self.best_alignment_features(frame, bpp, blocks_x, blocks_y);
        let mut payload = 0u64;
        let r = self.config.redundancy as usize;
        for bit in 0..64 {
            let mut votes = 0i32;
            for copy in 0..r {
                let base = (bit * r + copy) * SLOT_FEATURES;
                votes += if features[base] >= 0.0 { 1 } else { -1 };
            }
            if votes > 0 {
                payload |= 1 << (63 - bit);
            }
        }
        Some((payload, 0.5))
    }

    /// Per-slot chip responses for the best alignment (used by the trainer).
    /// Returns one raw response per slot (bits × redundancy entries).
    pub fn slot_responses(&self, frame: &VideoFrame) -> Option<Vec<f32>> {
        let bpp = match frame.format {
            VideoFormat::Rgb8 => 3usize,
            VideoFormat::Bgra8 => 4usize,
            VideoFormat::Yuv420 => return None,
        };
        let (blocks_x, blocks_y) = block_grid(frame.width, frame.height);
        if blocks_x * blocks_y < self.slot_count() {
            return None;
        }
        let (features, _) = self.best_alignment_features(frame, bpp, blocks_x, blocks_y);
        let r = self.config.redundancy as usize;
        Some((0..64 * r).map(|s| features[s * SLOT_FEATURES]).collect())
    }

    /// Pooled per-bit feature vectors for the trainer/eval harness:
    /// 64 bit rows of `MODEL_INPUT` features each (flattened, len 64 × 128).
    /// Uses the same best-alignment feature path as [`Self::extract`].
    pub fn bit_features(&self, frame: &VideoFrame) -> Option<Vec<f32>> {
        let bpp = match frame.format {
            VideoFormat::Rgb8 => 3usize,
            VideoFormat::Bgra8 => 4usize,
            VideoFormat::Yuv420 => return None,
        };
        let (blocks_x, blocks_y) = block_grid(frame.width, frame.height);
        if blocks_x * blocks_y < self.slot_count() {
            return None;
        }
        let (features, _) = self.best_alignment_features(frame, bpp, blocks_x, blocks_y);
        Some(features)
    }

    /// Try each block-aligned shift hypothesis (multiples of 8 up to 16 px,
    /// plus the identity), score by mean |chip response|, return the winning
    /// feature vector. This is what makes extraction robust to block-aligned
    /// content shifts (circular) within the frame.
    fn best_alignment_features(
        &self,
        frame: &VideoFrame,
        bpp: usize,
        blocks_x: usize,
        blocks_y: usize,
    ) -> (Vec<f32>, f32) {
        let cache = block_dct_cache(frame, bpp, blocks_x, blocks_y);
        let mut best: Option<(Vec<f32>, f32)> = None;
        for &dx in &[0usize, 8, 16] {
            for &dy in &[0usize, 8, 16] {
                let feats = features_from_cache(
                    &cache,
                    blocks_x,
                    blocks_y,
                    self.config.seed,
                    self.config.redundancy as usize,
                    dx,
                    dy,
                );
                let score = alignment_score(&feats, self.config.redundancy as usize);
                if best.as_ref().is_none_or(|(_, s)| score > *s) {
                    best = Some((feats, score));
                }
            }
        }
        best.expect("at least one hypothesis")
    }

    /// Decode 64 bits from a pooled feature vector via the MLP.
    fn decode(&self, features: &[f32]) -> (u64, f32) {
        let mut payload = 0u64;
        let mut conf_sum = 0.0f32;
        for bit in 0..64 {
            let base = bit * MODEL_INPUT;
            let logit = self.model.forward(&features[base..base + MODEL_INPUT]);
            // Per-bit decision confidence: distance of the logit from the
            // decision boundary, regardless of the bit's class.
            conf_sum += LearnedModel::confidence(logit.abs());
            if logit > 0.0 {
                payload |= 1 << (63 - bit);
            }
        }
        (payload, conf_sum / 64.0)
    }
}

/// Precompute the 2D DCT of every 8×8 green-channel block once per frame
/// (row-major block order), so all alignment hypotheses reuse it.
fn block_dct_cache(
    frame: &VideoFrame,
    bpp: usize,
    blocks_x: usize,
    blocks_y: usize,
) -> Vec<[f32; 64]> {
    let stride = frame.stride as usize;
    let mut block = [0u8; 64];
    let mut cache = Vec::with_capacity(blocks_x * blocks_y);
    for by in 0..blocks_y {
        for bx in 0..blocks_x {
            read_block(
                frame.data,
                stride,
                bpp,
                1,
                bx * BLOCK,
                by * BLOCK,
                &mut block,
            );
            let coeffs = dct_2d(&block);
            let mut row = [0.0f32; 64];
            for (r, c) in row.iter_mut().zip(coeffs.iter()) {
                *r = *c as f32;
            }
            cache.push(row);
        }
    }
    cache
}

/// Build the raw per-slot feature vector for one shift hypothesis from a
/// precomputed block-DCT cache: per slot
/// `[response, response / rms, mean|coef|, max|coef|]`, pooled across slots
/// to the fixed 128-input model width.
fn features_from_cache(
    cache: &[[f32; 64]],
    blocks_x: usize,
    blocks_y: usize,
    seed: u64,
    r: usize,
    dx: usize,
    dy: usize,
) -> Vec<f32> {
    let order = block_order(seed, blocks_x, blocks_y);
    let mut raw = Vec::with_capacity(64 * r * SLOT_FEATURES);
    for bit in 0..64 {
        for copy in 0..r {
            let (coefs, signs) = slot_chip(seed, bit, copy);
            let slot = bit * r + copy;
            let block_lin = order[slot];
            let bx = block_lin % blocks_x;
            let by = block_lin / blocks_x;
            // new[(x, y)] = orig[(x+dx, y+dy)] moves content left/up, so the
            // scheduled block's content now sits at (bx - dx/8, by - dy/8)
            // modulo the block grid.
            let sx = (bx + blocks_x - dx / BLOCK) % blocks_x;
            let sy = (by + blocks_y - dy / BLOCK) % blocks_y;
            let coeffs = &cache[sy * blocks_x + sx];
            let mut resp = 0.0f32;
            let mut energy = 0.0f32;
            let mut mean_abs = 0.0f32;
            let mut max_abs = 0.0f32;
            for (c, s) in coefs.iter().zip(signs.iter()) {
                let v = coeffs[*c];
                resp += s * v;
                energy += v * v;
                mean_abs += v.abs();
                max_abs = max_abs.max(v.abs());
            }
            let rms = (energy / CHIPS as f32).sqrt().max(1e-3);
            raw.push(resp);
            raw.push(resp / rms);
            raw.push(mean_abs / CHIPS as f32);
            raw.push(max_abs);
        }
    }
    pool_features(&raw, r)
}

/// Pool `64 × r × 4` raw per-slot features into the fixed
/// `64 × 128` model input: when `r < 32` pad slots with zeros; when
/// `r > 32` average adjacent slots; when `r = 32` pass through.
fn pool_features(raw: &[f32], redundancy: usize) -> Vec<f32> {
    let target = 32;
    let mut out = vec![0.0f32; 64 * target * SLOT_FEATURES];
    if redundancy == target {
        out.copy_from_slice(raw);
        return out;
    }
    for bit in 0..64 {
        for t in 0..target {
            if redundancy < target {
                let s = t * redundancy / target;
                let src = (bit * redundancy + s) * SLOT_FEATURES;
                let dst = (bit * target + t) * SLOT_FEATURES;
                out[dst..dst + SLOT_FEATURES].copy_from_slice(&raw[src..src + SLOT_FEATURES]);
            } else {
                let lo = t * redundancy / target;
                let hi = ((t + 1) * redundancy / target).max(lo + 1);
                let dst = (bit * target + t) * SLOT_FEATURES;
                for k in 0..SLOT_FEATURES {
                    let mut acc = 0.0f32;
                    for s in lo..hi {
                        acc += raw[(bit * redundancy + s) * SLOT_FEATURES + k];
                    }
                    out[dst + k] = acc / (hi - lo) as f32;
                }
            }
        }
    }
    out
}

/// Alignment score: per-bit vote-consistency. For each bit, sum the signs of
/// its slots' chip responses; the correct block alignment produces strongly
/// consistent votes, while a misaligned hypothesis yields near-random signs
/// (all scheduled blocks carry chips, so mean |response| alone does not
/// discriminate). Higher is better.
fn alignment_score(features: &[f32], redundancy: usize) -> f32 {
    let mut total = 0.0f32;
    for bit in 0..64 {
        let mut votes = 0i32;
        for copy in 0..redundancy {
            votes += if features[(bit * redundancy + copy) * SLOT_FEATURES] >= 0.0 {
                1
            } else {
                -1
            };
        }
        total += votes.unsigned_abs() as f32;
    }
    total / 64.0
}

/// Block grid dimensions for a frame size.
fn block_grid(width: u32, height: u32) -> (usize, usize) {
    (width as usize / BLOCK, height as usize / BLOCK)
}

/// Read an 8×8 block from packed pixel data.
fn read_block(
    data: &[u8],
    stride: usize,
    bpp: usize,
    channel: usize,
    bx: usize,
    by: usize,
    out: &mut [u8; 64],
) {
    for i in 0..8 {
        for j in 0..8 {
            let offset = (by + i) * stride + (bx + j) * bpp + channel;
            out[i * 8 + j] = if offset < data.len() {
                data[offset]
            } else {
                128
            };
        }
    }
}

/// Write an 8×8 block back to packed pixel data.
fn write_block(
    data: &mut [u8],
    stride: usize,
    bpp: usize,
    channel: usize,
    bx: usize,
    by: usize,
    block: &[u8; 64],
) {
    for i in 0..8 {
        for j in 0..8 {
            let offset = (by + i) * stride + (bx + j) * bpp + channel;
            if offset < data.len() {
                data[offset] = block[i * 8 + j];
            }
        }
    }
}

/// Parse and validate the committed weights file:
/// `[magic 'LWM1'][version u8][len u64 LE][weights bytes][blake3 32]`.
fn parse_weights(raw: &[u8]) -> anyhow::Result<LearnedModel> {
    if raw.len() < 4 + 1 + 8 + 32 {
        anyhow::bail!("weights.bin truncated: {} bytes", raw.len());
    }
    if &raw[0..4] != MAGIC {
        anyhow::bail!("weights.bin bad magic");
    }
    if raw[4] != VERSION {
        anyhow::bail!("weights.bin unsupported version {}", raw[4]);
    }
    let len = u64::from_le_bytes(raw[5..13].try_into().expect("8 bytes")) as usize;
    let payload_end = 13 + len;
    if raw.len() != payload_end + 32 {
        anyhow::bail!(
            "weights.bin length mismatch: declared {} payload, file {} bytes",
            len,
            raw.len()
        );
    }
    let payload = &raw[13..payload_end];
    let digest = blake3::hash(payload);
    if digest.as_bytes()[..] != raw[payload_end..] {
        anyhow::bail!("weights.bin blake3 checksum mismatch");
    }
    LearnedModel::from_bytes(payload)
}

/// Simulated CRF28-scale DCT quantization step for zigzag frequency `z`
/// (used by tests/trainer as the in-repo acceptance analog of H.264 CRF 28).
///
/// H.264 at QP 28 quantizes mid-frequency transform coefficients with steps
/// of roughly `2^((QP-4)/6) ≈ 16`, growing with frequency; the simulated
/// table uses `step = round(16 * (1 + (u+v)/12))` (u, v = 2D frequency
/// coordinates of the zigzag position), i.e. 16 for DC/low and ≈27 for
/// mid frequencies — consistent with libx264 CRF 28 behavior on 640×480
/// I-frames at default AQ settings.
pub fn sim_quant_step(zigzag: usize) -> f64 {
    let lin = ZIGZAG[zigzag.min(63)];
    let u = lin / 8;
    let v = lin % 8;
    16.0 * (1.0 + (u + v) as f64 / 12.0)
}

#[cfg(test)]
mod tests;
