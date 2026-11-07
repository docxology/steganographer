//! # Steganalysis
//!
//! Statistical observations for LSB (Least Significant Bit) replacement.
//! Inputs are adjacent scalar samples, not encoded image-file bytes. For RGB
//! imagery callers should analyze each channel separately. A statistical
//! indicator is neither forensic proof of embedding nor proof of absence.
//!
//! ## Implemented methods
//!
//! 1. **Chi-squared pair equalization** — reports compatibility with equal
//!    value-pair frequencies. Its upper-tail p-value is not a probability of
//!    steganography, and a positive is only a statistical observation.
//! 2. **Sample-pair heuristic** — observes adjacent-pair/histogram patterns;
//!    it is not a validated embedding-rate estimator.
//! 3. **RS analysis** — regular/singular group counts and the Fridrich,
//!    Goljan and Du quadratic estimate of randomly scattered replacement rate.
//! 4. **Combined analysis** — runs all three detectors and returns an
//!    aggregated [`CombinedResult`].

use std::f64::consts;

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/// Result of a single steganalysis detection.
#[derive(Debug, Clone)]
pub struct DetectionResult {
    /// Whether this method produced an operational observation. Unavailable
    /// and invalid/insufficient results must never be interpreted as negatives.
    pub available: bool,
    /// Statistical indicator, not proof of embedding or a clean bill of health.
    pub detected: bool,
    /// Method-specific score in `[0, 1]`, NOT a posterior probability of stego.
    pub confidence: f64,
    /// Human-readable detail.
    pub message: String,
}

impl DetectionResult {
    fn new(detected: bool, confidence: f64, message: impl Into<String>) -> Self {
        Self {
            available: true,
            detected,
            confidence: if confidence.is_finite() {
                confidence.clamp(0.0, 1.0)
            } else {
                0.0
            },
            message: message.into(),
        }
    }

    fn unavailable(message: impl Into<String>) -> Self {
        Self {
            available: false,
            detected: false,
            confidence: 0.0,
            message: message.into(),
        }
    }
}

/// Aggregated result from [`analyze_combined`].
#[derive(Debug, Clone)]
pub struct CombinedResult {
    pub chi_squared: DetectionResult,
    pub sample_pairs: DetectionResult,
    pub rs_analysis: DetectionResult,
    /// Whether any available method reports a statistical indicator.
    /// This does not establish forensic detection.
    pub detected: bool,
    /// Average method-specific score among firing available methods, or all
    /// available methods when none fires. Not a probability of steganography.
    pub confidence: f64,
    pub message: String,
}

// ---------------------------------------------------------------------------
// 1. Chi-squared test (Westfeld & Pfitzmann)
// ---------------------------------------------------------------------------

/// Pair-histogram equalization observation (Westfeld & Pfitzmann direction).
///
/// Under equal pair frequencies each populated pair contributes one degree
/// of freedom. The upper-tail p-value measures compatibility with that null,
/// not the probability of steganography. Expected cell counts below five are
/// excluded; their presence makes this asymptotic observation unavailable.
pub fn chi_squared_detect(data: &[u8]) -> DetectionResult {
    if data.len() < 64 {
        return DetectionResult::unavailable(if data.is_empty() {
            "No data to analyse (empty input)"
        } else {
            "Insufficient data for chi-squared test"
        });
    }

    // Build histogram of all 256 possible byte values.
    let mut hist = [0u64; 256];
    for &b in data {
        hist[b as usize] += 1;
    }

    // Pair (2i, 2i+1): expected frequency = (k[2i] + k[2i+1]) / 2.
    // Chi-squared = Σ (k[2i] - k[2i+1])² / (k[2i] + k[2i+1])   (simplified).
    let mut chi_sq = 0.0_f64;
    let mut df = 0u32;
    let mut sparse = false;
    for i in 0..128 {
        let pair_total = hist[2 * i] + hist[2 * i + 1];
        if pair_total > 0 {
            if pair_total < 10 {
                sparse = true;
                continue;
            }
            let diff = hist[2 * i] as f64 - hist[2 * i + 1] as f64;
            chi_sq += diff * diff / pair_total as f64;
            df += 1;
        }
    }

    if df == 0 || sparse {
        return DetectionResult::unavailable(
            "Insufficient expected pair counts for asymptotic chi-squared observation",
        );
    }
    let p_value = chi_squared_p_value(chi_sq, df);
    let equalization = p_value >= 0.05;
    DetectionResult::new(
        equalization,
        p_value,
        format!(
            "Chi-squared: {} (χ²={chi_sq:.2}, df={df}, upper-tail p={p_value:.4}; compatibility score, not steganography probability)",
            if equalization { "pair equalization compatible" } else { "pair equality rejected" }
        ),
    )
}

/// Upper-tail chi-squared probability via the regularized incomplete gamma
/// function. The series/continued fraction are bounded and use log-Gamma for
/// integer/half-integer df/2, avoiding the poor small-df normal approximation.
fn chi_squared_p_value(x: f64, df: u32) -> f64 {
    if x <= 0.0 || df == 0 {
        return 1.0;
    }
    let a = df as f64 / 2.0;
    let z = x / 2.0;
    let mut log_gamma = if df.is_multiple_of(2) {
        0.0
    } else {
        0.5 * consts::PI.ln()
    };
    let mut term = if df.is_multiple_of(2) { 1.0 } else { 0.5 };
    while term < a {
        log_gamma += term.ln();
        term += 1.0;
    }
    let scale = (a * z.ln() - z - log_gamma).exp();
    if z < a + 1.0 {
        let mut sum = 1.0 / a;
        let mut delta = sum;
        for i in 1..=512 {
            delta *= z / (a + i as f64);
            sum += delta;
            if delta.abs() < sum.abs() * 1e-14 {
                break;
            }
        }
        (1.0 - scale * sum).clamp(0.0, 1.0)
    } else {
        let mut b = z + 1.0 - a;
        let mut c = 1e300;
        let mut d = 1.0 / b;
        let mut h = d;
        for i in 1..=512 {
            let an = -(i as f64) * (i as f64 - a);
            b += 2.0;
            d = an * d + b;
            if d.abs() < 1e-300 {
                d = 1e-300;
            }
            c = b + an / c;
            if c.abs() < 1e-300 {
                c = 1e-300;
            }
            d = 1.0 / d;
            let delta = d * c;
            h *= delta;
            if (delta - 1.0).abs() < 1e-14 {
                break;
            }
        }
        (scale * h).clamp(0.0, 1.0)
    }
}

// ---------------------------------------------------------------------------
// 2. Sample-pair analysis (Fridrich et al.)
// ---------------------------------------------------------------------------

/// Adjacent-pair/histogram heuristic, not the validated SPA quadratic.
///
/// Reports pair equalization together with a high close-pair ratio. These
/// patterns can occur in benign covers; no embedding rate is estimated.
pub fn sample_pair_detect(data: &[u8]) -> DetectionResult {
    if data.is_empty() {
        return DetectionResult::unavailable("No data to analyse (empty input)");
    }
    if data.len() < 32 {
        return DetectionResult::unavailable("Insufficient data for sample-pair analysis");
    }

    // Work on consecutive pairs.
    let n_pairs = data.len() / 2;

    // Partition pairs into:
    //   D = pairs where |a - b| > 1  (different, "wide")
    //   S = pairs where |a - b| <= 1 (similar, "narrow")
    // LSB embedding tends to move pairs from S into D or vice versa by
    // changing the LSB of one member.
    //
    // The classic SPA estimates the embedding rate p from:
    //   |D| = |D₀| + (p/2)(|S| - |D₀|)  (simplified)
    //
    // We compute the ratio of "close pairs" (|a-b|<=1) to total pairs.
    // In clean natural data, close pairs are a minority. After LSB embedding
    // the proportion of pairs with the same value (|a-b|=0) increases
    // relative to pairs that differ only in LSB.

    let mut same_or_lsb_diff = 0u64; // |a-b| == 0 or |a-b| == 1
    let mut total = 0u64;
    // Also track "exact same" pairs.
    let mut exact_same = 0u64;

    for i in 0..n_pairs {
        let a = data[2 * i];
        let b = data[2 * i + 1];
        total += 1;
        let diff = (a as i16 - b as i16).unsigned_abs();
        if diff <= 1 {
            same_or_lsb_diff += 1;
        }
        if diff == 0 {
            exact_same += 1;
        }
    }

    let close_ratio = same_or_lsb_diff as f64 / total as f64;
    let exact_ratio = exact_same as f64 / total as f64;

    // In natural data with correlated neighbours, close_ratio is typically
    // moderate (0.1–0.4 depending on content). After full LSB embedding the
    // LSB of each byte is randomised, so pairs that differed only in LSB
    // (diff==1) may now have diff==0 or diff==1 with equal probability.
    //
    // Key signal: after embedding, the ratio of diff==0 to diff==1 approaches
    // equality. In clean data, diff==0 and diff==1 have different frequencies.
    //
    // We measure the "pair-value-pair (PVP) histogram" for pairs (2i, 2i+1)
    // within each byte and compute the imbalance.

    // Reuse the chi-squared approach on the pair histogram of each byte
    // to get a cleaner signal.
    let _pair_hist = [0u64; 128]; // pair index = min(a,b)/2 concept
                                  // Actually, SPA uses the "value pair" concept: (2i, 2i+1).
                                  // We compute how many bytes fall into value 2i vs 2i+1.
    let mut val_hist = [0u64; 256];
    for &b in data {
        val_hist[b as usize] += 1;
    }

    // Compute the fraction of pairs where |k[2i] - k[2i+1]| is small
    // (LSB embedding equalises these).
    let mut pair_imbalance = 0.0_f64;
    let mut pair_count = 0u32;
    for i in 0..128 {
        let k0 = val_hist[2 * i];
        let k1 = val_hist[2 * i + 1];
        let sum = k0 + k1;
        if sum > 0 {
            let expected = sum as f64 / 2.0;
            let diff = (k0 as f64 - k1 as f64).abs();
            pair_imbalance += diff * diff / (sum as f64);
            pair_count += 1;
            let _ = expected;
        }
    }

    // pair_imbalance is essentially the chi-squared statistic.
    // For SPA we also look at the close_ratio.
    // If pair_imbalance is low (pairs are equalised) AND close_ratio is
    // elevated, embedding is likely.

    let imb_per_pair = if pair_count > 0 {
        pair_imbalance / pair_count as f64
    } else {
        0.0
    };

    // Threshold: imb_per_pair < 0.5 indicates equalised pairs (embedded).
    // close_ratio > 0.15 with low imbalance strengthens the signal.
    let embedded = imb_per_pair < 0.5 && close_ratio > 0.05;

    if embedded {
        let confidence =
            ((0.5 - imb_per_pair) / 0.5 * 0.7 + (close_ratio.min(0.5) / 0.5) * 0.3).clamp(0.5, 1.0);
        DetectionResult::new(
            true,
            confidence,
            format!(
                "Sample-pair: statistical indicator (imbalance/pair={:.4}, close_ratio={:.4}, exact_ratio={:.4}; heuristic, not proof of embedding)",
                imb_per_pair, close_ratio, exact_ratio
            ),
        )
    } else {
        let confidence = (imb_per_pair / 2.0).clamp(0.0, 0.5);
        DetectionResult::new(
            false,
            confidence,
            format!(
                "Sample-pair: no statistical indicator (imbalance/pair={:.4}, close_ratio={:.4}, exact_ratio={:.4}; not proof of absence)",
                imb_per_pair, close_ratio, exact_ratio
            ),
        )
    }
}

// ---------------------------------------------------------------------------
// 3. RS analysis (Regular / Singular)
// ---------------------------------------------------------------------------

/// RS estimate for disjoint groups of eight adjacent scalar samples.
///
/// Implements Fridrich, Goljan and Du, *Reliable Detection of LSB Steganography
/// in Color and Grayscale Images* (2001), sections 3–4, equation (4):
/// <http://ws.binghamton.edu/fridrich/research/acm_2001_03.pdf>.
/// Assumes a correlated cover and randomly scattered, unbiased replacement
/// bits. Cover bias, noise, channel mixing and sequential placement can violate
/// this model. The score is the clipped estimated replacement rate, not
/// statistical confidence or a probability of embedding.
pub fn rs_analyze(data: &[u8]) -> DetectionResult {
    rs_analyze_with_group_size(data, 8)
}

/// Custom group size, using the periodic mask `[0, 1, 1, 0]`.
///
/// At least two samples and four complete groups are required. Incomplete
/// trailing groups are ignored. No group-sized allocation or input copy is
/// made. Invalid input or an unidentifiable/nonphysical model fit is explicitly
/// unavailable, never a clean negative.
pub fn rs_analyze_with_group_size(data: &[u8], group_size: usize) -> DetectionResult {
    if group_size < 2 {
        return DetectionResult::unavailable("Invalid RS group size: must be at least 2");
    }
    if data.is_empty() {
        return DetectionResult::unavailable("RS: empty input");
    }
    let groups = data.len() / group_size;
    if groups < 4 {
        return DetectionResult::unavailable("Insufficient complete groups for RS analysis");
    }

    let counts = rs_counts(data, group_size);
    let differences = std::array::from_fn(|i| {
        (counts.regular[i] as f64 - counts.singular[i] as f64) / groups as f64
    });
    let rate = match rs_payload_rate(differences) {
        Ok(rate) => rate,
        Err(reason) => {
            return DetectionResult::unavailable(format!("RS model inconclusive: {reason}"));
        }
    };
    // An explicit reporting threshold, not an empirically calibrated accuracy
    // claim. Small positive and negative cover bias is expected by the paper.
    let indicator = rate > 0.05;
    DetectionResult::new(
        indicator,
        rate,
        format!(
            "RS: {} (estimated replacement rate={rate:.4}, groups={groups}, R_M={}, S_M={}, R_-M={}, S_-M={}; rate score, not embedding probability; threshold=0.05)",
            if indicator { "statistical indicator" } else { "no statistical indicator" },
            counts.regular[0], counts.singular[0], counts.regular[1], counts.singular[1],
        ),
    )
}

/// F_1 swaps 0<->1, 2<->3, ... . F_-1 swaps -1<->0, 1<->2,
/// ... , 255<->256. Clipping or byte wrapping would change the method.
fn rs_flip(value: i16, negative: bool) -> i16 {
    if negative {
        if value & 1 == 0 {
            value - 1
        } else {
            value + 1
        }
    } else {
        value ^ 1
    }
}

#[derive(Default)]
struct RsCounts {
    // M, -M, M after complementing every LSB, -M after complementing every LSB.
    regular: [usize; 4],
    singular: [usize; 4],
}

fn rs_counts(data: &[u8], group_size: usize) -> RsCounts {
    let mut counts = RsCounts::default();
    for group in data.chunks_exact(group_size) {
        // Original, M, -M, complemented, complemented M, complemented -M.
        let mut previous = [0i16; 6];
        // u128 accommodates even a maximum-length slice times the largest
        // extended-domain difference (257), with no group-size overflow.
        let mut variation = [0u128; 6];
        for (index, &byte) in group.iter().enumerate() {
            let value = i16::from(byte);
            let complement = value ^ 1;
            let masked = matches!(index % 4, 1 | 2);
            let values = if masked {
                [
                    value,
                    rs_flip(value, false),
                    rs_flip(value, true),
                    complement,
                    rs_flip(complement, false),
                    rs_flip(complement, true),
                ]
            } else {
                [value, value, value, complement, complement, complement]
            };
            if index > 0 {
                for i in 0..6 {
                    variation[i] += u128::from((values[i] - previous[i]).unsigned_abs());
                }
            }
            previous = values;
        }
        for (i, (baseline, flipped)) in [(0, 1), (0, 2), (3, 4), (3, 5)].into_iter().enumerate() {
            if variation[flipped] > variation[baseline] {
                counts.regular[i] += 1;
            } else if variation[flipped] < variation[baseline] {
                counts.singular[i] += 1;
            }
            // Equal discriminants are unusable groups: retain them in the
            // denominator but neither the regular nor singular counts.
        }
    }
    counts
}

fn rs_payload_rate([d0, dm0, d1, dm1]: [f64; 4]) -> Result<f64, &'static str> {
    if [d0, dm0, d1, dm1]
        .iter()
        .any(|d| !d.is_finite() || d.abs() > 1.0)
    {
        return Err("invalid regular/singular proportions");
    }
    // Primary paper §4: 2(d1+d0)x²+(dm0-dm1-d1-3d0)x+d0-dm0=0.
    let a = 2.0 * (d1 + d0);
    let b = dm0 - dm1 - d1 - 3.0 * d0;
    let c = d0 - dm0;
    let epsilon = 1e-12;
    let x = if a.abs() <= epsilon {
        if b.abs() <= epsilon {
            // At full replacement both inner differences vanish while the
            // shifted-plane differences remain equal and positive. The
            // intersection tends to infinity and x/(x-1/2) tends to one.
            // This is not the all-zero/unidentifiable diagram.
            if d0.abs() <= epsilon
                && d1.abs() <= epsilon
                && (dm0 - dm1).abs() <= epsilon
                && dm0 > epsilon
            {
                return Ok(1.0);
            }
            return Err("unidentifiable regular/singular intersection");
        }
        -c / b
    } else {
        let discriminant = b * b - 4.0 * a * c;
        if discriminant < -epsilon {
            return Err("no real regular/singular intersection");
        }
        // Stable quadratic evaluation avoids cancellation near a zero root.
        let q = -0.5 * (b + discriminant.max(0.0).sqrt().copysign(b));
        let (x1, x2) = if q.abs() <= epsilon {
            let root = -b / (2.0 * a);
            (root, root)
        } else {
            (q / a, c / q)
        };
        if x1.abs() <= x2.abs() {
            x1
        } else {
            x2
        }
    };
    if !x.is_finite() || (x - 0.5).abs() <= epsilon {
        return Err("singular replacement-rate denominator");
    }
    let rate = x / (x - 0.5);
    if !rate.is_finite() || rate > 1.0 + epsilon {
        return Err("replacement-rate estimate outside physical upper bound");
    }
    // Negative initial bias is meaningful, and is reported rather than
    // disguised as evidence of embedding. The public score alone is clipped.
    Ok(rate.min(1.0))
}

// ---------------------------------------------------------------------------
// 4. Combined analysis
// ---------------------------------------------------------------------------

/// Run all three steganalysis detectors and return an aggregated result.
pub fn analyze_combined(data: &[u8]) -> CombinedResult {
    let chi = chi_squared_detect(data);
    let spa = sample_pair_detect(data);
    let rs = rs_analyze(data);

    let detected = chi.detected || spa.detected || rs.detected;

    // Unavailable methods do not dilute the score or masquerade as negatives.
    let mut sum = 0.0;
    let mut count = 0usize;
    for result in [&chi, &spa, &rs] {
        if result.available && (!detected || result.detected) {
            sum += result.confidence;
            count += 1;
        }
    }
    let confidence = if count == 0 { 0.0 } else { sum / count as f64 };

    let mut detectors_fired = Vec::new();
    if chi.detected {
        detectors_fired.push("chi-squared");
    }
    if spa.detected {
        detectors_fired.push("sample-pair");
    }
    if rs.detected {
        detectors_fired.push("RS");
    }

    let message = if detected {
        format!(
            "Combined: statistical indicators from {} method(s): {} (not forensic detection or a steganography probability)",
            detectors_fired.len(),
            detectors_fired.join(", ")
        )
    } else {
        "Combined: no statistical indicator from available methods (not proof of absence)"
            .to_string()
    };

    CombinedResult {
        chi_squared: chi,
        sample_pairs: spa,
        rs_analysis: rs,
        detected,
        confidence,
        message,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Independently labeled cover/stego controls, not generated by the RS
    /// implementation. Each cover group is constant 128 or 129. Enumerating
    /// all four independent base-eight digits gives exact, unbiased message
    /// bits and uniform placement at rates 0, 1/4, 1/2, 3/4 and 1.
    fn replacement_control(rate_quarters: u8) -> Vec<u8> {
        let mut data = Vec::with_capacity(2 * 4096 * 4);
        for cover_bit in 0..=1 {
            for placement_and_message in 0usize..4096 {
                for sample in 0..4 {
                    let digit = ((placement_and_message >> (3 * sample)) & 7) as u8;
                    let bit = if digit < 2 * rate_quarters {
                        digit & 1
                    } else {
                        cover_bit
                    };
                    data.push(128 | bit);
                }
            }
        }
        data
    }

    #[test]
    fn rs_recovers_independently_labeled_replacement_rates() {
        for quarters in 0..=4 {
            let data = replacement_control(quarters);
            let result = rs_analyze_with_group_size(&data, 4);
            let expected = f64::from(quarters) / 4.0;
            assert!(result.available, "{}", result.message);
            assert_eq!(result.detected, quarters != 0, "{}", result.message);
            assert!(
                (result.confidence - expected).abs() < 1e-12,
                "{}",
                result.message
            );
            let counts = rs_counts(&data, 4);
            // Exact constant-cover clique model: d_M=(1-p)^2, d_-M=1.
            let d = (counts.regular[0] as f64 - counts.singular[0] as f64) / 8192.0;
            assert!((d - (1.0 - expected).powi(2)).abs() < 1e-12);
            assert_eq!(counts.regular[1], 8192);
            assert_eq!(counts.singular[1], 0);
        }
    }

    #[test]
    fn rs_default_group_detects_complete_independent_lsb_replacement() {
        // All 256 eight-bit messages, once each, in constant-128 cover groups.
        let data: Vec<u8> = (0u16..256)
            .flat_map(|message| (0..8).map(move |bit| 128 | ((message >> bit) & 1) as u8))
            .collect();
        let result = rs_analyze(&data);
        assert!(result.available && result.detected, "{}", result.message);
        assert!((result.confidence - 1.0).abs() < 1e-12);
    }

    #[test]
    fn rs_extended_integer_flips_are_distinct_involutions() {
        assert_eq!(rs_flip(0, false), 1);
        assert_eq!(rs_flip(0, true), -1);
        assert_eq!(rs_flip(255, false), 254);
        assert_eq!(rs_flip(255, true), 256);
        for value in -1..=256 {
            for negative in [false, true] {
                assert_eq!(rs_flip(rs_flip(value, negative), negative), value);
            }
        }
        // Exact equal-upper-bits clique: M=0110 has 4R,4S,8U;
        // all 16 negative-mask groups are regular.
        let data: Vec<u8> = (0u8..16)
            .flat_map(|message| (0..4).map(move |bit| (message >> bit) & 1))
            .collect();
        let counts = rs_counts(&data, 4);
        assert_eq!(counts.regular, [4, 16, 4, 16]);
        assert_eq!(counts.singular, [4, 0, 4, 0]);
    }

    #[test]
    fn constant_covers_are_not_embedding_indicators_at_byte_boundaries() {
        for value in [0, 1, 128, 254, 255] {
            let data = [value; 256];
            let chi = chi_squared_detect(&data);
            let rs = rs_analyze(&data);
            assert!(chi.available && !chi.detected, "{}", chi.message);
            assert!(chi.confidence < 0.001);
            assert!(rs.available && !rs.detected, "{}", rs.message);
            assert_eq!(rs.confidence, 0.0);
            assert!(!analyze_combined(&data).detected);
        }
    }

    #[test]
    fn chi_square_equalization_direction_is_not_forensic_proof() {
        let cover = replacement_control(0);
        // Balanced histogram despite zero embedding: equality proves nothing.
        let observation = chi_squared_detect(&cover);
        assert!(observation.available && observation.detected);
        assert_eq!(observation.confidence, 1.0);
        assert!(observation
            .message
            .contains("not steganography probability"));
        let scan = crate::forensics::scan_bytes(&cover);
        assert!(scan.statistical.detected);
        assert!(!scan.detected);
        // Known even-only cover and exact full-replacement pair.
        let even_cover = [128; 256];
        let full_stego: Vec<u8> = (0..256).map(|i| 128 | (i % 2) as u8).collect();
        assert!(!chi_squared_detect(&even_cover).detected);
        assert!(chi_squared_detect(&full_stego).detected);
    }

    #[test]
    fn chi_square_reference_tail_and_sparse_admission() {
        assert!((chi_squared_p_value(3.841458820694124, 1) - 0.05).abs() < 1e-10);
        assert!((chi_squared_p_value(5.991464547107979, 2) - 0.05).abs() < 1e-10);
        assert!(!chi_squared_detect(&[]).available);
        assert!(!chi_squared_detect(&[0; 63]).available);
        let sparse: Vec<u8> = (0u8..64).collect();
        assert!(!chi_squared_detect(&sparse).available);
    }

    #[test]
    fn rs_invalid_insufficient_and_trailing_groups() {
        for size in [0, 1, usize::MAX, 1usize << (usize::BITS - 2)] {
            let result = rs_analyze_with_group_size(&[0; 64], size);
            assert!(!result.available && !result.detected);
            assert_eq!(result.confidence, 0.0);
        }
        assert!(!rs_analyze(&[]).available);
        assert!(!rs_analyze(&[0; 31]).available);
        for size in [2, 4, 8, 16] {
            let exact = vec![128; size * 4];
            let mut trailing = exact.clone();
            trailing.extend(std::iter::repeat_n(255, size - 1));
            let baseline = rs_analyze_with_group_size(&exact, size);
            let with_tail = rs_analyze_with_group_size(&trailing, size);
            assert!(baseline.available && with_tail.available);
            assert!(!baseline.detected && !with_tail.detected);
            assert_eq!(baseline.confidence, with_tail.confidence);
        }
    }

    #[test]
    fn rs_degenerate_ramps_are_inconclusive_not_clean_verdicts() {
        let ascending: Vec<u8> = (0u8..=255).cycle().take(2048).collect();
        let even: Vec<u8> = (0u8..128).map(|v| v * 2).cycle().take(2048).collect();
        for data in [ascending, even] {
            let result = rs_analyze(&data);
            assert!(!result.available && !result.detected, "{}", result.message);
            assert!(result.message.contains("inconclusive"));
        }
    }

    #[test]
    fn rs_solver_rejects_invalid_or_unidentifiable_domains() {
        for differences in [
            [f64::NAN, 0.0, 0.0, 0.0],
            [0.0, f64::INFINITY, 0.0, 0.0],
            [2.0, 0.0, 0.0, 0.0],
            [0.0; 4],
            [0.0, 1.0, -1.0, 1.0],  // Ascending ramp: negative discriminant.
            [0.0, -1.0, 0.0, -1.0], // Inverted, not the full-rate model.
            [0.5, -0.5, -0.5, 0.5], // Linear root x=1/2.
        ] {
            assert!(rs_payload_rate(differences).is_err());
        }
        assert_eq!(rs_payload_rate([0.0, 1.0, 0.0, 1.0]).unwrap(), 1.0);
        assert_eq!(rs_payload_rate([1.0; 4]).unwrap(), 0.0);
        assert_eq!(rs_payload_rate([0.25, 0.25, -0.25, 0.0]).unwrap(), 0.0);
        assert_eq!(
            DetectionResult::new(false, f64::NAN, "invalid score").confidence,
            0.0
        );
    }

    #[test]
    fn combined_unavailable_methods_are_not_clean_negatives() {
        let empty = analyze_combined(&[]);
        assert!(!empty.chi_squared.available);
        assert!(!empty.sample_pairs.available);
        assert!(!empty.rs_analysis.available);
        assert!(!empty.detected);
        assert_eq!(empty.confidence, 0.0);
        // Balanced but independently known cover: statistical indicators are
        // deliberately not promoted into the content-derived forensic verdict.
        let control = replacement_control(0);
        let combined = analyze_combined(&control);
        assert!(combined.detected);
        assert!(combined.message.contains("not forensic detection"));
    }
}
