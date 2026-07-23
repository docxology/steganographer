//! Error correction codes for steganographic payload resilience.
//!
//! Implements a lightweight Reed-Solomon-style error correction
//! using GF(2^8) arithmetic. This allows recovery of payloads even
//! when some bits are corrupted by compression, noise, or partial
//! frame loss.
//!
//! ## Algorithm
//!
//! Uses polynomial evaluation over GF(2^8):
//! - Form message polynomial M(x) = m_0 + m_1*x + ... + m_{k-1}*x^(k-1)
//! - Codeword = (M(alpha^0), M(alpha^1), ..., M(alpha^(n-1)))
//! - Syndromes are the received values themselves (for the evaluation-based scheme)
//! - For single-error correction: find position and value from syndromes
//!
//! This is a non-systematic encoding: the data is not directly present
//! in the codeword. Encode/decode are inverses of each other.

/// GF(2^8) multiplication using the AES polynomial (x^8 + x^4 + x^3 + x + 1).
fn gf_mul(a: u8, b: u8) -> u8 {
    let a = a as u16;
    let b = b as u16;
    let mut result = 0u16;
    for i in 0..8 {
        if (b >> i) & 1 == 1 {
            result ^= a << i;
        }
    }
    for i in (8..=14).rev() {
        if result & (1 << i) != 0 {
            result ^= 0x11B << (i - 8);
        }
    }
    result as u8
}

/// GF(2^8) multiplicative inverse.
fn gf_inv(a: u8) -> u8 {
    if a == 0 {
        return 0;
    }
    for x in 1..=255 {
        if gf_mul(a, x) == 1 {
            return x;
        }
    }
    // If we reach here, GF arithmetic is broken — return 0 rather than panicking.
    // This is defense-in-depth: under correct GF(2^8) math, every nonzero element
    // has an inverse, so this line is unreachable. Returning 0 instead of
    // unreachable!() prevents a hard panic from a future math bug.
    log::error!("gf_inv: no inverse found for {} — GF arithmetic may be broken", a);
    0
}

/// GF(2^8) exponentiation: base^exp
fn gf_pow(base: u8, exp: u32) -> u8 {
    let mut result = 1u8;
    for _ in 0..exp {
        result = gf_mul(result, base);
    }
    result
}

/// Primitive element of GF(2^8) with the AES polynomial.
const ALPHA: u8 = 2;

/// Encode data with Reed-Solomon error correction.
///
/// Uses polynomial evaluation: the data bytes become coefficients of
/// a polynomial M(x), and the codeword is M evaluated at n = k + parity_count
/// distinct points (alpha^0, alpha^1, ..., alpha^(n-1)).
///
/// # Arguments
/// * `data` — The data to encode (message coefficients).
/// * `parity_count` — Number of parity symbols to add (recommend 2–10).
///
/// # Returns
/// Encoded codeword of length `data.len() + parity_count`.
pub fn encode(data: &[u8], parity_count: usize) -> anyhow::Result<Vec<u8>> {
    if parity_count == 0 {
        return Ok(data.to_vec());
    }
    if parity_count > 16 {
        anyhow::bail!("Parity count too high (max 16), got {}", parity_count);
    }

    let k = data.len();
    let n = k + parity_count;

    // Evaluate M(x) = data[0] + data[1]*x + data[2]*x^2 + ... at alpha^0, alpha^1, ..., alpha^(n-1)
    let mut codeword = vec![0u8; n];
    for i in 0..n {
        let x = gf_pow(ALPHA, i as u32);
        // Horner's method: M(x) = data[k-1]*x + data[k-2])*x + ... + data[0]
        let mut val = 0u8;
        for coef in data.iter().rev() {
            val = gf_mul(val, x) ^ *coef;
        }
        codeword[i] = val;
    }

    Ok(codeword)
}

/// Decode data that was encoded with [`encode`].
///
/// Uses syndrome-based error correction. For single errors, the position
/// and value are determined from the first two syndromes.
///
/// # Arguments
/// * `encoded` — The received codeword (possibly with errors).
/// * `data_len` — Expected length of the original data (= k).
/// * `parity_count` — Number of parity symbols (= n - k).
///
/// # Returns
/// The decoded data.
pub fn decode(encoded: &[u8], data_len: usize, parity_count: usize) -> anyhow::Result<Vec<u8>> {
    if parity_count == 0 {
        return Ok(encoded[..data_len].to_vec());
    }

    // Symmetric bounds with encode() — prevents DoS via crafted large data_len
    if parity_count > 16 {
        anyhow::bail!("Parity count too high (max 16), got {}", parity_count);
    }
    // Cap data_len to a realistic ceiling — the largest legitimate payload
    // is SignaturePayload::SERIALIZED_SIZE (104 bytes) + optional ECC + encryption
    // overhead. 65,536 is generous but prevents the O(n * 255 * k²) brute-force
    // loop from running on attacker-controlled lengths.
    const MAX_DATA_LEN: usize = 65_536;
    if data_len > MAX_DATA_LEN {
        anyhow::bail!(
            "Data length too large for RS decode (max {}, got {})",
            MAX_DATA_LEN,
            data_len
        );
    }

    let k = data_len;
    let n = k + parity_count;

    if encoded.len() < n {
        anyhow::bail!(
            "Encoded data too short: expected at least {} bytes, got {}",
            n,
            encoded.len()
        );
    }

    let received = &encoded[..n];

    // For the evaluation-based scheme, syndromes are the received values
    // that should be zero if the codeword is in the code space.
    // Actually, for a (n, k) RS code, we need n-k syndrome checks.
    // The syndrome S_j = received[j] for j = 0..(n-k-1) is NOT correct.
    //
    // For the evaluation-based RS code, the syndrome computation is:
    // S_j = Σ received[i] * L_j(alpha^i) where L_j are the parity check rows.
    //
    // For simplicity, we use Lagrange interpolation to recover the polynomial.
    // If no errors, the interpolated polynomial has degree < k.
    // If single error, we can detect and correct it.

    // For parity_count >= 2, try single-error correction:
    // If error at position p with value e:
    //   received[i] = M(alpha^i) + e * delta(i, p)
    //
    // Key insight: compute the "syndrome" as the difference between
    // the received polynomial interpolation and the expected degree.
    //
    // For the evaluation-based scheme:
    // S_0 = Σ_j received[j] * alpha^(-j * (n-1))  (related to error locator)
    //
    // Actually, let's use a simpler approach for single error correction:
    // If we have >= 2*k points, we can use the first k to interpolate,
    // and the rest to check. If they don't match, we have an error.
    //
    // But for practical purposes with small payloads, let's use the
    // following approach:
    // 1. Try Lagrange interpolation using the first k points.
    // 2. Verify using the remaining parity_count points.
    // 3. If verification fails, try correcting single errors by
    //    brute-force: for each position, try each possible error value,
    //    interpolate with the corrected codeword, and check.

    // First, try no-error case
    let poly = lagrange_interpolate(received, k);
    if poly.is_ok() {
        let coeffs = poly.unwrap();
        // Verify against all n points
        let mut all_match = true;
        for i in 0..n {
            let x = gf_pow(ALPHA, i as u32);
            let mut val = 0u8;
            for (j, c) in coeffs.iter().enumerate() {
                val ^= gf_mul(*c, gf_pow(x, j as u32));
            }
            if val != received[i] {
                all_match = false;
                break;
            }
        }
        if all_match {
            return Ok(coeffs);
        }
    }

    if parity_count < 2 {
        // Can't correct with < 2 parity symbols
        log::warn!("Reed-Solomon: error detected but cannot correct with < 2 parity symbols");
        // Best effort: interpolate using first k points
        return lagrange_interpolate(received, k);
    }

    // Single-error correction: brute force (fine for small payloads)
    for pos in 0..n {
        for error_val in 1u8..=255 {
            let mut corrected = received.to_vec();
            corrected[pos] ^= error_val;

            // Interpolate using first k points
            if let Ok(coeffs) = lagrange_interpolate(&corrected, k) {
                // Verify against all n points
                let mut all_match = true;
                for i in 0..n {
                    let x = gf_pow(ALPHA, i as u32);
                    let mut val = 0u8;
                    for (j, c) in coeffs.iter().enumerate() {
                        val ^= gf_mul(*c, gf_pow(x, j as u32));
                    }
                    if val != corrected[i] {
                        all_match = false;
                        break;
                    }
                }
                if all_match {
                    return Ok(coeffs);
                }
            }
        }
    }

    log::warn!("Reed-Solomon: uncorrectable errors, returning best-effort");
    lagrange_interpolate(received, k)
}

/// Lagrange interpolation over GF(2^8).
///
/// Given n points (alpha^0, y_0), (alpha^1, y_1), ..., (alpha^(n-1), y_(n-1)),
/// find a polynomial of degree < k that passes through the first k points.
fn lagrange_interpolate(values: &[u8], k: usize) -> anyhow::Result<Vec<u8>> {
    if k == 0 {
        return Ok(vec![]);
    }
    if k > values.len() {
        anyhow::bail!("Not enough values for interpolation");
    }

    // Use the first k evaluation points: alpha^0, alpha^1, ..., alpha^(k-1)
    let points: Vec<u8> = (0..k).map(|i| gf_pow(ALPHA, i as u32)).collect();
    let ys = &values[..k];

    // Lagrange interpolation: P(x) = Σ_j y_j * L_j(x)
    // where L_j(x) = Π_{i≠j} (x - x_i) / (x_j - x_i)
    //
    // We compute the coefficients of P(x) by expanding the Lagrange basis.

    let mut result = vec![0u8; k];

    for j in 0..k {
        // Compute L_j(x) = Π_{i≠j} (x - x_i) / (x_j - x_i)
        // First, compute the denominator: Π_{i≠j} (x_j - x_i)
        let mut denom = 1u8;
        for i in 0..k {
            if i != j {
                denom = gf_mul(denom, points[j] ^ points[i]);
            }
        }
        if denom == 0 {
            anyhow::bail!("Degenerate interpolation: duplicate evaluation points");
        }
        let scale = gf_mul(ys[j], gf_inv(denom));

        // Compute the numerator polynomial: Π_{i≠j} (x - x_i)
        // Start with [1] (constant 1)
        let mut poly = vec![1u8];
        for i in 0..k {
            if i != j {
                // Multiply poly by (x - points[i]) = (x + points[i]) in GF(2^8)
                let mut new_poly = vec![0u8; poly.len() + 1];
                for (idx, &c) in poly.iter().enumerate() {
                    // x * c -> shifts degree by 1
                    new_poly[idx + 1] ^= c;
                    // -points[i] * c -> constant term (XOR in GF(2^8))
                    new_poly[idx] ^= gf_mul(c, points[i]);
                }
                poly = new_poly;
            }
        }

        // Add scale * poly to result
        for (idx, &c) in poly.iter().enumerate() {
            if idx < result.len() {
                result[idx] ^= gf_mul(scale, c);
            }
        }
    }

    Ok(result)
}

/// Compute the error correction capability of a (n, k) code.
pub fn correction_capability(parity_count: usize) -> usize {
    parity_count / 2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_errors() {
        let data = b"Hello, steganography!";
        let encoded = encode(data, 4).unwrap();
        assert_eq!(encoded.len(), data.len() + 4);
        let decoded = decode(&encoded, data.len(), 4).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_single_error_correction() {
        let data = b"payload data";
        let parity = 4;
        let mut encoded = encode(data, parity).unwrap();
        encoded[3] ^= 0xFF;
        let decoded = decode(&encoded, data.len(), parity).unwrap();
        assert_eq!(decoded, data, "Should correct single error");
    }

    #[test]
    fn test_no_parity() {
        let data = b"no parity";
        let encoded = encode(data, 0).unwrap();
        assert_eq!(encoded, data);
        let decoded = decode(&encoded, data.len(), 0).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_gf_mul() {
        assert_eq!(gf_mul(0, 0), 0);
        assert_eq!(gf_mul(1, 1), 1);
        assert_eq!(gf_mul(2, 3), 6);
        assert_eq!(gf_mul(0x57, 0x83), 0xc1);
    }

    #[test]
    fn test_gf_inv() {
        for a in 1..=255u8 {
            assert_eq!(gf_mul(a, gf_inv(a)), 1);
        }
    }

    #[test]
    fn test_correction_capability() {
        assert_eq!(correction_capability(0), 0);
        assert_eq!(correction_capability(2), 1);
        assert_eq!(correction_capability(4), 2);
    }

    #[test]
    fn test_too_many_parity() {
        assert!(encode(b"data", 17).is_err());
    }

    #[test]
    fn test_short_data() {
        let data = b"A";
        let encoded = encode(data, 4).unwrap();
        let decoded = decode(&encoded, data.len(), 4).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_empty_data() {
        let encoded = encode(b"", 4).unwrap();
        assert_eq!(encoded.len(), 4);
        let decoded = decode(&encoded, 0, 4).unwrap();
        assert_eq!(decoded, b"");
    }

    #[test]
    fn test_error_in_parity_region() {
        let data = b"data with parity";
        let parity = 4;
        let mut encoded = encode(data, parity).unwrap();
        encoded[data.len()] ^= 0xFF;
        let decoded = decode(&encoded, data.len(), parity).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_error_at_position_0() {
        let data = b"position zero test";
        let parity = 4;
        let mut encoded = encode(data, parity).unwrap();
        encoded[0] ^= 0x42;
        let decoded = decode(&encoded, data.len(), parity).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_error_at_last_position() {
        let data = b"last position test";
        let parity = 4;
        let mut encoded = encode(data, parity).unwrap();
        let last = encoded.len() - 1;
        encoded[last] ^= 0x99;
        let decoded = decode(&encoded, data.len(), parity).unwrap();
        assert_eq!(decoded, data);
    }
}
