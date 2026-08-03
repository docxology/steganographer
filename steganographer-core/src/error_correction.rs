//! Error correction codes for steganographic payload resilience.
//!
//! Implements an evaluation-form Reed-Solomon code over GF(2^8) using
//! Berlekamp-Welch decoding for bounded, polynomial-time error correction.
//!
//! ## Algorithm
//!
//! - **Encode**: Treat the message bytes as coefficients of a polynomial
//!   `M(x)` and evaluate it at `n = data_len + parity_count` distinct field
//!   points.
//! - **Decode**: Interpolate intact codewords directly. For corrupted
//!   codewords, solve `Q(x_i) = y_i E(x_i)` for the message product `Q` and
//!   error-locator `E`, divide `Q / E`, and verify the recovered message.
//!
//! This is a non-systematic encoding: the data is not directly present in
//! the codeword. The decoder rejects uncorrectable data rather than returning
//! silently corrupted best-effort bytes.

/// GF(2^8) multiplication using the AES polynomial
/// `x^8 + x^4 + x^3 + x + 1`.
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

/// GF(2^8) exponentiation by squaring.
fn gf_pow(mut base: u8, mut exponent: u32) -> u8 {
    let mut result = 1u8;
    while exponent != 0 {
        if exponent & 1 == 1 {
            result = gf_mul(result, base);
        }
        base = gf_mul(base, base);
        exponent >>= 1;
    }
    result
}

/// GF(2^8) multiplicative inverse.
fn gf_inv(value: u8) -> u8 {
    if value == 0 {
        return 0;
    }
    // Fermat's little theorem in GF(2^8): a^-1 = a^(2^8 - 2).
    gf_pow(value, 254)
}

/// GF(2^8) division. Returns zero when the denominator is zero.
fn gf_div(numerator: u8, denominator: u8) -> u8 {
    if denominator == 0 {
        return 0;
    }
    gf_mul(numerator, gf_inv(denominator))
}

/// Evaluate a polynomial whose coefficients are in ascending degree order.
fn gf_poly_eval(polynomial: &[u8], x: u8) -> u8 {
    let mut result = 0u8;
    for &coefficient in polynomial.iter().rev() {
        result = gf_mul(result, x) ^ coefficient;
    }
    result
}

/// Primitive element of GF(2^8) under the AES polynomial.
///
/// `2` has multiplicative order 51 under this polynomial and therefore
/// repeats evaluation points inside a normal signature payload. `3` has
/// order 255 and visits every non-zero field element exactly once.
const ALPHA: u8 = 3;
const MAX_CODEWORD_LEN: usize = 255;
const MAX_PARITY_COUNT: usize = 16;

/// Encode data with Reed-Solomon error correction.
///
/// The data bytes are coefficients of `M(x)`, and the returned codeword is
/// `M` evaluated at `alpha^0` through `alpha^(n-1)`.
pub fn encode(data: &[u8], parity_count: usize) -> anyhow::Result<Vec<u8>> {
    if parity_count == 0 {
        return Ok(data.to_vec());
    }
    validate_lengths(data.len(), parity_count)?;

    let codeword_len = data.len() + parity_count;
    let mut codeword = Vec::with_capacity(codeword_len);
    for i in 0..codeword_len {
        codeword.push(gf_poly_eval(data, gf_pow(ALPHA, i as u32)));
    }
    Ok(codeword)
}

/// Decode data encoded with [`encode`].
///
/// Up to `parity_count / 2` corrupted symbols can be corrected. More damaged
/// or malformed codewords return an error.
pub fn decode(encoded: &[u8], data_len: usize, parity_count: usize) -> anyhow::Result<Vec<u8>> {
    if parity_count == 0 {
        if encoded.len() < data_len {
            anyhow::bail!(
                "Encoded data too short: expected at least {} bytes, got {}",
                data_len,
                encoded.len()
            );
        }
        return Ok(encoded[..data_len].to_vec());
    }

    validate_lengths(data_len, parity_count)?;
    let codeword_len = data_len + parity_count;
    if encoded.len() < codeword_len {
        anyhow::bail!(
            "Encoded data too short: expected at least {} bytes, got {}",
            codeword_len,
            encoded.len()
        );
    }
    let received = &encoded[..codeword_len];

    // The intact path is both the common case and considerably cheaper than
    // constructing an error-locator system.
    if let Ok(message) = lagrange_interpolate(received, data_len) {
        if mismatch_count(&message, received) == 0 {
            return Ok(message);
        }
    }

    // Solving with the exact number of actual errors avoids the singular
    // systems that can arise when fewer than the maximum errors occurred.
    for error_count in 1..=correction_capability(parity_count) {
        if let Ok(message) = berlekamp_welch(received, data_len, error_count) {
            if mismatch_count(&message, received) <= error_count {
                return Ok(message);
            }
        }
    }

    anyhow::bail!(
        "Uncorrectable Reed-Solomon codeword: more than {} symbol errors",
        correction_capability(parity_count)
    )
}

fn validate_lengths(data_len: usize, parity_count: usize) -> anyhow::Result<()> {
    if parity_count > MAX_PARITY_COUNT {
        anyhow::bail!(
            "Parity count too high (max {}), got {}",
            MAX_PARITY_COUNT,
            parity_count
        );
    }
    let codeword_len = data_len
        .checked_add(parity_count)
        .ok_or_else(|| anyhow::anyhow!("Codeword length overflow"))?;
    if codeword_len > MAX_CODEWORD_LEN {
        anyhow::bail!(
            "Codeword too long for GF(2^8): max {}, got {}",
            MAX_CODEWORD_LEN,
            codeword_len
        );
    }
    Ok(())
}

fn mismatch_count(message: &[u8], received: &[u8]) -> usize {
    received
        .iter()
        .enumerate()
        .filter(|(i, value)| gf_poly_eval(message, gf_pow(ALPHA, *i as u32)) != **value)
        .count()
}

/// Recover a message with the Berlekamp-Welch construction.
fn berlekamp_welch(
    received: &[u8],
    data_len: usize,
    error_count: usize,
) -> anyhow::Result<Vec<u8>> {
    let q_len = data_len + error_count;
    let variable_count = q_len + error_count;
    if received.len() < variable_count {
        anyhow::bail!("Not enough Reed-Solomon symbols for requested correction");
    }

    // Unknowns are Q's coefficients followed by the lower coefficients of
    // monic E. Each row represents Q(x_i) + y_i*E_lower(x_i) = y_i*x_i^e.
    let mut matrix = vec![vec![0u8; variable_count + 1]; received.len()];
    for (i, (&received_value, row)) in received.iter().zip(matrix.iter_mut()).enumerate() {
        let x = gf_pow(ALPHA, i as u32);

        let mut power = 1u8;
        for cell in row.iter_mut().take(q_len) {
            *cell = power;
            power = gf_mul(power, x);
        }

        power = 1;
        for cell in row.iter_mut().skip(q_len).take(error_count) {
            *cell = gf_mul(received_value, power);
            power = gf_mul(power, x);
        }

        row[variable_count] = gf_mul(received_value, gf_pow(x, error_count as u32));
    }

    let solution = solve_linear_system(matrix, variable_count)?;
    let q = &solution[..q_len];
    let mut error_locator = solution[q_len..].to_vec();
    error_locator.push(1);
    polynomial_divide_exact(q, &error_locator, data_len)
}

/// Solve an overdetermined linear system over GF(2^8) in reduced row-echelon
/// form. The solution must be both consistent and unique.
fn solve_linear_system(mut matrix: Vec<Vec<u8>>, variable_count: usize) -> anyhow::Result<Vec<u8>> {
    let row_count = matrix.len();
    let mut pivot_rows = vec![None; variable_count];
    let mut next_row = 0usize;

    for column in 0..variable_count {
        let Some(pivot_row) = (next_row..row_count).find(|&row| matrix[row][column] != 0) else {
            continue;
        };
        matrix.swap(next_row, pivot_row);

        let inverse = gf_inv(matrix[next_row][column]);
        for cell in &mut matrix[next_row][column..=variable_count] {
            *cell = gf_mul(*cell, inverse);
        }

        for row in 0..row_count {
            if row == next_row {
                continue;
            }
            let factor = matrix[row][column];
            if factor == 0 {
                continue;
            }
            for col in column..=variable_count {
                matrix[row][col] ^= gf_mul(factor, matrix[next_row][col]);
            }
        }

        pivot_rows[column] = Some(next_row);
        next_row += 1;
        if next_row == row_count {
            break;
        }
    }

    for row in &matrix {
        if row[..variable_count]
            .iter()
            .all(|&coefficient| coefficient == 0)
            && row[variable_count] != 0
        {
            anyhow::bail!("Inconsistent Reed-Solomon correction system");
        }
    }
    if pivot_rows.iter().any(Option::is_none) {
        anyhow::bail!("Singular Reed-Solomon correction system");
    }

    Ok(pivot_rows
        .into_iter()
        .map(|row| matrix[row.expect("all pivot rows checked")][variable_count])
        .collect())
}

/// Divide a numerator by a monic denominator and require an exact quotient.
fn polynomial_divide_exact(
    numerator: &[u8],
    denominator: &[u8],
    expected_len: usize,
) -> anyhow::Result<Vec<u8>> {
    if denominator.is_empty() || *denominator.last().unwrap_or(&0) == 0 {
        anyhow::bail!("Invalid Reed-Solomon error-locator polynomial");
    }
    if numerator.len() < denominator.len() {
        anyhow::bail!("Invalid Reed-Solomon polynomial degrees");
    }

    let denominator_degree = denominator.len() - 1;
    let mut remainder = numerator.to_vec();
    let mut quotient = vec![0u8; numerator.len() - denominator_degree];

    for degree in (denominator_degree..numerator.len()).rev() {
        let coefficient = gf_div(remainder[degree], denominator[denominator_degree]);
        let quotient_degree = degree - denominator_degree;
        quotient[quotient_degree] = coefficient;
        for (offset, &denominator_coefficient) in denominator.iter().enumerate() {
            remainder[quotient_degree + offset] ^= gf_mul(coefficient, denominator_coefficient);
        }
    }

    if remainder[..denominator_degree]
        .iter()
        .any(|&coefficient| coefficient != 0)
    {
        anyhow::bail!("Reed-Solomon polynomial division had a non-zero remainder");
    }
    if quotient.len() != expected_len {
        anyhow::bail!("Unexpected Reed-Solomon message polynomial length");
    }
    Ok(quotient)
}

/// Lagrange interpolation over GF(2^8).
///
/// Finds the unique polynomial of degree below `k` that passes through the
/// first `k` evaluation points.
fn lagrange_interpolate(values: &[u8], k: usize) -> anyhow::Result<Vec<u8>> {
    if k == 0 {
        return Ok(Vec::new());
    }
    if k > values.len() {
        anyhow::bail!("Not enough values for interpolation");
    }

    let points: Vec<u8> = (0..k).map(|i| gf_pow(ALPHA, i as u32)).collect();
    let mut result = vec![0u8; k];

    for j in 0..k {
        let mut denominator = 1u8;
        for i in 0..k {
            if i != j {
                denominator = gf_mul(denominator, points[j] ^ points[i]);
            }
        }
        if denominator == 0 {
            anyhow::bail!("Degenerate interpolation: duplicate evaluation points");
        }
        let scale = gf_mul(values[j], gf_inv(denominator));

        let mut basis = vec![1u8];
        for i in 0..k {
            if i == j {
                continue;
            }
            let mut next_basis = vec![0u8; basis.len() + 1];
            for (degree, &coefficient) in basis.iter().enumerate() {
                next_basis[degree + 1] ^= coefficient;
                next_basis[degree] ^= gf_mul(coefficient, points[i]);
            }
            basis = next_basis;
        }

        for (degree, &coefficient) in basis.iter().enumerate() {
            result[degree] ^= gf_mul(scale, coefficient);
        }
    }

    Ok(result)
}

/// Compute the number of corrupt symbols that can be corrected.
pub fn correction_capability(parity_count: usize) -> usize {
    parity_count / 2
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `ALPHA` must be a *primitive* element of GF(2⁸) under the AES
    /// polynomial `0x11B`, i.e. have multiplicative order exactly 255, so that
    /// `alpha^0 .. alpha^(n-1)` are distinct for every supported codeword
    /// length.
    ///
    /// This guards a real bug: `ALPHA` used to be `2`, whose order is only 51.
    /// Codewords longer than 51 symbols reused evaluation points, which made
    /// Lagrange interpolation degenerate and silently broke the 104-byte
    /// signature payload. Changing `ALPHA` is also a wire-format change, so if
    /// this test ever fails, bump `crypto::FORMAT_VERSION` too.
    #[test]
    fn alpha_is_primitive() {
        // No smaller power may return to 1.
        let mut x: u8 = 1;
        for exponent in 1..255u32 {
            x = gf_mul(x, ALPHA);
            assert_ne!(
                x, 1,
                "ALPHA = {ALPHA} has order {exponent}, not 255 — it is not a \
                 primitive element, so evaluation points repeat after \
                 {exponent} symbols"
            );
        }
        // ...and alpha^255 must be 1.
        assert_eq!(gf_mul(x, ALPHA), 1, "alpha^255 must equal 1");
    }

    /// All evaluation points used by a maximum-length codeword are distinct.
    /// This is the property `alpha_is_primitive` exists to protect, asserted
    /// directly.
    #[test]
    fn evaluation_points_are_distinct_at_max_length() {
        let mut seen = vec![false; 256];
        for i in 0..MAX_CODEWORD_LEN {
            let point = gf_pow(ALPHA, i as u32);
            assert!(
                !seen[point as usize],
                "evaluation point {point} repeats at index {i}"
            );
            seen[point as usize] = true;
        }
    }

    /// The real steganographic payload is 104 bytes of RS-protected data
    /// (`SignaturePayload::SERIALIZED_SIZE` less its 5-byte magic+version
    /// header). This is the size that regressed when `ALPHA` was non-primitive,
    /// so pin it explicitly rather than relying on short-payload tests.
    #[test]
    fn round_trip_at_real_payload_size() {
        let data: Vec<u8> = (0..104u32).map(|i| (i * 37 + 11) as u8).collect();
        let encoded = encode(&data, 4).unwrap();
        assert_eq!(encoded.len(), 108);
        assert_eq!(decode(&encoded, data.len(), 4).unwrap(), data);
    }

    #[test]
    fn no_errors() {
        let data = b"Hello, steganography!";
        let encoded = encode(data, 4).unwrap();
        assert_eq!(encoded.len(), data.len() + 4);
        assert_eq!(decode(&encoded, data.len(), 4).unwrap(), data);
    }

    #[test]
    fn signature_sized_payload_roundtrip() {
        let data: Vec<u8> = (0..109).map(|value| value as u8).collect();
        let encoded = encode(&data, 4).unwrap();
        assert_eq!(decode(&encoded, data.len(), 4).unwrap(), data);
    }

    #[test]
    fn single_error_correction() {
        let data = b"payload data";
        let mut encoded = encode(data, 4).unwrap();
        encoded[3] ^= 0xFF;
        assert_eq!(decode(&encoded, data.len(), 4).unwrap(), data);
    }

    #[test]
    fn two_error_correction() {
        let data = b"two symbol error correction";
        let mut encoded = encode(data, 4).unwrap();
        encoded[1] ^= 0x42;
        let next_to_last = encoded.len() - 2;
        encoded[next_to_last] ^= 0xAB;
        assert_eq!(decode(&encoded, data.len(), 4).unwrap(), data);
    }

    #[test]
    fn four_error_correction() {
        let data = b"multi-error correction test payload";
        let mut encoded = encode(data, 8).unwrap();
        encoded[1] ^= 0x11;
        encoded[5] ^= 0x22;
        encoded[10] ^= 0x33;
        encoded[15] ^= 0x44;
        assert_eq!(decode(&encoded, data.len(), 8).unwrap(), data);
    }

    #[test]
    fn errors_in_message_and_parity_regions() {
        let data = b"position coverage";
        let mut encoded = encode(data, 4).unwrap();
        encoded[0] ^= 0x42;
        let last = encoded.len() - 1;
        encoded[last] ^= 0x99;
        assert_eq!(decode(&encoded, data.len(), 4).unwrap(), data);
    }

    #[test]
    fn uncorrectable_codeword_is_rejected() {
        let data = b"reject excessive errors";
        let mut encoded = encode(data, 4).unwrap();
        encoded[0] ^= 0x11;
        encoded[1] ^= 0x22;
        encoded[2] ^= 0x33;
        assert!(decode(&encoded, data.len(), 4).is_err());
    }

    #[test]
    fn no_parity() {
        let data = b"no parity";
        let encoded = encode(data, 0).unwrap();
        assert_eq!(encoded, data);
        assert_eq!(decode(&encoded, data.len(), 0).unwrap(), data);
    }

    #[test]
    fn empty_data() {
        let encoded = encode(b"", 4).unwrap();
        assert_eq!(encoded, vec![0; 4]);
        assert_eq!(decode(&encoded, 0, 4).unwrap(), b"");
    }

    #[test]
    fn evaluation_points_are_unique() {
        let mut seen = [false; 256];
        for exponent in 0..MAX_CODEWORD_LEN {
            let point = gf_pow(ALPHA, exponent as u32);
            assert_ne!(point, 0);
            assert!(!seen[point as usize], "duplicate at exponent {exponent}");
            seen[point as usize] = true;
        }
    }

    #[test]
    fn field_arithmetic() {
        assert_eq!(gf_mul(0, 0), 0);
        assert_eq!(gf_mul(1, 1), 1);
        assert_eq!(gf_mul(2, 3), 6);
        assert_eq!(gf_mul(0x57, 0x83), 0xc1);
        for value in 1..=255u8 {
            assert_eq!(gf_mul(value, gf_inv(value)), 1);
        }
    }

    #[test]
    fn bounds_are_enforced() {
        assert!(encode(b"data", 17).is_err());
        assert!(encode(&vec![0; MAX_CODEWORD_LEN], 1).is_err());
        assert!(decode(b"short", 10, 0).is_err());
    }

    #[test]
    fn correction_capabilities() {
        assert_eq!(correction_capability(0), 0);
        assert_eq!(correction_capability(2), 1);
        assert_eq!(correction_capability(4), 2);
    }
}
