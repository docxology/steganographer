//! Canonical carrier hashing for offline embed/verify workflows.
//!
//! Embedding necessarily changes a carrier. Signing the exact pre-embedding
//! bytes therefore cannot be verified from the encoded output. These helpers
//! remove the locations owned by the selected kernel before hashing, producing
//! the same binding bytes before and after embedding.

use steganographer_core::crypto::SignaturePayload;

pub fn canonicalize(
    data: &[u8],
    stego_type: &str,
    bits: u8,
    width: u32,
    height: u32,
    embedded_payload_len: usize,
) -> anyhow::Result<Vec<u8>> {
    let mut canonical = data.to_vec();
    match stego_type {
        "lsb_video" => {
            let mask = lsb_clear_mask(bits)?;
            for byte in &mut canonical {
                *byte &= mask;
            }
        }
        "lsb_audio" => {
            let mask = !((1i16 << validate_bits(bits)?) - 1);
            for sample in canonical.chunks_exact_mut(2) {
                let value = i16::from_le_bytes([sample[0], sample[1]]) & mask;
                sample.copy_from_slice(&value.to_le_bytes());
            }
        }
        "spread_spectrum_video" => {
            let payload_bits = embedded_payload_len
                .checked_mul(8)
                .and_then(|value| value.checked_add(32))
                .ok_or_else(|| anyhow::anyhow!("Spread-spectrum payload length overflow"))?;
            let modified_bytes = payload_bits
                .checked_mul(64)
                .ok_or_else(|| anyhow::anyhow!("Spread-spectrum region length overflow"))?;
            if modified_bytes > canonical.len() {
                anyhow::bail!(
                    "Spread-spectrum binding region exceeds carrier: need {}, have {}",
                    modified_bytes,
                    canonical.len()
                );
            }
            canonical[..modified_bytes].fill(0);
        }
        "dct_video" => {
            canonicalize_dct_regions(&mut canonical, width, height)?;
        }
        _ => {}
    }
    Ok(canonical)
}

fn validate_bits(bits: u8) -> anyhow::Result<u8> {
    if !(1..=4).contains(&bits) {
        anyhow::bail!("LSB bits must be in the range 1-4, got {}", bits);
    }
    Ok(bits)
}

fn lsb_clear_mask(bits: u8) -> anyhow::Result<u8> {
    Ok(!((1u8 << validate_bits(bits)?) - 1))
}

fn canonicalize_dct_regions(data: &mut [u8], width: u32, height: u32) -> anyhow::Result<()> {
    let blocks_x = width as usize / 8;
    let blocks_y = height as usize / 8;
    let required_blocks = SignaturePayload::SERIALIZED_SIZE * 8;
    if blocks_x
        .checked_mul(blocks_y)
        .ok_or_else(|| anyhow::anyhow!("DCT block count overflow"))?
        < required_blocks
    {
        anyhow::bail!(
            "Not enough DCT blocks for carrier binding: need {}, have {}",
            required_blocks,
            blocks_x * blocks_y
        );
    }

    let stride = width as usize * 3;
    for payload_bit in 0..required_blocks {
        let block_x = (payload_bit % blocks_x) * 8;
        let block_y = (payload_bit / blocks_x) * 8;
        for row in 0..8 {
            for column in 0..8 {
                let offset = (block_y + row)
                    .checked_mul(stride)
                    .and_then(|value| value.checked_add((block_x + column) * 3 + 1))
                    .ok_or_else(|| anyhow::anyhow!("DCT binding offset overflow"))?;
                if offset >= data.len() {
                    anyhow::bail!(
                        "DCT binding offset {} exceeds decoded carrier length {}",
                        offset,
                        data.len()
                    );
                }
                data[offset] = 0;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn video_lsb_binding_ignores_selected_low_bits() {
        let original = [0b1010_1010, 0b0101_0101];
        let modified = [0b1010_1011, 0b0101_0100];
        assert_eq!(
            canonicalize(&original, "lsb_video", 1, 0, 0, 0).unwrap(),
            canonicalize(&modified, "lsb_video", 1, 0, 0, 0).unwrap()
        );
    }

    #[test]
    fn audio_lsb_binding_ignores_selected_low_bits() {
        let original = 0x1234i16.to_le_bytes();
        let modified = 0x1237i16.to_le_bytes();
        assert_eq!(
            canonicalize(&original, "lsb_audio", 2, 0, 0, 0).unwrap(),
            canonicalize(&modified, "lsb_audio", 2, 0, 0, 0).unwrap()
        );
    }
}
