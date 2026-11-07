//! Canonical carrier hashing for offline and native embed/verify workflows.
//!
//! Embedding necessarily changes a carrier. Signing the exact pre-embedding
//! bytes therefore cannot be verified from the encoded output. These helpers
//! remove the locations owned by the selected kernel before hashing, producing
//! the same binding bytes before and after embedding.
//!
//! Inputs are packed logical carrier bytes, never row padding. The
//! spread-spectrum case is the CLI scalar-bitstream format with its 32-bit
//! prefix and spread factor 64; it is not the green-only trait-video format.

use crate::crypto::SignaturePayload;

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
            let bpp = if width == 0 && height == 0 {
                // Dimensionless byte streams retain the original RGB contract.
                3
            } else {
                anyhow::ensure!(
                    width > 0 && height > 0,
                    "Video binding dimensions must be positive"
                );
                let pixels = (width as usize)
                    .checked_mul(height as usize)
                    .ok_or_else(|| anyhow::anyhow!("Video binding geometry overflow"))?;
                if pixels.checked_mul(3) == Some(canonical.len()) {
                    3
                } else if pixels.checked_mul(4) == Some(canonical.len()) {
                    4
                } else {
                    anyhow::bail!("Video binding requires packed RGB or BGRA pixels");
                }
            };
            for (index, byte) in canonical.iter_mut().enumerate() {
                if bpp != 4 || index % 4 != 3 {
                    *byte &= mask;
                }
            }
        }
        "lsb_audio" => {
            anyhow::ensure!(
                canonical.len().is_multiple_of(2),
                "LSB audio binding requires complete S16LE samples"
            );
            let mask = !((1i16 << validate_bits(bits)?) - 1);
            let (sample_chunks, _remainder) = canonical.as_chunks_mut::<2>();
            for sample in sample_chunks.iter_mut() {
                let value = i16::from_le_bytes(*sample) & mask;
                *sample = value.to_le_bytes();
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
        _ => anyhow::bail!("Unsupported carrier binding kernel: {}", stego_type),
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
    let expected_len = (width as usize)
        .checked_mul(height as usize)
        .and_then(|pixels| pixels.checked_mul(3))
        .ok_or_else(|| anyhow::anyhow!("DCT binding geometry overflow"))?;
    anyhow::ensure!(
        width > 0 && height > 0 && data.len() == expected_len,
        "DCT binding requires a complete packed RGB frame"
    );
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

    let stride = (width as usize)
        .checked_mul(3)
        .ok_or_else(|| anyhow::anyhow!("DCT binding stride overflow"))?;
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
    fn bgra_alpha_is_authenticated_and_row_padding_is_not_accepted() {
        let pixels = [0xff, 0xfe, 0xfd, 0xfb];
        assert_eq!(
            canonicalize(&pixels, "lsb_video", 2, 1, 1, 109).unwrap(),
            [0xfc, 0xfc, 0xfc, 0xfb]
        );
        assert!(canonicalize(&[0; 5], "lsb_video", 2, 1, 1, 109).is_err());
    }

    #[test]
    fn verifies_actual_delivered_lsb_pixels() {
        use crate::{Signer, Verifier, VideoFormat, VideoFrame, VideoStegoModule};
        let signer = Signer::generate();
        let verifier = Verifier::new(signer.verifying_key());
        let mut pixels = vec![0xff; 32 * 32 * 3];
        let before = canonicalize(&pixels, "lsb_video", 2, 32, 32, 109).unwrap();
        let payload = signer.sign_frame(9, &before, None);
        let mut kernel = crate::lsb_video::LsbVideo::new(2);
        let mut frame = VideoFrame {
            width: 32,
            height: 32,
            stride: 96,
            format: VideoFormat::Rgb8,
            data: &mut pixels,
            frame_index: 9,
        };
        kernel.embed(&mut frame, Some(&payload)).unwrap();
        let extracted = kernel.extract(&frame).unwrap().unwrap();
        let delivered = canonicalize(frame.data, "lsb_video", 2, 32, 32, 109).unwrap();
        assert!(verifier.verify(&extracted, &delivered, None));
        frame.data[2000] ^= 0x40;
        let tampered = canonicalize(frame.data, "lsb_video", 2, 32, 32, 109).unwrap();
        assert!(!verifier.verify(&extracted, &tampered, None));
    }

    #[test]
    fn unsupported_or_truncated_bindings_are_errors() {
        assert!(canonicalize(&[1], "lsb_audio", 1, 0, 0, 109).is_err());
        assert!(canonicalize(&[], "unknown", 1, 0, 0, 109).is_err());
        assert!(canonicalize(&[0; 3], "dct_video", 1, u32::MAX, u32::MAX, 109).is_err());
    }

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
