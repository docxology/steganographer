//! Transform pipeline for opt-in generic packets.
//!
//! The packet envelope records an ordered list of
//! [`TransformDescriptor`](crate::packet::TransformDescriptor)s and the locator
//! flags mirror them. This module owns the *meaning* of those descriptors: it
//! applies transforms to a logical payload (producing the encoded body) and
//! reverses them (recovering and re-verifying the logical payload).
//!
//! Transform order is fixed and matches the platform plan
//! ("sign logical content; compress; AEAD encrypt; ECC; embed"):
//!
//! 1. **Signing** — Ed25519 over the logical payload, recording the public
//!    key and signature so a decoder can attribute the payload to an identity.
//! 2. **Compression** — DEFLATE via `flate2`, recorded only when it actually
//!    shrinks the payload.
//! 3. **AEAD encryption** — ChaCha20-Poly1305 (RFC 8439) via
//!    [`crate::encryption`]. The ciphertext is bound to the packet identity
//!    (packet id + payload kind + original length) as associated data, and the
//!    packet nonce supplies 8 bytes of the encryption nonce so a fresh packet
//!    never reuses a nonce.
//! 4. **Error correction** — chunked Reed-Solomon over GF(2⁸) via
//!    [`crate::error_correction`], so payloads larger than the 255-symbol RS
//!    codeword ceiling are covered by independent per-chunk codewords.
//!
//! A decoder that meets an unknown *critical* transform fails closed with
//! [`TransformError::UnsupportedTransform`].

use std::io::{Read, Write};

use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};

use crate::encryption::{self, EncryptionKey};
use crate::error_correction;
use crate::packet::{
    TransformDescriptor, FLAG_COMPRESSED, FLAG_ENCRYPTED, FLAG_ERROR_CORRECTED, FLAG_PAYLOAD_SIGNED,
};
use thiserror::Error;

/// ChaCha20-Poly1305 AEAD transform.
pub const TRANSFORM_AEAD_CHACHA20_POLY1305: u16 = 1;
/// Chunked Reed-Solomon error-correction transform.
pub const TRANSFORM_ECC_REED_SOLOMON: u16 = 2;
/// DEFLATE compression transform.
pub const TRANSFORM_COMPRESS_DEFLATE: u16 = 3;
/// Ed25519 payload-signature transform.
pub const TRANSFORM_PAYLOAD_SIGN_ED25519: u16 = 4;

/// Serialized size of the Ed25519 sign-transform parameters
/// (`public_key || signature`).
pub const SIGN_PARAMS_SIZE: usize = 32 + 64;

/// Default per-chunk Reed-Solomon data length (symbols). `239 + 16 parity`
/// stays within the 255-symbol GF(2⁸) codeword ceiling.
pub const DEFAULT_ECC_CHUNK_LEN: usize = 239;
/// Reed-Solomon parity upper bound (also the `error_correction` ceiling).
pub const MAX_ECC_PARITY: usize = 16;

/// Identity material shared between encode and decode so transforms bind to a
/// specific packet and are reproducible.
#[derive(Debug, Clone, Copy)]
pub struct TransformContext<'a> {
    /// The 16-byte packet identifier (from the envelope).
    pub packet_id: &'a [u8; 16],
    /// The 8-byte locator nonce.
    pub nonce: &'a [u8; 8],
    /// The raw `u16` payload-kind discriminant.
    pub payload_kind: u16,
    /// The logical (untransformed) payload length in bytes.
    pub original_len: u64,
}

impl TransformContext<'_> {
    /// Associated data binding the ciphertext to the packet identity.
    fn aad(&self) -> Vec<u8> {
        let mut aad = Vec::with_capacity(16 + 2 + 8);
        aad.extend_from_slice(self.packet_id);
        aad.extend_from_slice(&self.payload_kind.to_be_bytes());
        aad.extend_from_slice(&self.original_len.to_be_bytes());
        aad
    }

    /// Encryption nonce seed derived from the packet nonce.
    fn frame_index(&self) -> u64 {
        u64::from_be_bytes(*self.nonce)
    }
}

/// Transform-pipeline failures.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TransformError {
    #[error("transform algorithm {0} is unknown")]
    UnknownTransform(u16),
    #[error("transform algorithm {0} is not supported by this decoder")]
    UnsupportedTransform(u16),
    #[error("encrypted packet requires a {what} key, but none was provided")]
    MissingKey { what: &'static str },
    #[error("transform descriptor is malformed: {0}")]
    InvalidDescriptor(&'static str),
    #[error("recovered payload length {actual} does not match the envelope ({expected})")]
    LengthMismatch { expected: u64, actual: usize },
    #[error("recovered payload digest does not match the envelope")]
    DigestMismatch,
    #[error("transform arithmetic overflow")]
    LengthOverflow,
    #[error("encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("compression failed: {0}")]
    CompressionFailed(String),
    #[error("decompression failed: {0}")]
    DecompressionFailed(String),
    #[error("error correction failed: {0}")]
    ErrorCorrectionFailed(String),
    #[error("payload signature is invalid or was made by a different key")]
    SignatureInvalid,
}

/// Whether an AEAD transform is present (and therefore a key is required to
/// reverse the packet).
pub fn is_encrypted(transforms: &[TransformDescriptor]) -> bool {
    transforms
        .iter()
        .any(|t| t.algorithm == TRANSFORM_AEAD_CHACHA20_POLY1305)
}

/// Apply signing (optional), compression (optional), encryption (optional),
/// and error correction (optional) to a logical payload, returning the encoded
/// body, the transform descriptors, and the locator flag bits to set.
pub fn apply(
    payload: &[u8],
    context: &TransformContext<'_>,
    signer: Option<&SigningKey>,
    compress: bool,
    encrypt_key: Option<&EncryptionKey>,
    ecc_parity: usize,
    ecc_chunk_len: usize,
) -> Result<(Vec<u8>, Vec<TransformDescriptor>, u16), TransformError> {
    let mut body = payload.to_vec();
    let mut transforms = Vec::with_capacity(4);
    let mut flags = 0u16;

    if let Some(signing_key) = signer {
        // Sign the logical payload before any other transform, so the signature
        // authenticates the exact bytes a decoder recovers.
        let signature: Signature = signing_key.sign(payload);
        let mut parameters = Vec::with_capacity(SIGN_PARAMS_SIZE);
        parameters.extend_from_slice(&signing_key.verifying_key().to_bytes());
        parameters.extend_from_slice(&signature.to_bytes());
        transforms.push(TransformDescriptor {
            algorithm: TRANSFORM_PAYLOAD_SIGN_ED25519,
            version: 1,
            critical: true,
            parameters,
        });
        flags |= FLAG_PAYLOAD_SIGNED;
    }

    if compress {
        let compressed = deflate_compress(&body)?;
        // Record the transform only when it actually shrinks the payload;
        // otherwise the descriptor would add overhead for no benefit.
        if compressed.len() < body.len() {
            body = compressed;
            transforms.push(TransformDescriptor {
                algorithm: TRANSFORM_COMPRESS_DEFLATE,
                version: 1,
                critical: true,
                parameters: Vec::new(),
            });
            flags |= FLAG_COMPRESSED;
        }
    }

    if let Some(key) = encrypt_key {
        body = encryption::encrypt(key, context.frame_index(), &body, Some(&context.aad()))
            .map_err(|e| TransformError::EncryptionFailed(e.to_string()))?;
        transforms.push(TransformDescriptor {
            algorithm: TRANSFORM_AEAD_CHACHA20_POLY1305,
            version: 1,
            critical: true,
            parameters: Vec::new(),
        });
        flags |= FLAG_ENCRYPTED;
    }

    if ecc_parity > 0 {
        // Record the pre-ECC length: it is the byte count the decoder must
        // recover, and differs from the post-ECC codeword length.
        let input_len = body.len();
        body = ecc_encode(&body, ecc_parity, ecc_chunk_len)?;
        transforms.push(TransformDescriptor {
            algorithm: TRANSFORM_ECC_REED_SOLOMON,
            version: 1,
            critical: true,
            parameters: ecc_params(ecc_parity, input_len, ecc_chunk_len),
        });
        flags |= FLAG_ERROR_CORRECTED;
    }

    Ok((body, transforms, flags))
}

/// Reverse the transforms recorded in an envelope, recovering the logical
/// payload and re-verifying it against the envelope's `original_len` and
/// `content_digest`.
pub fn reverse(
    encoded_body: &[u8],
    context: &TransformContext<'_>,
    encrypt_key: Option<&EncryptionKey>,
    transforms: &[TransformDescriptor],
    original_len: u64,
) -> Result<Vec<u8>, TransformError> {
    let mut body = encoded_body.to_vec();

    // Reverse transforms in the opposite order they were applied. ECC and
    // encryption are commutative with nothing here, but we preserve the
    // canonical order so future non-commutative transforms stay correct.
    for transform in transforms.iter().rev() {
        match transform.algorithm {
            TRANSFORM_AEAD_CHACHA20_POLY1305 => {
                let key = encrypt_key.ok_or(TransformError::MissingKey { what: "decryption" })?;
                body = encryption::decrypt(key, context.frame_index(), &body, Some(&context.aad()))
                    .map_err(|e| TransformError::DecryptionFailed(e.to_string()))?;
            }
            TRANSFORM_ECC_REED_SOLOMON => {
                let (parity, data_len, chunk_len) = parse_ecc_params(&transform.parameters)?;
                body = ecc_decode(&body, data_len, parity, chunk_len)?;
            }
            TRANSFORM_COMPRESS_DEFLATE => {
                // Compression is the first transform applied, so decompression
                // is the last reversed; its output length must equal the
                // logical payload length. `original_len + 1` bounds the read
                // to reject a decompression bomb.
                body = deflate_decompress(&body, original_len as usize)?;
            }
            TRANSFORM_PAYLOAD_SIGN_ED25519 => {
                // Signing is the innermost transform, so by the time we reach
                // it the recovered body is the logical payload that was signed.
                verify_ed25519_signature(&body, &transform.parameters)?;
            }
            other => {
                return Err(if transform.critical {
                    TransformError::UnsupportedTransform(other)
                } else {
                    TransformError::UnknownTransform(other)
                });
            }
        }
    }

    let actual = body.len() as u64;
    if actual != original_len {
        return Err(TransformError::LengthMismatch {
            expected: original_len,
            actual: body.len(),
        });
    }
    Ok(body)
}

/// Chunked Reed-Solomon encode: each chunk is an independent codeword, so
/// payloads larger than the 255-symbol ceiling remain covered.
fn ecc_encode(body: &[u8], parity: usize, chunk_len: usize) -> Result<Vec<u8>, TransformError> {
    validate_ecc_params(parity, chunk_len)?;
    if body.is_empty() {
        return Ok(Vec::new());
    }
    let mut output = Vec::with_capacity(body.len() + body.len().div_ceil(chunk_len) * parity);
    for chunk in body.chunks(chunk_len) {
        output.extend(
            error_correction::encode(chunk, parity)
                .map_err(|e| TransformError::ErrorCorrectionFailed(e.to_string()))?,
        );
    }
    Ok(output)
}

/// Chunked Reed-Solomon decode. `data_len` is the pre-ECC byte length and
/// `chunk_len` the per-chunk data ceiling, both recorded in the transform
/// descriptor.
fn ecc_decode(
    encoded: &[u8],
    data_len: usize,
    parity: usize,
    chunk_len: usize,
) -> Result<Vec<u8>, TransformError> {
    validate_ecc_params(parity, chunk_len)?;
    if parity == 0 {
        if encoded.len() < data_len {
            return Err(TransformError::InvalidDescriptor("ECC data is truncated"));
        }
        return Ok(encoded[..data_len].to_vec());
    }
    if data_len == 0 {
        return Ok(Vec::new());
    }

    let full_chunks = data_len / chunk_len;
    let last_len = data_len % chunk_len;
    let mut output = Vec::with_capacity(data_len);
    let mut offset = 0usize;
    for _ in 0..full_chunks {
        let codeword_len = chunk_len + parity;
        let end = offset
            .checked_add(codeword_len)
            .ok_or(TransformError::LengthOverflow)?;
        if end > encoded.len() {
            return Err(TransformError::InvalidDescriptor("ECC data is truncated"));
        }
        output.extend(
            error_correction::decode(&encoded[offset..end], chunk_len, parity)
                .map_err(|e| TransformError::ErrorCorrectionFailed(e.to_string()))?,
        );
        offset = end;
    }
    if last_len > 0 {
        let codeword_len = last_len + parity;
        let end = offset
            .checked_add(codeword_len)
            .ok_or(TransformError::LengthOverflow)?;
        if end > encoded.len() {
            return Err(TransformError::InvalidDescriptor("ECC data is truncated"));
        }
        output.extend(
            error_correction::decode(&encoded[offset..end], last_len, parity)
                .map_err(|e| TransformError::ErrorCorrectionFailed(e.to_string()))?,
        );
    }
    Ok(output)
}

/// Verify an Ed25519 signature recorded in the sign-transform parameters
/// (`public_key || signature`) over the recovered logical payload.
fn verify_ed25519_signature(body: &[u8], parameters: &[u8]) -> Result<(), TransformError> {
    if parameters.len() != SIGN_PARAMS_SIZE {
        return Err(TransformError::InvalidDescriptor(
            "Ed25519 sign transform parameters must be 96 bytes (pubkey || signature)",
        ));
    }
    let public_key =
        VerifyingKey::from_bytes(&parameters[..32].try_into().expect("fixed slice"))
            .map_err(|_| TransformError::InvalidDescriptor("invalid Ed25519 public key"))?;
    let signature = Signature::from_bytes(&parameters[32..].try_into().expect("fixed slice"));
    public_key
        .verify(body, &signature)
        .map_err(|_| TransformError::SignatureInvalid)
}

/// DEFLATE-compress a byte slice.
fn deflate_compress(data: &[u8]) -> Result<Vec<u8>, TransformError> {
    let mut encoder =
        flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    encoder
        .write_all(data)
        .map_err(|e| TransformError::CompressionFailed(e.to_string()))?;
    encoder
        .finish()
        .map_err(|e| TransformError::CompressionFailed(e.to_string()))
}

/// DEFLATE-decompress a byte slice, bounded to `limit` bytes (inclusive) so a
/// malicious or corrupt stream cannot expand into a decompression bomb.
fn deflate_decompress(data: &[u8], limit: usize) -> Result<Vec<u8>, TransformError> {
    let decoder = flate2::read::DeflateDecoder::new(data);
    let mut output = Vec::new();
    decoder
        .take((limit as u64).saturating_add(1))
        .read_to_end(&mut output)
        .map_err(|e| TransformError::DecompressionFailed(e.to_string()))?;
    if output.len() != limit {
        return Err(TransformError::InvalidDescriptor(
            "decompressed payload length does not match the envelope",
        ));
    }
    Ok(output)
}

fn validate_ecc_params(parity: usize, chunk_len: usize) -> Result<(), TransformError> {
    if parity > MAX_ECC_PARITY {
        return Err(TransformError::InvalidDescriptor(
            "Reed-Solomon parity exceeds the supported maximum",
        ));
    }
    if chunk_len == 0 || chunk_len + parity > 255 {
        return Err(TransformError::InvalidDescriptor(
            "Reed-Solomon chunk length + parity must not exceed 255 symbols",
        ));
    }
    Ok(())
}

/// Serialize the ECC descriptor parameters:
/// `parity (u8) || data_len (u32 BE) || chunk_len (u16 BE)`.
fn ecc_params(parity: usize, data_len: usize, chunk_len: usize) -> Vec<u8> {
    let mut params = Vec::with_capacity(7);
    params.push(parity as u8);
    params.extend_from_slice(&(data_len as u32).to_be_bytes());
    params.extend_from_slice(&(chunk_len as u16).to_be_bytes());
    params
}

fn parse_ecc_params(params: &[u8]) -> Result<(usize, usize, usize), TransformError> {
    if params.len() != 7 {
        return Err(TransformError::InvalidDescriptor(
            "Reed-Solomon transform parameters must be 7 bytes",
        ));
    }
    let parity = params[0] as usize;
    let data_len = u32::from_be_bytes([params[1], params[2], params[3], params[4]]) as usize;
    let chunk_len = u16::from_be_bytes([params[5], params[6]]) as usize;
    validate_ecc_params(parity, chunk_len)?;
    Ok((parity, data_len, chunk_len))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::GenericPacket;

    fn context(packet: &GenericPacket) -> TransformContext<'_> {
        TransformContext {
            packet_id: &packet.envelope.packet_id,
            nonce: &packet.locator.nonce,
            payload_kind: packet.envelope.payload_kind as u16,
            original_len: packet.envelope.original_len,
        }
    }

    fn test_key() -> EncryptionKey {
        EncryptionKey::from_bytes(&[7u8; 32])
    }

    #[test]
    fn encryption_roundtrip_and_wrong_key_fails() {
        let payload = b"top secret generic payload".to_vec();
        let packet = GenericPacket::new_untransformed(
            payload.clone(),
            *b"0123456789abcdef",
            *b"nonce123",
            crate::packet::PayloadKind::Bytes,
            crate::packet::AlgorithmDescriptor::new(1, 1, Vec::new()),
            crate::packet::AlgorithmDescriptor::new(1, 1, vec![1]),
            &crate::packet::DecodeLimits::default(),
        )
        .unwrap();
        let ctx = context(&packet);

        let key = test_key();
        let (body, transforms, flags) = apply(
            &payload,
            &ctx,
            None,
            false,
            Some(&key),
            0,
            DEFAULT_ECC_CHUNK_LEN,
        )
        .unwrap();
        assert!(flags & FLAG_ENCRYPTED != 0);
        assert_eq!(transforms.len(), 1);
        assert_ne!(body, payload);

        let recovered =
            reverse(&body, &ctx, Some(&key), &transforms, payload.len() as u64).unwrap();
        assert_eq!(recovered, payload);

        let wrong = EncryptionKey::from_bytes(&[9u8; 32]);
        assert!(matches!(
            reverse(&body, &ctx, Some(&wrong), &transforms, payload.len() as u64),
            Err(TransformError::DecryptionFailed(_))
        ));

        // Missing key fails closed.
        assert!(matches!(
            reverse(&body, &ctx, None, &transforms, payload.len() as u64),
            Err(TransformError::MissingKey { .. })
        ));
    }

    #[test]
    fn ecc_chunked_roundtrip_and_correction() {
        // 600 bytes > 239 chunk ceiling → three chunks.
        let payload: Vec<u8> = (0..600u32).map(|i| (i % 251) as u8).collect();
        let packet = GenericPacket::new_untransformed(
            payload.clone(),
            *b"0123456789abcdef",
            *b"nonce123",
            crate::packet::PayloadKind::Bytes,
            crate::packet::AlgorithmDescriptor::new(1, 1, Vec::new()),
            crate::packet::AlgorithmDescriptor::new(1, 1, vec![1]),
            &crate::packet::DecodeLimits::default(),
        )
        .unwrap();
        let ctx = context(&packet);

        let parity = 4;
        let (body, transforms, flags) = apply(
            &payload,
            &ctx,
            None,
            false,
            None,
            parity,
            DEFAULT_ECC_CHUNK_LEN,
        )
        .unwrap();
        assert!(flags & FLAG_ERROR_CORRECTED != 0);
        assert_eq!(transforms.len(), 1);

        // Flip a few symbols inside one chunk; ECC should repair them.
        let mut corrupted = body.clone();
        for i in 0..(parity / 2) {
            corrupted[i] ^= 1;
        }
        let recovered = reverse(&corrupted, &ctx, None, &transforms, payload.len() as u64).unwrap();
        assert_eq!(recovered, payload);
    }

    #[test]
    fn ecc_and_encryption_compose_and_reverse_in_order() {
        let payload = b"encrypted then corrected".to_vec();
        let packet = GenericPacket::new_untransformed(
            payload.clone(),
            *b"0123456789abcdef",
            *b"nonce123",
            crate::packet::PayloadKind::Bytes,
            crate::packet::AlgorithmDescriptor::new(1, 1, Vec::new()),
            crate::packet::AlgorithmDescriptor::new(1, 1, vec![1]),
            &crate::packet::DecodeLimits::default(),
        )
        .unwrap();
        let ctx = context(&packet);

        let key = test_key();
        let (body, transforms, flags) = apply(
            &payload,
            &ctx,
            None,
            false,
            Some(&key),
            8,
            DEFAULT_ECC_CHUNK_LEN,
        )
        .unwrap();
        assert_eq!(flags, FLAG_ENCRYPTED | FLAG_ERROR_CORRECTED);
        assert_eq!(transforms.len(), 2);
        assert_eq!(transforms[0].algorithm, TRANSFORM_AEAD_CHACHA20_POLY1305);
        assert_eq!(transforms[1].algorithm, TRANSFORM_ECC_REED_SOLOMON);

        let recovered =
            reverse(&body, &ctx, Some(&key), &transforms, payload.len() as u64).unwrap();
        assert_eq!(recovered, payload);
    }

    #[test]
    fn compression_roundtrip_shrinks_and_reverses() {
        let payload = vec![b'a'; 1000]; // highly compressible
        let packet = GenericPacket::new_untransformed(
            payload.clone(),
            *b"0123456789abcdef",
            *b"nonce123",
            crate::packet::PayloadKind::Bytes,
            crate::packet::AlgorithmDescriptor::new(1, 1, Vec::new()),
            crate::packet::AlgorithmDescriptor::new(1, 1, vec![1]),
            &crate::packet::DecodeLimits::default(),
        )
        .unwrap();
        let ctx = context(&packet);

        let (body, transforms, flags) =
            apply(&payload, &ctx, None, true, None, 0, DEFAULT_ECC_CHUNK_LEN).unwrap();
        assert!(flags & FLAG_COMPRESSED != 0);
        assert_eq!(transforms.len(), 1);
        assert_eq!(transforms[0].algorithm, TRANSFORM_COMPRESS_DEFLATE);
        assert!(body.len() < payload.len(), "DEFLATE must shrink 1000 'a's");

        let recovered = reverse(&body, &ctx, None, &transforms, payload.len() as u64).unwrap();
        assert_eq!(recovered, payload);
    }

    #[test]
    fn compression_of_incompressible_data_is_skipped() {
        // Deterministic pseudorandom bytes via a BLAKE3 hash chain; DEFLATE
        // cannot shrink this, so the transform must not be recorded.
        let mut data = Vec::new();
        let mut seed = b"compress test seed".to_vec();
        while data.len() < 256 {
            let digest = blake3::hash(&seed);
            data.extend_from_slice(digest.as_bytes());
            seed = digest.as_bytes().to_vec();
        }
        data.truncate(256);

        let packet = GenericPacket::new_untransformed(
            data.clone(),
            *b"0123456789abcdef",
            *b"nonce123",
            crate::packet::PayloadKind::Bytes,
            crate::packet::AlgorithmDescriptor::new(1, 1, Vec::new()),
            crate::packet::AlgorithmDescriptor::new(1, 1, vec![1]),
            &crate::packet::DecodeLimits::default(),
        )
        .unwrap();
        let ctx = context(&packet);

        let (body, transforms, flags) =
            apply(&data, &ctx, None, true, None, 0, DEFAULT_ECC_CHUNK_LEN).unwrap();
        assert_eq!(
            flags & FLAG_COMPRESSED,
            0,
            "incompressible data must not be flagged"
        );
        assert!(transforms.is_empty());
        assert_eq!(body, data);
    }

    #[test]
    fn compress_encrypt_ecc_compose_in_canonical_order() {
        let payload = vec![b'b'; 600];
        let packet = GenericPacket::new_untransformed(
            payload.clone(),
            *b"0123456789abcdef",
            *b"nonce123",
            crate::packet::PayloadKind::Bytes,
            crate::packet::AlgorithmDescriptor::new(1, 1, Vec::new()),
            crate::packet::AlgorithmDescriptor::new(1, 1, vec![1]),
            &crate::packet::DecodeLimits::default(),
        )
        .unwrap();
        let ctx = context(&packet);
        let key = test_key();

        let (body, transforms, flags) = apply(
            &payload,
            &ctx,
            None,
            true,
            Some(&key),
            4,
            DEFAULT_ECC_CHUNK_LEN,
        )
        .unwrap();
        assert_eq!(
            flags,
            FLAG_COMPRESSED | FLAG_ENCRYPTED | FLAG_ERROR_CORRECTED
        );
        assert_eq!(transforms.len(), 3);
        assert_eq!(transforms[0].algorithm, TRANSFORM_COMPRESS_DEFLATE);
        assert_eq!(transforms[1].algorithm, TRANSFORM_AEAD_CHACHA20_POLY1305);
        assert_eq!(transforms[2].algorithm, TRANSFORM_ECC_REED_SOLOMON);

        let recovered =
            reverse(&body, &ctx, Some(&key), &transforms, payload.len() as u64).unwrap();
        assert_eq!(recovered, payload);
    }

    #[test]
    fn signing_roundtrip_and_tamper_detection() {
        let payload = b"signed logical payload".to_vec();
        let packet = GenericPacket::new_untransformed(
            payload.clone(),
            *b"0123456789abcdef",
            *b"nonce123",
            crate::packet::PayloadKind::Bytes,
            crate::packet::AlgorithmDescriptor::new(1, 1, Vec::new()),
            crate::packet::AlgorithmDescriptor::new(1, 1, vec![1]),
            &crate::packet::DecodeLimits::default(),
        )
        .unwrap();
        let ctx = context(&packet);
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);

        let (body, transforms, flags) = apply(
            &payload,
            &ctx,
            Some(&signing_key),
            false,
            None,
            0,
            DEFAULT_ECC_CHUNK_LEN,
        )
        .unwrap();
        assert!(flags & FLAG_PAYLOAD_SIGNED != 0);
        assert_eq!(transforms.len(), 1);
        assert_eq!(transforms[0].algorithm, TRANSFORM_PAYLOAD_SIGN_ED25519);
        assert_eq!(transforms[0].parameters.len(), SIGN_PARAMS_SIZE);

        // Valid signature reverses cleanly.
        let recovered = reverse(&body, &ctx, None, &transforms, payload.len() as u64).unwrap();
        assert_eq!(recovered, payload);

        // A tampered recovered payload fails verification.
        let tampered = b"signed logical payload!".to_vec();
        let mut bad_transforms = transforms.clone();
        // Signature was over the original payload; verifying over the tampered
        // body must fail.
        assert!(matches!(
            verify_ed25519_signature(&tampered, &bad_transforms[0].parameters),
            Err(TransformError::SignatureInvalid)
        ));

        // Corrupting the recorded signature must fail verification.
        bad_transforms[0].parameters[40] ^= 1;
        assert!(matches!(
            reverse(&body, &ctx, None, &bad_transforms, payload.len() as u64),
            Err(TransformError::SignatureInvalid)
        ));
    }

    #[test]
    fn signing_composes_with_encrypt_and_ecc() {
        let payload = b"signed, encrypted, corrected".to_vec();
        let packet = GenericPacket::new_untransformed(
            payload.clone(),
            *b"0123456789abcdef",
            *b"nonce123",
            crate::packet::PayloadKind::Bytes,
            crate::packet::AlgorithmDescriptor::new(1, 1, Vec::new()),
            crate::packet::AlgorithmDescriptor::new(1, 1, vec![1]),
            &crate::packet::DecodeLimits::default(),
        )
        .unwrap();
        let ctx = context(&packet);
        let signing_key = SigningKey::from_bytes(&[11u8; 32]);
        let key = test_key();

        let (body, transforms, flags) = apply(
            &payload,
            &ctx,
            Some(&signing_key),
            false,
            Some(&key),
            4,
            DEFAULT_ECC_CHUNK_LEN,
        )
        .unwrap();
        assert_eq!(
            flags,
            FLAG_PAYLOAD_SIGNED | FLAG_ENCRYPTED | FLAG_ERROR_CORRECTED
        );
        assert_eq!(transforms.len(), 3);
        assert_eq!(transforms[0].algorithm, TRANSFORM_PAYLOAD_SIGN_ED25519);
        assert_eq!(transforms[1].algorithm, TRANSFORM_AEAD_CHACHA20_POLY1305);
        assert_eq!(transforms[2].algorithm, TRANSFORM_ECC_REED_SOLOMON);

        let recovered =
            reverse(&body, &ctx, Some(&key), &transforms, payload.len() as u64).unwrap();
        assert_eq!(recovered, payload);
    }

    #[test]
    fn aad_binding_rejects_transplanted_packet() {
        let payload = b"bind me to my packet".to_vec();
        let packet_a = GenericPacket::new_untransformed(
            payload.clone(),
            *b"aaaaaaaaaaaaaaaa",
            *b"nonce123",
            crate::packet::PayloadKind::Bytes,
            crate::packet::AlgorithmDescriptor::new(1, 1, Vec::new()),
            crate::packet::AlgorithmDescriptor::new(1, 1, vec![1]),
            &crate::packet::DecodeLimits::default(),
        )
        .unwrap();
        let key = test_key();
        let (body, transforms, _) = apply(
            &payload,
            &context(&packet_a),
            None,
            false,
            Some(&key),
            0,
            DEFAULT_ECC_CHUNK_LEN,
        )
        .unwrap();

        // Decode with a *different* packet identity → AEAD must reject.
        let packet_b = GenericPacket::new_untransformed(
            payload.clone(),
            *b"bbbbbbbbbbbbbbbb",
            *b"nonce123",
            crate::packet::PayloadKind::Bytes,
            crate::packet::AlgorithmDescriptor::new(1, 1, Vec::new()),
            crate::packet::AlgorithmDescriptor::new(1, 1, vec![1]),
            &crate::packet::DecodeLimits::default(),
        )
        .unwrap();
        assert!(matches!(
            reverse(
                &body,
                &context(&packet_b),
                Some(&key),
                &transforms,
                payload.len() as u64
            ),
            Err(TransformError::DecryptionFailed(_))
        ));
    }

    #[test]
    fn unknown_critical_transform_fails_closed() {
        let transforms = vec![TransformDescriptor {
            algorithm: 9999,
            version: 1,
            critical: true,
            parameters: Vec::new(),
        }];
        let payload = b"x".to_vec();
        let packet = GenericPacket::new_untransformed(
            payload.clone(),
            *b"0123456789abcdef",
            *b"nonce123",
            crate::packet::PayloadKind::Bytes,
            crate::packet::AlgorithmDescriptor::new(1, 1, Vec::new()),
            crate::packet::AlgorithmDescriptor::new(1, 1, vec![1]),
            &crate::packet::DecodeLimits::default(),
        )
        .unwrap();
        let ctx = context(&packet);
        assert!(matches!(
            reverse(b"abc", &ctx, None, &transforms, 1),
            Err(TransformError::UnsupportedTransform(9999))
        ));
    }

    #[test]
    fn ecc_params_roundtrip() {
        let params = ecc_params(8, 12345, DEFAULT_ECC_CHUNK_LEN);
        assert_eq!(params.len(), 7);
        assert_eq!(
            parse_ecc_params(&params).unwrap(),
            (8, 12345, DEFAULT_ECC_CHUNK_LEN)
        );
        assert!(parse_ecc_params(&[0u8; 6]).is_err());
    }
}
