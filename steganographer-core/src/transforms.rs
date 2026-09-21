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
//!    (packet id + payload kind + original length) as associated data. The
//!    AEAD nonce is derived from the 16-byte packet identifier plus a fresh
//!    per-invocation salt, so it never depends on public transport data and a
//!    fresh packet never reuses a nonce.
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
use crate::password::{self, Argon2Params};
use thiserror::Error;

/// ChaCha20-Poly1305 AEAD transform.
pub const TRANSFORM_AEAD_CHACHA20_POLY1305: u16 = 1;
/// Chunked Reed-Solomon error-correction transform.
pub const TRANSFORM_ECC_REED_SOLOMON: u16 = 2;
/// DEFLATE compression transform.
pub const TRANSFORM_COMPRESS_DEFLATE: u16 = 3;
/// Ed25519 payload-signature transform.
pub const TRANSFORM_PAYLOAD_SIGN_ED25519: u16 = 4;
/// Argon2id password key-derivation transform (PKT-007). Additive descriptor:
/// packets written before this identifier existed decode unchanged, and
/// decoders that predate it fail closed on the critical descriptor.
pub const TRANSFORM_KDF_ARGON2ID: u16 = 5;

/// Serialized size of the Argon2id KDF transform parameters, pinned layout:
/// `[salt (16B)] [memory_kib u32 LE] [iterations u32 LE] [lanes u8] [output_len u16 LE]`.
pub const KDF_ARGON2ID_PARAMS_SIZE: usize = 16 + 4 + 4 + 1 + 2;
/// Salt length carried in the KDF descriptor (128-bit).
pub const KDF_ARGON2ID_SALT_LEN: usize = 16;
/// Pinned KDF output length: the derived master secret *is* the 32-byte
/// ChaCha20-Poly1305 key.
pub const KDF_ARGON2ID_OUTPUT_LEN: u16 = 32;
/// DoS ceiling on the unauthenticated `memory_kib` descriptor field (1 GiB):
/// a hostile descriptor must not direct a decoder to spend attacker-chosen
/// memory per decode attempt.
pub const MAX_KDF_MEMORY_KIB: u32 = 1024 * 1024;
/// DoS ceiling on the unauthenticated iteration count.
pub const MAX_KDF_ITERATIONS: u32 = 1024;

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
    /// The 16-byte packet identifier (from the envelope). Also anchors the
    /// AEAD nonce derivation, so the public locator nonce is never trusted.
    pub packet_id: &'a [u8; 16],
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
    #[error("Argon2id key derivation failed: {0}")]
    KdfFailed(String),
    #[error("a password and a raw encryption key were both supplied; they are mutually exclusive")]
    AmbiguousKeySource,
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

/// Password credentials for the Argon2id KDF transform (PKT-007). On apply
/// the salt is fresh-random and the descriptor records it alongside the
/// Argon2 parameters so [`reverse_with_password`] can re-derive the key.
#[derive(Debug, Clone, Copy)]
pub struct PasswordKdfCredentials<'a> {
    pub password: &'a [u8],
    /// Argon2id parameters; `output_len` must be 32 (the AEAD key size).
    pub params: Argon2Params,
}

/// Parsed Argon2id KDF descriptor parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2idKdfParams {
    pub salt: [u8; KDF_ARGON2ID_SALT_LEN],
    pub memory_kib: u32,
    pub iterations: u32,
    pub lanes: u8,
}

/// Validate the Argon2id parameter bounds a decoder will spend: the
/// algorithmic floor from [`Argon2Params::validate`] plus hard DoS ceilings
/// ([`MAX_KDF_MEMORY_KIB`], [`MAX_KDF_ITERATIONS`]) because the descriptor is
/// unauthenticated.
fn validate_kdf_bounds(memory_kib: u32, iterations: u32, lanes: u8) -> Result<(), TransformError> {
    if memory_kib == 0 || memory_kib > MAX_KDF_MEMORY_KIB {
        return Err(TransformError::InvalidDescriptor(
            "Argon2id memory cost is zero or exceeds the decode ceiling",
        ));
    }
    if iterations == 0 || iterations > MAX_KDF_ITERATIONS {
        return Err(TransformError::InvalidDescriptor(
            "Argon2id iteration count is zero or exceeds the decode ceiling",
        ));
    }
    Argon2Params {
        memory_kib,
        iterations,
        parallelism: u32::from(lanes),
        output_len: usize::from(KDF_ARGON2ID_OUTPUT_LEN),
    }
    .validate()
    .map_err(|e| TransformError::KdfFailed(e.to_string()))
}

/// Serialize the Argon2id KDF descriptor parameters, pinned layout:
/// `[salt (16B)] [memory_kib u32 LE] [iterations u32 LE] [lanes u8] [output_len u16 LE]`.
fn kdf_argon2id_params(salt: &[u8; KDF_ARGON2ID_SALT_LEN], params: &Argon2Params) -> Vec<u8> {
    let mut out = Vec::with_capacity(KDF_ARGON2ID_PARAMS_SIZE);
    out.extend_from_slice(salt);
    out.extend_from_slice(&params.memory_kib.to_le_bytes());
    out.extend_from_slice(&params.iterations.to_le_bytes());
    out.push(u8::try_from(params.parallelism).expect("lane count fits in one byte"));
    out.extend_from_slice(&KDF_ARGON2ID_OUTPUT_LEN.to_le_bytes());
    out
}

/// Parse and bound-check the Argon2id KDF descriptor parameters.
pub fn parse_kdf_argon2id_params(params: &[u8]) -> Result<Argon2idKdfParams, TransformError> {
    if params.len() != KDF_ARGON2ID_PARAMS_SIZE {
        return Err(TransformError::InvalidDescriptor(
            "Argon2id KDF transform parameters must be 27 bytes",
        ));
    }
    let output_len = u16::from_le_bytes([params[25], params[26]]);
    if output_len != KDF_ARGON2ID_OUTPUT_LEN {
        return Err(TransformError::InvalidDescriptor(
            "Argon2id KDF output length must be 32 bytes",
        ));
    }
    let memory_kib = u32::from_le_bytes(params[16..20].try_into().expect("fixed slice"));
    let iterations = u32::from_le_bytes(params[20..24].try_into().expect("fixed slice"));
    let lanes = params[24];
    validate_kdf_bounds(memory_kib, iterations, lanes)?;
    Ok(Argon2idKdfParams {
        salt: params[..16].try_into().expect("fixed slice"),
        memory_kib,
        iterations,
        lanes,
    })
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
    apply_with_password(
        payload,
        context,
        signer,
        compress,
        None,
        encrypt_key,
        ecc_parity,
        ecc_chunk_len,
    )
}

/// [`apply`] with the PKT-007 password path: when `password` is set, the AEAD
/// key is derived with Argon2id (`password.rs`) and recorded in a
/// [`TRANSFORM_KDF_ARGON2ID`] descriptor ahead of the AEAD descriptor it
/// feeds. `password` and `encrypt_key` are mutually exclusive.
#[allow(clippy::too_many_arguments)] // transform-chain application context
pub fn apply_with_password(
    payload: &[u8],
    context: &TransformContext<'_>,
    signer: Option<&SigningKey>,
    compress: bool,
    password: Option<&PasswordKdfCredentials<'_>>,
    encrypt_key: Option<&EncryptionKey>,
    ecc_parity: usize,
    ecc_chunk_len: usize,
) -> Result<(Vec<u8>, Vec<TransformDescriptor>, u16), TransformError> {
    if password.is_some() && encrypt_key.is_some() {
        return Err(TransformError::AmbiguousKeySource);
    }
    let mut body = payload.to_vec();
    let mut transforms = Vec::with_capacity(5);
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

    // PKT-007: password mode derives the AEAD key with Argon2id and records
    // the descriptor before the AEAD transform, so a decoder re-derives the
    // key and hands it to the AEAD reverse (KDF applied before AEAD; reversed
    // after it in the reverse pass).
    let mut derived_key = None;
    if let Some(credentials) = password {
        let params = credentials.params;
        if params.output_len != usize::from(KDF_ARGON2ID_OUTPUT_LEN) {
            return Err(TransformError::InvalidDescriptor(
                "Argon2id KDF output length must be 32 bytes to feed the AEAD key",
            ));
        }
        params
            .validate()
            .map_err(|e| TransformError::KdfFailed(e.to_string()))?;
        u8::try_from(params.parallelism).map_err(|_| {
            TransformError::InvalidDescriptor("Argon2id lane count must fit in one byte")
        })?;
        let salt = password::generate_salt();
        let master = password::derive_master_from_password(credentials.password, &salt, &params)
            .map_err(|e| TransformError::KdfFailed(e.to_string()))?;
        transforms.push(TransformDescriptor {
            algorithm: TRANSFORM_KDF_ARGON2ID,
            version: 1,
            critical: true,
            parameters: kdf_argon2id_params(&salt, &params),
        });
        derived_key = Some(EncryptionKey::from_bytes(
            master.as_slice().try_into().expect("output_len is 32"),
        ));
    }
    let effective_key = encrypt_key.or(derived_key.as_ref());
    if let Some(key) = effective_key {
        body = encryption::encrypt(key, context.packet_id, &body, Some(&context.aad()))
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
    reverse_with_password(
        encoded_body,
        context,
        encrypt_key,
        None,
        transforms,
        original_len,
    )
}

/// [`reverse`] with the PKT-007 password path: when the envelope records a
/// [`TRANSFORM_KDF_ARGON2ID`] descriptor, `password` re-derives the AEAD key
/// from the descriptor's salt and Argon2 parameters and hands it to the AEAD
/// reverse. A KDF descriptor without a password fails closed.
pub fn reverse_with_password(
    encoded_body: &[u8],
    context: &TransformContext<'_>,
    encrypt_key: Option<&EncryptionKey>,
    password: Option<&[u8]>,
    transforms: &[TransformDescriptor],
    original_len: u64,
) -> Result<Vec<u8>, TransformError> {
    // The KDF descriptor is applied before (and therefore reversed after) the
    // AEAD descriptor it feeds, so the key must be re-derived before the
    // reverse loop reaches AEAD.
    let mut derived_key = None;
    let mut kdf_seen = false;
    for transform in transforms {
        if transform.algorithm == TRANSFORM_KDF_ARGON2ID {
            if kdf_seen {
                return Err(TransformError::InvalidDescriptor(
                    "duplicate Argon2id KDF transform",
                ));
            }
            kdf_seen = true;
            let kdf = parse_kdf_argon2id_params(&transform.parameters)?;
            // Fail closed before any Argon2 work on ambiguous or absent
            // credentials.
            if encrypt_key.is_some() {
                return Err(TransformError::AmbiguousKeySource);
            }
            let password = password.ok_or(TransformError::MissingKey { what: "password" })?;
            let master = password::derive_master_from_password(
                password,
                &kdf.salt,
                &Argon2Params {
                    memory_kib: kdf.memory_kib,
                    iterations: kdf.iterations,
                    parallelism: u32::from(kdf.lanes),
                    output_len: usize::from(KDF_ARGON2ID_OUTPUT_LEN),
                },
            )
            .map_err(|e| TransformError::KdfFailed(e.to_string()))?;
            derived_key = Some(EncryptionKey::from_bytes(
                master.as_slice().try_into().expect("pinned output length"),
            ));
        }
    }
    if kdf_seen
        && !transforms
            .iter()
            .any(|t| t.algorithm == TRANSFORM_AEAD_CHACHA20_POLY1305)
    {
        return Err(TransformError::InvalidDescriptor(
            "Argon2id KDF transform requires a ChaCha20-Poly1305 AEAD transform",
        ));
    }
    let effective_key = derived_key.as_ref().or(encrypt_key);

    let mut body = encoded_body.to_vec();

    // Reverse transforms in the opposite order they were applied. ECC and
    // encryption are commutative with nothing here, but we preserve the
    // canonical order so future non-commutative transforms stay correct.
    for transform in transforms.iter().rev() {
        match transform.algorithm {
            TRANSFORM_KDF_ARGON2ID => {
                // Key material was re-derived before the loop (this descriptor
                // is applied before, and reversed after, the AEAD transform it
                // feeds); it transforms no bytes. Bounds were already checked
                // in the pre-scan.
                parse_kdf_argon2id_params(&transform.parameters)?;
            }
            TRANSFORM_AEAD_CHACHA20_POLY1305 => {
                let key = effective_key.ok_or(TransformError::MissingKey { what: "decryption" })?;
                body = encryption::decrypt(key, context.packet_id, &body, Some(&context.aad()))
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
///
/// The descriptor is unauthenticated, so before ANY allocation the claimed
/// geometry must account for every byte of the codeword stream exactly:
///
/// `full_chunks * (chunk_len + parity) + trailing(last_len + parity) ==
/// encoded.len()`
///
/// A hostile descriptor (e.g. `data_len = 0xFFFF_FFFF` against a tiny body)
/// is therefore rejected with a typed error instead of a multi-gigabyte
/// `Vec::with_capacity(data_len)`.
fn ecc_decode(
    encoded: &[u8],
    data_len: usize,
    parity: usize,
    chunk_len: usize,
) -> Result<Vec<u8>, TransformError> {
    validate_ecc_params(parity, chunk_len)?;

    let full_chunks = data_len / chunk_len;
    let last_len = data_len % chunk_len;
    let expected_codeword_len = full_chunks
        .checked_mul(chunk_len + parity)
        .and_then(|total| total.checked_add(if last_len > 0 { last_len + parity } else { 0 }))
        .ok_or(TransformError::LengthOverflow)?;
    if expected_codeword_len != encoded.len() {
        return Err(TransformError::InvalidDescriptor(
            "ECC descriptor geometry is inconsistent with the codeword stream",
        ));
    }
    if parity == 0 {
        return Ok(encoded[..data_len].to_vec());
    }
    if data_len == 0 {
        return Ok(Vec::new());
    }

    // Geometry is proven consistent above, so every offset below is in range
    // and the output allocation is bounded by `encoded.len()`.
    let mut output = Vec::with_capacity(data_len);
    let mut offset = 0usize;
    for _ in 0..full_chunks {
        let end = offset + chunk_len + parity;
        output.extend(
            error_correction::decode(&encoded[offset..end], chunk_len, parity)
                .map_err(|e| TransformError::ErrorCorrectionFailed(e.to_string()))?,
        );
        offset = end;
    }
    if last_len > 0 {
        let end = offset + last_len + parity;
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

/// Hard ceiling on any single DEFLATE expansion, checked before reading so a
/// hostile envelope that claims a huge `original_len` cannot expand a small
/// stream into a decompression bomb. Generous relative to the protocol's
/// default body ceiling (16 MiB); legitimate envelopes are additionally
/// bounded by `DecodeLimits::max_original_len` in `packet.rs` before
/// [`reverse`] is ever invoked.
pub const MAX_DECOMPRESS_OUTPUT: usize = 64 * 1024 * 1024;

/// DEFLATE-decompress a byte slice, bounded to `limit` bytes (inclusive) so a
/// malicious or corrupt stream cannot expand into a decompression bomb.
fn deflate_decompress(data: &[u8], limit: usize) -> Result<Vec<u8>, TransformError> {
    if limit > MAX_DECOMPRESS_OUTPUT {
        return Err(TransformError::InvalidDescriptor(
            "declared decompressed length exceeds the transform output ceiling",
        ));
    }
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
        for byte in corrupted.iter_mut().take(parity / 2) {
            *byte ^= 1;
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

    #[test]
    fn hostile_ecc_data_len_is_rejected_before_allocation() {
        // The descriptor is unauthenticated: a 4 GiB `data_len` claim against
        // a tiny codeword stream must fail the geometry precheck (typed
        // error) instead of attempting `Vec::with_capacity(0xFFFF_FFFF)`.
        let params = ecc_params(1, 0xFFFF_FFFF, DEFAULT_ECC_CHUNK_LEN);
        let transforms = vec![TransformDescriptor {
            algorithm: TRANSFORM_ECC_REED_SOLOMON,
            version: 1,
            critical: true,
            parameters: params,
        }];
        let payload = b"tiny".to_vec();
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
        assert!(matches!(
            reverse(
                b"only-32-bytes-here!!!!!!!!!!!!!!!",
                &context(&packet),
                None,
                &transforms,
                4
            ),
            Err(TransformError::InvalidDescriptor(_))
        ));

        // Same rejection directly at the decode layer.
        assert!(matches!(
            ecc_decode(&[0u8; 32], 0xFFFF_FFFF, 1, DEFAULT_ECC_CHUNK_LEN),
            Err(TransformError::InvalidDescriptor(_))
        ));
    }

    #[test]
    fn ecc_geometry_mismatch_is_rejected() {
        // data_len + parity overhead must equal the stream length exactly.
        // 8 data bytes + 1 parity = 9 expected, but 10 provided.
        assert!(matches!(
            ecc_decode(&[0u8; 10], 8, 1, DEFAULT_ECC_CHUNK_LEN),
            Err(TransformError::InvalidDescriptor(_))
        ));
        // Consistent geometry still decodes.
        let body = b"abcdefgh";
        let codeword = error_correction::encode(body, 1).unwrap();
        assert_eq!(
            ecc_decode(&codeword, body.len(), 1, DEFAULT_ECC_CHUNK_LEN).unwrap(),
            body
        );
    }

    #[test]
    fn decompression_bomb_is_capped_by_the_output_ceiling() {
        // 1 MiB of zeros compresses to a few hundred bytes; claiming a 2^40
        // expansion must be rejected by the ceiling before any read loop.
        let bomb = deflate_compress(&vec![0u8; 1024 * 1024]).unwrap();
        assert!(bomb.len() < 4096);
        assert!(matches!(
            deflate_decompress(&bomb, (1u64 << 40) as usize),
            Err(TransformError::InvalidDescriptor(_))
        ));
    }

    #[test]
    fn kdf_password_roundtrip_and_wrong_password_fails_closed() {
        let payload = b"password-protected payload".to_vec();
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
        let credentials = PasswordKdfCredentials {
            password: b"correct horse battery staple",
            params: Argon2Params::fast(),
        };
        let (body, transforms, flags) = apply_with_password(
            &payload,
            &ctx,
            None,
            false,
            Some(&credentials),
            None,
            0,
            DEFAULT_ECC_CHUNK_LEN,
        )
        .unwrap();
        assert_eq!(flags, FLAG_ENCRYPTED);
        assert_eq!(transforms.len(), 2);
        assert_eq!(transforms[0].algorithm, TRANSFORM_KDF_ARGON2ID);
        assert_eq!(transforms[1].algorithm, TRANSFORM_AEAD_CHACHA20_POLY1305);
        // Pinned 27-byte layout: salt || memory u32 LE || iterations u32 LE
        // || lanes u8 || output u16 LE.
        assert_eq!(transforms[0].parameters.len(), KDF_ARGON2ID_PARAMS_SIZE);
        let kdf = parse_kdf_argon2id_params(&transforms[0].parameters).unwrap();
        assert_eq!(kdf.memory_kib, Argon2Params::fast().memory_kib);
        assert_eq!(kdf.iterations, Argon2Params::fast().iterations);
        assert_eq!(kdf.lanes, 1);

        let recovered = reverse_with_password(
            &body,
            &ctx,
            None,
            Some(b"correct horse battery staple"),
            &transforms,
            payload.len() as u64,
        )
        .unwrap();
        assert_eq!(recovered, payload);

        // Wrong password fails closed (Poly1305 tag), missing password fails
        // closed with the typed missing-key error.
        assert!(matches!(
            reverse_with_password(
                &body,
                &ctx,
                None,
                Some(b"incorrect horse battery staple"),
                &transforms,
                payload.len() as u64,
            ),
            Err(TransformError::DecryptionFailed(_))
        ));
        assert!(matches!(
            reverse_with_password(&body, &ctx, None, None, &transforms, payload.len() as u64),
            Err(TransformError::MissingKey { what: "password" })
        ));
    }

    #[test]
    fn kdf_fixed_salt_descriptor_is_deterministic() {
        let packet = GenericPacket::new_untransformed(
            b"seed".to_vec(),
            *b"0123456789abcdef",
            *b"nonce123",
            crate::packet::PayloadKind::Bytes,
            crate::packet::AlgorithmDescriptor::new(1, 1, Vec::new()),
            crate::packet::AlgorithmDescriptor::new(1, 1, vec![1]),
            &crate::packet::DecodeLimits::default(),
        )
        .unwrap();
        let ctx = context(&packet);
        let params = Argon2Params::fast();
        let salt = [0x42u8; KDF_ARGON2ID_SALT_LEN];
        let descriptor = kdf_argon2id_params(&salt, &params);

        // Same salt + params + password always yields the same key.
        let master = crate::password::derive_master_from_password(b"pw", &salt, &params).unwrap();
        assert_eq!(
            master,
            crate::password::derive_master_from_password(b"pw", &salt, &params).unwrap()
        );
        let key = EncryptionKey::from_bytes(master.as_slice().try_into().unwrap());

        // Encrypt independently with the derived key; the descriptor-driven
        // reverse must land on exactly that key.
        let body = encryption::encrypt(
            &key,
            ctx.packet_id,
            b"secret nested payload",
            Some(&ctx.aad()),
        )
        .unwrap();
        let transforms = vec![
            TransformDescriptor {
                algorithm: TRANSFORM_KDF_ARGON2ID,
                version: 1,
                critical: true,
                parameters: descriptor.clone(),
            },
            TransformDescriptor {
                algorithm: TRANSFORM_AEAD_CHACHA20_POLY1305,
                version: 1,
                critical: true,
                parameters: Vec::new(),
            },
        ];
        let recovered = reverse_with_password(
            &body,
            &ctx,
            None,
            Some(b"pw"),
            &transforms,
            b"secret nested payload".len() as u64,
        )
        .unwrap();
        assert_eq!(recovered, b"secret nested payload");

        // Descriptor round-trips through the parser unchanged.
        let kdf = parse_kdf_argon2id_params(&descriptor).unwrap();
        assert_eq!(kdf.salt, salt);
        assert_eq!(kdf.memory_kib, params.memory_kib);
    }

    #[test]
    fn kdf_descriptor_param_bounds_are_enforced() {
        let salt = [0u8; KDF_ARGON2ID_SALT_LEN];
        let good = kdf_argon2id_params(&salt, &Argon2Params::fast());
        assert_eq!(good.len(), KDF_ARGON2ID_PARAMS_SIZE);

        // Wrong total length and wrong pinned output length are rejected.
        let mut short = good.clone();
        short.pop();
        assert!(matches!(
            parse_kdf_argon2id_params(&short),
            Err(TransformError::InvalidDescriptor(_))
        ));
        let mut bad_output = good.clone();
        let len = bad_output.len();
        bad_output[len - 2..].copy_from_slice(&33u16.to_le_bytes());
        assert!(matches!(
            parse_kdf_argon2id_params(&bad_output),
            Err(TransformError::InvalidDescriptor(_))
        ));

        // DoS ceilings: memory and iteration counts above the hard caps are
        // rejected before any Argon2 work.
        let mut huge_memory = good.clone();
        huge_memory[16..20].copy_from_slice(&(MAX_KDF_MEMORY_KIB + 1).to_le_bytes());
        assert!(matches!(
            parse_kdf_argon2id_params(&huge_memory),
            Err(TransformError::InvalidDescriptor(_))
        ));
        let mut zero_memory = good.clone();
        zero_memory[16..20].copy_from_slice(&0u32.to_le_bytes());
        assert!(matches!(
            parse_kdf_argon2id_params(&zero_memory),
            Err(TransformError::InvalidDescriptor(_))
        ));
        let mut huge_iterations = good.clone();
        huge_iterations[20..24].copy_from_slice(&(MAX_KDF_ITERATIONS + 1).to_le_bytes());
        assert!(matches!(
            parse_kdf_argon2id_params(&huge_iterations),
            Err(TransformError::InvalidDescriptor(_))
        ));

        // Below the algorithmic floor (memory >= 8 KiB × lanes) fails too.
        let mut tiny = good.clone();
        tiny[16..20].copy_from_slice(&4u32.to_le_bytes());
        tiny[24] = 2;
        assert!(matches!(
            parse_kdf_argon2id_params(&tiny),
            Err(TransformError::KdfFailed(_))
        ));
    }

    #[test]
    fn kdf_apply_rejects_mismatched_output_len_and_key_sources() {
        let packet = GenericPacket::new_untransformed(
            b"payload".to_vec(),
            *b"0123456789abcdef",
            *b"nonce123",
            crate::packet::PayloadKind::Bytes,
            crate::packet::AlgorithmDescriptor::new(1, 1, Vec::new()),
            crate::packet::AlgorithmDescriptor::new(1, 1, vec![1]),
            &crate::packet::DecodeLimits::default(),
        )
        .unwrap();
        let ctx = context(&packet);
        let mut short_params = Argon2Params::fast();
        short_params.output_len = 16;
        let credentials = PasswordKdfCredentials {
            password: b"pw",
            params: short_params,
        };
        assert!(matches!(
            apply_with_password(
                b"x",
                &ctx,
                None,
                false,
                Some(&credentials),
                None,
                0,
                DEFAULT_ECC_CHUNK_LEN
            ),
            Err(TransformError::InvalidDescriptor(_))
        ));

        let good_credentials = PasswordKdfCredentials {
            password: b"pw",
            params: Argon2Params::fast(),
        };
        assert!(matches!(
            apply_with_password(
                b"x",
                &ctx,
                None,
                false,
                Some(&good_credentials),
                Some(&test_key()),
                0,
                DEFAULT_ECC_CHUNK_LEN
            ),
            Err(TransformError::AmbiguousKeySource)
        ));
    }

    #[test]
    fn kdf_descriptor_without_aead_fails_closed() {
        let packet = GenericPacket::new_untransformed(
            b"payload".to_vec(),
            *b"0123456789abcdef",
            *b"nonce123",
            crate::packet::PayloadKind::Bytes,
            crate::packet::AlgorithmDescriptor::new(1, 1, Vec::new()),
            crate::packet::AlgorithmDescriptor::new(1, 1, vec![1]),
            &crate::packet::DecodeLimits::default(),
        )
        .unwrap();
        let ctx = context(&packet);
        let descriptor = kdf_argon2id_params(&[0u8; KDF_ARGON2ID_SALT_LEN], &Argon2Params::fast());
        let transforms = vec![TransformDescriptor {
            algorithm: TRANSFORM_KDF_ARGON2ID,
            version: 1,
            critical: true,
            parameters: descriptor,
        }];
        // A KDF descriptor with nothing to feed is a protocol violation.
        assert!(matches!(
            reverse_with_password(b"ciphertext", &ctx, None, Some(b"pw"), &transforms, 7),
            Err(TransformError::InvalidDescriptor(_))
        ));
        // The legacy password-less reverse fails closed with a missing key.
        assert!(matches!(
            reverse(b"ciphertext", &ctx, None, &transforms, 7),
            Err(TransformError::MissingKey { what: "password" })
        ));
    }
}
