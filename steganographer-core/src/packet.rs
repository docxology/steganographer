//! Versioned, bounded packet framing for generic steganographic payloads.
//!
//! This module is the opt-in protocol-v1 foundation. It intentionally has no
//! filesystem or media-format dependencies: callers provide payload bytes,
//! packet identifiers, nonces, and carrier descriptors.

use crate::crypto::SignaturePayload;
use sha2::Digest as _;
use thiserror::Error;

/// Public packet magic. This is deliberately distinct from legacy `STEG` v2.
pub const PACKET_MAGIC: [u8; 4] = *b"STG3";
pub const PROTOCOL_MAJOR: u8 = 1;
pub const PROTOCOL_MINOR: u8 = 0;
pub const LOCATOR_SIZE: usize = 32;

/// Initial registry identifiers used by the generic spatial-LSB slice.
pub const PLACEMENT_SEQUENTIAL: u16 = 1;
pub const PLACEMENT_KEYED: u16 = 2;
pub const KERNEL_SPATIAL_LSB: u16 = 1;

pub const FLAG_COMPRESSED: u16 = 1 << 0;
pub const FLAG_ENCRYPTED: u16 = 1 << 1;
pub const FLAG_ERROR_CORRECTED: u16 = 1 << 2;
pub const FLAG_KEYED_LOCATOR: u16 = 1 << 3;
pub const FLAG_PAYLOAD_SIGNED: u16 = 1 << 4;
pub const KNOWN_FLAGS: u16 = FLAG_COMPRESSED
    | FLAG_ENCRYPTED
    | FLAG_ERROR_CORRECTED
    | FLAG_KEYED_LOCATOR
    | FLAG_PAYLOAD_SIGNED;

const FIELD_CRITICAL: u16 = 1 << 15;
const FIELD_ID_MASK: u16 = !FIELD_CRITICAL;
const TLV_HEADER_SIZE: usize = 6;

const FIELD_PACKET_ID: u16 = 1;
const FIELD_PAYLOAD_KIND: u16 = 2;
const FIELD_ORIGINAL_LENGTH: u16 = 3;
const FIELD_CONTENT_DIGEST: u16 = 4;
const FIELD_TRANSFORM: u16 = 5;
const FIELD_PLACEMENT: u16 = 6;
const FIELD_KERNEL: u16 = 7;
const FIELD_CREATED_VERSION: u16 = 8;
const FIELD_MIME_TYPE: u16 = 16;
const FIELD_FILENAME: u16 = 17;
const FIELD_CREATED_AT: u16 = 18;
const FIRST_EXTENSION_FIELD: u16 = 128;

/// Extension field: the 32-byte SHA-256 digest that was stamped with the
/// OpenTimestamps service. Present only when OTS stamping was active for the
/// segment this packet belongs to. See [`crate::ots_client`].
pub const FIELD_OTS_DIGEST: u16 = 128;
/// Extension field: the attestation method tag (1 byte): `0 = bitcoin`,
/// `1 = ethereum`. See [`crate::ots_client::OTSMethod`].
pub const FIELD_OTS_METHOD: u16 = 129;
/// Extension field: the attestation Unix timestamp (8 bytes, big-endian)
/// from the OTS proof, for quick display without re-verifying the proof.
pub const FIELD_OTS_TIMESTAMP_HEX: u16 = 130;

/// Resource limits checked before packet or field allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodeLimits {
    pub max_envelope_len: usize,
    pub max_body_len: usize,
    pub max_packet_len: usize,
    pub max_field_len: usize,
    pub max_fields: usize,
    pub max_transforms: usize,
    pub max_extensions: usize,
    pub max_filename_len: usize,
    pub max_mime_len: usize,
}

impl Default for DecodeLimits {
    fn default() -> Self {
        Self {
            max_envelope_len: 16 * 1024,
            max_body_len: 16 * 1024 * 1024,
            max_packet_len: 16 * 1024 * 1024 + 16 * 1024 + LOCATOR_SIZE,
            max_field_len: 8 * 1024,
            max_fields: 128,
            max_transforms: 16,
            max_extensions: 64,
            max_filename_len: 255,
            max_mime_len: 127,
        }
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PacketError {
    #[error("packet data is truncated: need {needed} bytes, have {available}")]
    Truncated { needed: usize, available: usize },
    #[error("packet magic does not match")]
    InvalidMagic,
    #[error("unsupported packet protocol {major}.{minor}")]
    UnsupportedVersion { major: u8, minor: u8 },
    #[error("packet has unknown flag bits 0x{0:04x}")]
    UnknownFlags(u16),
    #[error("{what} length {actual} exceeds configured maximum {maximum}")]
    LimitExceeded {
        what: &'static str,
        actual: usize,
        maximum: usize,
    },
    #[error("packet length arithmetic overflow")]
    LengthOverflow,
    #[error("envelope CRC32C mismatch")]
    EnvelopeChecksum,
    #[error("envelope field {field_id} is out of canonical order")]
    NonCanonicalOrder { field_id: u16 },
    #[error("duplicate singleton envelope field {field_id}")]
    DuplicateField { field_id: u16 },
    #[error("required envelope field {field_id} is missing")]
    MissingField { field_id: u16 },
    #[error("unknown critical envelope field {field_id}")]
    UnknownCriticalField { field_id: u16 },
    #[error("invalid envelope field {field_id}: {reason}")]
    InvalidField { field_id: u16, reason: &'static str },
    #[error("envelope text field {field_id} is not valid UTF-8")]
    InvalidUtf8 { field_id: u16 },
    #[error("packet body length does not match its untransformed envelope")]
    BodyLengthMismatch,
    #[error("packet body digest does not match its envelope")]
    DigestMismatch,
    #[error("legacy signature payload must be exactly {expected} bytes, got {actual}")]
    LegacyLength { expected: usize, actual: usize },
    #[error("legacy signature payload is invalid: {0}")]
    LegacyPayload(String),
}

/// Fixed-size public locator decoded before any variable-size allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Locator {
    pub protocol_major: u8,
    pub protocol_minor: u8,
    pub flags: u16,
    pub envelope_len: u32,
    pub encoded_body_len: u64,
    pub envelope_crc32c: u32,
    pub nonce: [u8; 8],
}

impl Locator {
    pub fn new(
        flags: u16,
        envelope_len: usize,
        encoded_body_len: usize,
        envelope_crc32c: u32,
        nonce: [u8; 8],
        limits: &DecodeLimits,
    ) -> Result<Self, PacketError> {
        validate_flags(flags)?;
        validate_lengths(envelope_len, encoded_body_len, limits)?;
        Ok(Self {
            protocol_major: PROTOCOL_MAJOR,
            protocol_minor: PROTOCOL_MINOR,
            flags,
            envelope_len: u32::try_from(envelope_len).map_err(|_| PacketError::LengthOverflow)?,
            encoded_body_len: u64::try_from(encoded_body_len)
                .map_err(|_| PacketError::LengthOverflow)?,
            envelope_crc32c,
            nonce,
        })
    }

    pub fn to_bytes(self) -> [u8; LOCATOR_SIZE] {
        let mut bytes = [0u8; LOCATOR_SIZE];
        bytes[..4].copy_from_slice(&PACKET_MAGIC);
        bytes[4] = self.protocol_major;
        bytes[5] = self.protocol_minor;
        bytes[6..8].copy_from_slice(&self.flags.to_be_bytes());
        bytes[8..12].copy_from_slice(&self.envelope_len.to_be_bytes());
        bytes[12..20].copy_from_slice(&self.encoded_body_len.to_be_bytes());
        bytes[20..24].copy_from_slice(&self.envelope_crc32c.to_be_bytes());
        bytes[24..32].copy_from_slice(&self.nonce);
        bytes
    }

    pub fn from_bytes(input: &[u8], limits: &DecodeLimits) -> Result<Self, PacketError> {
        if input.len() < LOCATOR_SIZE {
            return Err(PacketError::Truncated {
                needed: LOCATOR_SIZE,
                available: input.len(),
            });
        }
        if input[..4] != PACKET_MAGIC {
            return Err(PacketError::InvalidMagic);
        }
        let protocol_major = input[4];
        let protocol_minor = input[5];
        if protocol_major != PROTOCOL_MAJOR || protocol_minor > PROTOCOL_MINOR {
            return Err(PacketError::UnsupportedVersion {
                major: protocol_major,
                minor: protocol_minor,
            });
        }

        let flags = u16::from_be_bytes([input[6], input[7]]);
        validate_flags(flags)?;
        let envelope_len =
            u32::from_be_bytes(input[8..12].try_into().expect("fixed locator slice"));
        let encoded_body_len =
            u64::from_be_bytes(input[12..20].try_into().expect("fixed locator slice"));
        let envelope_crc32c =
            u32::from_be_bytes(input[20..24].try_into().expect("fixed locator slice"));
        let nonce = input[24..32].try_into().expect("fixed locator slice");

        let body_len =
            usize::try_from(encoded_body_len).map_err(|_| PacketError::LengthOverflow)?;
        validate_lengths(envelope_len as usize, body_len, limits)?;
        Ok(Self {
            protocol_major,
            protocol_minor,
            flags,
            envelope_len,
            encoded_body_len,
            envelope_crc32c,
            nonce,
        })
    }

    pub fn packet_len(self) -> Result<usize, PacketError> {
        let body_len =
            usize::try_from(self.encoded_body_len).map_err(|_| PacketError::LengthOverflow)?;
        LOCATOR_SIZE
            .checked_add(self.envelope_len as usize)
            .and_then(|length| length.checked_add(body_len))
            .ok_or(PacketError::LengthOverflow)
    }
}

fn validate_flags(flags: u16) -> Result<(), PacketError> {
    let unknown = flags & !KNOWN_FLAGS;
    if unknown != 0 {
        return Err(PacketError::UnknownFlags(unknown));
    }
    Ok(())
}

fn validate_lengths(
    envelope_len: usize,
    body_len: usize,
    limits: &DecodeLimits,
) -> Result<(), PacketError> {
    check_limit("envelope", envelope_len, limits.max_envelope_len)?;
    check_limit("body", body_len, limits.max_body_len)?;
    let packet_len = LOCATOR_SIZE
        .checked_add(envelope_len)
        .and_then(|length| length.checked_add(body_len))
        .ok_or(PacketError::LengthOverflow)?;
    check_limit("packet", packet_len, limits.max_packet_len)
}

fn check_limit(what: &'static str, actual: usize, maximum: usize) -> Result<(), PacketError> {
    if actual > maximum {
        return Err(PacketError::LimitExceeded {
            what,
            actual,
            maximum,
        });
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum PayloadKind {
    Bytes = 1,
    Text = 2,
    File = 3,
    FrameAttestation = 4,
    Manifest = 5,
}

impl TryFrom<u16> for PayloadKind {
    type Error = PacketError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Bytes),
            2 => Ok(Self::Text),
            3 => Ok(Self::File),
            4 => Ok(Self::FrameAttestation),
            5 => Ok(Self::Manifest),
            _ => Err(PacketError::InvalidField {
                field_id: FIELD_PAYLOAD_KIND,
                reason: "unknown payload kind",
            }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DigestAlgorithm {
    Blake3 = 1,
    Sha256 = 2,
    Sha3_256 = 3,
}

impl TryFrom<u8> for DigestAlgorithm {
    type Error = PacketError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Blake3),
            2 => Ok(Self::Sha256),
            3 => Ok(Self::Sha3_256),
            _ => Err(PacketError::InvalidField {
                field_id: FIELD_CONTENT_DIGEST,
                reason: "unknown digest algorithm",
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentDigest {
    pub algorithm: DigestAlgorithm,
    pub bytes: Vec<u8>,
}

impl ContentDigest {
    pub fn blake3(payload: &[u8]) -> Self {
        Self {
            algorithm: DigestAlgorithm::Blake3,
            bytes: blake3::hash(payload).as_bytes().to_vec(),
        }
    }

    pub fn verify(&self, payload: &[u8]) -> bool {
        match self.algorithm {
            DigestAlgorithm::Blake3 => self.bytes == blake3::hash(payload).as_bytes(),
            DigestAlgorithm::Sha256 => self.bytes == sha2::Sha256::digest(payload).as_slice(),
            DigestAlgorithm::Sha3_256 => self.bytes == sha3::Sha3_256::digest(payload).as_slice(),
        }
    }
}

/// Numeric algorithm descriptor shared by placement and kernel metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlgorithmDescriptor {
    pub algorithm: u16,
    pub version: u8,
    pub parameters: Vec<u8>,
}

impl AlgorithmDescriptor {
    pub fn new(algorithm: u16, version: u8, parameters: Vec<u8>) -> Self {
        Self {
            algorithm,
            version,
            parameters,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransformDescriptor {
    pub algorithm: u16,
    pub version: u8,
    pub critical: bool,
    pub parameters: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionField {
    pub id: u16,
    pub value: Vec<u8>,
}

/// OpenTimestamps metadata extracted from packet envelope extension fields.
///
/// This is a convenience view over the three OTS-related extension fields
/// ([`FIELD_OTS_DIGEST`], [`FIELD_OTS_METHOD`], [`FIELD_OTS_TIMESTAMP_HEX`]).
/// All fields are `Option` because OTS is entirely optional — a packet
/// without OTS stamping simply has none of these extensions present.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OtsMetadata {
    /// The raw 32-byte digest that was stamped, if present.
    pub digest: Option<[u8; 32]>,
    /// The digest as hex (for display), if present.
    pub digest_hex: Option<String>,
    /// Attestation method tag: `0 = bitcoin`, `1 = ethereum`.
    pub method_tag: Option<u8>,
    /// Attestation Unix timestamp (seconds), if the proof carried one.
    pub timestamp: Option<u64>,
}

impl OtsMetadata {
    /// Whether any OTS metadata is present in this packet.
    pub fn is_present(&self) -> bool {
        self.digest.is_some()
    }

    /// The method name (`"bitcoin"`, `"ethereum"`, or `"none"`).
    pub fn method_name(&self) -> &'static str {
        match self.method_tag {
            Some(0) => "bitcoin",
            Some(1) => "ethereum",
            _ => "none",
        }
    }

    /// Extract OTS metadata from a packet's extension fields.
    pub fn from_extensions(extensions: &[ExtensionField]) -> Self {
        let mut meta = Self::default();
        for ext in extensions {
            match ext.id {
                FIELD_OTS_DIGEST if ext.value.len() == 32 => {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&ext.value);
                    meta.digest = Some(arr);
                    meta.digest_hex = Some(hex_encode_ots(&arr));
                }
                FIELD_OTS_METHOD if ext.value.len() == 1 => {
                    meta.method_tag = Some(ext.value[0]);
                }
                FIELD_OTS_TIMESTAMP_HEX if ext.value.len() == 8 => {
                    let bytes: [u8; 8] = ext.value[..8].try_into().expect("checked length");
                    meta.timestamp = Some(u64::from_be_bytes(bytes));
                }
                _ => {}
            }
        }
        meta
    }

    /// Build the OTS extension fields from this metadata, ready to be
    /// appended to a [`PacketEnvelope`]'s `extensions` vector.
    pub fn to_extensions(&self) -> Vec<ExtensionField> {
        let mut fields = Vec::new();
        if let Some(ref digest) = self.digest {
            fields.push(ExtensionField {
                id: FIELD_OTS_DIGEST,
                value: digest.to_vec(),
            });
        }
        if let Some(tag) = self.method_tag {
            fields.push(ExtensionField {
                id: FIELD_OTS_METHOD,
                value: vec![tag],
            });
        }
        if let Some(ts) = self.timestamp {
            fields.push(ExtensionField {
                id: FIELD_OTS_TIMESTAMP_HEX,
                value: ts.to_be_bytes().to_vec(),
            });
        }
        fields
    }
}

fn hex_encode_ots(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Canonical public metadata for a generic packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketEnvelope {
    pub packet_id: [u8; 16],
    pub payload_kind: PayloadKind,
    pub original_len: u64,
    pub content_digest: ContentDigest,
    pub transforms: Vec<TransformDescriptor>,
    pub placement: AlgorithmDescriptor,
    pub kernel: AlgorithmDescriptor,
    pub created_version: (u8, u8),
    pub mime_type: Option<String>,
    pub filename: Option<String>,
    pub created_at_unix: Option<u64>,
    pub extensions: Vec<ExtensionField>,
}

impl PacketEnvelope {
    /// Construct an untransformed envelope with a BLAKE3 payload digest.
    pub fn for_payload(
        packet_id: [u8; 16],
        payload_kind: PayloadKind,
        payload: &[u8],
        placement: AlgorithmDescriptor,
        kernel: AlgorithmDescriptor,
    ) -> Self {
        Self {
            packet_id,
            payload_kind,
            original_len: payload.len() as u64,
            content_digest: ContentDigest::blake3(payload),
            transforms: Vec::new(),
            placement,
            kernel,
            created_version: (PROTOCOL_MAJOR, PROTOCOL_MINOR),
            mime_type: None,
            filename: None,
            created_at_unix: None,
            extensions: Vec::new(),
        }
    }

    pub fn encode(&self, limits: &DecodeLimits) -> Result<Vec<u8>, PacketError> {
        validate_envelope(self, limits)?;
        let field_count = 8usize
            .checked_add(self.transforms.len())
            .and_then(|count| count.checked_add(self.extensions.len()))
            .and_then(|count| count.checked_add(usize::from(self.mime_type.is_some())))
            .and_then(|count| count.checked_add(usize::from(self.filename.is_some())))
            .and_then(|count| count.checked_add(usize::from(self.created_at_unix.is_some())))
            .ok_or(PacketError::LengthOverflow)?;
        check_limit("envelope field count", field_count, limits.max_fields)?;
        let mut output = Vec::new();
        push_tlv(&mut output, FIELD_PACKET_ID, true, &self.packet_id, limits)?;
        push_tlv(
            &mut output,
            FIELD_PAYLOAD_KIND,
            true,
            &encode_minimal_u64(self.payload_kind as u16 as u64),
            limits,
        )?;
        push_tlv(
            &mut output,
            FIELD_ORIGINAL_LENGTH,
            true,
            &encode_minimal_u64(self.original_len),
            limits,
        )?;
        let mut digest = Vec::with_capacity(1 + self.content_digest.bytes.len());
        digest.push(self.content_digest.algorithm as u8);
        digest.extend_from_slice(&self.content_digest.bytes);
        push_tlv(&mut output, FIELD_CONTENT_DIGEST, true, &digest, limits)?;
        for transform in &self.transforms {
            push_tlv(
                &mut output,
                FIELD_TRANSFORM,
                transform.critical,
                &encode_algorithm(
                    transform.algorithm,
                    transform.version,
                    &transform.parameters,
                ),
                limits,
            )?;
        }
        push_tlv(
            &mut output,
            FIELD_PLACEMENT,
            true,
            &encode_descriptor(&self.placement),
            limits,
        )?;
        push_tlv(
            &mut output,
            FIELD_KERNEL,
            true,
            &encode_descriptor(&self.kernel),
            limits,
        )?;
        push_tlv(
            &mut output,
            FIELD_CREATED_VERSION,
            true,
            &[self.created_version.0, self.created_version.1],
            limits,
        )?;
        if let Some(value) = &self.mime_type {
            push_tlv(
                &mut output,
                FIELD_MIME_TYPE,
                false,
                value.as_bytes(),
                limits,
            )?;
        }
        if let Some(value) = &self.filename {
            push_tlv(&mut output, FIELD_FILENAME, false, value.as_bytes(), limits)?;
        }
        if let Some(value) = self.created_at_unix {
            push_tlv(
                &mut output,
                FIELD_CREATED_AT,
                false,
                &encode_minimal_u64(value),
                limits,
            )?;
        }

        let mut extensions = self.extensions.clone();
        extensions.sort_by_key(|field| field.id);
        for extension in &extensions {
            push_tlv(&mut output, extension.id, false, &extension.value, limits)?;
        }
        check_limit("envelope", output.len(), limits.max_envelope_len)?;
        Ok(output)
    }

    pub fn decode(input: &[u8], limits: &DecodeLimits) -> Result<Self, PacketError> {
        check_limit("envelope", input.len(), limits.max_envelope_len)?;
        let mut cursor = 0usize;
        let mut field_count = 0usize;
        let mut previous_id = 0u16;

        let mut packet_id = None;
        let mut payload_kind = None;
        let mut original_len = None;
        let mut content_digest = None;
        let mut transforms = Vec::new();
        let mut placement = None;
        let mut kernel = None;
        let mut created_version = None;
        let mut mime_type = None;
        let mut filename = None;
        let mut created_at_unix = None;
        let mut extensions = Vec::new();

        while cursor < input.len() {
            field_count += 1;
            check_limit("envelope field count", field_count, limits.max_fields)?;
            if input.len() - cursor < TLV_HEADER_SIZE {
                return Err(PacketError::Truncated {
                    needed: cursor + TLV_HEADER_SIZE,
                    available: input.len(),
                });
            }
            let raw_id = u16::from_be_bytes([input[cursor], input[cursor + 1]]);
            let critical = raw_id & FIELD_CRITICAL != 0;
            let field_id = raw_id & FIELD_ID_MASK;
            let length = u32::from_be_bytes(
                input[cursor + 2..cursor + 6]
                    .try_into()
                    .expect("fixed TLV header"),
            ) as usize;
            cursor += TLV_HEADER_SIZE;

            if field_id == 0 || field_id < previous_id {
                return Err(PacketError::NonCanonicalOrder { field_id });
            }
            previous_id = field_id;
            check_limit("envelope field", length, limits.max_field_len)?;
            let end = cursor
                .checked_add(length)
                .ok_or(PacketError::LengthOverflow)?;
            if end > input.len() {
                return Err(PacketError::Truncated {
                    needed: end,
                    available: input.len(),
                });
            }
            let value = &input[cursor..end];
            cursor = end;

            match field_id {
                FIELD_PACKET_ID => {
                    set_once(&packet_id, field_id)?;
                    packet_id = Some(value.try_into().map_err(|_| PacketError::InvalidField {
                        field_id,
                        reason: "packet identifier must be 16 bytes",
                    })?);
                }
                FIELD_PAYLOAD_KIND => {
                    set_once(&payload_kind, field_id)?;
                    let value = decode_minimal_u64(value, field_id)?;
                    payload_kind = Some(PayloadKind::try_from(u16::try_from(value).map_err(
                        |_| PacketError::InvalidField {
                            field_id,
                            reason: "payload kind is out of range",
                        },
                    )?)?);
                }
                FIELD_ORIGINAL_LENGTH => {
                    set_once(&original_len, field_id)?;
                    original_len = Some(decode_minimal_u64(value, field_id)?);
                }
                FIELD_CONTENT_DIGEST => {
                    set_once(&content_digest, field_id)?;
                    if value.len() != 33 {
                        return Err(PacketError::InvalidField {
                            field_id,
                            reason: "initial digest profiles require 32 digest bytes",
                        });
                    }
                    content_digest = Some(ContentDigest {
                        algorithm: DigestAlgorithm::try_from(value[0])?,
                        bytes: value[1..].to_vec(),
                    });
                }
                FIELD_TRANSFORM => {
                    check_limit(
                        "transform count",
                        transforms.len() + 1,
                        limits.max_transforms,
                    )?;
                    let descriptor = decode_descriptor(value, field_id)?;
                    transforms.push(TransformDescriptor {
                        algorithm: descriptor.algorithm,
                        version: descriptor.version,
                        critical,
                        parameters: descriptor.parameters,
                    });
                }
                FIELD_PLACEMENT => {
                    set_once(&placement, field_id)?;
                    placement = Some(decode_descriptor(value, field_id)?);
                }
                FIELD_KERNEL => {
                    set_once(&kernel, field_id)?;
                    kernel = Some(decode_descriptor(value, field_id)?);
                }
                FIELD_CREATED_VERSION => {
                    set_once(&created_version, field_id)?;
                    if value.len() != 2 {
                        return Err(PacketError::InvalidField {
                            field_id,
                            reason: "created version must be two bytes",
                        });
                    }
                    created_version = Some((value[0], value[1]));
                }
                FIELD_MIME_TYPE => {
                    set_once(&mime_type, field_id)?;
                    check_limit("MIME type", value.len(), limits.max_mime_len)?;
                    mime_type = Some(decode_text(value, field_id)?);
                }
                FIELD_FILENAME => {
                    set_once(&filename, field_id)?;
                    check_limit("filename", value.len(), limits.max_filename_len)?;
                    filename = Some(decode_text(value, field_id)?);
                }
                FIELD_CREATED_AT => {
                    set_once(&created_at_unix, field_id)?;
                    created_at_unix = Some(decode_minimal_u64(value, field_id)?);
                }
                unknown if unknown >= FIRST_EXTENSION_FIELD && !critical => {
                    check_limit(
                        "extension count",
                        extensions.len() + 1,
                        limits.max_extensions,
                    )?;
                    extensions.push(ExtensionField {
                        id: unknown,
                        value: value.to_vec(),
                    });
                }
                unknown if critical => {
                    return Err(PacketError::UnknownCriticalField { field_id: unknown });
                }
                _ => {
                    // Unknown non-critical fields below the extension registry
                    // range are ignored for forward-compatible minor versions.
                }
            }
        }

        let envelope = Self {
            packet_id: packet_id.ok_or(PacketError::MissingField {
                field_id: FIELD_PACKET_ID,
            })?,
            payload_kind: payload_kind.ok_or(PacketError::MissingField {
                field_id: FIELD_PAYLOAD_KIND,
            })?,
            original_len: original_len.ok_or(PacketError::MissingField {
                field_id: FIELD_ORIGINAL_LENGTH,
            })?,
            content_digest: content_digest.ok_or(PacketError::MissingField {
                field_id: FIELD_CONTENT_DIGEST,
            })?,
            transforms,
            placement: placement.ok_or(PacketError::MissingField {
                field_id: FIELD_PLACEMENT,
            })?,
            kernel: kernel.ok_or(PacketError::MissingField {
                field_id: FIELD_KERNEL,
            })?,
            created_version: created_version.ok_or(PacketError::MissingField {
                field_id: FIELD_CREATED_VERSION,
            })?,
            mime_type,
            filename,
            created_at_unix,
            extensions,
        };
        validate_envelope(&envelope, limits)?;
        Ok(envelope)
    }
}

fn validate_envelope(envelope: &PacketEnvelope, limits: &DecodeLimits) -> Result<(), PacketError> {
    if envelope.created_version.0 != PROTOCOL_MAJOR || envelope.created_version.1 > PROTOCOL_MINOR {
        return Err(PacketError::UnsupportedVersion {
            major: envelope.created_version.0,
            minor: envelope.created_version.1,
        });
    }
    if envelope.content_digest.bytes.len() != 32 {
        return Err(PacketError::InvalidField {
            field_id: FIELD_CONTENT_DIGEST,
            reason: "initial digest profiles require 32 digest bytes",
        });
    }
    check_limit(
        "transform count",
        envelope.transforms.len(),
        limits.max_transforms,
    )?;
    check_limit(
        "extension count",
        envelope.extensions.len(),
        limits.max_extensions,
    )?;
    if envelope.placement.algorithm == 0 || envelope.kernel.algorithm == 0 {
        return Err(PacketError::InvalidField {
            field_id: if envelope.placement.algorithm == 0 {
                FIELD_PLACEMENT
            } else {
                FIELD_KERNEL
            },
            reason: "algorithm identifier zero is reserved",
        });
    }
    if envelope
        .transforms
        .iter()
        .any(|transform| transform.algorithm == 0)
    {
        return Err(PacketError::InvalidField {
            field_id: FIELD_TRANSFORM,
            reason: "algorithm identifier zero is reserved",
        });
    }
    if let Some(value) = &envelope.filename {
        check_limit("filename", value.len(), limits.max_filename_len)?;
    }
    if let Some(value) = &envelope.mime_type {
        check_limit("MIME type", value.len(), limits.max_mime_len)?;
    }
    let mut previous = 0u16;
    for extension in &envelope.extensions {
        if !(FIRST_EXTENSION_FIELD..=FIELD_ID_MASK).contains(&extension.id) {
            return Err(PacketError::InvalidField {
                field_id: extension.id,
                reason: "extension identifier is outside the extension registry",
            });
        }
        if extension.id < previous {
            return Err(PacketError::NonCanonicalOrder {
                field_id: extension.id,
            });
        }
        previous = extension.id;
        check_limit(
            "envelope field",
            extension.value.len(),
            limits.max_field_len,
        )?;
    }
    Ok(())
}

fn set_once<T>(slot: &Option<T>, field_id: u16) -> Result<(), PacketError> {
    if slot.is_some() {
        return Err(PacketError::DuplicateField { field_id });
    }
    Ok(())
}

fn push_tlv(
    output: &mut Vec<u8>,
    field_id: u16,
    critical: bool,
    value: &[u8],
    limits: &DecodeLimits,
) -> Result<(), PacketError> {
    if field_id == 0 || field_id > FIELD_ID_MASK {
        return Err(PacketError::InvalidField {
            field_id,
            reason: "field identifier is out of range",
        });
    }
    check_limit("envelope field", value.len(), limits.max_field_len)?;
    let wire_id = field_id | if critical { FIELD_CRITICAL } else { 0 };
    let length = u32::try_from(value.len()).map_err(|_| PacketError::LengthOverflow)?;
    output.extend_from_slice(&wire_id.to_be_bytes());
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn encode_descriptor(descriptor: &AlgorithmDescriptor) -> Vec<u8> {
    encode_algorithm(
        descriptor.algorithm,
        descriptor.version,
        &descriptor.parameters,
    )
}

fn encode_algorithm(algorithm: u16, version: u8, parameters: &[u8]) -> Vec<u8> {
    let mut value = Vec::with_capacity(3 + parameters.len());
    value.extend_from_slice(&algorithm.to_be_bytes());
    value.push(version);
    value.extend_from_slice(parameters);
    value
}

fn decode_descriptor(value: &[u8], field_id: u16) -> Result<AlgorithmDescriptor, PacketError> {
    if value.len() < 3 {
        return Err(PacketError::InvalidField {
            field_id,
            reason: "algorithm descriptor is shorter than three bytes",
        });
    }
    Ok(AlgorithmDescriptor {
        algorithm: u16::from_be_bytes([value[0], value[1]]),
        version: value[2],
        parameters: value[3..].to_vec(),
    })
}

fn encode_minimal_u64(value: u64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let first = bytes
        .iter()
        .position(|&byte| byte != 0)
        .unwrap_or(bytes.len() - 1);
    bytes[first..].to_vec()
}

fn decode_minimal_u64(value: &[u8], field_id: u16) -> Result<u64, PacketError> {
    if value.is_empty() || value.len() > 8 || (value.len() > 1 && value[0] == 0) {
        return Err(PacketError::InvalidField {
            field_id,
            reason: "integer is not minimally encoded",
        });
    }
    let mut bytes = [0u8; 8];
    bytes[8 - value.len()..].copy_from_slice(value);
    Ok(u64::from_be_bytes(bytes))
}

fn decode_text(value: &[u8], field_id: u16) -> Result<String, PacketError> {
    std::str::from_utf8(value)
        .map(str::to_owned)
        .map_err(|_| PacketError::InvalidUtf8 { field_id })
}

/// Complete generic packet: public locator, canonical envelope, and encoded body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenericPacket {
    pub locator: Locator,
    pub envelope: PacketEnvelope,
    pub body: Vec<u8>,
}

impl GenericPacket {
    pub fn new_untransformed(
        payload: Vec<u8>,
        packet_id: [u8; 16],
        nonce: [u8; 8],
        payload_kind: PayloadKind,
        placement: AlgorithmDescriptor,
        kernel: AlgorithmDescriptor,
        limits: &DecodeLimits,
    ) -> Result<Self, PacketError> {
        check_limit("body", payload.len(), limits.max_body_len)?;
        let envelope =
            PacketEnvelope::for_payload(packet_id, payload_kind, &payload, placement, kernel);
        let envelope_bytes = envelope.encode(limits)?;
        let locator = Locator::new(
            0,
            envelope_bytes.len(),
            payload.len(),
            crc32c(&envelope_bytes),
            nonce,
            limits,
        )?;
        Ok(Self {
            locator,
            envelope,
            body: payload,
        })
    }

    pub fn encode(&self, limits: &DecodeLimits) -> Result<Vec<u8>, PacketError> {
        if self.locator.protocol_major != PROTOCOL_MAJOR
            || self.locator.protocol_minor > PROTOCOL_MINOR
        {
            return Err(PacketError::UnsupportedVersion {
                major: self.locator.protocol_major,
                minor: self.locator.protocol_minor,
            });
        }
        validate_flags(self.locator.flags)?;
        let envelope = self.envelope.encode(limits)?;
        validate_lengths(envelope.len(), self.body.len(), limits)?;
        if self.locator.envelope_len as usize != envelope.len()
            || self.locator.encoded_body_len as usize != self.body.len()
            || self.locator.envelope_crc32c != crc32c(&envelope)
        {
            return Err(PacketError::InvalidField {
                field_id: 0,
                reason: "locator does not describe the encoded envelope and body",
            });
        }
        validate_untransformed_body(&self.envelope, &self.body)?;

        let mut output = Vec::with_capacity(self.locator.packet_len()?);
        output.extend_from_slice(&self.locator.to_bytes());
        output.extend_from_slice(&envelope);
        output.extend_from_slice(&self.body);
        Ok(output)
    }

    pub fn decode(input: &[u8], limits: &DecodeLimits) -> Result<Self, PacketError> {
        let locator = Locator::from_bytes(input, limits)?;
        let packet_len = locator.packet_len()?;
        if input.len() < packet_len {
            return Err(PacketError::Truncated {
                needed: packet_len,
                available: input.len(),
            });
        }

        let envelope_start = LOCATOR_SIZE;
        let envelope_end = envelope_start + locator.envelope_len as usize;
        let body_end = envelope_end + locator.encoded_body_len as usize;
        let envelope_bytes = &input[envelope_start..envelope_end];
        if crc32c(envelope_bytes) != locator.envelope_crc32c {
            return Err(PacketError::EnvelopeChecksum);
        }
        let envelope = PacketEnvelope::decode(envelope_bytes, limits)?;
        let body = input[envelope_end..body_end].to_vec();
        validate_untransformed_body(&envelope, &body)?;

        Ok(Self {
            locator,
            envelope,
            body,
        })
    }

    pub fn encoded_len(&self) -> Result<usize, PacketError> {
        self.locator.packet_len()
    }
}

fn validate_untransformed_body(envelope: &PacketEnvelope, body: &[u8]) -> Result<(), PacketError> {
    if !envelope.transforms.is_empty() {
        return Ok(());
    }
    if envelope.original_len != body.len() as u64 {
        return Err(PacketError::BodyLengthMismatch);
    }
    if !envelope.content_digest.verify(body) {
        return Err(PacketError::DigestMismatch);
    }
    Ok(())
}

/// Byte-oriented codec contract used by generic and legacy payload adapters.
pub trait PacketCodec {
    type Value;

    fn encoded_len(&self, value: &Self::Value) -> Result<usize, PacketError>;
    fn encode(&self, value: &Self::Value, output: &mut Vec<u8>) -> Result<(), PacketError>;
    fn decode(&self, input: &[u8], limits: &DecodeLimits) -> Result<Self::Value, PacketError>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct GenericPacketCodec;

impl PacketCodec for GenericPacketCodec {
    type Value = GenericPacket;

    fn encoded_len(&self, value: &Self::Value) -> Result<usize, PacketError> {
        value.encoded_len()
    }

    fn encode(&self, value: &Self::Value, output: &mut Vec<u8>) -> Result<(), PacketError> {
        output.extend_from_slice(&value.encode(&DecodeLimits::default())?);
        Ok(())
    }

    fn decode(&self, input: &[u8], limits: &DecodeLimits) -> Result<Self::Value, PacketError> {
        GenericPacket::decode(input, limits)
    }
}

/// Adapter for the immutable 109-byte legacy v2 signature representation.
#[derive(Debug, Clone, Copy, Default)]
pub struct SignaturePayloadCodec;

impl PacketCodec for SignaturePayloadCodec {
    type Value = SignaturePayload;

    fn encoded_len(&self, _value: &Self::Value) -> Result<usize, PacketError> {
        Ok(SignaturePayload::SERIALIZED_SIZE)
    }

    fn encode(&self, value: &Self::Value, output: &mut Vec<u8>) -> Result<(), PacketError> {
        output.extend_from_slice(&value.to_bytes());
        Ok(())
    }

    fn decode(&self, input: &[u8], _limits: &DecodeLimits) -> Result<Self::Value, PacketError> {
        if input.len() != SignaturePayload::SERIALIZED_SIZE {
            return Err(PacketError::LegacyLength {
                expected: SignaturePayload::SERIALIZED_SIZE,
                actual: input.len(),
            });
        }
        let bytes: [u8; SignaturePayload::SERIALIZED_SIZE] =
            input.try_into().expect("length checked");
        SignaturePayload::from_bytes(&bytes)
            .map_err(|error| PacketError::LegacyPayload(error.to_string()))
    }
}

/// CRC32C (Castagnoli) for public envelope corruption filtering.
pub fn crc32c(input: &[u8]) -> u32 {
    const POLYNOMIAL: u32 = 0x82F6_3B78;
    let mut crc = !0u32;
    for &byte in input {
        crc ^= byte as u32;
        for _ in 0..8 {
            crc = (crc >> 1) ^ (POLYNOMIAL & (0u32.wrapping_sub(crc & 1)));
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Signer;

    fn descriptor(algorithm: u16) -> AlgorithmDescriptor {
        AlgorithmDescriptor::new(algorithm, 1, Vec::new())
    }

    fn packet(payload: &[u8]) -> GenericPacket {
        GenericPacket::new_untransformed(
            payload.to_vec(),
            *b"0123456789abcdef",
            *b"nonce123",
            PayloadKind::Bytes,
            descriptor(1),
            descriptor(1),
            &DecodeLimits::default(),
        )
        .unwrap()
    }

    #[test]
    fn crc32c_matches_standard_vector() {
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
    }

    #[test]
    fn locator_vector_and_roundtrip() {
        let locator = Locator::new(
            FLAG_ENCRYPTED,
            258,
            0x0001_0203,
            0x1122_3344,
            *b"nonce123",
            &DecodeLimits::default(),
        )
        .unwrap();
        let bytes = locator.to_bytes();
        assert_eq!(&bytes[..4], b"STG3");
        assert_eq!(&bytes[6..8], &[0, FLAG_ENCRYPTED as u8]);
        assert_eq!(&bytes[8..12], &[0, 0, 1, 2]);
        assert_eq!(&bytes[12..20], &[0, 0, 0, 0, 0, 1, 2, 3]);
        assert_eq!(
            Locator::from_bytes(&bytes, &DecodeLimits::default()).unwrap(),
            locator
        );
    }

    #[test]
    fn generic_packet_roundtrip_is_canonical() {
        let packet = packet(b"generic steganographic payload");
        let bytes = packet.encode(&DecodeLimits::default()).unwrap();
        let decoded = GenericPacket::decode(&bytes, &DecodeLimits::default()).unwrap();
        assert_eq!(decoded, packet);
        assert_eq!(decoded.encode(&DecodeLimits::default()).unwrap(), bytes);
    }

    #[test]
    fn envelope_optional_metadata_roundtrip() {
        let mut packet = packet(b"hello");
        packet.envelope.payload_kind = PayloadKind::Text;
        packet.envelope.mime_type = Some("text/plain".to_string());
        packet.envelope.filename = Some("greeting.txt".to_string());
        packet.envelope.created_at_unix = Some(1_700_000_000);
        packet.envelope.extensions.push(ExtensionField {
            id: 128,
            value: b"app.example".to_vec(),
        });
        let envelope = packet.envelope.encode(&DecodeLimits::default()).unwrap();
        packet.locator.envelope_len = envelope.len() as u32;
        packet.locator.envelope_crc32c = crc32c(&envelope);

        let bytes = packet.encode(&DecodeLimits::default()).unwrap();
        let decoded = GenericPacket::decode(&bytes, &DecodeLimits::default()).unwrap();
        assert_eq!(decoded.envelope, packet.envelope);
    }

    #[test]
    fn limits_are_checked_from_locator_before_body_access() {
        let mut bytes = packet(b"small").encode(&DecodeLimits::default()).unwrap();
        bytes[12..20].copy_from_slice(&(1_000_000u64).to_be_bytes());
        let limits = DecodeLimits {
            max_body_len: 32,
            ..DecodeLimits::default()
        };
        assert!(matches!(
            GenericPacket::decode(&bytes, &limits),
            Err(PacketError::LimitExceeded { what: "body", .. })
        ));
    }

    #[test]
    fn corrupt_envelope_and_body_are_rejected() {
        let mut envelope_corrupt = packet(b"payload").encode(&DecodeLimits::default()).unwrap();
        envelope_corrupt[LOCATOR_SIZE + 4] ^= 1;
        assert_eq!(
            GenericPacket::decode(&envelope_corrupt, &DecodeLimits::default()).unwrap_err(),
            PacketError::EnvelopeChecksum
        );

        let mut body_corrupt = packet(b"payload").encode(&DecodeLimits::default()).unwrap();
        *body_corrupt.last_mut().unwrap() ^= 1;
        assert_eq!(
            GenericPacket::decode(&body_corrupt, &DecodeLimits::default()).unwrap_err(),
            PacketError::DigestMismatch
        );
    }

    #[test]
    fn malformed_and_noncanonical_fields_are_rejected() {
        let packet = packet(b"payload");
        let mut envelope = packet.envelope.encode(&DecodeLimits::default()).unwrap();
        envelope.extend_from_slice(&(FIELD_CREATED_VERSION | FIELD_CRITICAL).to_be_bytes());
        envelope.extend_from_slice(&2u32.to_be_bytes());
        envelope.extend_from_slice(&[PROTOCOL_MAJOR, PROTOCOL_MINOR]);
        assert!(matches!(
            PacketEnvelope::decode(&envelope, &DecodeLimits::default()),
            Err(PacketError::NonCanonicalOrder { .. }) | Err(PacketError::DuplicateField { .. })
        ));

        let mut unknown = Vec::new();
        push_tlv(&mut unknown, 127, true, b"x", &DecodeLimits::default()).unwrap();
        assert!(matches!(
            PacketEnvelope::decode(&unknown, &DecodeLimits::default()),
            Err(PacketError::UnknownCriticalField { field_id: 127 })
        ));
    }

    #[test]
    fn nonminimal_integer_is_rejected() {
        assert!(matches!(
            decode_minimal_u64(&[0, 1], FIELD_ORIGINAL_LENGTH),
            Err(PacketError::InvalidField { .. })
        ));
    }

    #[test]
    fn legacy_signature_codec_roundtrip() {
        let signer = Signer::generate();
        let payload = signer.sign_frame(7, b"frame", None);
        let codec = SignaturePayloadCodec;
        let mut bytes = Vec::new();
        codec.encode(&payload, &mut bytes).unwrap();
        let decoded = codec.decode(&bytes, &DecodeLimits::default()).unwrap();
        assert_eq!(decoded.to_bytes(), payload.to_bytes());
    }
}
