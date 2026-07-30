//! Generic byte-carrier contracts and the first spatial-LSB vertical slice.
//!
//! Packet framing remains in [`crate::packet`]. This module only maps already
//! encoded packet bytes to carrier units and extracts them again.

use crate::packet::{
    DecodeLimits, GenericPacket, PacketError, KERNEL_SPATIAL_LSB, LOCATOR_SIZE,
    PLACEMENT_SEQUENTIAL,
};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CarrierKind {
    Rgb8,
    ByteStream,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CarrierDescriptor {
    pub kind: CarrierKind,
    pub unit_count: usize,
}

impl CarrierDescriptor {
    pub fn rgb8(byte_len: usize) -> Self {
        Self {
            kind: CarrierKind::Rgb8,
            unit_count: byte_len,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmbeddingConfig {
    pub bits_per_unit: u8,
}

impl EmbeddingConfig {
    pub fn new(bits_per_unit: u8) -> Result<Self, CarrierError> {
        if !(1..=4).contains(&bits_per_unit) {
            return Err(CarrierError::InvalidBits(bits_per_unit));
        }
        Ok(Self { bits_per_unit })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapacityReport {
    pub usable_units: usize,
    pub available_bits: usize,
    pub max_packet_bytes: usize,
}

impl CapacityReport {
    pub fn fits(&self, packet_len: usize) -> bool {
        packet_len <= self.max_packet_bytes
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmbedReport {
    pub packet_bytes: usize,
    pub modified_units: usize,
    pub remaining_capacity_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractReport {
    pub packet: GenericPacket,
    pub consumed_units: usize,
    pub bits_per_unit: u8,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CarrierError {
    #[error("bits per carrier unit must be in the range 1-4, got {0}")]
    InvalidBits(u8),
    #[error("carrier capacity arithmetic overflow")]
    CapacityOverflow,
    #[error("packet needs {needed_bits} carrier bits but only {available_bits} are available")]
    InsufficientCapacity {
        needed_bits: usize,
        available_bits: usize,
    },
    #[error("packet descriptor does not match sequential spatial-LSB configuration")]
    DescriptorMismatch,
    #[error(transparent)]
    Packet(#[from] PacketError),
}

pub trait CarrierEmbedder {
    fn capacity(
        &self,
        carrier: &CarrierDescriptor,
        config: &EmbeddingConfig,
    ) -> Result<CapacityReport, CarrierError>;

    fn embed_packet(
        &self,
        carrier: &mut [u8],
        packet: &[u8],
        config: &EmbeddingConfig,
    ) -> Result<EmbedReport, CarrierError>;
}

pub trait CarrierExtractor {
    fn extract_packet(
        &self,
        carrier: &[u8],
        config: &EmbeddingConfig,
        limits: &DecodeLimits,
    ) -> Result<ExtractReport, CarrierError>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SpatialLsb;

impl CarrierEmbedder for SpatialLsb {
    fn capacity(
        &self,
        carrier: &CarrierDescriptor,
        config: &EmbeddingConfig,
    ) -> Result<CapacityReport, CarrierError> {
        EmbeddingConfig::new(config.bits_per_unit)?;
        let available_bits = carrier
            .unit_count
            .checked_mul(config.bits_per_unit as usize)
            .ok_or(CarrierError::CapacityOverflow)?;
        Ok(CapacityReport {
            usable_units: carrier.unit_count,
            available_bits,
            max_packet_bytes: available_bits / 8,
        })
    }

    fn embed_packet(
        &self,
        carrier: &mut [u8],
        packet: &[u8],
        config: &EmbeddingConfig,
    ) -> Result<EmbedReport, CarrierError> {
        let descriptor = CarrierDescriptor::rgb8(carrier.len());
        let capacity = self.capacity(&descriptor, config)?;
        let needed_bits = packet
            .len()
            .checked_mul(8)
            .ok_or(CarrierError::CapacityOverflow)?;
        if needed_bits > capacity.available_bits {
            return Err(CarrierError::InsufficientCapacity {
                needed_bits,
                available_bits: capacity.available_bits,
            });
        }

        let bits = config.bits_per_unit;
        let mask = !((1u8 << bits) - 1);
        let mut bit_index = 0usize;
        for unit in carrier.iter_mut() {
            if bit_index >= needed_bits {
                break;
            }
            let mut low_bits = 0u8;
            for shift in (0..bits).rev() {
                if bit_index < needed_bits {
                    low_bits |= packet_bit(packet, bit_index) << shift;
                    bit_index += 1;
                }
            }
            *unit = (*unit & mask) | low_bits;
        }

        let modified_units = needed_bits.div_ceil(bits as usize);
        Ok(EmbedReport {
            packet_bytes: packet.len(),
            modified_units,
            remaining_capacity_bytes: capacity.max_packet_bytes - packet.len(),
        })
    }
}

impl CarrierExtractor for SpatialLsb {
    fn extract_packet(
        &self,
        carrier: &[u8],
        config: &EmbeddingConfig,
        limits: &DecodeLimits,
    ) -> Result<ExtractReport, CarrierError> {
        EmbeddingConfig::new(config.bits_per_unit)?;
        let descriptor = CarrierDescriptor::rgb8(carrier.len());
        let capacity = self.capacity(&descriptor, config)?;
        if capacity.max_packet_bytes < LOCATOR_SIZE {
            return Err(CarrierError::InsufficientCapacity {
                needed_bits: LOCATOR_SIZE * 8,
                available_bits: capacity.available_bits,
            });
        }

        let locator_bytes = extract_bytes(carrier, LOCATOR_SIZE, config.bits_per_unit)?;
        let locator = crate::packet::Locator::from_bytes(&locator_bytes, limits)?;
        let packet_len = locator.packet_len()?;
        if !capacity.fits(packet_len) {
            return Err(CarrierError::InsufficientCapacity {
                needed_bits: packet_len
                    .checked_mul(8)
                    .ok_or(CarrierError::CapacityOverflow)?,
                available_bits: capacity.available_bits,
            });
        }

        let packet_bytes = extract_bytes(carrier, packet_len, config.bits_per_unit)?;
        let packet = GenericPacket::decode(&packet_bytes, limits)?;
        if packet.envelope.placement.algorithm != PLACEMENT_SEQUENTIAL
            || packet.envelope.placement.version != 1
            || !packet.envelope.placement.parameters.is_empty()
            || packet.envelope.kernel.algorithm != KERNEL_SPATIAL_LSB
            || packet.envelope.kernel.version != 1
            || packet.envelope.kernel.parameters != [config.bits_per_unit]
        {
            return Err(CarrierError::DescriptorMismatch);
        }

        Ok(ExtractReport {
            packet,
            consumed_units: (packet_len * 8).div_ceil(config.bits_per_unit as usize),
            bits_per_unit: config.bits_per_unit,
        })
    }
}

fn packet_bit(packet: &[u8], bit_index: usize) -> u8 {
    let byte = packet[bit_index / 8];
    (byte >> (7 - bit_index % 8)) & 1
}

fn extract_bytes(
    carrier: &[u8],
    byte_count: usize,
    bits_per_unit: u8,
) -> Result<Vec<u8>, CarrierError> {
    let bit_count = byte_count
        .checked_mul(8)
        .ok_or(CarrierError::CapacityOverflow)?;
    let required_units = bit_count.div_ceil(bits_per_unit as usize);
    if required_units > carrier.len() {
        return Err(CarrierError::InsufficientCapacity {
            needed_bits: bit_count,
            available_bits: carrier.len().saturating_mul(bits_per_unit as usize),
        });
    }

    let mut output = vec![0u8; byte_count];
    let mut bit_index = 0usize;
    for &unit in &carrier[..required_units] {
        for shift in (0..bits_per_unit).rev() {
            if bit_index >= bit_count {
                break;
            }
            let bit = (unit >> shift) & 1;
            output[bit_index / 8] |= bit << (7 - bit_index % 8);
            bit_index += 1;
        }
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{AlgorithmDescriptor, PayloadKind};

    fn packet(bits: u8, payload: &[u8]) -> Vec<u8> {
        GenericPacket::new_untransformed(
            payload.to_vec(),
            *b"0123456789abcdef",
            *b"nonce123",
            PayloadKind::Bytes,
            AlgorithmDescriptor::new(PLACEMENT_SEQUENTIAL, 1, Vec::new()),
            AlgorithmDescriptor::new(KERNEL_SPATIAL_LSB, 1, vec![bits]),
            &DecodeLimits::default(),
        )
        .unwrap()
        .encode(&DecodeLimits::default())
        .unwrap()
    }

    #[test]
    fn packet_roundtrip_at_every_supported_strength() {
        for bits in 1..=4 {
            let packet = packet(bits, b"generic carrier payload");
            let config = EmbeddingConfig::new(bits).unwrap();
            let mut carrier = vec![0xA5; packet.len() * 8 + 64];
            let report = SpatialLsb
                .embed_packet(&mut carrier, &packet, &config)
                .unwrap();
            assert_eq!(report.packet_bytes, packet.len());

            let extracted = SpatialLsb
                .extract_packet(&carrier, &config, &DecodeLimits::default())
                .unwrap();
            assert_eq!(extracted.packet.body, b"generic carrier payload");
            assert_eq!(extracted.bits_per_unit, bits);
        }
    }

    #[test]
    fn exact_capacity_and_insufficient_carrier_are_reported() {
        let packet = packet(2, b"payload");
        let config = EmbeddingConfig::new(2).unwrap();
        let exact_units = (packet.len() * 8).div_ceil(2);
        let capacity = SpatialLsb
            .capacity(&CarrierDescriptor::rgb8(exact_units), &config)
            .unwrap();
        assert!(capacity.fits(packet.len()));

        let mut short = vec![0; exact_units - 1];
        assert!(matches!(
            SpatialLsb.embed_packet(&mut short, &packet, &config),
            Err(CarrierError::InsufficientCapacity { .. })
        ));
    }

    #[test]
    fn invalid_strength_and_wrong_probe_are_rejected() {
        assert_eq!(
            EmbeddingConfig::new(0).unwrap_err(),
            CarrierError::InvalidBits(0)
        );
        let packet = packet(3, b"payload");
        let mut carrier = vec![0; packet.len() * 8];
        SpatialLsb
            .embed_packet(&mut carrier, &packet, &EmbeddingConfig::new(3).unwrap())
            .unwrap();
        assert!(SpatialLsb
            .extract_packet(
                &carrier,
                &EmbeddingConfig::new(1).unwrap(),
                &DecodeLimits::default()
            )
            .is_err());

        let limits = DecodeLimits::default();
        let wrong_version = GenericPacket::new_untransformed(
            b"payload".to_vec(),
            *b"0123456789abcdef",
            *b"nonce123",
            PayloadKind::Bytes,
            AlgorithmDescriptor::new(PLACEMENT_SEQUENTIAL, 2, Vec::new()),
            AlgorithmDescriptor::new(KERNEL_SPATIAL_LSB, 1, vec![3]),
            &limits,
        )
        .unwrap()
        .encode(&limits)
        .unwrap();
        let mut carrier = vec![0; wrong_version.len() * 8];
        SpatialLsb
            .embed_packet(
                &mut carrier,
                &wrong_version,
                &EmbeddingConfig::new(3).unwrap(),
            )
            .unwrap();
        assert_eq!(
            SpatialLsb
                .extract_packet(&carrier, &EmbeddingConfig::new(3).unwrap(), &limits)
                .unwrap_err(),
            CarrierError::DescriptorMismatch
        );
    }

    #[test]
    fn locator_limits_block_oversized_claims() {
        let packet = packet(1, b"payload");
        let mut carrier = vec![0; packet.len() * 8];
        SpatialLsb
            .embed_packet(&mut carrier, &packet, &EmbeddingConfig::new(1).unwrap())
            .unwrap();

        let limits = DecodeLimits {
            max_body_len: 3,
            ..DecodeLimits::default()
        };
        assert!(matches!(
            SpatialLsb.extract_packet(&carrier, &EmbeddingConfig::new(1).unwrap(), &limits),
            Err(CarrierError::Packet(PacketError::LimitExceeded {
                what: "body",
                ..
            }))
        ));
    }
}
