//! Authorization policy for Ed25519 signing identities, separate from signature mathematics.
//!
//! The historical key documented in `docs/key-rotation.md` is always revoked. A local
//! registry adds identities; an empty or absent registry cannot restore a compromised key.

use crate::crypto::decode_hex_array;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

const COMPROMISED_KEY: [u8; 32] = [
    0xd2, 0xa0, 0x5f, 0x7c, 0x69, 0x24, 0x9d, 0xbf, 0xba, 0x54, 0x08, 0xdd, 0x8c, 0x35, 0x55, 0x13,
    0x17, 0xb0, 0x4b, 0xfc, 0xc6, 0xf7, 0x93, 0xc5, 0xe7, 0x62, 0x21, 0x77, 0x8c, 0x61, 0xd5, 0x52,
];

/// Whether an identity is covered by the repository's documented key compromise.
pub fn is_known_compromised_key(public_key: &[u8; 32]) -> bool {
    public_key == &COMPROMISED_KEY
}

/// A mathematical signature is not authorization to trust a revoked identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("Ed25519 signing identity is revoked")]
pub struct RevokedKey;

/// Reject known compromised identities before managed signing or trust decisions.
pub fn check_known_revocations(public_key: &[u8; 32]) -> Result<(), RevokedKey> {
    if is_known_compromised_key(public_key) {
        Err(RevokedKey)
    } else {
        Ok(())
    }
}

/// Additional revoked identities, encoded as a JSON array of 64-character hex keys.
///
/// Keys are normalized, sorted, and deduplicated on input. Policy lookups allocate
/// nothing and include the built-in compromise independently of registry contents.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RevocationList {
    keys: Vec<PublicKey>,
}

impl RevocationList {
    /// Add an explicit registry entry; return whether it was newly recorded.
    pub fn insert(&mut self, public_key: [u8; 32]) -> bool {
        match self.keys.binary_search_by(|key| key.0.cmp(&public_key)) {
            Ok(_) => false,
            Err(index) => {
                self.keys.insert(index, PublicKey(public_key));
                true
            }
        }
    }

    /// Number of explicit registry entries, excluding implicit compromise policy.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the explicit registry has entries; built-in policy still applies.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Check both immutable compromise policy and the additional registry.
    pub fn is_revoked(&self, public_key: &[u8; 32]) -> bool {
        is_known_compromised_key(public_key)
            || self
                .keys
                .binary_search_by(|key| key.0.cmp(public_key))
                .is_ok()
    }
}

impl<'de> Deserialize<'de> for RevocationList {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let mut keys = Vec::<PublicKey>::deserialize(deserializer)?;
        keys.sort_unstable();
        keys.dedup();
        Ok(Self { keys })
    }
}

impl Serialize for RevocationList {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.keys.iter().map(|key| HexKey(&key.0)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct PublicKey([u8; 32]);

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct KeyVisitor;

        impl de::Visitor<'_> for KeyVisitor {
            type Value = PublicKey;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a 64-character hexadecimal Ed25519 public key")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                decode_hex_array(value).map(PublicKey).map_err(E::custom)
            }
        }

        deserializer.deserialize_str(KeyVisitor)
    }
}

struct HexKey<'a>(&'a [u8; 32]);

impl Serialize for HexKey<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = [0; 64];
        for (pair, byte) in encoded.as_chunks_mut::<2>().0.iter_mut().zip(self.0) {
            pair[0] = DIGITS[(byte >> 4) as usize];
            pair[1] = DIGITS[(byte & 0xf) as usize];
        }
        serializer.serialize_str(std::str::from_utf8(&encoded).expect("hex encoding is ASCII"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_registry_cannot_restore_the_compromised_identity() {
        let list: RevocationList = serde_json::from_str("[]").unwrap();
        assert!(list.is_revoked(&COMPROMISED_KEY));
        assert_eq!(check_known_revocations(&COMPROMISED_KEY), Err(RevokedKey));
        assert!(!list.is_revoked(&[9; 32]));
        assert_eq!(check_known_revocations(&[9; 32]), Ok(()));
    }

    #[test]
    fn registry_case_and_duplicates_do_not_change_policy() {
        let mut list: RevocationList = serde_json::from_value(serde_json::json!([
            "AB".repeat(32),
            "ab".repeat(32),
            "12".repeat(32)
        ]))
        .unwrap();
        assert!(list.is_revoked(&[0xab; 32]));
        assert!(!list.insert([0xab; 32]));
        assert!(list.insert([0xcd; 32]));
        assert_eq!(
            serde_json::to_value(&list).unwrap(),
            serde_json::json!(["12".repeat(32), "ab".repeat(32), "cd".repeat(32)])
        );
    }

    #[test]
    fn malformed_registry_entries_never_produce_partial_policy() {
        for invalid in ["zz".repeat(32), "ab".repeat(31), "é".repeat(32)] {
            assert!(serde_json::from_value::<RevocationList>(serde_json::json!([
                "12".repeat(32),
                invalid
            ]))
            .is_err());
        }
        assert!(serde_json::from_str::<RevocationList>("{}").is_err());
    }
}
