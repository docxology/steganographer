//! Argon2id password-based key derivation.
//!
//! [`kdf`](crate::kdf) derives keys from an already high-entropy master secret
//! using BLAKE3's `derive_key`. That is intentionally *not* a password-hard
//! function — a short or memorable passphrase can be brute-forced at hash
//! speed. This module is the password counterpart: it stretches a
//! human-chosen password with **Argon2id** (RFC 9106) into a high-entropy
//! master secret, which is then fed through the same domain-separated
//! [`kdf::derive_all`](crate::kdf::derive_all) so the rest of the system is
//! unchanged.
//!
//! ## Design
//!
//! - **Algorithm**: Argon2id, version 0x13 (the memory-hard hybrid of
//!   Argon2i/Argon2d recommended by RFC 9106 and the OWASP Password Storage
//!   Cheat Sheet).
//! - **Salt**: 16 random bytes (128-bit), unique per password. The caller must
//!   persist it alongside the derived material to reproduce the keys later.
//! - **Defaults**: 19 MiB memory, 2 iterations, 1 lane (OWASP's current
//!   minimums). The [`Argon2Params::validate`] floor is only the *algorithmic*
//!   requirement (memory ≥ 8 KiB × lanes); the stronger recommended floor is
//!   exposed as [`RECOMMENDED_MEMORY_KIB`] / [`RECOMMENDED_ITERATIONS`] so
//!   callers can warn rather than reject.
//!
//! ## Example
//!
//! ```ignore
//! use steganographer_core::password::{self, Argon2Params};
//!
//! let salt = password::generate_salt();
//! let keys = password::derive_all_from_password(b"correct horse battery staple", &salt, &Argon2Params::default())?;
//! // keys.signing_key / keys.encryption_key / keys.embedding_key
//! # Ok::<(), steganographer_core::password::PasswordKdfError>(())
//! ```

use argon2::{Algorithm, Argon2, Params, Version};
use rand::rngs::OsRng;
use rand::RngCore;
use thiserror::Error;

/// Salt length in bytes (128-bit, unique per password).
pub const SALT_LEN: usize = 16;
/// Minimum acceptable salt length in bytes.
pub const MIN_SALT_LEN: usize = 16;
/// Minimum derived output length in bytes.
pub const MIN_OUTPUT_LEN: usize = 16;
/// Maximum Argon2 output length in bytes (hard limit of the algorithm).
pub const MAX_OUTPUT_LEN: usize = 64;
/// OWASP/RFC 9106 recommended memory floor (KiB).
pub const RECOMMENDED_MEMORY_KIB: u32 = 19 * 1024;
/// OWASP recommended iteration floor.
pub const RECOMMENDED_ITERATIONS: u32 = 2;

/// Argon2id derivation parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Params {
    /// Memory cost in KiB (1 KiB = 1024 bytes).
    pub memory_kib: u32,
    /// Time cost (number of passes).
    pub iterations: u32,
    /// Degree of parallelism (lanes).
    pub parallelism: u32,
    /// Derived output length in bytes (16–64).
    pub output_len: usize,
}

impl Default for Argon2Params {
    /// OWASP 2024 minimums: 19 MiB, 2 iterations, 1 lane, 32-byte output.
    fn default() -> Self {
        Self {
            memory_kib: RECOMMENDED_MEMORY_KIB,
            iterations: RECOMMENDED_ITERATIONS,
            parallelism: 1,
            output_len: 32,
        }
    }
}

impl Argon2Params {
    /// Validate the *algorithmic* constraints Argon2 needs to run and to be
    /// minimally sound: `memory_kib ≥ 8 × parallelism`, `iterations ≥ 1`,
    /// `parallelism ≥ 1`, and `16 ≤ output_len ≤ 64`.
    ///
    /// This is a lower floor than the security recommendation
    /// ([`RECOMMENDED_MEMORY_KIB`] / [`RECOMMENDED_ITERATIONS`]); callers that
    /// accept user-supplied parameters should additionally warn below that.
    pub fn validate(&self) -> Result<(), PasswordKdfError> {
        if self.parallelism < 1 {
            return Err(PasswordKdfError::ParallelismTooLow(self.parallelism));
        }
        let minimum_memory = self
            .parallelism
            .checked_mul(8)
            .ok_or(PasswordKdfError::LengthOverflow)?;
        if self.memory_kib < minimum_memory {
            return Err(PasswordKdfError::MemoryTooLow {
                memory_kib: self.memory_kib,
                minimum: minimum_memory,
            });
        }
        if self.iterations < 1 {
            return Err(PasswordKdfError::IterationsTooLow(self.iterations));
        }
        if !(MIN_OUTPUT_LEN..=MAX_OUTPUT_LEN).contains(&self.output_len) {
            return Err(PasswordKdfError::InvalidOutputLen(self.output_len));
        }
        Ok(())
    }

    /// Whether these parameters meet the OWASP recommended floor.
    pub fn meets_recommendation(&self) -> bool {
        self.memory_kib >= RECOMMENDED_MEMORY_KIB && self.iterations >= RECOMMENDED_ITERATIONS
    }

    /// A deliberately weak profile for **tests and demos only**. Never use for
    /// real secrets — 8 KiB of memory offers essentially no brute-force
    /// resistance.
    pub fn fast() -> Self {
        Self {
            memory_kib: 8,
            iterations: 1,
            parallelism: 1,
            output_len: 32,
        }
    }
}

/// Password-KDF failures.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PasswordKdfError {
    #[error("Argon2 memory cost {memory_kib} KiB is below the required {minimum} KiB (8 KiB × parallelism)")]
    MemoryTooLow { memory_kib: u32, minimum: u32 },
    #[error("Argon2 iterations must be at least 1, got {0}")]
    IterationsTooLow(u32),
    #[error("Argon2 parallelism must be at least 1, got {0}")]
    ParallelismTooLow(u32),
    #[error("Argon2 output length {0} must be in {MIN_OUTPUT_LEN}..={MAX_OUTPUT_LEN}")]
    InvalidOutputLen(usize),
    #[error("salt must be at least {MIN_SALT_LEN} bytes, got {0}")]
    SaltTooShort(usize),
    #[error("password must not be empty")]
    EmptyPassword,
    #[error("parameter arithmetic overflow")]
    LengthOverflow,
    #[error("Argon2 parameter construction failed: {0}")]
    InvalidParams(String),
    #[error("Argon2id derivation failed: {0}")]
    DerivationFailed(String),
}

/// Generate a fresh random 128-bit salt.
pub fn generate_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Stretch a password into a high-entropy master secret using Argon2id.
///
/// The output length is `params.output_len` (32 bytes by default). The same
/// `salt` and `params` must be supplied to reproduce the secret later.
pub fn derive_master_from_password(
    password: &[u8],
    salt: &[u8],
    params: &Argon2Params,
) -> Result<Vec<u8>, PasswordKdfError> {
    params.validate()?;
    if password.is_empty() {
        return Err(PasswordKdfError::EmptyPassword);
    }
    if salt.len() < MIN_SALT_LEN {
        return Err(PasswordKdfError::SaltTooShort(salt.len()));
    }

    let argon_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(params.output_len),
    )
    .map_err(|e| PasswordKdfError::InvalidParams(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    let mut output = vec![0u8; params.output_len];
    argon
        .hash_password_into(password, salt, &mut output)
        .map_err(|e| PasswordKdfError::DerivationFailed(e.to_string()))?;
    Ok(output)
}

/// Derive the full signing/encryption/embedding key set from a password.
///
/// This is [`derive_master_from_password`] followed by
/// [`kdf::derive_all`](crate::kdf::derive_all), so the resulting
/// [`crate::kdf::DerivedKeys`] are interchangeable with those derived from a
/// raw high-entropy master secret.
pub fn derive_all_from_password(
    password: &[u8],
    salt: &[u8],
    params: &Argon2Params,
) -> Result<crate::kdf::DerivedKeys, PasswordKdfError> {
    let master = derive_master_from_password(password, salt, params)?;
    Ok(crate::kdf::derive_all(&master))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_is_deterministic_for_same_salt_and_params() {
        let params = Argon2Params::fast();
        let salt = generate_salt();
        let a = derive_all_from_password(b"correct horse", &salt, &params).unwrap();
        let b = derive_all_from_password(b"correct horse", &salt, &params).unwrap();
        assert_eq!(a.signing_key, b.signing_key);
        assert_eq!(a.encryption_key, b.encryption_key);
        assert_eq!(a.embedding_key, b.embedding_key);
    }

    #[test]
    fn different_salts_derive_different_keys() {
        let params = Argon2Params::fast();
        let a = derive_all_from_password(b"same password", &generate_salt(), &params).unwrap();
        let b = derive_all_from_password(b"same password", &generate_salt(), &params).unwrap();
        assert_ne!(a.signing_key, b.signing_key);
        assert_ne!(a.encryption_key, b.encryption_key);
        assert_ne!(a.embedding_key, b.embedding_key);
    }

    #[test]
    fn different_passwords_derive_different_keys() {
        let params = Argon2Params::fast();
        let salt = generate_salt();
        let a = derive_all_from_password(b"password A", &salt, &params).unwrap();
        let b = derive_all_from_password(b"password B", &salt, &params).unwrap();
        assert_ne!(a.signing_key, b.signing_key);
    }

    #[test]
    fn derived_keys_are_mutually_distinct() {
        let keys =
            derive_all_from_password(b"test password", &generate_salt(), &Argon2Params::fast())
                .unwrap();
        assert_ne!(keys.signing_key, keys.encryption_key);
        assert_ne!(keys.signing_key, keys.embedding_key);
        assert_ne!(keys.encryption_key, keys.embedding_key);
    }

    #[test]
    fn default_params_meet_recommendation() {
        let params = Argon2Params::default();
        assert!(params.meets_recommendation());
        assert!(params.validate().is_ok());
    }

    #[test]
    fn fast_params_are_below_recommendation_but_valid() {
        let params = Argon2Params::fast();
        assert!(!params.meets_recommendation());
        assert!(params.validate().is_ok());
    }

    #[test]
    fn memory_below_parallelism_floor_is_rejected() {
        let params = Argon2Params {
            memory_kib: 15,
            parallelism: 2,
            ..Argon2Params::fast()
        };
        assert!(matches!(
            params.validate(),
            Err(PasswordKdfError::MemoryTooLow { .. })
        ));
    }

    #[test]
    fn empty_password_is_rejected() {
        let params = Argon2Params::fast();
        assert!(matches!(
            derive_master_from_password(b"", &generate_salt(), &params),
            Err(PasswordKdfError::EmptyPassword)
        ));
    }

    #[test]
    fn short_salt_is_rejected() {
        let params = Argon2Params::fast();
        assert!(matches!(
            derive_master_from_password(b"pw", &[0u8; 8], &params),
            Err(PasswordKdfError::SaltTooShort(8))
        ));
    }

    #[test]
    fn output_len_is_bounded() {
        let params = Argon2Params {
            output_len: 65,
            ..Argon2Params::fast()
        };
        assert!(matches!(
            params.validate(),
            Err(PasswordKdfError::InvalidOutputLen(65))
        ));

        let params = Argon2Params {
            output_len: 8,
            ..Argon2Params::fast()
        };
        assert!(matches!(
            params.validate(),
            Err(PasswordKdfError::InvalidOutputLen(8))
        ));
    }

    #[test]
    fn zero_iterations_and_parallelism_are_rejected() {
        let params = Argon2Params {
            iterations: 0,
            ..Argon2Params::fast()
        };
        assert!(matches!(
            params.validate(),
            Err(PasswordKdfError::IterationsTooLow(0))
        ));

        let params = Argon2Params {
            parallelism: 0,
            ..Argon2Params::fast()
        };
        assert!(matches!(
            params.validate(),
            Err(PasswordKdfError::ParallelismTooLow(0))
        ));
    }

    #[test]
    fn non_default_output_len_roundtrips() {
        let params = Argon2Params {
            output_len: 48,
            ..Argon2Params::fast()
        };
        let salt = generate_salt();
        let master = derive_master_from_password(b"pw", &salt, &params).unwrap();
        assert_eq!(master.len(), 48);
        assert!(master.iter().any(|&b| b != 0));
    }
}
