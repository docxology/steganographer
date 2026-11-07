use ed25519_dalek::{Signature, VerifyingKey};
use steganographer_core::crypto::{
    decode_hex, encode_hex, HashAlgorithm, SignaturePayload, Signer, Verifier,
};
use steganographer_core::encryption::{self, EncryptionKey, LEGACY_ENCRYPTION_OVERHEAD};
use steganographer_core::multi_frame;
use steganographer_core::signer_backend::{Ed25519Backend, Ed25519Verifier, SignerBackend};

#[test]
fn media_partitions_and_absent_audio_are_authenticated() {
    for algorithm in [
        HashAlgorithm::Blake3,
        HashAlgorithm::Sha256,
        HashAlgorithm::Sha3_256,
    ] {
        let signer = Signer::from_bytes_with_algo(&[17; 32], algorithm);
        let verifier = Verifier::with_hash_algorithm(signer.verifying_key(), algorithm);
        let payload = signer.sign_frame(7, b"ab", Some(b"c"));
        assert!(verifier.verify(&payload, b"ab", Some(b"c")));
        assert!(!verifier.verify(&payload, b"a", Some(b"bc")));
        assert!(!verifier.verify(&payload, b"abc", None));
        let no_audio = signer.sign_frame(7, b"abc", None);
        assert!(!verifier.verify(&no_audio, b"abc", Some(b"")));
        assert_ne!(
            algorithm.hash(7, b"ab", Some(b"c")),
            algorithm.hash(8, b"ab", Some(b"c"))
        );
    }
}

#[test]
fn identity_key_forgery_is_rejected_at_import_and_typed_boundaries() {
    let mut identity = [0u8; 32];
    identity[0] = 1;
    let weak_key = VerifyingKey::from_bytes(&identity).unwrap();
    assert!(weak_key.is_weak());
    let mut forged = [0u8; 64];
    forged[0] = 1; // R = identity, S = zero: no private key required.
    assert!(Verifier::from_bytes(&identity).is_err());
    assert!(Ed25519Verifier::from_bytes(&identity).is_err());
    assert!(!Ed25519Verifier::new(weak_key).verify(b"arbitrary message", &forged));
    for algorithm in [
        HashAlgorithm::Blake3,
        HashAlgorithm::Sha256,
        HashAlgorithm::Sha3_256,
    ] {
        assert!(Verifier::from_bytes_with_algo(&identity, algorithm).is_err());
        let payload = SignaturePayload {
            frame_index: 5,
            hash: algorithm.hash(5, b"forged media", None),
            signature: Signature::from_bytes(&forged),
        };
        let verifier = Verifier::with_hash_algorithm(weak_key, algorithm);
        assert!(!verifier.verify(&payload, b"forged media", None));
    }
    assert!(!Verifier::new(weak_key).verify(
        &SignaturePayload {
            frame_index: 5,
            hash: HashAlgorithm::Blake3.hash(5, b"forged media", None),
            signature: Signature::from_bytes(&forged),
        },
        b"forged media",
        None
    ));
}

#[test]
fn ordinary_signatures_require_the_pinned_identity() {
    let alice = Ed25519Backend::from_bytes(&[21; 32]);
    let bob = Ed25519Backend::from_bytes(&[22; 32]);
    let trusted = Ed25519Verifier::new(alice.verifying_key());
    let message = b"authorship is not just an embedded key";
    assert!(trusted.verify(message, &alice.sign(message)));
    assert!(!trusted.verify(message, &bob.sign(message)));
    let signer = Signer::from_bytes(&[21; 32]);
    let verifier = Verifier::from_bytes(&signer.verifying_key().to_bytes()).unwrap();
    assert_eq!(verifier.verifying_key(), signer.verifying_key());
}

#[test]
fn hex_rejects_unicode_and_accepts_both_ascii_cases() {
    for malformed in [
        "€a".to_owned(),
        "€".repeat(21) + "a",
        "é".repeat(32),
        "00 ff".to_owned(),
        "0g".to_owned(),
    ] {
        assert!(decode_hex(&malformed).is_err());
        assert!(EncryptionKey::from_hex(&malformed).is_err());
    }
    assert_eq!(decode_hex("00aAfF").unwrap(), [0, 170, 255]);
    assert_eq!(encode_hex(&[0, 170, 255]), "00aaff");
    assert_eq!(decode_hex("").unwrap(), Vec::<u8>::new());
    let key = EncryptionKey::from_hex(&"Aa".repeat(32)).unwrap();
    assert_eq!(key.as_bytes(), &[170; 32]);
    assert_eq!(key.expose_hex(), "aa".repeat(32));
}

#[test]
fn legacy_wrapper_authenticates_all_bytes_and_has_no_raw_fallback() {
    let key = EncryptionKey::from_bytes(&[29; 32]);
    let message = b"legacy media commitment";
    let encrypted = encryption::encrypt_legacy(&key, message, Some(b"carrier binding")).unwrap();
    assert_eq!(encrypted.len(), message.len() + LEGACY_ENCRYPTION_OVERHEAD);
    assert_eq!(
        encryption::decrypt_legacy(&key, &encrypted, Some(b"carrier binding")).unwrap(),
        message
    );
    assert!(encryption::decrypt_legacy(&key, &encrypted, Some(b"other carrier")).is_err());
    assert!(encryption::decrypt_legacy(
        &EncryptionKey::from_bytes(&[30; 32]),
        &encrypted,
        Some(b"carrier binding")
    )
    .is_err());
    for index in 0..encrypted.len() {
        let mut tampered = encrypted.clone();
        tampered[index] ^= 1;
        assert!(
            encryption::decrypt_legacy(&key, &tampered, Some(b"carrier binding")).is_err(),
            "tampered byte {index}"
        );
    }
    for len in 0..encrypted.len() {
        assert!(
            encryption::decrypt_legacy(&key, &encrypted[..len], Some(b"carrier binding")).is_err()
        );
    }
    let old_zero_id = encryption::encrypt(&key, &[0; 16], message, None).unwrap();
    assert!(encryption::decrypt_legacy(&key, &old_zero_id, None).is_err());
    // The full 128-bit ID is carried and actually feeds the unchanged raw cipher.
    let header_len = LEGACY_ENCRYPTION_OVERHEAD - encryption::SALT_SIZE - encryption::TAG_SIZE;
    let packet_id: &[u8; 16] = encrypted[5..header_len].try_into().unwrap();
    assert_eq!(
        encryption::decrypt(
            &key,
            packet_id,
            &encrypted[header_len..],
            Some(b"carrier binding")
        )
        .unwrap(),
        message
    );
}

#[test]
fn shard_counter_boundary_is_checked_for_both_public_splitters() {
    let signature = Signer::from_bytes(&[31; 32]).sign_frame(0, b"frame", None);
    for count in 2u8..=8 {
        let last_safe = u64::MAX - u64::from(count - 1);
        let generic = multi_frame::split_payload_bytes(b"payload", count, last_safe).unwrap();
        let legacy = multi_frame::split(&signature, count, last_safe).unwrap();
        assert_eq!(generic.last().unwrap().frame_index, u64::MAX);
        assert_eq!(legacy.last().unwrap().frame_index, u64::MAX);
        assert_eq!(
            multi_frame::reconstruct_payload_bytes(&generic).unwrap(),
            b"payload"
        );
        assert_eq!(
            multi_frame::reconstruct(&legacy).unwrap().to_bytes(),
            signature.to_bytes()
        );
        assert!(multi_frame::split_payload_bytes(b"payload", count, last_safe + 1).is_err());
        assert!(multi_frame::split(&signature, count, last_safe + 1).is_err());
    }
}

#[test]
fn streaming_secret_derivation_preserves_existing_key_domains() {
    use steganographer_core::kdf;
    let master = b"owned secret copies should not linger";
    assert_eq!(
        kdf::derive_signing_key(master),
        blake3::derive_key("steganographer-signing-v1", master)
    );
    assert_eq!(
        kdf::derive_encryption_key(master),
        blake3::derive_key("steganographer-encryption-v1", master)
    );
    assert_eq!(
        kdf::derive_embedding_key(master),
        blake3::derive_key("steganographer-embedding-v1", master)
    );
    let mut input = zeroize::Zeroizing::new(master.to_vec());
    input.extend_from_slice(&u64::MAX.to_le_bytes());
    assert_eq!(
        kdf::derive_session_signing_key(master, u64::MAX),
        blake3::derive_key("steganographer-session-signing-v1", &input)
    );
    assert_eq!(
        kdf::derive_session_encryption_key(master, u64::MAX),
        blake3::derive_key("steganographer-session-encryption-v1", &input)
    );
}

#[test]
fn hybrid_rejects_forged_classical_half_even_with_valid_post_quantum_half() {
    use steganographer_core::signer_backend::{
        HybridVerifier, MlDsaBackend, MlDsaLevel, MlDsaVerifier,
    };
    let level = MlDsaLevel::MlDsa44;
    let pq = MlDsaBackend::from_seed(level, [33; 32]);
    let mut identity = [0u8; 32];
    identity[0] = 1;
    let weak_key = VerifyingKey::from_bytes(&identity).unwrap();
    let mut public_key = identity.to_vec();
    public_key.extend_from_slice(&pq.public_key_bytes());
    assert!(HybridVerifier::from_public_key_bytes(level, &public_key).is_err());
    let hybrid = HybridVerifier::new(
        Ed25519Verifier::new(weak_key),
        MlDsaVerifier::from_public_key_bytes(level, &pq.public_key_bytes()).unwrap(),
    );
    let message = b"valid PQ half cannot repair forged classical identity";
    let mut signature = vec![0u8; 64];
    signature[0] = 1;
    signature.extend_from_slice(&pq.sign(message));
    assert!(!hybrid.verify(message, &signature));
}
