use serde_json::Value;
use vectis::core::crypto;
use vectis::ops::key_material::{KeyMaterialOutput, KeyMaterialSpec, create_key_material};
use vectis::ops::key_validation::validate_key_material;

struct ProfileCase {
    name: &'static str,
    hash: &'static str,
    symmetric: &'static str,
    eddsa: &'static str,
    xecdh: &'static str,
    ml_dsa: &'static str,
    ml_kem: &'static str,
}

const PROFILE_CASES: &[ProfileCase] = &[
    ProfileCase {
        name: "hybrid-performance-v1",
        hash: "BLAKE2b(256)",
        symmetric: "ChaCha20Poly1305",
        eddsa: "Ed25519",
        xecdh: "X25519",
        ml_dsa: "ML-DSA-44",
        ml_kem: "ML-KEM-512",
    },
    ProfileCase {
        name: "hybrid-high-assurance-v1",
        hash: "SHA-3(384)",
        symmetric: "AES-256/GCM",
        eddsa: "Ed25519",
        xecdh: "X25519",
        ml_dsa: "ML-DSA-65",
        ml_kem: "ML-KEM-768",
    },
    ProfileCase {
        name: "hybrid-long-term-v1",
        hash: "SHA-3(512)",
        symmetric: "AES-256/GCM",
        eddsa: "Ed448",
        xecdh: "X448",
        ml_dsa: "ML-DSA-87",
        ml_kem: "ML-KEM-1024",
    },
];

fn spec(case: &ProfileCase) -> KeyMaterialSpec {
    KeyMaterialSpec::new(
        case.hash,
        case.symmetric,
        case.eddsa,
        case.xecdh,
        case.ml_dsa,
        case.ml_kem,
    )
}

fn create_profile_material(case: &ProfileCase) -> KeyMaterialOutput {
    create_key_material(&spec(case)).expect(case.name)
}

#[test]
fn profiles_create_valid_key_material() {
    for case in PROFILE_CASES {
        let material = create_profile_material(case);
        let keys = material.keys();

        assert_eq!(material.hash_variant(), case.hash, "{}", case.name);
        assert_eq!(keys.symmetric().variant(), case.symmetric, "{}", case.name);
        assert_eq!(keys.eddsa().variant(), case.eddsa, "{}", case.name);
        assert_eq!(keys.xecdh().variant(), case.xecdh, "{}", case.name);
        assert_eq!(keys.ml_dsa().variant(), case.ml_dsa, "{}", case.name);
        assert_eq!(keys.ml_kem().variant(), case.ml_kem, "{}", case.name);
    }
}

#[test]
fn generated_key_material_validates_end_to_end() {
    let aad = "version=v1;type=crypto-integration-test";
    let message = "Vectis crypto integration smoke test";

    for case in PROFILE_CASES {
        let material = create_profile_material(case);
        let validation = validate_key_material(&material, aad, message).expect(case.name);
        let value = serde_json::to_value(validation).expect("validation output must serialize");

        assert_eq!(value["aad"], aad, "{}", case.name);
        assert_eq!(value["hash"]["variant"], case.hash, "{}", case.name);
        assert_variant_valid(&value, "symmetric", case.symmetric, case.name);
        assert_variant_valid(&value, "eddsa", case.eddsa, case.name);
        assert_variant_valid(&value, "xecdh", case.xecdh, case.name);
        assert_variant_valid(&value, "ml-dsa", case.ml_dsa, case.name);
        assert_variant_valid(&value, "ml-kem", case.ml_kem, case.name);
    }
}

#[test]
fn hybrid_kem_and_symmetric_encryption_compose() {
    for case in PROFILE_CASES {
        let material = create_profile_material(case);
        let keys = material.keys();
        let xecdh_private_key =
            crypto::load_private_key_der_hex(keys.xecdh().private_key_der_hex()).expect(case.name);
        let ml_kem_private_key =
            crypto::load_private_key_der_hex(keys.ml_kem().private_key_der_hex()).expect(case.name);

        let ephemeral_private_key =
            crypto::create_x_key_agreement_private_key(keys.xecdh().variant()).expect(case.name);
        let ephemeral_public_key =
            crypto::key_agreement_public_key(&ephemeral_private_key).expect(case.name);
        let recipient_xecdh_public_key =
            hex::decode(keys.xecdh().public_key_hex()).expect(case.name);
        let sender_xecdh_shared =
            crypto::agree_key(&ephemeral_private_key, &recipient_xecdh_public_key)
                .expect(case.name);
        let receiver_xecdh_shared =
            crypto::agree_key(&xecdh_private_key, &ephemeral_public_key).expect(case.name);
        assert_eq!(sender_xecdh_shared, receiver_xecdh_shared, "{}", case.name);

        let ml_kem_public_key =
            crypto::load_public_key_der_hex(keys.ml_kem().public_key_der_hex()).expect(case.name);
        let ml_kem_salt = crypto::random_bytes(32).expect(case.name);
        let ml_kem_encapsulation =
            crypto::encapsulate_ml_kem_shared_key(&ml_kem_public_key, &ml_kem_salt, 32)
                .expect(case.name);
        let ml_kem_decapsulated = crypto::decapsulate_ml_kem_shared_key(
            &ml_kem_private_key,
            &ml_kem_encapsulation.encapsulated_key,
            &ml_kem_salt,
            32,
        )
        .expect(case.name);
        assert_eq!(
            ml_kem_encapsulation.shared_key, ml_kem_decapsulated,
            "{}",
            case.name
        );

        let mut hybrid_secret = Vec::new();
        hybrid_secret.extend_from_slice(&sender_xecdh_shared);
        hybrid_secret.extend_from_slice(&ml_kem_encapsulation.shared_key);

        let cipher = crypto::symmetric_cipher(keys.symmetric().variant()).expect(case.name);
        let hkdf_salt = crypto::random_bytes(32).expect(case.name);
        let hkdf_info = format!("crypto-integration:{}", case.name);
        let message_key = crypto::hkdf_sha256(
            &hybrid_secret,
            &hkdf_salt,
            hkdf_info.as_bytes(),
            cipher.key_size_bytes,
        )
        .expect(case.name);
        let nonce = crypto::random_bytes(cipher.nonce_size_bytes).expect(case.name);
        let aad = format!(
            "version=v1;type=crypto-integration;profile={};cipher={}",
            case.name, cipher.algorithm
        );
        let plaintext = format!("hello from {}", case.name);
        let ciphertext = crypto::encrypt_symmetric(
            cipher.algorithm,
            &plaintext,
            &message_key,
            &nonce,
            aad.as_bytes(),
        )
        .expect(case.name);
        let decrypted = crypto::decrypt_symmetric(
            cipher.algorithm,
            &ciphertext,
            &message_key,
            &nonce,
            aad.as_bytes(),
        )
        .expect(case.name);

        assert_eq!(decrypted, plaintext.as_bytes(), "{}", case.name);
    }
}

#[test]
fn corrupt_public_material_fails_cleanly() {
    assert!(crypto::validate_der_public_key_hex("public_key_der_hex", "aa").is_err());
    assert!(
        crypto::validate_x_key_agreement_public_key_hex("public_key_hex", "X25519", "aa").is_err()
    );
    assert!(crypto::validate_ml_kem_public_key_hex("ml_kem_public_key_der_hex", "aa", 32).is_err());
}

#[test]
fn aead_rejects_tampered_inputs() {
    for case in PROFILE_CASES {
        let cipher = crypto::symmetric_cipher(case.symmetric).expect(case.name);
        let key = crypto::random_bytes(cipher.key_size_bytes).expect(case.name);
        let nonce = crypto::random_bytes(cipher.nonce_size_bytes).expect(case.name);
        let aad = b"version=v1;type=aead-negative";
        let plaintext = "authentic message";
        let ciphertext = crypto::encrypt_symmetric(cipher.algorithm, plaintext, &key, &nonce, aad)
            .expect(case.name);

        assert!(
            crypto::decrypt_symmetric(cipher.algorithm, &ciphertext, &key, &nonce, aad).is_ok(),
            "{} baseline decrypt",
            case.name
        );

        let mut tampered = ciphertext.clone();
        tampered[0] ^= 0x01;
        assert!(
            crypto::decrypt_symmetric(cipher.algorithm, &tampered, &key, &nonce, aad).is_err(),
            "{} tampered ciphertext",
            case.name
        );

        let wrong_key = crypto::random_bytes(cipher.key_size_bytes).expect(case.name);
        assert!(
            crypto::decrypt_symmetric(cipher.algorithm, &ciphertext, &wrong_key, &nonce, aad)
                .is_err(),
            "{} wrong key",
            case.name
        );

        let mut wrong_nonce = nonce.clone();
        wrong_nonce[0] ^= 0x01;
        assert!(
            crypto::decrypt_symmetric(cipher.algorithm, &ciphertext, &key, &wrong_nonce, aad)
                .is_err(),
            "{} wrong nonce",
            case.name
        );

        let wrong_aad = b"version=v1;type=different";
        assert!(
            crypto::decrypt_symmetric(cipher.algorithm, &ciphertext, &key, &nonce, wrong_aad)
                .is_err(),
            "{} wrong aad",
            case.name
        );
    }
}

fn is_verified<E>(result: Result<bool, E>) -> bool {
    matches!(result, Ok(true))
}

#[test]
fn signatures_reject_tampering() {
    let message = "signed by vectis";
    for case in PROFILE_CASES {
        let material = create_profile_material(case);
        let keys = material.keys();

        let eddsa_private =
            crypto::load_private_key_der_hex(keys.eddsa().private_key_der_hex()).expect(case.name);
        let eddsa_public =
            crypto::load_public_key_der_hex(keys.eddsa().public_key_der_hex()).expect(case.name);
        let eddsa_sig = crypto::sign_message(&eddsa_private, message).expect(case.name);
        assert!(
            is_verified(crypto::verify_message(&eddsa_public, message, &eddsa_sig)),
            "{} eddsa valid",
            case.name
        );
        assert!(
            !is_verified(crypto::verify_message(
                &eddsa_public,
                "tampered message",
                &eddsa_sig
            )),
            "{} eddsa tampered message",
            case.name
        );
        let mut bad_eddsa_sig = eddsa_sig.clone();
        bad_eddsa_sig[0] ^= 0x01;
        assert!(
            !is_verified(crypto::verify_message(
                &eddsa_public,
                message,
                &bad_eddsa_sig
            )),
            "{} eddsa tampered signature",
            case.name
        );

        let ml_dsa_private =
            crypto::load_private_key_der_hex(keys.ml_dsa().private_key_der_hex()).expect(case.name);
        let ml_dsa_public =
            crypto::load_public_key_der_hex(keys.ml_dsa().public_key_der_hex()).expect(case.name);
        let ml_dsa_sig = crypto::sign_ml_dsa_message(&ml_dsa_private, message).expect(case.name);
        assert!(
            is_verified(crypto::verify_ml_dsa_message(
                &ml_dsa_public,
                message,
                &ml_dsa_sig
            )),
            "{} ml-dsa valid",
            case.name
        );
        assert!(
            !is_verified(crypto::verify_ml_dsa_message(
                &ml_dsa_public,
                "tampered message",
                &ml_dsa_sig
            )),
            "{} ml-dsa tampered message",
            case.name
        );
        let mut bad_ml_dsa_sig = ml_dsa_sig.clone();
        bad_ml_dsa_sig[0] ^= 0x01;
        assert!(
            !is_verified(crypto::verify_ml_dsa_message(
                &ml_dsa_public,
                message,
                &bad_ml_dsa_sig
            )),
            "{} ml-dsa tampered signature",
            case.name
        );
    }
}

#[test]
fn ml_kem_decapsulation_rejects_wrong_ciphertext() {
    for case in PROFILE_CASES {
        let material = create_profile_material(case);
        let keys = material.keys();
        let public_key =
            crypto::load_public_key_der_hex(keys.ml_kem().public_key_der_hex()).expect(case.name);
        let private_key =
            crypto::load_private_key_der_hex(keys.ml_kem().private_key_der_hex()).expect(case.name);
        let salt = crypto::random_bytes(32).expect(case.name);
        let encapsulation =
            crypto::encapsulate_ml_kem_shared_key(&public_key, &salt, 32).expect(case.name);

        let good = crypto::decapsulate_ml_kem_shared_key(
            &private_key,
            &encapsulation.encapsulated_key,
            &salt,
            32,
        )
        .expect(case.name);
        assert_eq!(good, encapsulation.shared_key, "{}", case.name);

        let mut wrong_ciphertext = encapsulation.encapsulated_key.clone();
        wrong_ciphertext[0] ^= 0x01;
        // Tampered ciphertext must not recover the original shared secret; ML-KEM
        // implicit rejection yields a different key, and a hard error is also fine.
        if let Ok(shared) =
            crypto::decapsulate_ml_kem_shared_key(&private_key, &wrong_ciphertext, &salt, 32)
        {
            assert_ne!(shared, encapsulation.shared_key, "{}", case.name);
        }
    }
}

fn assert_variant_valid(value: &Value, field: &str, variant: &str, case_name: &str) {
    assert_eq!(value[field]["variant"], variant, "{case_name}");
    assert_eq!(value[field]["valid"], true, "{case_name}");
}
