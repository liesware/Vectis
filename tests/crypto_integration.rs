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

fn assert_variant_valid(value: &Value, field: &str, variant: &str, case_name: &str) {
    assert_eq!(value[field]["variant"], variant, "{case_name}");
    assert_eq!(value[field]["valid"], true, "{case_name}");
}
