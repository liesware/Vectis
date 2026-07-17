use crate::core::config;
use crate::error::DynError;
use botan::{Cipher, CipherDirection, MsgAuthCode};
use botan::{
    HashFunction, KeyDecapsulation, KeyEncapsulation, Privkey, Pubkey, RandomNumberGenerator,
    Signer, Verifier,
};
use zeroize::Zeroizing;

pub type CryptoRng = RandomNumberGenerator;

pub fn new_rng() -> Result<CryptoRng, botan::Error> {
    RandomNumberGenerator::new()
}

pub fn random_bytes(size: usize) -> Result<Vec<u8>, botan::Error> {
    let mut rng = new_rng()?;

    random_bytes_with_rng(&mut rng, size)
}

pub fn random_bytes_with_rng(rng: &mut CryptoRng, size: usize) -> Result<Vec<u8>, botan::Error> {
    rng.read(size)
}

pub const HASH_ALGORITHMS: &[&str] = &[
    "BLAKE2b(160)",
    "BLAKE2b(224)",
    "BLAKE2b(256)",
    "BLAKE2b(384)",
    "BLAKE2b(512)",
    "SHA-224",
    "SHA-256",
    "SHA-384",
    "SHA-512",
    "SHA-512-256",
    "SHA-3(224)",
    "SHA-3(256)",
    "SHA-3(384)",
    "SHA-3(512)",
    "Whirlpool",
];

pub fn hash_text(algorithm: &str, message: &str) -> Result<Vec<u8>, botan::Error> {
    hash_bytes(algorithm, message.as_bytes())
}

pub fn hash_bytes(algorithm: &str, message: &[u8]) -> Result<Vec<u8>, botan::Error> {
    let mut hash = HashFunction::new(algorithm)?;
    hash.update(message)?;

    hash.finish()
}

pub fn create_hkdf(
    input_key_material: &[u8],
    salt: &[u8],
    info: &[u8],
    output_len: usize,
) -> Result<Vec<u8>, botan::Error> {
    botan::kdf(
        config::INTERNAL_KEYS_HKDF,
        output_len,
        input_key_material,
        salt,
        info,
    )
}

pub fn create_hmac(key: &[u8], message: &[u8]) -> Result<Vec<u8>, botan::Error> {
    create_hmac_with_algorithm(config::INTERNAL_KEYS_HMAC, key, message)
}

pub fn create_hmac_with_algorithm(
    algorithm: &str,
    key: &[u8],
    message: &[u8],
) -> Result<Vec<u8>, botan::Error> {
    let mut mac = MsgAuthCode::new(algorithm)?;
    mac.set_key(key)?;
    mac.update(message)?;

    mac.finish()
}

pub fn create_kmac_with_algorithm(
    algorithm: &str,
    key: &[u8],
    customization: &[u8],
    message: &[u8],
) -> Result<Vec<u8>, botan::Error> {
    let mut mac = MsgAuthCode::new(algorithm)?;
    mac.set_key(key)?;
    mac.set_nonce(customization)?;
    mac.update(message)?;

    mac.finish()
}

pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }

    let mut diff = 0u8;
    for (left, right) in left.iter().zip(right.iter()) {
        diff |= left ^ right;
    }

    diff == 0
}

pub fn encrypt_symmetric(
    algorithm: &str,
    message: &str,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, botan::Error> {
    let mut encryptor = Cipher::new(algorithm, CipherDirection::Encrypt)?;
    encryptor.set_key(key)?;
    encryptor.set_associated_data(aad)?;

    let ciphertext = encryptor.process(nonce, message.as_bytes())?;

    Ok(ciphertext)
}

pub fn decrypt_symmetric(
    algorithm: &str,
    ciphertext: &[u8],
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, botan::Error> {
    let mut decryptor = Cipher::new(algorithm, CipherDirection::Decrypt)?;
    decryptor.set_key(key)?;
    decryptor.set_associated_data(aad)?;

    let plaintext = decryptor.process(nonce, ciphertext)?;

    Ok(plaintext)
}

pub struct SymmetricCipherSpec {
    pub algorithm: &'static str,
    pub key_size_bytes: usize,
    pub nonce_size_bytes: usize,
}

pub const SYMMETRIC_ALGORITHMS: &[&str] = &[
    "ChaCha20Poly1305",
    "AES-128/GCM",
    "AES-192/GCM",
    "AES-256/GCM",
];

pub fn symmetric_cipher(algorithm: &str) -> Option<SymmetricCipherSpec> {
    match algorithm {
        "ChaCha20Poly1305" => Some(SymmetricCipherSpec {
            algorithm: "ChaCha20Poly1305",
            key_size_bytes: 32,
            nonce_size_bytes: 24,
        }),
        "AES-128/GCM" => Some(SymmetricCipherSpec {
            algorithm: "AES-128/GCM",
            key_size_bytes: 16,
            nonce_size_bytes: 12,
        }),
        "AES-192/GCM" => Some(SymmetricCipherSpec {
            algorithm: "AES-192/GCM",
            key_size_bytes: 24,
            nonce_size_bytes: 12,
        }),
        "AES-256/GCM" => Some(SymmetricCipherSpec {
            algorithm: "AES-256/GCM",
            key_size_bytes: 32,
            nonce_size_bytes: 12,
        }),
        _ => None,
    }
}

const EDDSA_PADDING: &str = "Pure";

pub fn create_eddsa_private_key(algorithm: &str) -> Result<Privkey, botan::Error> {
    let mut rng = new_rng()?;

    create_eddsa_private_key_with_rng(&mut rng, algorithm)
}

pub fn create_eddsa_private_key_with_rng(
    rng: &mut CryptoRng,
    algorithm: &str,
) -> Result<Privkey, botan::Error> {
    Privkey::create(algorithm, "", rng)
}

pub fn public_key(private_key: &Privkey) -> Result<Pubkey, botan::Error> {
    private_key.pubkey()
}

pub fn public_key_der(public_key: &Pubkey) -> Result<Vec<u8>, botan::Error> {
    public_key.der_encode()
}

pub fn private_key_der(private_key: &Privkey) -> Result<Vec<u8>, botan::Error> {
    private_key.der_encode()
}

pub fn private_key_der_hex(private_key: &Privkey) -> Result<String, DynError> {
    let private_key_der = Zeroizing::new(private_key_der(private_key)?);

    Ok(hex::encode(&*private_key_der))
}

pub fn load_private_key_der(private_key_der: &[u8]) -> Result<Privkey, botan::Error> {
    Privkey::load_der(private_key_der)
}

pub fn load_public_key_der(public_key_der: &[u8]) -> Result<Pubkey, botan::Error> {
    Pubkey::load_der(public_key_der)
}

pub fn load_private_key_der_hex(private_key_der_hex: &str) -> Result<Privkey, DynError> {
    let private_key_der = Zeroizing::new(hex::decode(private_key_der_hex)?);

    Ok(load_private_key_der(&private_key_der)?)
}

pub fn load_public_key_der_hex(public_key_der_hex: &str) -> Result<Pubkey, DynError> {
    let public_key_der = hex::decode(public_key_der_hex)?;

    Ok(load_public_key_der(&public_key_der)?)
}

pub fn validate_der_public_key_hex(
    field_name: &str,
    public_key_der_hex: &str,
) -> Result<Pubkey, DynError> {
    load_public_key_der_hex(public_key_der_hex).map_err(|err| {
        crate::error::invalid_input(format!("{field_name} is not a valid public key: {err}"))
    })
}

pub fn sign_message(private_key: &Privkey, message: &str) -> Result<Vec<u8>, botan::Error> {
    let mut rng = new_rng()?;

    sign_message_with_rng(&mut rng, private_key, message)
}

pub fn sign_message_with_rng(
    rng: &mut CryptoRng,
    private_key: &Privkey,
    message: &str,
) -> Result<Vec<u8>, botan::Error> {
    let mut signer = Signer::new(private_key, EDDSA_PADDING)?;

    signer.update(message.as_bytes())?;
    signer.finish(rng)
}

pub fn verify_message(
    public_key: &Pubkey,
    message: &str,
    signature: &[u8],
) -> Result<bool, botan::Error> {
    let mut verifier = Verifier::new(public_key, EDDSA_PADDING)?;

    verifier.update(message.as_bytes())?;
    verifier.finish(signature)
}

const X_KEY_AGREEMENT_KDF: &str = "Raw";

pub fn create_x_key_agreement_private_key(algorithm: &str) -> Result<Privkey, botan::Error> {
    let mut rng = new_rng()?;

    create_x_key_agreement_private_key_with_rng(&mut rng, algorithm)
}

pub fn create_x_key_agreement_private_key_with_rng(
    rng: &mut CryptoRng,
    algorithm: &str,
) -> Result<Privkey, botan::Error> {
    Privkey::create(algorithm, "", rng)
}

pub fn key_agreement_public_key(private_key: &Privkey) -> Result<Vec<u8>, botan::Error> {
    private_key.key_agreement_key()
}

pub fn agree_key(private_key: &Privkey, peer_public_key: &[u8]) -> Result<Vec<u8>, botan::Error> {
    private_key.agree(peer_public_key, 0, &[], X_KEY_AGREEMENT_KDF)
}

pub fn validate_x_key_agreement_public_key_hex(
    field_name: &str,
    algorithm: &str,
    public_key_hex: &str,
) -> Result<Vec<u8>, DynError> {
    let public_key = hex::decode(public_key_hex)?;
    let expected_size = match algorithm {
        "X25519" => 32,
        "X448" => 56,
        _ => {
            return Err(crate::error::invalid_input(format!(
                "{field_name} algorithm is not supported"
            )));
        }
    };

    if public_key.len() != expected_size {
        return Err(crate::error::invalid_input(format!(
            "{field_name} must be {expected_size} bytes for {algorithm}, got {}",
            public_key.len()
        )));
    }

    Ok(public_key)
}

const ML_DSA_SIGNING_MODE: &str = "Randomized";
const ML_DSA_VERIFY_MODE: &str = "Pure";

#[allow(dead_code)]
pub enum MlDsaVariant {
    MlDsa44,
    MlDsa65,
    MlDsa87,
}

impl MlDsaVariant {
    pub fn from_name(name: &str) -> Option<Self> {
        match normalize_variant_name(name).as_str() {
            "ML-DSA-44" | "MLDSA44" | "ML-DSA-4X4" => Some(MlDsaVariant::MlDsa44),
            "ML-DSA-65" | "MLDSA65" | "ML-DSA-6X5" => Some(MlDsaVariant::MlDsa65),
            "ML-DSA-87" | "MLDSA87" | "ML-DSA-8X7" => Some(MlDsaVariant::MlDsa87),
            _ => None,
        }
    }

    pub fn botan_mode(&self) -> &'static str {
        match self {
            MlDsaVariant::MlDsa44 => "ML-DSA-4x4",
            MlDsaVariant::MlDsa65 => "ML-DSA-6x5",
            MlDsaVariant::MlDsa87 => "ML-DSA-8x7",
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            MlDsaVariant::MlDsa44 => "ML-DSA-44",
            MlDsaVariant::MlDsa65 => "ML-DSA-65",
            MlDsaVariant::MlDsa87 => "ML-DSA-87",
        }
    }
}

pub fn create_ml_dsa_private_key(variant: &MlDsaVariant) -> Result<Privkey, botan::Error> {
    let mut rng = new_rng()?;

    create_ml_dsa_private_key_with_rng(&mut rng, variant)
}

pub fn create_ml_dsa_private_key_with_rng(
    rng: &mut CryptoRng,
    variant: &MlDsaVariant,
) -> Result<Privkey, botan::Error> {
    Privkey::create("ML-DSA", variant.botan_mode(), rng)
}

pub fn sign_ml_dsa_message(private_key: &Privkey, message: &str) -> Result<Vec<u8>, botan::Error> {
    let mut rng = new_rng()?;

    sign_ml_dsa_message_with_rng(&mut rng, private_key, message)
}

pub fn sign_ml_dsa_message_with_rng(
    rng: &mut CryptoRng,
    private_key: &Privkey,
    message: &str,
) -> Result<Vec<u8>, botan::Error> {
    let mut signer = Signer::new(private_key, ML_DSA_SIGNING_MODE)?;

    signer.update(message.as_bytes())?;
    signer.finish(rng)
}

pub fn verify_ml_dsa_message(
    public_key: &Pubkey,
    message: &str,
    signature: &[u8],
) -> Result<bool, botan::Error> {
    let mut verifier = Verifier::new(public_key, ML_DSA_VERIFY_MODE)?;

    verifier.update(message.as_bytes())?;
    verifier.finish(signature)
}

const ML_KEM_KDF: &str = "KDF2(SHA-256)";

#[allow(dead_code)]
pub enum MlKemVariant {
    MlKem512,
    MlKem768,
    MlKem1024,
}

impl MlKemVariant {
    pub fn from_name(name: &str) -> Option<Self> {
        match normalize_variant_name(name).as_str() {
            "ML-KEM-512" | "MLKEM512" => Some(MlKemVariant::MlKem512),
            "ML-KEM-768" | "MLKEM768" => Some(MlKemVariant::MlKem768),
            "ML-KEM-1024" | "MLKEM1024" => Some(MlKemVariant::MlKem1024),
            _ => None,
        }
    }

    pub fn botan_mode(&self) -> &'static str {
        match self {
            MlKemVariant::MlKem512 => "ML-KEM-512",
            MlKemVariant::MlKem768 => "ML-KEM-768",
            MlKemVariant::MlKem1024 => "ML-KEM-1024",
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            MlKemVariant::MlKem512 => "ML-KEM-512",
            MlKemVariant::MlKem768 => "ML-KEM-768",
            MlKemVariant::MlKem1024 => "ML-KEM-1024",
        }
    }
}

fn normalize_variant_name(name: &str) -> String {
    name.trim().to_ascii_uppercase().replace('_', "-")
}

pub struct KemEncapsulation {
    pub shared_key: Vec<u8>,
    pub encapsulated_key: Vec<u8>,
}

pub fn create_ml_kem_private_key(variant: &MlKemVariant) -> Result<Privkey, botan::Error> {
    let mut rng = new_rng()?;

    create_ml_kem_private_key_with_rng(&mut rng, variant)
}

pub fn create_ml_kem_private_key_with_rng(
    rng: &mut CryptoRng,
    variant: &MlKemVariant,
) -> Result<Privkey, botan::Error> {
    Privkey::create("ML-KEM", variant.botan_mode(), rng)
}

pub fn encapsulate_ml_kem_shared_key(
    public_key: &Pubkey,
    salt: &[u8],
    shared_key_len: usize,
) -> Result<KemEncapsulation, botan::Error> {
    let mut rng = new_rng()?;

    encapsulate_ml_kem_shared_key_with_rng(&mut rng, public_key, salt, shared_key_len)
}

pub fn encapsulate_ml_kem_shared_key_with_rng(
    rng: &mut CryptoRng,
    public_key: &Pubkey,
    salt: &[u8],
    shared_key_len: usize,
) -> Result<KemEncapsulation, botan::Error> {
    let kem = KeyEncapsulation::new(public_key, ML_KEM_KDF)?;
    let (shared_key, encapsulated_key) = kem.create_shared_key(rng, salt, shared_key_len)?;

    Ok(KemEncapsulation {
        shared_key,
        encapsulated_key,
    })
}

pub fn validate_ml_kem_public_key_hex(
    field_name: &str,
    public_key_der_hex: &str,
    shared_key_len: usize,
) -> Result<(), DynError> {
    let public_key = validate_der_public_key_hex(field_name, public_key_der_hex)?;
    let salt = Zeroizing::new(random_bytes(32)?);
    encapsulate_ml_kem_shared_key(&public_key, &salt, shared_key_len).map_err(|err| {
        crate::error::invalid_input(format!("{field_name} cannot encapsulate: {err}"))
    })?;

    Ok(())
}

pub fn decapsulate_ml_kem_shared_key(
    private_key: &Privkey,
    encapsulated_key: &[u8],
    salt: &[u8],
    shared_key_len: usize,
) -> Result<Vec<u8>, botan::Error> {
    let kem = KeyDecapsulation::new(private_key, ML_KEM_KDF)?;

    kem.decrypt_shared_key(encapsulated_key, salt, shared_key_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_hkdf_uses_internal_hkdf_constant() {
        let input = b"input key material";
        let salt = b"salt";
        let info = b"info";
        let actual = create_hkdf(input, salt, info, 32).expect("hkdf must derive");
        let expected = botan::kdf(config::INTERNAL_KEYS_HKDF, 32, input, salt, info)
            .expect("hkdf must derive");

        assert_eq!(actual, expected);
    }

    #[test]
    fn create_hmac_uses_internal_hmac_constant() {
        let key = b"0123456789abcdef0123456789abcdef";
        let message = b"message";
        let actual = create_hmac(key, message).expect("hmac must sign");
        assert_eq!(actual.len(), 32);

        let mut mac = MsgAuthCode::new(config::INTERNAL_KEYS_HMAC).expect("hmac must create");
        mac.set_key(key).expect("hmac key must set");
        mac.update(message).expect("hmac message must update");
        let expected = mac.finish().expect("hmac must finish");

        assert_eq!(actual, expected);
    }

    #[test]
    fn create_kmac_with_algorithm_uses_supplied_algorithm_and_customization() {
        let key = b"0123456789abcdef0123456789abcdef";
        let customization = b"vectis:test:kmac:v1";
        let message = b"message";
        let algorithm = "KMAC-256(384)";
        let actual = create_kmac_with_algorithm(algorithm, key, customization, message)
            .expect("kmac must sign");
        assert_eq!(actual.len(), 48);

        let mut mac = MsgAuthCode::new(algorithm).expect("kmac must create");
        mac.set_key(key).expect("kmac key must set");
        mac.set_nonce(customization)
            .expect("kmac customization must set");
        mac.update(message).expect("kmac message must update");
        let expected = mac.finish().expect("kmac must finish");

        assert_eq!(actual, expected);
    }

    #[test]
    fn create_kmac_supports_requested_output_sizes() {
        let key = b"0123456789abcdef0123456789abcdef";
        let customization = b"vectis:test:kmac:v1";
        let message = b"message";

        for (output_bits, output_bytes) in [(224, 28), (256, 32), (384, 48), (512, 64)] {
            let algorithm = format!("KMAC-256({output_bits})");
            let actual = create_kmac_with_algorithm(&algorithm, key, customization, message)
                .expect("kmac must sign");
            assert_eq!(actual.len(), output_bytes);
        }
    }

    #[test]
    fn create_kmac_binds_customization_and_message() {
        let key = b"0123456789abcdef0123456789abcdef";
        let customization = b"vectis:test:kmac:v1";
        let message = b"message";
        let algorithm = "KMAC-256(256)";

        let baseline = create_kmac_with_algorithm(algorithm, key, customization, message)
            .expect("kmac must sign");
        let repeated = create_kmac_with_algorithm(algorithm, key, customization, message)
            .expect("kmac must sign");
        let different_customization =
            create_kmac_with_algorithm(algorithm, key, b"vectis:test:other:v1", message)
                .expect("kmac must sign");
        let different_message =
            create_kmac_with_algorithm(algorithm, key, customization, b"other message")
                .expect("kmac must sign");

        assert_eq!(baseline, repeated);
        assert_ne!(baseline, different_customization);
        assert_ne!(baseline, different_message);
    }
}
