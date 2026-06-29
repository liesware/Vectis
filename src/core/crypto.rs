use crate::error::DynError;
use botan::{Cipher, CipherDirection, MsgAuthCode};
use botan::{
    HashFunction, KeyDecapsulation, KeyEncapsulation, Privkey, Pubkey, RandomNumberGenerator,
    Signer, Verifier,
};
use zeroize::Zeroizing;

pub fn random_bytes(size: usize) -> Result<Vec<u8>, botan::Error> {
    let mut rng = RandomNumberGenerator::new()?;
    let random = rng.read(size)?;

    Ok(random)
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

pub fn hkdf_sha256(
    input_key_material: &[u8],
    salt: &[u8],
    info: &[u8],
    output_len: usize,
) -> Result<Vec<u8>, botan::Error> {
    botan::kdf("HKDF(SHA-256)", output_len, input_key_material, salt, info)
}

pub fn hmac_sha256(key: &[u8], message: &[u8]) -> Result<Vec<u8>, botan::Error> {
    let mut mac = MsgAuthCode::new("HMAC(SHA-256)")?;
    mac.set_key(key)?;
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
    let mut rng = RandomNumberGenerator::new()?;

    Privkey::create(algorithm, "", &mut rng)
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

pub fn sign_message(private_key: &Privkey, message: &str) -> Result<Vec<u8>, botan::Error> {
    let mut rng = RandomNumberGenerator::new()?;
    let mut signer = Signer::new(private_key, EDDSA_PADDING)?;

    signer.update(message.as_bytes())?;
    signer.finish(&mut rng)
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
    let mut rng = RandomNumberGenerator::new()?;

    Privkey::create(algorithm, "", &mut rng)
}

pub fn key_agreement_public_key(private_key: &Privkey) -> Result<Vec<u8>, botan::Error> {
    private_key.key_agreement_key()
}

pub fn agree_key(private_key: &Privkey, peer_public_key: &[u8]) -> Result<Vec<u8>, botan::Error> {
    private_key.agree(peer_public_key, 0, &[], X_KEY_AGREEMENT_KDF)
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
    let mut rng = RandomNumberGenerator::new()?;

    Privkey::create("ML-DSA", variant.botan_mode(), &mut rng)
}

pub fn sign_ml_dsa_message(private_key: &Privkey, message: &str) -> Result<Vec<u8>, botan::Error> {
    let mut rng = RandomNumberGenerator::new()?;
    let mut signer = Signer::new(private_key, ML_DSA_SIGNING_MODE)?;

    signer.update(message.as_bytes())?;
    signer.finish(&mut rng)
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
    let mut rng = RandomNumberGenerator::new()?;

    Privkey::create("ML-KEM", variant.botan_mode(), &mut rng)
}

pub fn encapsulate_ml_kem_shared_key(
    public_key: &Pubkey,
    salt: &[u8],
    shared_key_len: usize,
) -> Result<KemEncapsulation, botan::Error> {
    let mut rng = RandomNumberGenerator::new()?;
    let kem = KeyEncapsulation::new(public_key, ML_KEM_KDF)?;
    let (shared_key, encapsulated_key) = kem.create_shared_key(&mut rng, salt, shared_key_len)?;

    Ok(KemEncapsulation {
        shared_key,
        encapsulated_key,
    })
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
