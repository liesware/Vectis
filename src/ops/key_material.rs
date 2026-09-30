use crate::core::{config, crypto};
use crate::error::DynError;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Clone, Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
pub struct KeyMaterialOutput {
    #[zeroize(skip)]
    pub(crate) hash: VariantHash,
    pub(crate) keys: KeyMaterialKeys,
}

#[derive(Clone, Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
pub struct KeyMaterialKeys {
    pub(crate) symmetric: VariantSymmetricKey,
    pub(crate) eddsa: VariantDerKeyPair,
    pub(crate) xecdh: VariantKeyAgreementKeyPair,
    #[serde(rename = "ml-dsa")]
    pub(crate) ml_dsa: VariantDerKeyPair,
    #[serde(rename = "ml-kem")]
    pub(crate) ml_kem: VariantDerKeyPair,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct VariantHash {
    pub(crate) variant: String,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct VariantSymmetricKey {
    pub(crate) variant: String,
    pub(crate) key_hex: String,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct VariantKeyAgreementKeyPair {
    pub(crate) variant: String,
    pub(crate) private_key_der_hex: String,
    pub(crate) public_key_hex: String,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct VariantDerKeyPair {
    pub(crate) variant: String,
    pub(crate) private_key_der_hex: String,
    pub(crate) public_key_der_hex: String,
}

pub struct KeyMaterialSpec {
    pub(crate) hash_algorithm: String,
    pub(crate) symmetric_algorithm: String,
    pub(crate) eddsa_algorithm: String,
    pub(crate) xecdh_algorithm: String,
    pub(crate) ml_dsa_variant: String,
    pub(crate) ml_kem_variant: String,
}

impl KeyMaterialSpec {
    pub fn new(
        hash_algorithm: impl Into<String>,
        symmetric_algorithm: impl Into<String>,
        eddsa_algorithm: impl Into<String>,
        xecdh_algorithm: impl Into<String>,
        ml_dsa_variant: impl Into<String>,
        ml_kem_variant: impl Into<String>,
    ) -> Self {
        Self {
            hash_algorithm: hash_algorithm.into(),
            symmetric_algorithm: symmetric_algorithm.into(),
            eddsa_algorithm: eddsa_algorithm.into(),
            xecdh_algorithm: xecdh_algorithm.into(),
            ml_dsa_variant: ml_dsa_variant.into(),
            ml_kem_variant: ml_kem_variant.into(),
        }
    }

    pub(crate) fn internal_keys() -> Self {
        Self {
            hash_algorithm: config::INTERNAL_KEYS_HASH.to_string(),
            symmetric_algorithm: config::INTERNAL_KEYS_CIPHER.to_string(),
            eddsa_algorithm: config::INTERNAL_KEYS_EDDSA_ALGORITHM.to_string(),
            xecdh_algorithm: config::INTERNAL_KEYS_XECDH_ALGORITHM.to_string(),
            ml_dsa_variant: config::INTERNAL_KEYS_ML_DSA_VARIANT.to_string(),
            ml_kem_variant: config::INTERNAL_KEYS_ML_KEM_VARIANT.to_string(),
        }
    }
}

impl Zeroize for VariantSymmetricKey {
    fn zeroize(&mut self) {
        self.key_hex.zeroize();
    }
}

impl Drop for VariantSymmetricKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for VariantSymmetricKey {}

impl Zeroize for VariantDerKeyPair {
    fn zeroize(&mut self) {
        self.private_key_der_hex.zeroize();
        self.public_key_der_hex.zeroize();
    }
}

impl Drop for VariantDerKeyPair {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for VariantDerKeyPair {}

impl Zeroize for VariantKeyAgreementKeyPair {
    fn zeroize(&mut self) {
        self.private_key_der_hex.zeroize();
        self.public_key_hex.zeroize();
    }
}

impl Drop for VariantKeyAgreementKeyPair {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for VariantKeyAgreementKeyPair {}

impl KeyMaterialOutput {
    pub fn hash_variant(&self) -> &str {
        &self.hash.variant
    }

    pub fn keys(&self) -> &KeyMaterialKeys {
        &self.keys
    }
}

impl KeyMaterialKeys {
    pub fn symmetric(&self) -> &VariantSymmetricKey {
        &self.symmetric
    }

    pub fn eddsa(&self) -> &VariantDerKeyPair {
        &self.eddsa
    }

    pub fn xecdh(&self) -> &VariantKeyAgreementKeyPair {
        &self.xecdh
    }

    pub fn ml_dsa(&self) -> &VariantDerKeyPair {
        &self.ml_dsa
    }

    pub fn ml_kem(&self) -> &VariantDerKeyPair {
        &self.ml_kem
    }
}

impl VariantSymmetricKey {
    pub fn variant(&self) -> &str {
        &self.variant
    }

    pub fn key_hex(&self) -> &str {
        &self.key_hex
    }
}

impl VariantDerKeyPair {
    pub fn variant(&self) -> &str {
        &self.variant
    }

    pub fn private_key_der_hex(&self) -> &str {
        &self.private_key_der_hex
    }

    pub fn public_key_der_hex(&self) -> &str {
        &self.public_key_der_hex
    }
}

impl VariantKeyAgreementKeyPair {
    pub fn variant(&self) -> &str {
        &self.variant
    }

    pub fn private_key_der_hex(&self) -> &str {
        &self.private_key_der_hex
    }

    pub fn public_key_hex(&self) -> &str {
        &self.public_key_hex
    }
}

pub fn create_key_material(spec: &KeyMaterialSpec) -> Result<KeyMaterialOutput, DynError> {
    let symmetric_cipher =
        crypto::symmetric_cipher(&spec.symmetric_algorithm).ok_or_else(|| {
            crate::error::invalid_input(format!(
                "invalid symmetric algorithm: {}",
                spec.symmetric_algorithm
            ))
        })?;
    let mut rng = crypto::new_rng()?;
    let symmetric_key = Zeroizing::new(crypto::random_bytes_with_rng(
        &mut rng,
        symmetric_cipher.key_size_bytes,
    )?);

    let eddsa_private_key =
        crypto::create_eddsa_private_key_with_rng(&mut rng, &spec.eddsa_algorithm)?;
    let eddsa_public_key = crypto::public_key(&eddsa_private_key)?;

    let xecdh_private_key =
        crypto::create_x_key_agreement_private_key_with_rng(&mut rng, &spec.xecdh_algorithm)?;
    let xecdh_public_key = crypto::key_agreement_public_key(&xecdh_private_key)?;

    let ml_dsa_variant =
        crypto::MlDsaVariant::from_name(&spec.ml_dsa_variant).ok_or_else(|| {
            crate::error::invalid_input(format!("invalid ml_dsa_variant: {}", spec.ml_dsa_variant))
        })?;
    let ml_dsa_private_key = crypto::create_ml_dsa_private_key_with_rng(&mut rng, &ml_dsa_variant)?;
    let ml_dsa_public_key = crypto::public_key(&ml_dsa_private_key)?;

    let ml_kem_variant =
        crypto::MlKemVariant::from_name(&spec.ml_kem_variant).ok_or_else(|| {
            crate::error::invalid_input(format!("invalid ml_kem_variant: {}", spec.ml_kem_variant))
        })?;
    let ml_kem_private_key = crypto::create_ml_kem_private_key_with_rng(&mut rng, &ml_kem_variant)?;
    let ml_kem_public_key = crypto::public_key(&ml_kem_private_key)?;

    Ok(KeyMaterialOutput {
        hash: VariantHash {
            variant: spec.hash_algorithm.clone(),
        },
        keys: KeyMaterialKeys {
            symmetric: VariantSymmetricKey {
                variant: spec.symmetric_algorithm.clone(),
                key_hex: hex::encode(&*symmetric_key),
            },
            eddsa: VariantDerKeyPair {
                variant: spec.eddsa_algorithm.clone(),
                private_key_der_hex: crypto::private_key_der_hex(&eddsa_private_key)?,
                public_key_der_hex: hex::encode(crypto::public_key_der(&eddsa_public_key)?),
            },
            xecdh: VariantKeyAgreementKeyPair {
                variant: spec.xecdh_algorithm.clone(),
                private_key_der_hex: crypto::private_key_der_hex(&xecdh_private_key)?,
                public_key_hex: hex::encode(xecdh_public_key),
            },
            ml_dsa: VariantDerKeyPair {
                variant: ml_dsa_variant.name().to_string(),
                private_key_der_hex: crypto::private_key_der_hex(&ml_dsa_private_key)?,
                public_key_der_hex: hex::encode(crypto::public_key_der(&ml_dsa_public_key)?),
            },
            ml_kem: VariantDerKeyPair {
                variant: ml_kem_variant.name().to_string(),
                private_key_der_hex: crypto::private_key_der_hex(&ml_kem_private_key)?,
                public_key_der_hex: hex::encode(crypto::public_key_der(&ml_kem_public_key)?),
            },
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_key_material() -> KeyMaterialOutput {
        KeyMaterialOutput {
            hash: VariantHash {
                variant: String::from("SHA-512"),
            },
            keys: KeyMaterialKeys {
                symmetric: VariantSymmetricKey {
                    variant: String::from("AES-256/GCM"),
                    key_hex: String::from("0011"),
                },
                eddsa: VariantDerKeyPair {
                    variant: String::from("Ed25519"),
                    private_key_der_hex: String::from("1122"),
                    public_key_der_hex: String::from("3344"),
                },
                xecdh: VariantKeyAgreementKeyPair {
                    variant: String::from("X25519"),
                    private_key_der_hex: String::from("5566"),
                    public_key_hex: String::from("7788"),
                },
                ml_dsa: VariantDerKeyPair {
                    variant: String::from("ML-DSA-44"),
                    private_key_der_hex: String::from("99aa"),
                    public_key_der_hex: String::from("bbcc"),
                },
                ml_kem: VariantDerKeyPair {
                    variant: String::from("ML-KEM-512"),
                    private_key_der_hex: String::from("ddee"),
                    public_key_der_hex: String::from("ff00"),
                },
            },
        }
    }

    #[test]
    fn secret_key_material_is_zeroize_on_drop() {
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

        assert_zeroize_on_drop::<VariantSymmetricKey>();
        assert_zeroize_on_drop::<VariantDerKeyPair>();
        assert_zeroize_on_drop::<VariantKeyAgreementKeyPair>();
        assert_zeroize_on_drop::<KeyMaterialKeys>();
        assert_zeroize_on_drop::<KeyMaterialOutput>();
    }

    #[test]
    fn zeroize_clears_all_key_material_fields() {
        let mut material = sample_key_material();

        material.zeroize();

        assert!(material.keys.symmetric.key_hex.is_empty());
        assert!(material.keys.eddsa.private_key_der_hex.is_empty());
        assert!(material.keys.eddsa.public_key_der_hex.is_empty());
        assert!(material.keys.xecdh.private_key_der_hex.is_empty());
        assert!(material.keys.xecdh.public_key_hex.is_empty());
        assert!(material.keys.ml_dsa.private_key_der_hex.is_empty());
        assert!(material.keys.ml_dsa.public_key_der_hex.is_empty());
        assert!(material.keys.ml_kem.private_key_der_hex.is_empty());
        assert!(material.keys.ml_kem.public_key_der_hex.is_empty());

        assert_eq!(material.hash.variant, "SHA-512");
        assert_eq!(material.keys.symmetric.variant, "AES-256/GCM");
        assert_eq!(material.keys.eddsa.variant, "Ed25519");
        assert_eq!(material.keys.xecdh.variant, "X25519");
        assert_eq!(material.keys.ml_dsa.variant, "ML-DSA-44");
        assert_eq!(material.keys.ml_kem.variant, "ML-KEM-512");
    }

    #[test]
    fn cloned_key_material_has_independent_ownership() {
        let mut original = sample_key_material();
        let cloned = original.clone();

        original.zeroize();

        assert_eq!(cloned.keys.symmetric.key_hex(), "0011");
        assert_eq!(cloned.keys.eddsa.private_key_der_hex(), "1122");
        assert_eq!(cloned.keys.xecdh.private_key_der_hex(), "5566");
        assert_eq!(cloned.keys.ml_dsa.private_key_der_hex(), "99aa");
        assert_eq!(cloned.keys.ml_kem.private_key_der_hex(), "ddee");
    }

    #[test]
    fn key_material_json_contract_is_unchanged() {
        let material = sample_key_material();
        let serialized = serde_json::to_string(&material).expect("key material must serialize");

        assert_eq!(
            serialized,
            r#"{"hash":{"variant":"SHA-512"},"keys":{"symmetric":{"variant":"AES-256/GCM","key_hex":"0011"},"eddsa":{"variant":"Ed25519","private_key_der_hex":"1122","public_key_der_hex":"3344"},"xecdh":{"variant":"X25519","private_key_der_hex":"5566","public_key_hex":"7788"},"ml-dsa":{"variant":"ML-DSA-44","private_key_der_hex":"99aa","public_key_der_hex":"bbcc"},"ml-kem":{"variant":"ML-KEM-512","private_key_der_hex":"ddee","public_key_der_hex":"ff00"}}}"#
        );

        let deserialized: KeyMaterialOutput =
            serde_json::from_str(&serialized).expect("key material must deserialize");
        let round_trip =
            serde_json::to_string(&deserialized).expect("key material must reserialize");

        assert_eq!(round_trip, serialized);
    }
}
