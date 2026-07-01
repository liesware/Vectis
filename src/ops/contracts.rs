use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct SignInput {
    pub message_hash: MessageHash,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct MessageHash {
    pub alg: String,
    pub hex: String,
}

#[derive(Deserialize, Serialize)]
pub struct TimestampToken {
    pub(crate) version: String,
    pub(crate) payload: TimestampPayload,
    pub(crate) signatures: TimestampSignatures,
}

impl TimestampToken {
    pub fn kid(&self) -> &str {
        &self.payload.kid
    }
}

#[derive(Deserialize, Serialize)]
pub(crate) struct TimestampPayload {
    pub(crate) version: String,
    #[serde(rename = "type")]
    pub(crate) token_type: String,
    pub(crate) created_at: String,
    pub(crate) info: String,
    pub(crate) kid: String,
    pub(crate) serial: String,
    pub(crate) message_hash: MessageHash,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct TimestampSignatures {
    pub(crate) eddsa: SignatureBlock,
    #[serde(rename = "ml-dsa")]
    pub(crate) ml_dsa: SignatureBlock,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct SignatureBlock {
    pub(crate) alg: String,
    pub(crate) sig: String,
}

#[derive(Serialize)]
pub struct VerificationOutput {
    pub(crate) status: VerificationStatus,
    pub(crate) valid: String,
}

#[derive(Serialize)]
pub(crate) struct VerificationStatus {
    pub(crate) eddsa: String,
    #[serde(rename = "ml-dsa")]
    pub(crate) ml_dsa: String,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct PublicKeysOutput {
    pub(crate) info: String,
    pub(crate) keys: PublicKeys,
}

#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct PublicKeys {
    pub(crate) eddsa: PublicDerKey,
    pub(crate) xecdh: PublicRawKey,
    #[serde(rename = "ml-dsa")]
    pub(crate) ml_dsa: PublicDerKey,
    #[serde(rename = "ml-kem")]
    pub(crate) ml_kem: PublicDerKey,
}

#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct PublicDerKey {
    pub(crate) alg: String,
    pub(crate) public_key_der_hex: String,
}

#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct PublicRawKey {
    pub(crate) alg: String,
    pub(crate) public_key_hex: String,
}

#[derive(Deserialize)]
pub struct SendMessageInput {
    pub recipient_kid: String,
    pub message: String,
}

#[derive(Deserialize, Serialize)]
pub struct ProtectedMessageToken {
    pub(crate) version: String,
    pub(crate) payload: ProtectedMessagePayload,
    pub(crate) signatures: TimestampSignatures,
}

impl ProtectedMessageToken {
    pub fn sender_host(&self) -> &str {
        &self.payload.sender.host
    }

    pub fn sender_kid(&self) -> &str {
        &self.payload.sender.kid
    }

    pub fn recipient_kid(&self) -> &str {
        &self.payload.recipient.kid
    }
}

#[derive(Deserialize, Serialize)]
pub(crate) struct ProtectedMessagePayload {
    pub(crate) version: String,
    #[serde(rename = "type")]
    pub(crate) token_type: String,
    pub(crate) created_at: String,
    pub(crate) sender: MessageSender,
    pub(crate) recipient: MessageRecipient,
    pub(crate) kem: MessageKem,
    pub(crate) cipher: MessageCipher,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct MessageSender {
    pub(crate) host: String,
    pub(crate) kid: String,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct MessageRecipient {
    pub(crate) kid: String,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct MessageKem {
    pub(crate) alg: String,
    pub(crate) xecdh_ephemeral_public: String,
    pub(crate) ml_kem_ciphertext: String,
    pub(crate) ml_kem_salt: String,
    pub(crate) hkdf_salt: String,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct MessageCipher {
    pub(crate) alg: String,
    pub(crate) nonce: String,
    pub(crate) aad: String,
    pub(crate) ct: String,
}
