use crate::core::{
    blocking, canonical, config, crypto, http_client, protocol,
    remote_routes::{PeerPublicKeys, RemoteRoute},
    routes::FinalAppRoute,
    validation,
};
use crate::error::DynError;
use crate::ops::contracts::{
    MessageCipher, MessageKem, MessageRecipient, MessageSender, ProtectedMessagePayload,
    ProtectedMessageToken, PublicDerKey, PublicKeys, PublicKeysOutput, PublicRawKey,
    SendMessageInput, SignatureBlock, TimestampSignatures,
};
use crate::ops::keys::{self, KeysDbState, LoadedOpsKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use tracing::info;
use zeroize::{Zeroize, Zeroizing};

const PROTECTED_MESSAGE_TYPE: &str = "protected-message";
const HYBRID_SECRET_SIZE_BYTES: usize = 32;

#[derive(Clone, Serialize)]
pub struct RemotePublicKeys {
    host: String,
    kid: String,
    loaded_at: String,
    info: String,
    keys: PublicKeysOutput,
}

impl RemotePublicKeys {
    pub(crate) fn host(&self) -> &str {
        &self.host
    }

    pub(crate) fn kid(&self) -> &str {
        &self.kid
    }

    pub(crate) fn keys(&self) -> &PublicKeysOutput {
        &self.keys
    }
}

impl Zeroize for RemotePublicKeys {
    fn zeroize(&mut self) {
        self.host.zeroize();
        self.kid.zeroize();
        self.loaded_at.zeroize();
        self.info.zeroize();
    }
}

#[derive(Serialize)]
pub struct SendMessageOutput {
    pub message: MessageStatus,
    pub symmetric: MessageVariantStatus,
    pub eddsa: MessageVariantStatus,
    pub xecdh: MessageVariantStatus,
    #[serde(rename = "ml-dsa")]
    pub ml_dsa: MessageVariantStatus,
    #[serde(rename = "ml-kem")]
    pub ml_kem: MessageVariantStatus,
}

#[derive(Serialize)]
pub struct MessageStatus {
    pub valid: bool,
}

#[derive(Serialize)]
pub struct MessageVariantStatus {
    pub variant: String,
    pub valid: bool,
}

#[derive(Serialize, Deserialize)]
pub struct ReceiveMessageOutput {
    pub status: String,
    pub sender_kid: String,
    pub recipient_kid: String,
    pub local_cipher: LocalCipherOutput,
}

#[derive(Serialize, Deserialize)]
pub struct LocalCipherOutput {
    pub alg: String,
    pub nonce: String,
    pub aad: String,
    pub ct: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecryptMessageInput {
    pub sender_host: String,
    pub sender_kid: String,
    pub timestamp: String,
    pub message: DecryptMessageCipher,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecryptMessageCipher {
    pub ctx: String,
    pub nonce: String,
    pub aad: String,
    pub variant: String,
}

#[derive(Serialize)]
pub struct DecryptMessageOutput {
    pub plaintext: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InternalEncryptMessageInput {
    pub plaintext: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InternalMessageOutput {
    pub timestamp: String,
    pub kid: String,
    pub message: InternalMessageCipher,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InternalMessageCipher {
    pub ctx: String,
    pub nonce: String,
    pub aad: String,
    pub variant: String,
}

pub struct PreparedDecryptMessage {
    recipient_key: Arc<LoadedOpsKey>,
    input: ValidatedDecryptMessageInput,
}

struct ValidatedDecryptMessageInput {
    input: DecryptMessageInput,
}

pub struct PreparedInternalEncryptMessage {
    key: Arc<LoadedOpsKey>,
    input: ValidatedInternalEncryptMessageInput,
}

struct ValidatedInternalEncryptMessageInput {
    plaintext: Zeroizing<String>,
}

pub struct PreparedInternalDecryptMessage {
    key: Arc<LoadedOpsKey>,
    input: ValidatedInternalDecryptMessageInput,
}

struct ValidatedInternalDecryptMessageInput {
    input: InternalMessageOutput,
}

#[derive(Serialize)]
struct FinalAppDelivery {
    sender_host: String,
    sender_kid: String,
    timestamp: String,
    message: FinalAppMessage,
}

#[derive(Serialize)]
struct FinalAppMessage {
    ctx: String,
    nonce: String,
    aad: String,
    variant: String,
}

pub struct PreparedSendMessage {
    sender_key: Arc<LoadedOpsKey>,
    input: ValidatedSendMessageInput,
}

impl PreparedSendMessage {
    pub fn recipient_kid(&self) -> &str {
        &self.input.recipient_kid
    }
}

pub struct ValidatedSendMessageInput {
    recipient_kid: String,
    message: Zeroizing<String>,
}

pub struct PreparedReceiveMessage {
    recipient_key: Arc<LoadedOpsKey>,
    envelope: ProtectedMessageToken,
}

impl PreparedReceiveMessage {
    pub fn sender_host(&self) -> &str {
        self.envelope.sender_host()
    }
}

pub fn parse_send_message_input(request: Value) -> Result<SendMessageInput, DynError> {
    serde_json::from_value(request)
        .map_err(|_| crate::error::invalid_input("invalid message request"))
}

pub fn prepare_send_message(
    keys_db_state: &KeysDbState,
    sender_kid: &str,
    input: SendMessageInput,
) -> Result<PreparedSendMessage, DynError> {
    keys::KeyId::parse(sender_kid)?;

    let input = validate_send_message_input(input)?;
    let sender_key = keys::get_loaded_key(keys_db_state, sender_kid)?;
    keys::require_lifecycle_for_new_use(&sender_key)?;

    Ok(PreparedSendMessage { sender_key, input })
}

pub fn parse_message_envelope(request: Value) -> Result<ProtectedMessageToken, DynError> {
    serde_json::from_value(request)
        .map_err(|_| crate::error::invalid_input("invalid protected message"))
}

pub fn parse_decrypt_message_input(request: Value) -> Result<DecryptMessageInput, DynError> {
    serde_json::from_value(request)
        .map_err(|_| crate::error::invalid_input("invalid message decrypt request"))
}

pub fn parse_internal_encrypt_message_input(
    request: Value,
) -> Result<InternalEncryptMessageInput, DynError> {
    serde_json::from_value(request)
        .map_err(|_| crate::error::invalid_input("invalid internal message encrypt request"))
}

pub fn parse_internal_decrypt_message_input(
    request: Value,
) -> Result<InternalMessageOutput, DynError> {
    serde_json::from_value(request)
        .map_err(|_| crate::error::invalid_input("invalid internal message decrypt request"))
}

pub fn decrypt_message_recipient_kid(input: &DecryptMessageInput) -> Result<String, DynError> {
    let aad = parse_aad_fields(&input.message.aad)?;
    let recipient_kid = aad_field(&aad, "recipient_kid")?;
    keys::KeyId::parse(recipient_kid)?;

    Ok(recipient_kid.to_string())
}

pub fn prepare_decrypt_message(
    keys_db_state: &KeysDbState,
    input: DecryptMessageInput,
) -> Result<PreparedDecryptMessage, DynError> {
    let input = validate_decrypt_message_input(input)?;
    let aad = parse_aad_fields(&input.input.message.aad)?;
    let recipient_kid = aad_field(&aad, "recipient_kid")?;
    let recipient_key = keys::get_loaded_key(keys_db_state, recipient_kid)?;
    keys::require_lifecycle_for_decrypt_or_verify(&recipient_key)?;

    Ok(PreparedDecryptMessage {
        recipient_key,
        input,
    })
}

pub fn prepare_internal_encrypt_message(
    keys_db_state: &KeysDbState,
    kid: &str,
    input: InternalEncryptMessageInput,
) -> Result<PreparedInternalEncryptMessage, DynError> {
    keys::KeyId::parse(kid)?;

    let input = validate_internal_encrypt_message_input(input)?;
    let key = keys::get_loaded_key(keys_db_state, kid)?;
    keys::require_lifecycle_for_new_use(&key)?;

    Ok(PreparedInternalEncryptMessage { key, input })
}

pub fn prepare_internal_decrypt_message(
    keys_db_state: &KeysDbState,
    input: InternalMessageOutput,
) -> Result<PreparedInternalDecryptMessage, DynError> {
    let input = validate_internal_decrypt_message_input(input)?;
    let key = keys::get_loaded_key(keys_db_state, &input.input.kid)?;
    keys::require_lifecycle_for_decrypt_or_verify(&key)?;

    Ok(PreparedInternalDecryptMessage { key, input })
}

pub fn prepare_receive_message(
    keys_db_state: &KeysDbState,
    envelope: ProtectedMessageToken,
) -> Result<PreparedReceiveMessage, DynError> {
    validate_message_envelope(&envelope)?;
    let recipient_key = keys::get_loaded_key(keys_db_state, envelope.recipient_kid())?;
    keys::require_lifecycle_for_decrypt_or_verify(&recipient_key)?;

    Ok(PreparedReceiveMessage {
        recipient_key,
        envelope,
    })
}

pub async fn send_message(
    config: &config::AppConfig,
    prepared: PreparedSendMessage,
    remote_route: RemoteRoute,
) -> Result<SendMessageOutput, DynError> {
    info!(
        sender_kid = %prepared.sender_key.id(),
        recipient_host = %remote_route.remote_addr(),
        recipient_kid = %prepared.input.recipient_kid,
        recipient_name = %remote_route.name(),
        "message send started"
    );
    let sender_key = prepared.sender_key;
    let input = prepared.input;
    let Some(peer) = remote_route.public_keys() else {
        return Err(crate::error::forbidden(
            "recipient route has no registered public keys in the signed config",
        ));
    };
    let recipient_public_keys =
        remote_public_keys_from_peer(remote_route.remote_addr(), &input.recipient_kid, peer)?;
    validate_remote_public_keys(&recipient_public_keys)?;
    info!(
        recipient_host = %recipient_public_keys.host(),
        recipient_kid = %recipient_public_keys.kid(),
        source = "config",
        "recipient public key ready"
    );

    let config = config.clone();
    let envelope_sender_key = Arc::clone(&sender_key);
    let envelope_recipient_public_keys = recipient_public_keys.clone();
    let (envelope, input) = blocking::spawn_blocking_crypto(move || {
        let envelope = create_message_envelope(
            &config,
            &envelope_sender_key,
            &envelope_recipient_public_keys,
            &input,
        )?;

        Ok((envelope, input))
    })
    .await?;
    let response = http_client::post_remote_json::<_, ReceiveMessageOutput>(
        remote_route.remote_addr(),
        "/message",
        &envelope,
    )
    .await
    .map_err(|err| recipient_delivery_error(remote_route.remote_addr(), err))?;
    let output = build_send_message_output(&sender_key, &input, &response);
    info!(
        sender_kid = %sender_key.id(),
        recipient_kid = %input.recipient_kid,
        delivered = output.message.valid,
        "message send completed"
    );

    Ok(output)
}

fn recipient_delivery_error(host: &str, err: DynError) -> DynError {
    crate::error::remote_unreachable(format!(
        "recipient can't be reached: host={host}, error={err}"
    ))
}

pub async fn receive_message(
    prepared: PreparedReceiveMessage,
    sender_public_keys: RemotePublicKeys,
    final_app_route: FinalAppRoute,
) -> Result<ReceiveMessageOutput, DynError> {
    let (envelope, local_cipher) = blocking::spawn_blocking_crypto(move || {
        process_received_message(prepared, sender_public_keys)
    })
    .await?;
    deliver_message_to_final_app(&final_app_route, &envelope, &local_cipher).await?;
    info!(
        sender_kid = %envelope.sender_kid(),
        recipient_kid = %envelope.recipient_kid(),
        route_kid = %final_app_route.kid(),
        final_app_name = %final_app_route.name(),
        final_app_addr = %final_app_route.final_app_addr(),
        final_app_path = %final_app_route.final_app_path(),
        "message delivered to final app"
    );

    Ok(ReceiveMessageOutput {
        status: String::from("ok"),
        sender_kid: envelope.sender_kid().to_string(),
        recipient_kid: envelope.recipient_kid().to_string(),
        local_cipher,
    })
}

fn process_received_message(
    prepared: PreparedReceiveMessage,
    sender_public_keys: RemotePublicKeys,
) -> Result<(ProtectedMessageToken, LocalCipherOutput), DynError> {
    info!(
        sender_host = %prepared.envelope.sender_host(),
        sender_kid = %prepared.envelope.sender_kid(),
        recipient_kid = %prepared.envelope.recipient_kid(),
        "message envelope received"
    );
    validate_message_envelope_for_recipient(&prepared.recipient_key, &prepared.envelope)?;

    validate_remote_public_keys(&sender_public_keys)?;
    info!(
        sender_host = %sender_public_keys.host(),
        sender_kid = %sender_public_keys.kid(),
        source = "config",
        "sender public key ready"
    );
    verify_message_signatures(&sender_public_keys, &prepared.envelope)?;
    info!(
        sender_kid = %prepared.envelope.sender_kid(),
        recipient_kid = %prepared.envelope.recipient_kid(),
        "message signatures verified"
    );

    let plaintext = open_message_cipher(&prepared.recipient_key, &prepared.envelope)?;
    info!(
        sender_kid = %prepared.envelope.sender_kid(),
        recipient_kid = %prepared.envelope.recipient_kid(),
        plaintext_len = plaintext.len(),
        "message decrypted"
    );
    let local_cipher =
        encrypt_local_message(&prepared.recipient_key, &plaintext, &prepared.envelope)?;
    info!(
        sender_kid = %prepared.envelope.sender_kid(),
        recipient_kid = %prepared.envelope.recipient_kid(),
        variant = %local_cipher.alg,
        ctx_len = local_cipher.ct.len(),
        "message reencrypted for local delivery"
    );

    Ok((prepared.envelope, local_cipher))
}

pub fn decrypt_message(prepared: PreparedDecryptMessage) -> Result<DecryptMessageOutput, DynError> {
    let input = prepared.input.input;
    info!(
        sender_host = %input.sender_host,
        sender_kid = %input.sender_kid,
        timestamp = %input.timestamp,
        variant = %input.message.variant,
        ctx_len = input.message.ctx.len(),
        "message decrypt requested"
    );
    let aad = parse_aad_fields(&input.message.aad)?;
    let sender_kid = aad_field(&aad, "sender_kid")?;
    let recipient_kid = aad_field(&aad, "recipient_kid")?;
    let cipher_alg = aad_field(&aad, "cipher_alg")?;

    if input.sender_kid != sender_kid {
        return Err(crate::error::invalid_input(
            "sender_kid does not match message aad",
        ));
    }
    if prepared.recipient_key.id() != recipient_kid {
        return Err(crate::error::invalid_input(
            "recipient key does not match message aad",
        ));
    }
    if input.message.variant != cipher_alg {
        return Err(crate::error::invalid_input(
            "message.variant does not match message aad cipher_alg",
        ));
    }
    if input.message.variant != prepared.recipient_key.keys().symmetric().variant() {
        return Err(crate::error::invalid_input(
            "message.variant does not match recipient symmetric key",
        ));
    }

    let cipher = crypto::symmetric_cipher(&input.message.variant)
        .ok_or_else(|| crate::error::invalid_input("message.variant is not supported"))?;
    validation::validate_symmetric_key(
        "recipient symmetric key",
        prepared.recipient_key.keys().symmetric().key_hex(),
        cipher.key_size_bytes,
    )?;

    let key = Zeroizing::new(hex::decode(
        prepared.recipient_key.keys().symmetric().key_hex(),
    )?);
    let nonce = Zeroizing::new(
        hex::decode(&input.message.nonce)
            .map_err(|_| crate::error::invalid_input("message.nonce is not valid hex"))?,
    );
    let ciphertext = hex::decode(&input.message.ctx)
        .map_err(|_| crate::error::invalid_input("message.ctx is not valid hex"))?;
    let plaintext_bytes = Zeroizing::new(
        crypto::decrypt_symmetric(
            cipher.algorithm,
            &ciphertext,
            &key,
            &nonce,
            input.message.aad.as_bytes(),
        )
        .map_err(|_| crate::error::invalid_input("message authentication failed"))?,
    );
    let plaintext = decrypted_message_string(plaintext_bytes)?;
    info!(
        sender_kid = %input.sender_kid,
        recipient_kid = %prepared.recipient_key.id(),
        plaintext_len = plaintext.len(),
        "message decrypt completed"
    );

    Ok(DecryptMessageOutput { plaintext })
}

pub fn encrypt_internal_message(
    prepared: PreparedInternalEncryptMessage,
) -> Result<InternalMessageOutput, DynError> {
    let timestamp = validation::current_timestamp()?;
    let cipher =
        crypto::symmetric_cipher(prepared.key.keys().symmetric().variant()).ok_or_else(|| {
            crate::error::invalid_input("internal message symmetric algorithm is not supported")
        })?;
    validation::validate_symmetric_key(
        "internal message symmetric key",
        prepared.key.keys().symmetric().key_hex(),
        cipher.key_size_bytes,
    )?;

    let key = Zeroizing::new(hex::decode(prepared.key.keys().symmetric().key_hex())?);
    let nonce = Zeroizing::new(crypto::random_bytes(cipher.nonce_size_bytes)?);
    let aad = validation::build_aad(&[
        ("version", protocol::PROTOCOL_VERSION_V1),
        ("type", "internal-message"),
        ("kid", prepared.key.id()),
        ("timestamp", &timestamp),
        ("cipher_alg", cipher.algorithm),
    ]);
    let ciphertext = crypto::encrypt_symmetric(
        cipher.algorithm,
        &prepared.input.plaintext,
        &key,
        &nonce,
        aad.as_bytes(),
    )?;
    info!(
        kid = %prepared.key.id(),
        variant = %cipher.algorithm,
        plaintext_len = prepared.input.plaintext.len(),
        "internal message encrypted"
    );

    Ok(InternalMessageOutput {
        timestamp,
        kid: prepared.key.id().to_string(),
        message: InternalMessageCipher {
            ctx: hex::encode(ciphertext),
            nonce: hex::encode(&*nonce),
            aad,
            variant: cipher.algorithm.to_string(),
        },
    })
}

pub fn decrypt_internal_message(
    prepared: PreparedInternalDecryptMessage,
) -> Result<DecryptMessageOutput, DynError> {
    let input = prepared.input.input;
    let aad = parse_aad_fields(&input.message.aad)?;
    let kid = aad_field(&aad, "kid")?;
    let timestamp = aad_field(&aad, "timestamp")?;
    let cipher_alg = aad_field(&aad, "cipher_alg")?;

    if input.kid != kid {
        return Err(crate::error::invalid_input(
            "kid does not match internal message aad",
        ));
    }
    if input.timestamp != timestamp {
        return Err(crate::error::invalid_input(
            "timestamp does not match internal message aad",
        ));
    }
    if input.message.variant != cipher_alg {
        return Err(crate::error::invalid_input(
            "message.variant does not match internal message aad cipher_alg",
        ));
    }
    if input.message.variant != prepared.key.keys().symmetric().variant() {
        return Err(crate::error::invalid_input(
            "message.variant does not match internal symmetric key",
        ));
    }

    let cipher = crypto::symmetric_cipher(&input.message.variant)
        .ok_or_else(|| crate::error::invalid_input("message.variant is not supported"))?;
    validation::validate_symmetric_key(
        "internal message symmetric key",
        prepared.key.keys().symmetric().key_hex(),
        cipher.key_size_bytes,
    )?;

    let key = Zeroizing::new(hex::decode(prepared.key.keys().symmetric().key_hex())?);
    let nonce = Zeroizing::new(
        hex::decode(&input.message.nonce)
            .map_err(|_| crate::error::invalid_input("message.nonce is not valid hex"))?,
    );
    let ciphertext = hex::decode(&input.message.ctx)
        .map_err(|_| crate::error::invalid_input("message.ctx is not valid hex"))?;
    let plaintext_bytes = Zeroizing::new(
        crypto::decrypt_symmetric(
            cipher.algorithm,
            &ciphertext,
            &key,
            &nonce,
            input.message.aad.as_bytes(),
        )
        .map_err(|_| crate::error::invalid_input("message authentication failed"))?,
    );
    let plaintext = decrypted_message_string(plaintext_bytes)?;
    info!(
        kid = %prepared.key.id(),
        variant = %input.message.variant,
        plaintext_len = plaintext.len(),
        "internal message decrypted"
    );

    Ok(DecryptMessageOutput { plaintext })
}

fn validate_send_message_input(
    input: SendMessageInput,
) -> Result<ValidatedSendMessageInput, DynError> {
    keys::KeyId::parse(&input.recipient_kid)?;
    validation::validate_text_field("message", &input.message)?;

    Ok(ValidatedSendMessageInput {
        recipient_kid: input.recipient_kid,
        message: Zeroizing::new(input.message),
    })
}

fn validate_decrypt_message_input(
    input: DecryptMessageInput,
) -> Result<ValidatedDecryptMessageInput, DynError> {
    validation::validate_host_port("sender_host", &input.sender_host)?;
    keys::KeyId::parse(&input.sender_kid)?;
    validation::validate_text_field("timestamp", &input.timestamp)?;
    validation::validate_hex_field("message.ctx", &input.message.ctx)?;
    validation::validate_hex_field("message.nonce", &input.message.nonce)?;
    validation::validate_text_field("message.aad", &input.message.aad)?;
    validation::validate_allowed_value(
        "message.variant",
        &input.message.variant,
        crypto::SYMMETRIC_ALGORITHMS,
    )?;
    let cipher = crypto::symmetric_cipher(&input.message.variant)
        .ok_or_else(|| crate::error::invalid_input("message.variant is not supported"))?;
    if input.message.nonce.len() != cipher.nonce_size_bytes * 2 {
        return Err(crate::error::invalid_input(
            "message.nonce length does not match message.variant",
        ));
    }

    let aad = parse_aad_fields(&input.message.aad)?;
    validation::validate_allowed_value(
        "message.aad.type",
        aad_field(&aad, "type")?,
        &["stored-protected-message"],
    )?;
    keys::KeyId::parse(aad_field(&aad, "sender_kid")?)?;
    keys::KeyId::parse(aad_field(&aad, "recipient_kid")?)?;
    validation::validate_text_field(
        "message.aad.source_created_at",
        aad_field(&aad, "source_created_at")?,
    )?;
    validation::validate_allowed_value(
        "message.aad.cipher_alg",
        aad_field(&aad, "cipher_alg")?,
        crypto::SYMMETRIC_ALGORITHMS,
    )?;

    Ok(ValidatedDecryptMessageInput { input })
}

fn validate_internal_encrypt_message_input(
    input: InternalEncryptMessageInput,
) -> Result<ValidatedInternalEncryptMessageInput, DynError> {
    validation::validate_text_field("plaintext", &input.plaintext)?;

    Ok(ValidatedInternalEncryptMessageInput {
        plaintext: Zeroizing::new(input.plaintext),
    })
}

fn validate_internal_decrypt_message_input(
    input: InternalMessageOutput,
) -> Result<ValidatedInternalDecryptMessageInput, DynError> {
    keys::KeyId::parse(&input.kid)?;
    validation::validate_text_field("timestamp", &input.timestamp)?;
    validation::validate_hex_field("message.ctx", &input.message.ctx)?;
    validation::validate_hex_field("message.nonce", &input.message.nonce)?;
    validation::validate_text_field("message.aad", &input.message.aad)?;
    validation::validate_allowed_value(
        "message.variant",
        &input.message.variant,
        crypto::SYMMETRIC_ALGORITHMS,
    )?;
    let cipher = crypto::symmetric_cipher(&input.message.variant)
        .ok_or_else(|| crate::error::invalid_input("message.variant is not supported"))?;
    if input.message.nonce.len() != cipher.nonce_size_bytes * 2 {
        return Err(crate::error::invalid_input(
            "message.nonce length does not match message.variant",
        ));
    }

    let aad = parse_aad_fields(&input.message.aad)?;
    validation::validate_allowed_value(
        "message.aad.type",
        aad_field(&aad, "type")?,
        &["internal-message"],
    )?;
    keys::KeyId::parse(aad_field(&aad, "kid")?)?;
    validation::validate_text_field("message.aad.timestamp", aad_field(&aad, "timestamp")?)?;
    validation::validate_allowed_value(
        "message.aad.cipher_alg",
        aad_field(&aad, "cipher_alg")?,
        crypto::SYMMETRIC_ALGORITHMS,
    )?;

    Ok(ValidatedInternalDecryptMessageInput { input })
}

fn parse_aad_fields(aad: &str) -> Result<Vec<(String, String)>, DynError> {
    validation::validate_text_field("aad", aad)?;

    let mut fields = Vec::new();
    for part in aad.split(';') {
        let Some((key, value)) = part.split_once('=') else {
            return Err(crate::error::invalid_input(
                "aad must contain key=value fields",
            ));
        };
        validation::validate_text_field("aad key", key)?;
        validation::validate_text_field("aad value", value)?;
        fields.push((key.to_string(), value.to_string()));
    }

    Ok(fields)
}

fn aad_field<'a>(fields: &'a [(String, String)], key: &str) -> Result<&'a str, DynError> {
    fields
        .iter()
        .find(|(field_key, _)| field_key == key)
        .map(|(_, value)| value.as_str())
        .ok_or_else(|| crate::error::invalid_input(format!("aad missing {key}")))
}

fn build_send_message_output(
    sender_key: &LoadedOpsKey,
    input: &ValidatedSendMessageInput,
    response: &ReceiveMessageOutput,
) -> SendMessageOutput {
    let message_valid = response.status == "ok"
        && response.sender_kid == sender_key.id()
        && response.recipient_kid == input.recipient_kid;

    SendMessageOutput {
        message: MessageStatus {
            valid: message_valid,
        },
        symmetric: MessageVariantStatus {
            variant: sender_key.keys().symmetric().variant().to_string(),
            valid: message_valid,
        },
        eddsa: MessageVariantStatus {
            variant: sender_key.keys().eddsa().variant().to_string(),
            valid: message_valid,
        },
        xecdh: MessageVariantStatus {
            variant: sender_key.keys().xecdh().variant().to_string(),
            valid: message_valid,
        },
        ml_dsa: MessageVariantStatus {
            variant: sender_key.keys().ml_dsa().variant().to_string(),
            valid: message_valid,
        },
        ml_kem: MessageVariantStatus {
            variant: sender_key.keys().ml_kem().variant().to_string(),
            valid: message_valid,
        },
    }
}

fn create_message_envelope(
    config: &config::AppConfig,
    sender_key: &LoadedOpsKey,
    recipient_public_keys: &RemotePublicKeys,
    input: &ValidatedSendMessageInput,
) -> Result<ProtectedMessageToken, DynError> {
    let created_at = validation::current_timestamp()?;
    let recipient_keys = recipient_public_keys.keys();
    let kem_alg = hybrid_kem_alg(
        &recipient_keys.keys.xecdh.alg,
        &recipient_keys.keys.ml_kem.alg,
    );
    let cipher =
        crypto::symmetric_cipher(sender_key.keys().symmetric().variant()).ok_or_else(|| {
            crate::error::invalid_input("sender symmetric algorithm is not supported")
        })?;
    let cipher_alg = cipher.algorithm.to_string();
    let sender_host = config.public_addr.clone();
    let mut rng = crypto::new_rng()?;
    let aad = build_message_aad(
        &config.protocol_version,
        &created_at,
        &sender_host,
        sender_key.id(),
        recipient_public_keys.kid(),
        &kem_alg,
        &cipher_alg,
    );

    let ephemeral_private_key = crypto::create_x_key_agreement_private_key_with_rng(
        &mut rng,
        &recipient_keys.keys.xecdh.alg,
    )?;
    let ephemeral_public_key = crypto::key_agreement_public_key(&ephemeral_private_key)?;
    let recipient_xecdh_public_key = hex::decode(&recipient_keys.keys.xecdh.public_key_hex)?;
    let xecdh_shared_key = Zeroizing::new(crypto::agree_key(
        &ephemeral_private_key,
        &recipient_xecdh_public_key,
    )?);

    let ml_kem_public_key =
        crypto::load_public_key_der_hex(&recipient_keys.keys.ml_kem.public_key_der_hex)?;
    let ml_kem_salt = Zeroizing::new(crypto::random_bytes_with_rng(&mut rng, 32)?);
    let ml_kem = crypto::encapsulate_ml_kem_shared_key_with_rng(
        &mut rng,
        &ml_kem_public_key,
        &ml_kem_salt,
        HYBRID_SECRET_SIZE_BYTES,
    )?;
    let ml_kem_shared_key = Zeroizing::new(ml_kem.shared_key);
    let ml_kem_ciphertext = ml_kem.encapsulated_key;
    let hkdf_salt = Zeroizing::new(crypto::random_bytes_with_rng(&mut rng, 32)?);
    let message_key = derive_message_key(
        &xecdh_shared_key,
        &ml_kem_shared_key,
        &hkdf_salt,
        aad.as_bytes(),
        cipher.key_size_bytes,
    )?;
    let nonce = Zeroizing::new(crypto::random_bytes_with_rng(
        &mut rng,
        cipher.nonce_size_bytes,
    )?);
    let ciphertext = crypto::encrypt_symmetric(
        &cipher_alg,
        &input.message,
        &message_key,
        &nonce,
        aad.as_bytes(),
    )?;

    let payload = ProtectedMessagePayload {
        version: protocol::PROTOCOL_VERSION_V1.to_string(),
        token_type: String::from(PROTECTED_MESSAGE_TYPE),
        created_at,
        sender: MessageSender {
            host: sender_host,
            kid: sender_key.id().to_string(),
        },
        recipient: MessageRecipient {
            kid: recipient_public_keys.kid().to_string(),
        },
        kem: MessageKem {
            alg: kem_alg,
            xecdh_ephemeral_public: hex::encode(ephemeral_public_key),
            ml_kem_ciphertext: hex::encode(ml_kem_ciphertext),
            ml_kem_salt: hex::encode(&*ml_kem_salt),
            hkdf_salt: hex::encode(&*hkdf_salt),
        },
        cipher: MessageCipher {
            alg: cipher_alg,
            nonce: hex::encode(&*nonce),
            aad,
            ct: hex::encode(ciphertext),
        },
    };
    let signatures = sign_message_payload(&mut rng, sender_key, &payload)?;

    Ok(ProtectedMessageToken {
        version: protocol::PROTOCOL_VERSION_V1.to_string(),
        payload,
        signatures,
    })
}

fn open_message_cipher(
    recipient_key: &LoadedOpsKey,
    envelope: &ProtectedMessageToken,
) -> Result<Zeroizing<String>, DynError> {
    let payload = &envelope.payload;
    let recipient_xecdh_private_key =
        crypto::load_private_key_der_hex(recipient_key.keys().xecdh().private_key_der_hex())?;
    let ephemeral_public_key = hex::decode(&payload.kem.xecdh_ephemeral_public).map_err(|_| {
        crate::error::invalid_input("message.kem.xecdh_ephemeral_public is not valid hex")
    })?;
    let xecdh_shared_key = Zeroizing::new(
        crypto::agree_key(&recipient_xecdh_private_key, &ephemeral_public_key).map_err(|_| {
            crate::error::invalid_input("message key agreement material is invalid")
        })?,
    );

    let ml_kem_private_key =
        crypto::load_private_key_der_hex(recipient_key.keys().ml_kem().private_key_der_hex())?;
    let ml_kem_ciphertext = hex::decode(&payload.kem.ml_kem_ciphertext).map_err(|_| {
        crate::error::invalid_input("message.kem.ml_kem_ciphertext is not valid hex")
    })?;
    let ml_kem_salt =
        Zeroizing::new(hex::decode(&payload.kem.ml_kem_salt).map_err(|_| {
            crate::error::invalid_input("message.kem.ml_kem_salt is not valid hex")
        })?);
    let ml_kem_shared_key = Zeroizing::new(
        crypto::decapsulate_ml_kem_shared_key(
            &ml_kem_private_key,
            &ml_kem_ciphertext,
            &ml_kem_salt,
            HYBRID_SECRET_SIZE_BYTES,
        )
        .map_err(|_| {
            crate::error::invalid_input("message key encapsulation material is invalid")
        })?,
    );
    let hkdf_salt = Zeroizing::new(
        hex::decode(&payload.kem.hkdf_salt)
            .map_err(|_| crate::error::invalid_input("message.kem.hkdf_salt is not valid hex"))?,
    );
    let cipher = crypto::symmetric_cipher(&payload.cipher.alg)
        .ok_or_else(|| crate::error::invalid_input("message cipher algorithm is not supported"))?;
    let message_key = derive_message_key(
        &xecdh_shared_key,
        &ml_kem_shared_key,
        &hkdf_salt,
        payload.cipher.aad.as_bytes(),
        cipher.key_size_bytes,
    )?;
    let nonce = Zeroizing::new(
        hex::decode(&payload.cipher.nonce)
            .map_err(|_| crate::error::invalid_input("message.cipher.nonce is not valid hex"))?,
    );
    let ciphertext = hex::decode(&payload.cipher.ct)
        .map_err(|_| crate::error::invalid_input("message.cipher.ct is not valid hex"))?;
    let plaintext_bytes = Zeroizing::new(
        crypto::decrypt_symmetric(
            &payload.cipher.alg,
            &ciphertext,
            &message_key,
            &nonce,
            payload.cipher.aad.as_bytes(),
        )
        .map_err(|_| crate::error::invalid_input("message authentication failed"))?,
    );
    let plaintext = Zeroizing::new(decrypted_message_string(plaintext_bytes)?);

    Ok(plaintext)
}

fn encrypt_local_message(
    recipient_key: &LoadedOpsKey,
    plaintext: &str,
    envelope: &ProtectedMessageToken,
) -> Result<LocalCipherOutput, DynError> {
    let cipher =
        crypto::symmetric_cipher(recipient_key.keys().symmetric().variant()).ok_or_else(|| {
            crate::error::invalid_input("recipient symmetric algorithm is not supported")
        })?;
    validation::validate_symmetric_key(
        "recipient symmetric key",
        recipient_key.keys().symmetric().key_hex(),
        cipher.key_size_bytes,
    )?;

    let key = Zeroizing::new(hex::decode(recipient_key.keys().symmetric().key_hex())?);
    let nonce = Zeroizing::new(crypto::random_bytes(cipher.nonce_size_bytes)?);
    let aad = validation::build_aad(&[
        ("version", &envelope.version),
        ("type", "stored-protected-message"),
        ("sender_kid", envelope.sender_kid()),
        ("recipient_kid", recipient_key.id()),
        ("source_created_at", &envelope.payload.created_at),
        ("cipher_alg", cipher.algorithm),
    ]);
    let ciphertext =
        crypto::encrypt_symmetric(cipher.algorithm, plaintext, &key, &nonce, aad.as_bytes())?;

    Ok(LocalCipherOutput {
        alg: cipher.algorithm.to_string(),
        nonce: hex::encode(&*nonce),
        aad,
        ct: hex::encode(ciphertext),
    })
}

fn decrypted_message_string(mut plaintext_bytes: Zeroizing<Vec<u8>>) -> Result<String, DynError> {
    String::from_utf8(std::mem::take(&mut *plaintext_bytes)).map_err(|err| {
        let mut bytes = err.into_bytes();
        bytes.zeroize();
        crate::error::invalid_input("decrypted message is not valid UTF-8")
    })
}

async fn deliver_message_to_final_app(
    route: &FinalAppRoute,
    envelope: &ProtectedMessageToken,
    local_cipher: &LocalCipherOutput,
) -> Result<(), DynError> {
    let delivery = FinalAppDelivery {
        sender_host: envelope.sender_host().to_string(),
        sender_kid: envelope.sender_kid().to_string(),
        timestamp: validation::current_timestamp()?,
        message: FinalAppMessage {
            ctx: local_cipher.ct.clone(),
            nonce: local_cipher.nonce.clone(),
            aad: local_cipher.aad.clone(),
            variant: local_cipher.alg.clone(),
        },
    };

    http_client::post_final_app_json::<_, serde_json::Value>(
        route.final_app_addr(),
        route.final_app_path(),
        &delivery,
    )
    .await
    .map_err(|err| final_app_delivery_error(route.final_app_addr(), route.final_app_path(), err))?;

    Ok(())
}

fn final_app_delivery_error(addr: &str, path: &str, err: DynError) -> DynError {
    crate::error::remote_unreachable(format!(
        "final app can't be reached: addr={addr}, path={path}, error={err}"
    ))
}

fn sign_message_payload(
    rng: &mut crypto::CryptoRng,
    sender_key: &LoadedOpsKey,
    payload: &ProtectedMessagePayload,
) -> Result<TimestampSignatures, DynError> {
    let payload_bytes = canonical::canonical_json_v1(payload)?;
    let payload_text = std::str::from_utf8(&payload_bytes)?;
    let eddsa = sender_key.keys().eddsa();
    let ml_dsa = sender_key.keys().ml_dsa();
    let eddsa_private_key = crypto::load_private_key_der_hex(eddsa.private_key_der_hex())?;
    let ml_dsa_private_key = crypto::load_private_key_der_hex(ml_dsa.private_key_der_hex())?;
    let eddsa_signature = crypto::sign_message_with_rng(rng, &eddsa_private_key, payload_text)?;
    let ml_dsa_signature =
        crypto::sign_ml_dsa_message_with_rng(rng, &ml_dsa_private_key, payload_text)?;

    Ok(TimestampSignatures {
        eddsa: SignatureBlock {
            alg: eddsa.variant().to_string(),
            sig: hex::encode(eddsa_signature),
        },
        ml_dsa: SignatureBlock {
            alg: ml_dsa.variant().to_string(),
            sig: hex::encode(ml_dsa_signature),
        },
    })
}

fn verify_message_signatures(
    sender_public_keys: &RemotePublicKeys,
    envelope: &ProtectedMessageToken,
) -> Result<(), DynError> {
    if envelope.signatures.eddsa.alg != sender_public_keys.keys.keys.eddsa.alg {
        return Err(crate::error::invalid_input(
            "signatures.eddsa.alg does not match sender public key",
        ));
    }
    if envelope.signatures.ml_dsa.alg != sender_public_keys.keys.keys.ml_dsa.alg {
        return Err(crate::error::invalid_input(
            "signatures.ml-dsa.alg does not match sender public key",
        ));
    }

    let payload_bytes = canonical::canonical_json_v1(&envelope.payload)?;
    let payload_text = std::str::from_utf8(&payload_bytes)?;
    let eddsa_public_key =
        crypto::load_public_key_der_hex(&sender_public_keys.keys.keys.eddsa.public_key_der_hex)
            .map_err(|_| crate::error::invalid_input("sender eddsa public key is invalid"))?;
    let ml_dsa_public_key =
        crypto::load_public_key_der_hex(&sender_public_keys.keys.keys.ml_dsa.public_key_der_hex)
            .map_err(|_| crate::error::invalid_input("sender ml-dsa public key is invalid"))?;
    let eddsa_signature = hex::decode(&envelope.signatures.eddsa.sig)
        .map_err(|_| crate::error::invalid_input("signatures.eddsa.sig is not valid hex"))?;
    let ml_dsa_signature = hex::decode(&envelope.signatures.ml_dsa.sig)
        .map_err(|_| crate::error::invalid_input("signatures.ml-dsa.sig is not valid hex"))?;
    let eddsa_valid = crypto::verify_message(&eddsa_public_key, payload_text, &eddsa_signature)
        .map_err(|_| crate::error::invalid_input("message eddsa signature is malformed"))?;
    let ml_dsa_valid =
        crypto::verify_ml_dsa_message(&ml_dsa_public_key, payload_text, &ml_dsa_signature)
            .map_err(|_| crate::error::invalid_input("message ml-dsa signature is malformed"))?;

    if !eddsa_valid || !ml_dsa_valid {
        return Err(crate::error::invalid_input(
            "message signatures are invalid",
        ));
    }

    Ok(())
}

fn validate_message_envelope(envelope: &ProtectedMessageToken) -> Result<(), DynError> {
    protocol::validate_protocol_version("version", &envelope.version)?;
    protocol::validate_protocol_version("payload.version", &envelope.payload.version)?;
    if envelope.version != envelope.payload.version {
        return Err(crate::error::invalid_input(
            "envelope version does not match signed payload version",
        ));
    }
    validation::validate_allowed_value(
        "payload.type",
        &envelope.payload.token_type,
        &[PROTECTED_MESSAGE_TYPE],
    )?;
    validation::validate_text_field("payload.created_at", &envelope.payload.created_at)?;
    validation::validate_host_port("payload.sender.host", &envelope.payload.sender.host)?;
    keys::KeyId::parse(&envelope.payload.sender.kid)?;
    keys::KeyId::parse(&envelope.payload.recipient.kid)?;
    validation::validate_allowed_value(
        "payload.cipher.alg",
        &envelope.payload.cipher.alg,
        crypto::SYMMETRIC_ALGORITHMS,
    )?;
    validation::validate_text_field("payload.cipher.aad", &envelope.payload.cipher.aad)?;
    validation::validate_hex_field("payload.cipher.ct", &envelope.payload.cipher.ct)?;
    validation::validate_hex_field("payload.cipher.nonce", &envelope.payload.cipher.nonce)?;
    validation::validate_text_field("payload.kem.alg", &envelope.payload.kem.alg)?;
    validation::validate_hex_field(
        "payload.kem.xecdh_ephemeral_public",
        &envelope.payload.kem.xecdh_ephemeral_public,
    )?;
    validation::validate_hex_field(
        "payload.kem.ml_kem_ciphertext",
        &envelope.payload.kem.ml_kem_ciphertext,
    )?;
    validation::validate_hex_field("payload.kem.ml_kem_salt", &envelope.payload.kem.ml_kem_salt)?;
    validation::validate_hex_field("payload.kem.hkdf_salt", &envelope.payload.kem.hkdf_salt)?;
    validation::validate_allowed_value(
        "signatures.eddsa.alg",
        &envelope.signatures.eddsa.alg,
        &["Ed25519", "Ed448"],
    )?;
    validation::validate_hex_field("signatures.eddsa.sig", &envelope.signatures.eddsa.sig)?;
    validation::validate_allowed_value(
        "signatures.ml-dsa.alg",
        &envelope.signatures.ml_dsa.alg,
        &["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"],
    )?;
    validation::validate_hex_field("signatures.ml-dsa.sig", &envelope.signatures.ml_dsa.sig)?;

    let expected_aad = build_message_aad(
        &envelope.version,
        &envelope.payload.created_at,
        &envelope.payload.sender.host,
        &envelope.payload.sender.kid,
        &envelope.payload.recipient.kid,
        &envelope.payload.kem.alg,
        &envelope.payload.cipher.alg,
    );
    if envelope.payload.cipher.aad != expected_aad {
        return Err(crate::error::invalid_input(
            "payload.cipher.aad does not match protected message metadata",
        ));
    }

    Ok(())
}

fn validate_message_envelope_for_recipient(
    recipient_key: &LoadedOpsKey,
    envelope: &ProtectedMessageToken,
) -> Result<(), DynError> {
    validate_message_envelope(envelope)?;

    if envelope.recipient_kid() != recipient_key.id() {
        return Err(crate::error::invalid_input(
            "payload.recipient.kid does not match loaded recipient key",
        ));
    }

    let expected_kem_alg = hybrid_kem_alg(
        recipient_key.keys().xecdh().variant(),
        recipient_key.keys().ml_kem().variant(),
    );
    if envelope.payload.kem.alg != expected_kem_alg {
        return Err(crate::error::invalid_input(
            "payload.kem.alg does not match recipient key algorithms",
        ));
    }

    let cipher = crypto::symmetric_cipher(&envelope.payload.cipher.alg)
        .ok_or_else(|| crate::error::invalid_input("payload.cipher.alg is not supported"))?;
    if envelope.payload.cipher.nonce.len() != cipher.nonce_size_bytes * 2 {
        return Err(crate::error::invalid_input(
            "payload.cipher.nonce length does not match cipher algorithm",
        ));
    }

    Ok(())
}

fn validate_remote_public_keys(remote_key: &RemotePublicKeys) -> Result<(), DynError> {
    validation::validate_host_port("remote.host", remote_key.host())?;
    keys::KeyId::parse(remote_key.kid())?;
    validation::validate_text_field("remote.info", &remote_key.info)?;
    validation::validate_allowed_value(
        "remote.keys.eddsa.alg",
        &remote_key.keys.keys.eddsa.alg,
        &["Ed25519", "Ed448"],
    )?;
    validation::validate_hex_field(
        "remote.keys.eddsa.public_key_der_hex",
        &remote_key.keys.keys.eddsa.public_key_der_hex,
    )?;
    validation::validate_allowed_value(
        "remote.keys.xecdh.alg",
        &remote_key.keys.keys.xecdh.alg,
        &["X25519", "X448"],
    )?;
    validation::validate_hex_field(
        "remote.keys.xecdh.public_key_hex",
        &remote_key.keys.keys.xecdh.public_key_hex,
    )?;
    validation::validate_allowed_value(
        "remote.keys.ml-dsa.alg",
        &remote_key.keys.keys.ml_dsa.alg,
        &["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"],
    )?;
    validation::validate_hex_field(
        "remote.keys.ml-dsa.public_key_der_hex",
        &remote_key.keys.keys.ml_dsa.public_key_der_hex,
    )?;
    validation::validate_allowed_value(
        "remote.keys.ml-kem.alg",
        &remote_key.keys.keys.ml_kem.alg,
        &["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"],
    )?;
    validation::validate_hex_field(
        "remote.keys.ml-kem.public_key_der_hex",
        &remote_key.keys.keys.ml_kem.public_key_der_hex,
    )?;
    validate_remote_public_key_material(remote_key)?;

    Ok(())
}

fn validate_remote_public_key_material(remote_key: &RemotePublicKeys) -> Result<(), DynError> {
    crypto::validate_der_public_key_hex(
        "remote.keys.eddsa.public_key_der_hex",
        &remote_key.keys.keys.eddsa.public_key_der_hex,
    )?;
    crypto::validate_x_key_agreement_public_key_hex(
        "remote.keys.xecdh.public_key_hex",
        &remote_key.keys.keys.xecdh.alg,
        &remote_key.keys.keys.xecdh.public_key_hex,
    )?;
    crypto::validate_der_public_key_hex(
        "remote.keys.ml-dsa.public_key_der_hex",
        &remote_key.keys.keys.ml_dsa.public_key_der_hex,
    )?;
    crypto::validate_ml_kem_public_key_hex(
        "remote.keys.ml-kem.public_key_der_hex",
        &remote_key.keys.keys.ml_kem.public_key_der_hex,
        HYBRID_SECRET_SIZE_BYTES,
    )?;

    Ok(())
}

fn derive_message_key(
    xecdh_shared_key: &[u8],
    ml_kem_shared_key: &[u8],
    salt: &[u8],
    aad: &[u8],
    key_size_bytes: usize,
) -> Result<Zeroizing<Vec<u8>>, DynError> {
    let mut input_key_material = Zeroizing::new(Vec::with_capacity(
        xecdh_shared_key.len() + ml_kem_shared_key.len(),
    ));
    input_key_material.extend_from_slice(xecdh_shared_key);
    input_key_material.extend_from_slice(ml_kem_shared_key);
    let info = [b"Vectis protected-message v1:".as_slice(), aad].concat();

    Ok(Zeroizing::new(crypto::create_hkdf(
        &input_key_material,
        salt,
        &info,
        key_size_bytes,
    )?))
}

fn build_message_aad(
    version: &str,
    created_at: &str,
    sender_host: &str,
    sender_kid: &str,
    recipient_kid: &str,
    kem_alg: &str,
    cipher_alg: &str,
) -> String {
    validation::build_aad(&[
        ("version", version),
        ("type", PROTECTED_MESSAGE_TYPE),
        ("created_at", created_at),
        ("sender_host", sender_host),
        ("sender_kid", sender_kid),
        ("recipient_kid", recipient_kid),
        ("kem_alg", kem_alg),
        ("cipher_alg", cipher_alg),
    ])
}

fn hybrid_kem_alg(xecdh_alg: &str, ml_kem_alg: &str) -> String {
    format!("{xecdh_alg}+{ml_kem_alg}")
}

pub fn remote_public_keys_from_peer(
    host: &str,
    kid: &str,
    peer: &PeerPublicKeys,
) -> Result<RemotePublicKeys, DynError> {
    let info = validation::build_aad(&[
        ("version", protocol::PROTOCOL_VERSION_V1),
        ("type", "peer-public-keys"),
        ("kid", kid),
    ]);
    let keys = PublicKeysOutput {
        info: info.clone(),
        keys: PublicKeys {
            eddsa: PublicDerKey {
                alg: peer.eddsa.alg.clone(),
                public_key_der_hex: peer.eddsa.public_key_der_hex.clone(),
            },
            xecdh: PublicRawKey {
                alg: peer.xecdh.alg.clone(),
                public_key_hex: peer.xecdh.public_key_hex.clone(),
            },
            ml_dsa: PublicDerKey {
                alg: peer.ml_dsa.alg.clone(),
                public_key_der_hex: peer.ml_dsa.public_key_der_hex.clone(),
            },
            ml_kem: PublicDerKey {
                alg: peer.ml_kem.alg.clone(),
                public_key_der_hex: peer.ml_kem.public_key_der_hex.clone(),
            },
        },
    };
    let remote_key = RemotePublicKeys {
        host: host.to_string(),
        kid: kid.to_string(),
        loaded_at: validation::current_timestamp()?,
        info,
        keys,
    };
    validate_remote_public_keys(&remote_key)?;

    Ok(remote_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use serde_json::json;

    fn nonce_hex_for(cipher_alg: &str) -> String {
        let cipher = crypto::symmetric_cipher(cipher_alg).expect("test cipher must be supported");

        "a".repeat(cipher.nonce_size_bytes * 2)
    }

    fn stored_message_aad(sender_kid: &str, recipient_kid: &str, cipher_alg: &str) -> String {
        validation::build_aad(&[
            ("type", "stored-protected-message"),
            ("sender_kid", sender_kid),
            ("recipient_kid", recipient_kid),
            ("source_created_at", "123456"),
            ("cipher_alg", cipher_alg),
        ])
    }

    fn internal_message_aad(kid: &str, cipher_alg: &str) -> String {
        validation::build_aad(&[
            ("type", "internal-message"),
            ("kid", kid),
            ("timestamp", "123456"),
            ("cipher_alg", cipher_alg),
        ])
    }

    fn protected_message_json(sender_kid: &str, recipient_kid: &str) -> serde_json::Value {
        let cipher_alg = "AES-256/GCM";
        let kem_alg = "X25519+ML-KEM-512";
        let sender_host = "localhost:3000";
        let created_at = "123456";

        json!({
            "version": protocol::PROTOCOL_VERSION_V1,
            "payload": {
                "version": protocol::PROTOCOL_VERSION_V1,
                "type": PROTECTED_MESSAGE_TYPE,
                "created_at": created_at,
                "sender": {
                    "host": sender_host,
                    "kid": sender_kid,
                },
                "recipient": {
                    "kid": recipient_kid,
                },
                "kem": {
                    "alg": kem_alg,
                    "xecdh_ephemeral_public": "aa",
                    "ml_kem_ciphertext": "aa",
                    "ml_kem_salt": "aa",
                    "hkdf_salt": "aa",
                },
                "cipher": {
                    "alg": cipher_alg,
                    "nonce": nonce_hex_for(cipher_alg),
                    "aad": build_message_aad(
                        protocol::PROTOCOL_VERSION_V1,
                        created_at,
                        sender_host,
                        sender_kid,
                        recipient_kid,
                        kem_alg,
                        cipher_alg,
                    ),
                    "ct": "aa",
                },
            },
            "signatures": {
                "eddsa": {
                    "alg": "Ed25519",
                    "sig": "aa",
                },
                "ml-dsa": {
                    "alg": "ML-DSA-44",
                    "sig": "aa",
                },
            },
        })
    }

    proptest! {
        #[test]
        fn parse_send_message_input_accepts_current_shape(
            recipient_kid in "[0-9a-f]{64}",
            message in "[A-Za-z0-9._:-][A-Za-z0-9 ._:-]{0,63}"
        ) {
            let input = parse_send_message_input(json!({
                "recipient_kid": recipient_kid,
                "message": message,
            }))
            .expect("generated send message input must parse");

            prop_assert!(validate_send_message_input(input).is_ok());
        }

        #[test]
        fn parse_send_message_input_rejects_legacy_or_unknown_fields(
            recipient_kid in "[0-9a-f]{64}",
            message in "[A-Za-z0-9._:-][A-Za-z0-9 ._:-]{0,63}",
            extra_value in "[A-Za-z0-9 ._:-]{1,32}"
        ) {
            let legacy_result = parse_send_message_input(json!({
                "recipient_host": "localhost:3000",
                "recipient_kid": recipient_kid,
                "message": message,
            }));
            prop_assert!(legacy_result.is_err());

            let unknown_result = parse_send_message_input(json!({
                "recipient_kid": recipient_kid,
                "message": message,
                "unexpected": extra_value,
            }));
            prop_assert!(unknown_result.is_err());
        }

        #[test]
        fn internal_encrypt_input_accepts_only_valid_plaintext(
            plaintext in "[A-Za-z0-9._:-][A-Za-z0-9 ._:-]{0,63}"
        ) {
            let input = parse_internal_encrypt_message_input(json!({
                "plaintext": plaintext,
            }))
            .expect("generated internal encrypt input must parse");
            prop_assert!(validate_internal_encrypt_message_input(input).is_ok());

            let null_result = parse_internal_encrypt_message_input(json!({
                "plaintext": null,
            }));
            prop_assert!(null_result.is_err());
            let number_result = parse_internal_encrypt_message_input(json!({
                "plaintext": 123,
            }));
            prop_assert!(number_result.is_err());
            let bool_result = parse_internal_encrypt_message_input(json!({
                "plaintext": true,
            }));
            prop_assert!(bool_result.is_err());
            let array_result = parse_internal_encrypt_message_input(json!({
                "plaintext": ["text"],
            }));
            prop_assert!(array_result.is_err());
            let object_result = parse_internal_encrypt_message_input(json!({
                "plaintext": {"text": "hello"},
            }));
            prop_assert!(object_result.is_err());

            let empty = parse_internal_encrypt_message_input(json!({
                "plaintext": "",
            }))
            .expect("empty plaintext input must parse before validation");
            prop_assert!(validate_internal_encrypt_message_input(empty).is_err());
        }

        #[test]
        fn decrypt_message_recipient_kid_round_trips_valid_aad(
            sender_kid in "[0-9a-f]{64}",
            recipient_kid in "[0-9a-f]{64}",
            cipher_alg in prop::sample::select(crypto::SYMMETRIC_ALGORITHMS)
        ) {
            let input = parse_decrypt_message_input(json!({
                "sender_host": "localhost:3000",
                "sender_kid": sender_kid,
                "timestamp": "123456",
                "message": {
                    "ctx": "aa",
                    "nonce": nonce_hex_for(cipher_alg),
                    "aad": stored_message_aad(&sender_kid, &recipient_kid, cipher_alg),
                    "variant": cipher_alg,
                }
            }))
            .expect("generated decrypt message input must parse");

            prop_assert_eq!(
                decrypt_message_recipient_kid(&input)
                    .expect("valid aad must expose recipient kid"),
                recipient_kid
            );
            prop_assert!(validate_decrypt_message_input(input).is_ok());
        }

        #[test]
        fn decrypt_message_input_enforces_nonce_length_and_aad_type(
            sender_kid in "[0-9a-f]{64}",
            recipient_kid in "[0-9a-f]{64}",
            cipher_alg in prop::sample::select(crypto::SYMMETRIC_ALGORITHMS)
        ) {
            let short_nonce = parse_decrypt_message_input(json!({
                "sender_host": "localhost:3000",
                "sender_kid": sender_kid,
                "timestamp": "123456",
                "message": {
                    "ctx": "aa",
                    "nonce": "aa",
                    "aad": stored_message_aad(&sender_kid, &recipient_kid, cipher_alg),
                    "variant": cipher_alg,
                }
            }))
            .expect("short nonce decrypt message input must parse");
            prop_assert!(validate_decrypt_message_input(short_nonce).is_err());

            let wrong_type_aad = validation::build_aad(&[
                ("type", "internal-message"),
                ("sender_kid", &sender_kid),
                ("recipient_kid", &recipient_kid),
                ("source_created_at", "123456"),
                ("cipher_alg", cipher_alg),
            ]);
            let wrong_type = parse_decrypt_message_input(json!({
                "sender_host": "localhost:3000",
                "sender_kid": sender_kid,
                "timestamp": "123456",
                "message": {
                    "ctx": "aa",
                    "nonce": nonce_hex_for(cipher_alg),
                    "aad": wrong_type_aad,
                    "variant": cipher_alg,
                }
            }))
            .expect("wrong aad type decrypt message input must parse");
            prop_assert!(validate_decrypt_message_input(wrong_type).is_err());
        }

        #[test]
        fn internal_decrypt_input_enforces_hex_nonce_and_aad_shape(
            kid in "[0-9a-f]{64}",
            cipher_alg in prop::sample::select(crypto::SYMMETRIC_ALGORITHMS)
        ) {
            let valid = parse_internal_decrypt_message_input(json!({
                "timestamp": "123456",
                "kid": kid,
                "message": {
                    "ctx": "aa",
                    "nonce": nonce_hex_for(cipher_alg),
                    "aad": internal_message_aad(&kid, cipher_alg),
                    "variant": cipher_alg,
                }
            }))
            .expect("generated internal decrypt input must parse");
            prop_assert!(validate_internal_decrypt_message_input(valid).is_ok());

            let invalid_hex = parse_internal_decrypt_message_input(json!({
                "timestamp": "123456",
                "kid": kid,
                "message": {
                    "ctx": "not-hex",
                    "nonce": nonce_hex_for(cipher_alg),
                    "aad": internal_message_aad(&kid, cipher_alg),
                    "variant": cipher_alg,
                }
            }))
            .expect("invalid hex internal decrypt input must parse");
            prop_assert!(validate_internal_decrypt_message_input(invalid_hex).is_err());

            let missing_aad_field = validation::build_aad(&[
                ("type", "internal-message"),
                ("kid", &kid),
                ("timestamp", "123456"),
            ]);
            let missing_aad = parse_internal_decrypt_message_input(json!({
                "timestamp": "123456",
                "kid": kid,
                "message": {
                    "ctx": "aa",
                    "nonce": nonce_hex_for(cipher_alg),
                    "aad": missing_aad_field,
                    "variant": cipher_alg,
                }
            }))
            .expect("missing aad field internal decrypt input must parse");
            prop_assert!(validate_internal_decrypt_message_input(missing_aad).is_err());
        }

        #[test]
        fn parse_message_envelope_rejects_unknown_fields(
            sender_kid in "[0-9a-f]{64}",
            recipient_kid in "[0-9a-f]{64}",
            extra_field in "[A-Za-z_][A-Za-z0-9_]{0,24}"
        ) {
            prop_assume!(!["version", "payload", "signatures"].contains(&extra_field.as_str()));
            let mut top_level = protected_message_json(&sender_kid, &recipient_kid);
            top_level
                .as_object_mut()
                .unwrap()
                .insert(extra_field.clone(), json!("unexpected"));
            prop_assert!(parse_message_envelope(top_level).is_err());

            prop_assume!(![
                "version",
                "type",
                "created_at",
                "sender",
                "recipient",
                "kem",
                "cipher",
            ]
            .contains(&extra_field.as_str()));
            let mut nested = protected_message_json(&sender_kid, &recipient_kid);
            nested["payload"]
                .as_object_mut()
                .unwrap()
                .insert(extra_field, json!("unexpected"));
            prop_assert!(parse_message_envelope(nested).is_err());
        }
    }
}
