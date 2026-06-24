use crate::core::{config, crypto, routes::FinalAppRoute, validation};
use crate::error::DynError;
use crate::ops::contracts::{
    MessageCipher, MessageKem, MessageRecipient, MessageSender, ProtectedMessagePayload,
    ProtectedMessageToken, PublicKeysOutput, SendMessageInput, SignatureBlock, TimestampSignatures,
};
use crate::ops::keys::{self, KeysDbState, LoadedOpsKey};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{info, warn};
use zeroize::{Zeroize, Zeroizing};

const PROTECTED_MESSAGE_TYPE: &str = "protected-message";
const HYBRID_SECRET_SIZE_BYTES: usize = 32;

#[derive(Default, Serialize)]
pub struct RemotePublicKeysState {
    remote_keys: Vec<RemotePublicKeys>,
}

#[derive(Clone, Serialize)]
pub struct RemotePublicKeys {
    host: String,
    kid: String,
    loaded_at: String,
    info: String,
    keys: PublicKeysOutput,
}

impl RemotePublicKeysState {
    pub(crate) fn get(&self, host: &str, kid: &str) -> Option<&RemotePublicKeys> {
        self.remote_keys
            .iter()
            .find(|remote_key| remote_key.host == host && remote_key.kid == kid)
    }

    pub(crate) fn upsert(&mut self, remote_key: RemotePublicKeys) {
        if let Some(index) = self.remote_keys.iter().position(|existing_key| {
            existing_key.host == remote_key.host && existing_key.kid == remote_key.kid
        }) {
            let mut existing_key = self.remote_keys.remove(index);
            existing_key.zeroize();
        }

        self.remote_keys.push(remote_key);
    }
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

impl Zeroize for RemotePublicKeysState {
    fn zeroize(&mut self) {
        self.remote_keys.zeroize();
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
pub struct DecryptMessageInput {
    pub sender_host: String,
    pub sender_kid: String,
    pub timestamp: String,
    pub message: DecryptMessageCipher,
}

#[derive(Deserialize)]
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
pub struct InternalEncryptMessageInput {
    pub plaintext: String,
}

#[derive(Serialize, Deserialize)]
pub struct InternalMessageOutput {
    pub timestamp: String,
    pub kid: String,
    pub message: InternalMessageCipher,
}

#[derive(Serialize, Deserialize)]
pub struct InternalMessageCipher {
    pub ctx: String,
    pub nonce: String,
    pub aad: String,
    pub variant: String,
}

pub struct PreparedDecryptMessage {
    recipient_key: LoadedOpsKey,
    input: ValidatedDecryptMessageInput,
}

struct ValidatedDecryptMessageInput {
    input: DecryptMessageInput,
}

pub struct PreparedInternalEncryptMessage {
    key: LoadedOpsKey,
    input: ValidatedInternalEncryptMessageInput,
}

struct ValidatedInternalEncryptMessageInput {
    plaintext: Zeroizing<String>,
}

pub struct PreparedInternalDecryptMessage {
    key: LoadedOpsKey,
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
    sender_key: LoadedOpsKey,
    input: ValidatedSendMessageInput,
}

impl PreparedSendMessage {
    pub fn recipient_host(&self) -> &str {
        &self.input.recipient_host
    }

    pub fn recipient_kid(&self) -> &str {
        &self.input.recipient_kid
    }
}

pub struct ValidatedSendMessageInput {
    recipient_host: String,
    recipient_kid: String,
    message: Zeroizing<String>,
}

pub struct PreparedReceiveMessage {
    recipient_key: LoadedOpsKey,
    envelope: ProtectedMessageToken,
}

impl PreparedReceiveMessage {
    pub fn sender_host(&self) -> &str {
        self.envelope.sender_host()
    }

    pub fn sender_kid(&self) -> &str {
        self.envelope.sender_kid()
    }

    pub fn recipient_kid(&self) -> &str {
        self.envelope.recipient_kid()
    }
}

pub struct OutboundMessageResult {
    pub output: SendMessageOutput,
    pub remote_public_keys: RemotePublicKeys,
}

pub struct InboundMessageResult {
    pub output: ReceiveMessageOutput,
    pub remote_public_keys: RemotePublicKeys,
}

pub fn parse_send_message_input(request: Value) -> Result<SendMessageInput, DynError> {
    serde_json::from_value(request).map_err(|err| {
        Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid message request: {err}"),
        )) as DynError
    })
}

pub fn prepare_send_message(
    keys_db_state: &KeysDbState,
    sender_kid: &str,
    input: SendMessageInput,
) -> Result<PreparedSendMessage, DynError> {
    keys::KeyId::parse(sender_kid)?;

    let input = validate_send_message_input(input)?;
    let sender_key = keys::get_loaded_key(keys_db_state, sender_kid)?.clone();

    Ok(PreparedSendMessage { sender_key, input })
}

pub fn parse_message_envelope(request: Value) -> Result<ProtectedMessageToken, DynError> {
    serde_json::from_value(request).map_err(|err| {
        Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid protected message: {err}"),
        )) as DynError
    })
}

pub fn parse_decrypt_message_input(request: Value) -> Result<DecryptMessageInput, DynError> {
    serde_json::from_value(request).map_err(|err| {
        Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid message decrypt request: {err}"),
        )) as DynError
    })
}

pub fn parse_internal_encrypt_message_input(
    request: Value,
) -> Result<InternalEncryptMessageInput, DynError> {
    serde_json::from_value(request).map_err(|err| {
        Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid internal message encrypt request: {err}"),
        )) as DynError
    })
}

pub fn parse_internal_decrypt_message_input(
    request: Value,
) -> Result<InternalMessageOutput, DynError> {
    serde_json::from_value(request).map_err(|err| {
        Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid internal message decrypt request: {err}"),
        )) as DynError
    })
}

pub fn prepare_decrypt_message(
    keys_db_state: &KeysDbState,
    input: DecryptMessageInput,
) -> Result<PreparedDecryptMessage, DynError> {
    let input = validate_decrypt_message_input(input)?;
    let aad = parse_aad_fields(&input.input.message.aad)?;
    let recipient_kid = aad_field(&aad, "recipient_kid")?;
    let recipient_key = keys::get_loaded_key(keys_db_state, recipient_kid)?.clone();

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
    let key = keys::get_loaded_key(keys_db_state, kid)?.clone();

    Ok(PreparedInternalEncryptMessage { key, input })
}

pub fn prepare_internal_decrypt_message(
    keys_db_state: &KeysDbState,
    input: InternalMessageOutput,
) -> Result<PreparedInternalDecryptMessage, DynError> {
    let input = validate_internal_decrypt_message_input(input)?;
    let key = keys::get_loaded_key(keys_db_state, &input.input.kid)?.clone();

    Ok(PreparedInternalDecryptMessage { key, input })
}

pub fn prepare_receive_message(
    keys_db_state: &KeysDbState,
    envelope: ProtectedMessageToken,
) -> Result<PreparedReceiveMessage, DynError> {
    validate_message_envelope(&envelope)?;
    let recipient_key = keys::get_loaded_key(keys_db_state, envelope.recipient_kid())?.clone();

    Ok(PreparedReceiveMessage {
        recipient_key,
        envelope,
    })
}

pub async fn send_message(
    prepared: PreparedSendMessage,
    cached_recipient: Option<RemotePublicKeys>,
) -> Result<OutboundMessageResult, DynError> {
    info!(
        sender_kid = %prepared.sender_key.id(),
        recipient_host = %prepared.input.recipient_host,
        recipient_kid = %prepared.input.recipient_kid,
        "message send started"
    );
    let recipient_key_source = if cached_recipient.is_some() {
        "cache"
    } else {
        "remote"
    };
    let recipient_public_keys = match cached_recipient {
        Some(remote_key) => remote_key,
        None => {
            fetch_remote_public_keys(
                &prepared.input.recipient_host,
                &prepared.input.recipient_kid,
            )
            .await?
        }
    };
    validate_remote_public_keys(&recipient_public_keys)?;
    info!(
        recipient_host = %recipient_public_keys.host(),
        recipient_kid = %recipient_public_keys.kid(),
        source = recipient_key_source,
        "recipient public key ready"
    );

    let envelope = create_message_envelope(
        &prepared.sender_key,
        &recipient_public_keys,
        &prepared.input,
    )?;
    let response =
        post_json::<_, ReceiveMessageOutput>(&prepared.input.recipient_host, "/message", &envelope)
            .await
            .map_err(|err| recipient_delivery_error(&prepared.input.recipient_host, err))?;
    let output = build_send_message_output(&prepared.sender_key, &prepared.input, &response);
    info!(
        sender_kid = %prepared.sender_key.id(),
        recipient_kid = %prepared.input.recipient_kid,
        delivered = output.message.valid,
        "message send completed"
    );

    Ok(OutboundMessageResult {
        output,
        remote_public_keys: recipient_public_keys,
    })
}

fn recipient_delivery_error(host: &str, err: DynError) -> DynError {
    Box::new(io::Error::new(
        io::ErrorKind::Other,
        format!("recipient can't be reached: host={host}, error={err}"),
    ))
}

pub async fn receive_message(
    prepared: PreparedReceiveMessage,
    cached_sender: Option<RemotePublicKeys>,
    final_app_route: FinalAppRoute,
) -> Result<InboundMessageResult, DynError> {
    info!(
        sender_host = %prepared.envelope.sender_host(),
        sender_kid = %prepared.envelope.sender_kid(),
        recipient_kid = %prepared.envelope.recipient_kid(),
        "message envelope received"
    );
    validate_message_envelope_for_recipient(&prepared.recipient_key, &prepared.envelope)?;

    let sender_key_source = if cached_sender.is_some() {
        "cache"
    } else {
        "remote"
    };
    let sender_public_keys = match cached_sender {
        Some(remote_key) => remote_key,
        None => {
            fetch_remote_public_keys(
                prepared.envelope.sender_host(),
                prepared.envelope.sender_kid(),
            )
            .await?
        }
    };
    validate_remote_public_keys(&sender_public_keys)?;
    info!(
        sender_host = %sender_public_keys.host(),
        sender_kid = %sender_public_keys.kid(),
        source = sender_key_source,
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
    deliver_message_to_final_app(&final_app_route, &prepared.envelope, &local_cipher).await?;
    info!(
        sender_kid = %prepared.envelope.sender_kid(),
        recipient_kid = %prepared.envelope.recipient_kid(),
        route_kid = %final_app_route.kid(),
        final_app_addr = %final_app_route.final_app_addr(),
        final_app_path = %final_app_route.final_app_path(),
        "message delivered to final app"
    );

    Ok(InboundMessageResult {
        output: ReceiveMessageOutput {
            status: String::from("ok"),
            sender_kid: prepared.envelope.sender_kid().to_string(),
            recipient_kid: prepared.envelope.recipient_kid().to_string(),
            local_cipher,
        },
        remote_public_keys: sender_public_keys,
    })
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
        return Err(Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            "sender_kid does not match message aad",
        )));
    }
    if prepared.recipient_key.id() != recipient_kid {
        return Err(Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            "recipient key does not match message aad",
        )));
    }
    if input.message.variant != cipher_alg {
        return Err(Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            "message.variant does not match message aad cipher_alg",
        )));
    }
    if input.message.variant != prepared.recipient_key.keys().symmetric().variant() {
        return Err(Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            "message.variant does not match recipient symmetric key",
        )));
    }

    let cipher = crypto::symmetric_cipher(&input.message.variant).ok_or_else(|| {
        Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            "message.variant is not supported",
        )) as DynError
    })?;
    validation::validate_symmetric_key(
        "recipient symmetric key",
        prepared.recipient_key.keys().symmetric().key_hex(),
        cipher.key_size_bytes,
    )?;

    let key = Zeroizing::new(hex::decode(
        prepared.recipient_key.keys().symmetric().key_hex(),
    )?);
    let nonce = Zeroizing::new(hex::decode(&input.message.nonce)?);
    let ciphertext = hex::decode(&input.message.ctx)?;
    let plaintext_bytes = Zeroizing::new(crypto::decrypt_symmetric(
        cipher.algorithm,
        &ciphertext,
        &key,
        &nonce,
        input.message.aad.as_bytes(),
    )?);
    let plaintext = String::from_utf8((*plaintext_bytes).clone())?;
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
            Box::new(io::Error::new(
                io::ErrorKind::InvalidInput,
                "internal message symmetric algorithm is not supported",
            )) as DynError
        })?;
    validation::validate_symmetric_key(
        "internal message symmetric key",
        prepared.key.keys().symmetric().key_hex(),
        cipher.key_size_bytes,
    )?;

    let key = Zeroizing::new(hex::decode(prepared.key.keys().symmetric().key_hex())?);
    let nonce = Zeroizing::new(crypto::random_bytes(cipher.nonce_size_bytes)?);
    let aad = validation::build_aad(&[
        ("version", "v1"),
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
        return Err(Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            "kid does not match internal message aad",
        )));
    }
    if input.timestamp != timestamp {
        return Err(Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            "timestamp does not match internal message aad",
        )));
    }
    if input.message.variant != cipher_alg {
        return Err(Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            "message.variant does not match internal message aad cipher_alg",
        )));
    }
    if input.message.variant != prepared.key.keys().symmetric().variant() {
        return Err(Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            "message.variant does not match internal symmetric key",
        )));
    }

    let cipher = crypto::symmetric_cipher(&input.message.variant).ok_or_else(|| {
        Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            "message.variant is not supported",
        )) as DynError
    })?;
    validation::validate_symmetric_key(
        "internal message symmetric key",
        prepared.key.keys().symmetric().key_hex(),
        cipher.key_size_bytes,
    )?;

    let key = Zeroizing::new(hex::decode(prepared.key.keys().symmetric().key_hex())?);
    let nonce = Zeroizing::new(hex::decode(&input.message.nonce)?);
    let ciphertext = hex::decode(&input.message.ctx)?;
    let plaintext_bytes = Zeroizing::new(crypto::decrypt_symmetric(
        cipher.algorithm,
        &ciphertext,
        &key,
        &nonce,
        input.message.aad.as_bytes(),
    )?);
    let plaintext = String::from_utf8((*plaintext_bytes).clone())?;
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
    validation::validate_host_port("recipient_host", &input.recipient_host)?;
    keys::KeyId::parse(&input.recipient_kid)?;
    validation::validate_text_field("message", &input.message)?;

    Ok(ValidatedSendMessageInput {
        recipient_host: input.recipient_host,
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
    let cipher = crypto::symmetric_cipher(&input.message.variant).ok_or_else(|| {
        Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            "message.variant is not supported",
        )) as DynError
    })?;
    if input.message.nonce.len() != cipher.nonce_size_bytes * 2 {
        return Err(Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            "message.nonce length does not match message.variant",
        )));
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
    let cipher = crypto::symmetric_cipher(&input.message.variant).ok_or_else(|| {
        Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            "message.variant is not supported",
        )) as DynError
    })?;
    if input.message.nonce.len() != cipher.nonce_size_bytes * 2 {
        return Err(Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            "message.nonce length does not match message.variant",
        )));
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
            return Err(Box::new(io::Error::new(
                io::ErrorKind::InvalidInput,
                "aad must contain key=value fields",
            )));
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
        .ok_or_else(|| {
            Box::new(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("aad missing {key}"),
            )) as DynError
        })
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
    sender_key: &LoadedOpsKey,
    recipient_public_keys: &RemotePublicKeys,
    input: &ValidatedSendMessageInput,
) -> Result<ProtectedMessageToken, DynError> {
    let config = config::app_config()?;
    let created_at = validation::current_timestamp()?;
    let recipient_keys = recipient_public_keys.keys();
    let kem_alg = hybrid_kem_alg(
        &recipient_keys.keys.xecdh.alg,
        &recipient_keys.keys.ml_kem.alg,
    );
    let cipher =
        crypto::symmetric_cipher(sender_key.keys().symmetric().variant()).ok_or_else(|| {
            Box::new(io::Error::new(
                io::ErrorKind::InvalidInput,
                "sender symmetric algorithm is not supported",
            )) as DynError
        })?;
    let cipher_alg = cipher.algorithm.to_string();
    let sender_host = config.public_addr;
    let aad = build_message_aad(
        &config.protocol_version,
        &created_at,
        &sender_host,
        sender_key.id(),
        recipient_public_keys.kid(),
        &kem_alg,
        &cipher_alg,
    );

    let ephemeral_private_key =
        crypto::create_x_key_agreement_private_key(&recipient_keys.keys.xecdh.alg)?;
    let ephemeral_public_key = crypto::key_agreement_public_key(&ephemeral_private_key)?;
    let recipient_xecdh_public_key = hex::decode(&recipient_keys.keys.xecdh.public_key_hex)?;
    let xecdh_shared_key = Zeroizing::new(crypto::agree_key(
        &ephemeral_private_key,
        &recipient_xecdh_public_key,
    )?);

    let ml_kem_public_key =
        crypto::load_public_key_der_hex(&recipient_keys.keys.ml_kem.public_key_der_hex)?;
    let ml_kem_salt = Zeroizing::new(crypto::random_bytes(32)?);
    let ml_kem = crypto::encapsulate_ml_kem_shared_key(
        &ml_kem_public_key,
        &ml_kem_salt,
        HYBRID_SECRET_SIZE_BYTES,
    )?;
    let ml_kem_shared_key = Zeroizing::new(ml_kem.shared_key);
    let ml_kem_ciphertext = ml_kem.encapsulated_key;
    let hkdf_salt = Zeroizing::new(crypto::random_bytes(32)?);
    let message_key = derive_message_key(
        &xecdh_shared_key,
        &ml_kem_shared_key,
        &hkdf_salt,
        aad.as_bytes(),
        cipher.key_size_bytes,
    )?;
    let nonce = Zeroizing::new(crypto::random_bytes(cipher.nonce_size_bytes)?);
    let ciphertext = crypto::encrypt_symmetric(
        &cipher_alg,
        &input.message,
        &message_key,
        &nonce,
        aad.as_bytes(),
    )?;

    let payload = ProtectedMessagePayload {
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
    let signatures = sign_message_payload(sender_key, &payload)?;

    Ok(ProtectedMessageToken {
        version: String::from("v1"),
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
    let ephemeral_public_key = hex::decode(&payload.kem.xecdh_ephemeral_public)?;
    let xecdh_shared_key = Zeroizing::new(crypto::agree_key(
        &recipient_xecdh_private_key,
        &ephemeral_public_key,
    )?);

    let ml_kem_private_key =
        crypto::load_private_key_der_hex(recipient_key.keys().ml_kem().private_key_der_hex())?;
    let ml_kem_ciphertext = hex::decode(&payload.kem.ml_kem_ciphertext)?;
    let ml_kem_salt = Zeroizing::new(hex::decode(&payload.kem.ml_kem_salt)?);
    let ml_kem_shared_key = Zeroizing::new(crypto::decapsulate_ml_kem_shared_key(
        &ml_kem_private_key,
        &ml_kem_ciphertext,
        &ml_kem_salt,
        HYBRID_SECRET_SIZE_BYTES,
    )?);
    let hkdf_salt = Zeroizing::new(hex::decode(&payload.kem.hkdf_salt)?);
    let cipher = crypto::symmetric_cipher(&payload.cipher.alg).ok_or_else(|| {
        Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            "message cipher algorithm is not supported",
        )) as DynError
    })?;
    let message_key = derive_message_key(
        &xecdh_shared_key,
        &ml_kem_shared_key,
        &hkdf_salt,
        payload.cipher.aad.as_bytes(),
        cipher.key_size_bytes,
    )?;
    let nonce = Zeroizing::new(hex::decode(&payload.cipher.nonce)?);
    let ciphertext = hex::decode(&payload.cipher.ct)?;
    let plaintext_bytes = Zeroizing::new(crypto::decrypt_symmetric(
        &payload.cipher.alg,
        &ciphertext,
        &message_key,
        &nonce,
        payload.cipher.aad.as_bytes(),
    )?);
    let plaintext = Zeroizing::new(String::from_utf8((*plaintext_bytes).clone())?);

    Ok(plaintext)
}

fn encrypt_local_message(
    recipient_key: &LoadedOpsKey,
    plaintext: &str,
    envelope: &ProtectedMessageToken,
) -> Result<LocalCipherOutput, DynError> {
    let cipher =
        crypto::symmetric_cipher(recipient_key.keys().symmetric().variant()).ok_or_else(|| {
            Box::new(io::Error::new(
                io::ErrorKind::InvalidInput,
                "recipient symmetric algorithm is not supported",
            )) as DynError
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

    post_json::<_, serde_json::Value>(route.final_app_addr(), route.final_app_path(), &delivery)
        .await
        .map_err(|err| {
            final_app_delivery_error(route.final_app_addr(), route.final_app_path(), err)
        })?;

    Ok(())
}

fn final_app_delivery_error(addr: &str, path: &str, err: DynError) -> DynError {
    Box::new(io::Error::new(
        io::ErrorKind::Other,
        format!("final app can't be reached: addr={addr}, path={path}, error={err}"),
    ))
}

fn sign_message_payload(
    sender_key: &LoadedOpsKey,
    payload: &ProtectedMessagePayload,
) -> Result<TimestampSignatures, DynError> {
    let payload_bytes = serde_json::to_vec(payload)?;
    let payload_text = std::str::from_utf8(&payload_bytes)?;
    let eddsa = sender_key.keys().eddsa();
    let ml_dsa = sender_key.keys().ml_dsa();
    let eddsa_private_key = crypto::load_private_key_der_hex(eddsa.private_key_der_hex())?;
    let ml_dsa_private_key = crypto::load_private_key_der_hex(ml_dsa.private_key_der_hex())?;
    let eddsa_signature = crypto::sign_message(&eddsa_private_key, payload_text)?;
    let ml_dsa_signature = crypto::sign_ml_dsa_message(&ml_dsa_private_key, payload_text)?;

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
        return Err(Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            "signatures.eddsa.alg does not match sender public key",
        )));
    }
    if envelope.signatures.ml_dsa.alg != sender_public_keys.keys.keys.ml_dsa.alg {
        return Err(Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            "signatures.ml-dsa.alg does not match sender public key",
        )));
    }

    let payload_bytes = serde_json::to_vec(&envelope.payload)?;
    let payload_text = std::str::from_utf8(&payload_bytes)?;
    let eddsa_public_key =
        crypto::load_public_key_der_hex(&sender_public_keys.keys.keys.eddsa.public_key_der_hex)?;
    let ml_dsa_public_key =
        crypto::load_public_key_der_hex(&sender_public_keys.keys.keys.ml_dsa.public_key_der_hex)?;
    let eddsa_signature = hex::decode(&envelope.signatures.eddsa.sig)?;
    let ml_dsa_signature = hex::decode(&envelope.signatures.ml_dsa.sig)?;
    let eddsa_valid = crypto::verify_message(&eddsa_public_key, payload_text, &eddsa_signature)?;
    let ml_dsa_valid =
        crypto::verify_ml_dsa_message(&ml_dsa_public_key, payload_text, &ml_dsa_signature)?;

    if !eddsa_valid || !ml_dsa_valid {
        return Err(Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            "message signatures are invalid",
        )));
    }

    Ok(())
}

fn validate_message_envelope(envelope: &ProtectedMessageToken) -> Result<(), DynError> {
    validation::validate_allowed_value("version", &envelope.version, &["v1"])?;
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
        return Err(Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            "payload.cipher.aad does not match protected message metadata",
        )));
    }

    Ok(())
}

fn validate_message_envelope_for_recipient(
    recipient_key: &LoadedOpsKey,
    envelope: &ProtectedMessageToken,
) -> Result<(), DynError> {
    validate_message_envelope(envelope)?;

    if envelope.recipient_kid() != recipient_key.id() {
        return Err(Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            "payload.recipient.kid does not match loaded recipient key",
        )));
    }

    let expected_kem_alg = hybrid_kem_alg(
        recipient_key.keys().xecdh().variant(),
        recipient_key.keys().ml_kem().variant(),
    );
    if envelope.payload.kem.alg != expected_kem_alg {
        return Err(Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            "payload.kem.alg does not match recipient key algorithms",
        )));
    }

    let cipher = crypto::symmetric_cipher(&envelope.payload.cipher.alg).ok_or_else(|| {
        Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            "payload.cipher.alg is not supported",
        )) as DynError
    })?;
    if envelope.payload.cipher.nonce.len() != cipher.nonce_size_bytes * 2 {
        return Err(Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            "payload.cipher.nonce length does not match cipher algorithm",
        )));
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
    crypto::load_public_key_der_hex(&remote_key.keys.keys.eddsa.public_key_der_hex).map_err(
        |err| {
            Box::new(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("remote.keys.eddsa.public_key_der_hex is not a valid public key: {err}"),
            )) as DynError
        },
    )?;
    let xecdh_public_key = hex::decode(&remote_key.keys.keys.xecdh.public_key_hex)?;
    validate_xecdh_public_key_size(&remote_key.keys.keys.xecdh.alg, xecdh_public_key.len())?;
    crypto::load_public_key_der_hex(&remote_key.keys.keys.ml_dsa.public_key_der_hex).map_err(
        |err| {
            Box::new(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("remote.keys.ml-dsa.public_key_der_hex is not a valid public key: {err}"),
            )) as DynError
        },
    )?;

    let ml_kem_public_key = crypto::load_public_key_der_hex(
        &remote_key.keys.keys.ml_kem.public_key_der_hex,
    )
    .map_err(|err| {
        Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("remote.keys.ml-kem.public_key_der_hex is not a valid public key: {err}"),
        )) as DynError
    })?;
    let salt = Zeroizing::new(crypto::random_bytes(32)?);
    crypto::encapsulate_ml_kem_shared_key(&ml_kem_public_key, &salt, HYBRID_SECRET_SIZE_BYTES)
        .map_err(|err| {
            Box::new(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("remote.keys.ml-kem.public_key_der_hex cannot encapsulate: {err}"),
            )) as DynError
        })?;

    Ok(())
}

fn validate_xecdh_public_key_size(algorithm: &str, size_bytes: usize) -> Result<(), DynError> {
    let expected_size = match algorithm {
        "X25519" => 32,
        "X448" => 56,
        _ => {
            return Err(Box::new(io::Error::new(
                io::ErrorKind::InvalidInput,
                "remote.keys.xecdh.alg is not supported",
            )));
        }
    };

    if size_bytes != expected_size {
        return Err(Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "remote.keys.xecdh.public_key_hex must be {expected_size} bytes for {algorithm}, got {size_bytes}"
            ),
        )));
    }

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

    Ok(Zeroizing::new(crypto::hkdf_sha256(
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

async fn fetch_remote_public_keys(host: &str, kid: &str) -> Result<RemotePublicKeys, DynError> {
    validation::validate_host_port("recipient_host", host)?;
    keys::KeyId::parse(kid)?;

    let path = format!("/pub/{kid}");
    let keys = get_json::<PublicKeysOutput>(host, &path)
        .await
        .map_err(|err| remote_public_key_error(host, kid, err))?;
    let remote_key = RemotePublicKeys {
        host: host.to_string(),
        kid: kid.to_string(),
        loaded_at: validation::current_timestamp()?,
        info: keys.info.clone(),
        keys,
    };
    validate_remote_public_keys(&remote_key)?;
    info!(host = %host, kid = %kid, "remote public key loaded");

    Ok(remote_key)
}

fn remote_public_key_error(host: &str, kid: &str, err: DynError) -> DynError {
    let kind = err
        .downcast_ref::<io::Error>()
        .map(io::Error::kind)
        .unwrap_or(io::ErrorKind::Other);

    let message = if kind == io::ErrorKind::NotFound {
        format!("recipient_kid not found in remote /pub response: host={host}, recipient_kid={kid}")
    } else {
        format!(
            "recipient_kid could not be loaded from remote /pub response: host={host}, recipient_kid={kid}, error={err}"
        )
    };

    Box::new(io::Error::new(kind, message))
}

async fn get_json<T>(host: &str, path: &str) -> Result<T, DynError>
where
    T: DeserializeOwned,
{
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
    );
    let body = send_http_request(host, &request).await?;

    Ok(serde_json::from_slice(&body)?)
}

async fn post_json<TRequest, TResponse>(
    host: &str,
    path: &str,
    body: &TRequest,
) -> Result<TResponse, DynError>
where
    TRequest: Serialize,
    TResponse: DeserializeOwned,
{
    let body = serde_json::to_vec(body)?;
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nAccept: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        std::str::from_utf8(&body)?,
    );
    let body = send_http_request(host, &request).await?;

    Ok(serde_json::from_slice(&body)?)
}

async fn send_http_request(host: &str, request: &str) -> Result<Vec<u8>, DynError> {
    let mut stream = TcpStream::connect(host).await?;
    stream.write_all(request.as_bytes()).await?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    let split_at = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| {
            Box::new(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid HTTP response",
            )) as DynError
        })?;
    let headers = std::str::from_utf8(&response[..split_at])?;
    let status_line = headers.lines().next().ok_or_else(|| {
        Box::new(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid HTTP response status",
        )) as DynError
    })?;
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| {
            Box::new(io::Error::new(
                io::ErrorKind::InvalidData,
                "missing HTTP response status code",
            )) as DynError
        })?
        .parse::<u16>()?;

    if !(200..300).contains(&status_code) {
        warn!(
            host = %host,
            status_code,
            "remote HTTP request returned non-success status"
        );
        let error_kind = match status_code {
            400 => io::ErrorKind::InvalidInput,
            401 | 403 => io::ErrorKind::PermissionDenied,
            404 => io::ErrorKind::NotFound,
            _ => io::ErrorKind::InvalidData,
        };

        return Err(Box::new(io::Error::new(
            error_kind,
            format!("remote HTTP request failed with status {status_code}"),
        )));
    }

    Ok(response[split_at + 4..].to_vec())
}
