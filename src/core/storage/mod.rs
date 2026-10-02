use crate::core::{config, validation};
use crate::error::DynError;
use serde::Serialize;
use std::collections::{HashMap, HashSet};

struct TokenBatchReadBudget<'a> {
    occurrences: HashMap<&'a str, usize>,
    remaining: usize,
}

impl<'a> TokenBatchReadBudget<'a> {
    fn new(hashids: &'a [String], max_bytes: usize) -> Self {
        let mut occurrences = HashMap::new();
        for hashid in hashids {
            *occurrences.entry(hashid.as_str()).or_insert(0) += 1;
        }
        Self {
            occurrences,
            remaining: max_bytes,
        }
    }

    fn retain(&mut self, hashid: &str, data: &str) -> Result<(), DynError> {
        validate_token_hashid(hashid)?;
        validate_storage_envelope(
            "tokens.data",
            data,
            config::STORAGE_TOKEN_ENVELOPE_MAX_CHARS,
        )?;
        let count = self
            .occurrences
            .get(hashid)
            .copied()
            .ok_or_else(|| crate::error::internal("unexpected token batch row"))?;
        let bytes = data
            .len()
            .checked_mul(count)
            .and_then(|bytes| self.remaining.checked_sub(bytes))
            .ok_or_else(|| {
                Box::new(crate::error::VectisError::TokenDecodeBatchTooLarge) as DynError
            })?;
        self.remaining = bytes;
        Ok(())
    }
}

fn resolve_tokens_in_request_order(
    mut found: HashMap<String, String>,
    hashids: &[String],
) -> Vec<Option<String>> {
    let mut occurrences: HashMap<&str, usize> = HashMap::new();
    for hashid in hashids {
        *occurrences.entry(hashid.as_str()).or_insert(0) += 1;
    }
    hashids
        .iter()
        .map(|hashid| {
            let remaining = occurrences
                .get_mut(hashid.as_str())
                .expect("hashid counted above");
            *remaining -= 1;
            if *remaining == 0 {
                found.remove(hashid)
            } else {
                found.get(hashid).cloned()
            }
        })
        .collect()
}

mod postgres;
mod sqlite;

pub const STORAGE_TYPES: &[&str] = &["sqlite", "postgres"];

#[derive(Debug, Serialize)]
pub struct OpsKeyRow {
    pub kid: String,
    pub keys: String,
    pub properties: String,
}

#[derive(Debug, Serialize)]
pub struct TokenRow {
    pub kid: String,
    pub hashid: String,
    pub data: String,
}

#[derive(Debug, Serialize)]
pub struct IndexRow {
    pub kid: String,
    pub digest: String,
}

#[derive(Debug, thiserror::Error)]
pub enum TokenBatchConsumeError {
    #[error("token not found")]
    MissingToken { hashid: String },
    #[error(transparent)]
    Other(#[from] DynError),
}

pub struct StorageState {
    backend: StorageBackend,
}

enum StorageBackend {
    Sqlite(sqlite::SqliteStorage),
    Postgres(postgres::PostgresStorage),
}

impl StorageState {
    pub async fn new(config: &config::AppConfig) -> Result<Self, DynError> {
        match config.storage_type.as_str() {
            "sqlite" => Ok(Self {
                backend: StorageBackend::Sqlite(
                    sqlite::SqliteStorage::new(&config.sqlite_path).await?,
                ),
            }),
            "postgres" => Ok(Self {
                backend: StorageBackend::Postgres(
                    postgres::PostgresStorage::new(&config.postgres_dsn).await?,
                ),
            }),
            storage => unsupported_storage(storage),
        }
    }

    pub async fn save_ops_keys(
        &self,
        kid: &str,
        keys: &str,
        properties: &str,
    ) -> Result<OpsKeyRow, DynError> {
        validate_ops_key_fields(kid, keys, properties)?;
        match &self.backend {
            StorageBackend::Sqlite(sqlite) => sqlite.save_ops_keys(kid, keys, properties).await,
            StorageBackend::Postgres(postgres) => {
                postgres.save_ops_keys(kid, keys, properties).await
            }
        }
    }

    pub async fn get_ops_keys(&self, kid: &str) -> Result<OpsKeyRow, DynError> {
        validate_storage_kid("opskeys.kid", kid)?;
        let row = match &self.backend {
            StorageBackend::Sqlite(sqlite) => sqlite.get_ops_keys(kid).await,
            StorageBackend::Postgres(postgres) => postgres.get_ops_keys(kid).await,
        }?;
        validate_ops_key_row(&row)?;
        Ok(row)
    }

    pub async fn list_ops_keys(&self) -> Result<Vec<OpsKeyRow>, DynError> {
        let rows = match &self.backend {
            StorageBackend::Sqlite(sqlite) => sqlite.list_ops_keys().await,
            StorageBackend::Postgres(postgres) => postgres.list_ops_keys().await,
        }?;
        for row in &rows {
            validate_ops_key_row(row)?;
        }
        Ok(rows)
    }

    pub async fn save_token(
        &self,
        kid: &str,
        hashid: &str,
        data: &str,
    ) -> Result<TokenRow, DynError> {
        validate_token_fields(kid, hashid, data)?;
        match &self.backend {
            StorageBackend::Sqlite(sqlite) => sqlite.save_token(kid, hashid, data).await,
            StorageBackend::Postgres(postgres) => postgres.save_token(kid, hashid, data).await,
        }
    }

    pub async fn save_tokens_batch(&self, records: &[TokenRow]) -> Result<(), DynError> {
        for record in records {
            validate_token_row(record)?;
        }
        match &self.backend {
            StorageBackend::Sqlite(sqlite) => sqlite.save_tokens_batch(records).await,
            StorageBackend::Postgres(postgres) => postgres.save_tokens_batch(records).await,
        }
    }

    pub async fn get_tokens_batch(
        &self,
        kid: &str,
        hashids: &[String],
        max_envelope_bytes: usize,
    ) -> Result<Vec<Option<String>>, DynError> {
        validate_storage_kid("tokens.kid", kid)?;
        for hashid in hashids {
            validate_token_hashid(hashid)?;
        }
        let found = match &self.backend {
            StorageBackend::Sqlite(sqlite) => {
                sqlite
                    .get_tokens_batch(kid, hashids, max_envelope_bytes)
                    .await
            }
            StorageBackend::Postgres(postgres) => {
                postgres
                    .get_tokens_batch(kid, hashids, max_envelope_bytes)
                    .await
            }
        }?;
        Ok(resolve_tokens_in_request_order(found, hashids))
    }

    pub async fn get_token(&self, kid: &str, hashid: &str) -> Result<TokenRow, DynError> {
        validate_storage_kid("tokens.kid", kid)?;
        validate_token_hashid(hashid)?;
        let row = match &self.backend {
            StorageBackend::Sqlite(sqlite) => sqlite.get_token(kid, hashid).await,
            StorageBackend::Postgres(postgres) => postgres.get_token(kid, hashid).await,
        }?;
        validate_token_row(&row)?;
        Ok(row)
    }

    pub async fn consume_token(&self, kid: &str, hashid: &str) -> Result<(), DynError> {
        self.delete_token(kid, hashid).await
    }

    pub async fn delete_token(&self, kid: &str, hashid: &str) -> Result<(), DynError> {
        validate_storage_kid("tokens.kid", kid)?;
        validate_token_hashid(hashid)?;
        match &self.backend {
            StorageBackend::Sqlite(sqlite) => sqlite.delete_token(kid, hashid).await,
            StorageBackend::Postgres(postgres) => postgres.delete_token(kid, hashid).await,
        }
    }

    pub async fn consume_tokens_batch(
        &self,
        kid: &str,
        hashids: &[String],
    ) -> Result<(), TokenBatchConsumeError> {
        validate_storage_kid("tokens.kid", kid).map_err(TokenBatchConsumeError::from)?;
        validate_unique_token_hashids(hashids).map_err(TokenBatchConsumeError::from)?;
        match &self.backend {
            StorageBackend::Sqlite(sqlite) => sqlite.consume_tokens_batch(kid, hashids).await,
            StorageBackend::Postgres(postgres) => postgres.consume_tokens_batch(kid, hashids).await,
        }
    }

    pub async fn save_index(&self, kid: &str, digest: &str) -> Result<IndexRow, DynError> {
        validate_index_fields(kid, digest)?;
        match &self.backend {
            StorageBackend::Sqlite(sqlite) => sqlite.save_index(kid, digest).await,
            StorageBackend::Postgres(postgres) => postgres.save_index(kid, digest).await,
        }
    }

    pub async fn save_indexes_batch(&self, records: &[IndexRow]) -> Result<(), DynError> {
        for record in records {
            validate_index_row(record)?;
        }
        match &self.backend {
            StorageBackend::Sqlite(sqlite) => sqlite.save_indexes_batch(records).await,
            StorageBackend::Postgres(postgres) => postgres.save_indexes_batch(records).await,
        }
    }

    pub async fn index_exists(&self, kid: &str, digest: &str) -> Result<bool, DynError> {
        validate_index_fields(kid, digest)?;
        match &self.backend {
            StorageBackend::Sqlite(sqlite) => sqlite.index_exists(kid, digest).await,
            StorageBackend::Postgres(postgres) => postgres.index_exists(kid, digest).await,
        }
    }

    pub async fn indexes_matching(
        &self,
        kid: &str,
        digests: &[String],
    ) -> Result<std::collections::HashSet<String>, DynError> {
        validate_storage_kid("indexes.kid", kid)?;
        for digest in digests {
            validate_index_digest(digest)?;
        }
        let found = match &self.backend {
            StorageBackend::Sqlite(sqlite) => sqlite.indexes_matching(kid, digests).await,
            StorageBackend::Postgres(postgres) => postgres.indexes_matching(kid, digests).await,
        }?;
        for digest in &found {
            validate_index_digest(digest)?;
        }
        Ok(found)
    }

    pub async fn update_ops_key_properties(
        &self,
        kid: &str,
        properties: &str,
    ) -> Result<OpsKeyRow, DynError> {
        validate_storage_kid("opskeys.kid", kid)?;
        validate_storage_envelope(
            "opskeys.properties",
            properties,
            config::STORAGE_ENVELOPE_MAX_CHARS,
        )?;
        match &self.backend {
            StorageBackend::Sqlite(sqlite) => {
                sqlite.update_ops_key_properties(kid, properties).await
            }
            StorageBackend::Postgres(postgres) => {
                postgres.update_ops_key_properties(kid, properties).await
            }
        }
    }

    pub async fn update_ops_key_properties_if_current(
        &self,
        kid: &str,
        current_properties: &str,
        new_properties: &str,
    ) -> Result<OpsKeyRow, DynError> {
        validate_storage_kid("opskeys.kid", kid)?;
        for properties in [current_properties, new_properties] {
            validate_storage_envelope(
                "opskeys.properties",
                properties,
                config::STORAGE_ENVELOPE_MAX_CHARS,
            )?;
        }
        match &self.backend {
            StorageBackend::Sqlite(sqlite) => {
                sqlite
                    .update_ops_key_properties_if_current(kid, current_properties, new_properties)
                    .await
            }
            StorageBackend::Postgres(postgres) => {
                postgres
                    .update_ops_key_properties_if_current(kid, current_properties, new_properties)
                    .await
            }
        }
    }

    pub async fn health_check(&self) -> Result<(), DynError> {
        match &self.backend {
            StorageBackend::Sqlite(sqlite) => sqlite.health_check().await,
            StorageBackend::Postgres(postgres) => postgres.health_check().await,
        }
    }
}

fn validate_storage_kid(field: &str, kid: &str) -> Result<(), DynError> {
    validation::validate_hash_hex_field(field, kid, config::INTERNAL_KEYS_HASH)
}

fn validate_storage_envelope(field: &str, value: &str, max_chars: usize) -> Result<(), DynError> {
    validation::validate_base64_standard_envelope_segments(field, value, max_chars)?;
    Ok(())
}

fn validate_ops_key_fields(kid: &str, keys: &str, properties: &str) -> Result<(), DynError> {
    validate_storage_kid("opskeys.kid", kid)?;
    validate_storage_envelope("opskeys.keys", keys, config::STORAGE_ENVELOPE_MAX_CHARS)?;
    validate_storage_envelope(
        "opskeys.properties",
        properties,
        config::STORAGE_ENVELOPE_MAX_CHARS,
    )?;
    Ok(())
}

fn validate_ops_key_row(row: &OpsKeyRow) -> Result<(), DynError> {
    validate_ops_key_fields(&row.kid, &row.keys, &row.properties)
}

fn validate_token_hashid(hashid: &str) -> Result<(), DynError> {
    validation::validate_hash_hex_field("tokens.hashid", hashid, config::INTERNAL_KEYS_HASH)
}

fn validate_token_fields(kid: &str, hashid: &str, data: &str) -> Result<(), DynError> {
    validate_storage_kid("tokens.kid", kid)?;
    validate_token_hashid(hashid)?;
    validate_storage_envelope(
        "tokens.data",
        data,
        config::STORAGE_TOKEN_ENVELOPE_MAX_CHARS,
    )?;
    Ok(())
}

fn validate_token_row(row: &TokenRow) -> Result<(), DynError> {
    validate_token_fields(&row.kid, &row.hashid, &row.data)
}

fn validate_unique_token_hashids(hashids: &[String]) -> Result<(), DynError> {
    let mut seen = HashSet::with_capacity(hashids.len());
    for hashid in hashids {
        validate_token_hashid(hashid)?;
        if !seen.insert(hashid) {
            return Err(crate::error::invalid_input(
                "token batch contains duplicated token",
            ));
        }
    }
    Ok(())
}

fn validate_index_digest(digest: &str) -> Result<(), DynError> {
    validation::validate_hex_field("indexes.digest", digest)?;
    if digest.len() > config::STORAGE_INDEX_DIGEST_MAX_CHARS {
        return Err(crate::error::invalid_input(format!(
            "indexes.digest exceeds maximum allowed length: {}",
            config::STORAGE_INDEX_DIGEST_MAX_CHARS
        )));
    }
    Ok(())
}

fn validate_index_fields(kid: &str, digest: &str) -> Result<(), DynError> {
    validate_storage_kid("indexes.kid", kid)?;
    validate_index_digest(digest)
}

fn validate_index_row(row: &IndexRow) -> Result<(), DynError> {
    validate_index_fields(&row.kid, &row.digest)
}

fn unsupported_storage<T>(storage: &str) -> Result<T, DynError> {
    Err(crate::error::invalid_input(format!(
        "unsupported VECTIS_STORAGE: {storage}"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose};

    const KID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn envelope() -> String {
        format!(
            "{}.{}.{}",
            general_purpose::STANDARD.encode([1_u8; 16]),
            general_purpose::STANDARD.encode([2_u8; config::INTERNAL_KEYS_NONCE_SIZE_BYTES]),
            general_purpose::STANDARD.encode(b"type=test")
        )
    }

    #[test]
    fn token_batch_budget_counts_occurrences_and_checks_overflow() {
        let hashid = "b".repeat(64);
        let data = envelope();
        let ids = vec![hashid.clone(), hashid.clone()];
        let mut budget = TokenBatchReadBudget::new(&ids, data.len() * 2);
        budget.retain(&hashid, &data).unwrap();
        assert_eq!(budget.remaining, 0);
        let mut budget = TokenBatchReadBudget::new(&ids, data.len() * 2 - 1);
        assert!(matches!(
            budget.retain(&hashid, &data).unwrap_err().downcast_ref(),
            Some(crate::error::VectisError::TokenDecodeBatchTooLarge)
        ));
        budget.occurrences.insert(&hashid, usize::MAX);
        assert!(budget.retain(&hashid, &data).is_err());
    }

    #[test]
    fn validates_storage_rows_before_backend_use() {
        let encrypted = envelope();
        assert!(validate_ops_key_fields(KID, &encrypted, &encrypted).is_ok());
        assert!(validate_token_fields(KID, &"b".repeat(64), &encrypted).is_ok());
        assert!(validate_index_fields(KID, &"c".repeat(128)).is_ok());

        assert!(validate_ops_key_fields("kid", &encrypted, &encrypted).is_err());
        assert!(validate_token_fields(KID, "hash", &encrypted).is_err());
        assert!(validate_token_fields(KID, &"b".repeat(64), "bad.data").is_err());
        assert!(validate_index_fields(KID, "not-hex").is_err());
        assert!(validate_index_fields(KID, &"d".repeat(130)).is_err());
    }

    #[test]
    fn token_envelope_limit_is_independent_of_operational_keys() {
        // Padded Base64 segments plus two dots have length 2 modulo 4.
        let overhead = envelope().len() - 24;
        let ciphertext_chars = (config::STORAGE_TOKEN_ENVELOPE_MAX_CHARS - overhead) / 4 * 4;
        let encrypted = format!("{}{}", "A".repeat(ciphertext_chars), &envelope()[24..]);
        assert_eq!(
            encrypted.len(),
            config::STORAGE_TOKEN_ENVELOPE_MAX_CHARS - 2
        );
        assert!(validate_token_fields(KID, &"b".repeat(64), &encrypted).is_ok());
        assert!(
            validate_token_row(&TokenRow {
                kid: KID.to_string(),
                hashid: "b".repeat(64),
                data: encrypted.clone(),
            })
            .is_ok()
        );
        assert!(validate_ops_key_fields(KID, &encrypted, &envelope()).is_err());
        assert!(validate_ops_key_fields(KID, &envelope(), &encrypted).is_err());
        let too_large = format!("AAAA{encrypted}");
        assert!(validate_token_fields(KID, &"b".repeat(64), &too_large).is_err());
    }

    #[test]
    fn token_batch_hashids_must_be_unique() {
        let hashid = "b".repeat(64);
        assert!(validate_unique_token_hashids(&[hashid.clone(), hashid]).is_err());
    }
}
