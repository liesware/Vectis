use crate::core::{config, validation};
use crate::error::DynError;
use serde::Serialize;
use std::collections::HashSet;

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
    ) -> Result<std::collections::HashMap<String, String>, DynError> {
        validate_storage_kid("tokens.kid", kid)?;
        for hashid in hashids {
            validate_token_hashid(hashid)?;
        }
        let found = match &self.backend {
            StorageBackend::Sqlite(sqlite) => sqlite.get_tokens_batch(kid, hashids).await,
            StorageBackend::Postgres(postgres) => postgres.get_tokens_batch(kid, hashids).await,
        }?;
        for (hashid, data) in &found {
            validate_token_hashid(hashid)?;
            validate_storage_envelope("tokens.data", data)?;
        }
        Ok(found)
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
        validate_storage_kid("tokens.kid", kid)?;
        validate_token_hashid(hashid)?;
        match &self.backend {
            StorageBackend::Sqlite(sqlite) => sqlite.consume_token(kid, hashid).await,
            StorageBackend::Postgres(postgres) => postgres.consume_token(kid, hashid).await,
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
        validate_storage_envelope("opskeys.properties", properties)?;
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
            validate_storage_envelope("opskeys.properties", properties)?;
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

fn validate_storage_envelope(field: &str, value: &str) -> Result<(), DynError> {
    validation::validate_base64_standard_envelope_segments(
        field,
        value,
        config::STORAGE_ENVELOPE_MAX_CHARS,
    )?;
    Ok(())
}

fn validate_ops_key_fields(kid: &str, keys: &str, properties: &str) -> Result<(), DynError> {
    validate_storage_kid("opskeys.kid", kid)?;
    validate_storage_envelope("opskeys.keys", keys)?;
    validate_storage_envelope("opskeys.properties", properties)?;
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
    validate_storage_envelope("tokens.data", data)?;
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
    fn token_batch_hashids_must_be_unique() {
        let hashid = "b".repeat(64);
        assert!(validate_unique_token_hashids(&[hashid.clone(), hashid]).is_err());
    }
}
