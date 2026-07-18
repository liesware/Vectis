use crate::core::config;
use crate::error::DynError;
use serde::Serialize;

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
        match &self.backend {
            StorageBackend::Sqlite(sqlite) => sqlite.save_ops_keys(kid, keys, properties).await,
            StorageBackend::Postgres(postgres) => {
                postgres.save_ops_keys(kid, keys, properties).await
            }
        }
    }

    pub async fn get_ops_keys(&self, kid: &str) -> Result<OpsKeyRow, DynError> {
        match &self.backend {
            StorageBackend::Sqlite(sqlite) => sqlite.get_ops_keys(kid).await,
            StorageBackend::Postgres(postgres) => postgres.get_ops_keys(kid).await,
        }
    }

    pub async fn list_ops_keys(&self) -> Result<Vec<OpsKeyRow>, DynError> {
        match &self.backend {
            StorageBackend::Sqlite(sqlite) => sqlite.list_ops_keys().await,
            StorageBackend::Postgres(postgres) => postgres.list_ops_keys().await,
        }
    }

    pub async fn save_token(
        &self,
        kid: &str,
        hashid: &str,
        data: &str,
    ) -> Result<TokenRow, DynError> {
        match &self.backend {
            StorageBackend::Sqlite(sqlite) => sqlite.save_token(kid, hashid, data).await,
            StorageBackend::Postgres(postgres) => postgres.save_token(kid, hashid, data).await,
        }
    }

    pub async fn save_tokens_batch(&self, records: &[TokenRow]) -> Result<(), DynError> {
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
        match &self.backend {
            StorageBackend::Sqlite(sqlite) => sqlite.get_tokens_batch(kid, hashids).await,
            StorageBackend::Postgres(postgres) => postgres.get_tokens_batch(kid, hashids).await,
        }
    }

    pub async fn get_token(&self, kid: &str, hashid: &str) -> Result<TokenRow, DynError> {
        match &self.backend {
            StorageBackend::Sqlite(sqlite) => sqlite.get_token(kid, hashid).await,
            StorageBackend::Postgres(postgres) => postgres.get_token(kid, hashid).await,
        }
    }

    pub async fn save_index(&self, kid: &str, digest: &str) -> Result<IndexRow, DynError> {
        match &self.backend {
            StorageBackend::Sqlite(sqlite) => sqlite.save_index(kid, digest).await,
            StorageBackend::Postgres(postgres) => postgres.save_index(kid, digest).await,
        }
    }

    pub async fn save_indexes_batch(&self, records: &[IndexRow]) -> Result<(), DynError> {
        match &self.backend {
            StorageBackend::Sqlite(sqlite) => sqlite.save_indexes_batch(records).await,
            StorageBackend::Postgres(postgres) => postgres.save_indexes_batch(records).await,
        }
    }

    pub async fn index_exists(&self, kid: &str, digest: &str) -> Result<bool, DynError> {
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
        match &self.backend {
            StorageBackend::Sqlite(sqlite) => sqlite.indexes_matching(kid, digests).await,
            StorageBackend::Postgres(postgres) => postgres.indexes_matching(kid, digests).await,
        }
    }

    pub async fn update_ops_key_properties(
        &self,
        kid: &str,
        properties: &str,
    ) -> Result<OpsKeyRow, DynError> {
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

fn unsupported_storage<T>(storage: &str) -> Result<T, DynError> {
    Err(crate::error::invalid_input(format!(
        "unsupported VECTIS_STORAGE: {storage}"
    )))
}
