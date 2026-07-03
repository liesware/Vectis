use crate::core::config;
use crate::error::DynError;
use serde::Serialize;

mod postgres;
mod sqlite;

pub const STORAGE_TYPES: &[&str] = &["sqlite", "postgres"];

#[derive(Serialize)]
pub struct OpsKeyRow {
    pub id: String,
    pub enc_keys: String,
    pub properties: String,
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
        id: &str,
        enc_keys: &str,
        properties: &str,
    ) -> Result<OpsKeyRow, DynError> {
        match &self.backend {
            StorageBackend::Sqlite(sqlite) => sqlite.save_ops_keys(id, enc_keys, properties).await,
            StorageBackend::Postgres(postgres) => {
                postgres.save_ops_keys(id, enc_keys, properties).await
            }
        }
    }

    pub async fn get_ops_keys(&self, id: &str) -> Result<OpsKeyRow, DynError> {
        match &self.backend {
            StorageBackend::Sqlite(sqlite) => sqlite.get_ops_keys(id).await,
            StorageBackend::Postgres(postgres) => postgres.get_ops_keys(id).await,
        }
    }

    pub async fn list_ops_keys(&self) -> Result<Vec<OpsKeyRow>, DynError> {
        match &self.backend {
            StorageBackend::Sqlite(sqlite) => sqlite.list_ops_keys().await,
            StorageBackend::Postgres(postgres) => postgres.list_ops_keys().await,
        }
    }

    pub async fn update_ops_key_properties(
        &self,
        id: &str,
        properties: &str,
    ) -> Result<OpsKeyRow, DynError> {
        match &self.backend {
            StorageBackend::Sqlite(sqlite) => {
                sqlite.update_ops_key_properties(id, properties).await
            }
            StorageBackend::Postgres(postgres) => {
                postgres.update_ops_key_properties(id, properties).await
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
