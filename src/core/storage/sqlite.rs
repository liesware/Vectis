use crate::core::storage::OpsKeyRow;
use crate::error::DynError;
use sqlx::Row;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool};
use tracing::info;

pub struct SqliteStorage {
    pool: SqlitePool,
}

impl SqliteStorage {
    pub async fn new(path: &std::path::Path) -> Result<Self, DynError> {
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(false);
        let pool = SqlitePool::connect_with(options).await.map_err(|err| {
            crate::error::storage(format!("failed to connect to ops sqlite: {err}"))
        })?;
        info!(path = %path.display(), "connected to ops sqlite");

        validate_ops_keys_schema(&pool).await?;
        info!("validated ops_keys sqlite schema");

        Ok(Self { pool })
    }

    pub async fn save_ops_keys(
        &self,
        id: &str,
        enc_keys: &str,
        properties: &str,
    ) -> Result<OpsKeyRow, DynError> {
        sqlx::query(
            "
            INSERT INTO ops_keys (id, enc_keys, properties)
            VALUES (?, ?, ?)
            ",
        )
        .bind(id)
        .bind(enc_keys)
        .bind(properties)
        .execute(&self.pool)
        .await?;
        info!(id, "inserted ops keys");

        Ok(OpsKeyRow {
            id: id.to_string(),
            enc_keys: enc_keys.to_string(),
            properties: properties.to_string(),
        })
    }

    pub async fn get_ops_keys(&self, id: &str) -> Result<OpsKeyRow, DynError> {
        let row = sqlx::query(
            "
            SELECT id, enc_keys, properties
            FROM ops_keys
            WHERE id = ?
            ",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row else {
            return Err(crate::error::not_found(format!("ops key not found: {id}")));
        };

        Ok(OpsKeyRow {
            id: row.get("id"),
            enc_keys: row.get("enc_keys"),
            properties: row.get("properties"),
        })
    }

    pub async fn list_ops_keys(&self) -> Result<Vec<OpsKeyRow>, DynError> {
        let rows = sqlx::query(
            "
            SELECT id, enc_keys, properties
            FROM ops_keys
            ORDER BY id
            ",
        )
        .fetch_all(&self.pool)
        .await?;

        let mut keys = Vec::new();
        for row in rows {
            keys.push(OpsKeyRow {
                id: row.get("id"),
                enc_keys: row.get("enc_keys"),
                properties: row.get("properties"),
            });
        }

        Ok(keys)
    }

    pub async fn update_ops_key_properties(
        &self,
        id: &str,
        properties: &str,
    ) -> Result<OpsKeyRow, DynError> {
        let result = sqlx::query(
            "
            UPDATE ops_keys
            SET properties = ?
            WHERE id = ?
            ",
        )
        .bind(properties)
        .bind(id)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(crate::error::not_found(format!("ops key not found: {id}")));
        }

        info!(id, "updated ops key properties");
        self.get_ops_keys(id).await
    }

    pub async fn update_ops_key_properties_if_current(
        &self,
        id: &str,
        current_properties: &str,
        new_properties: &str,
    ) -> Result<OpsKeyRow, DynError> {
        let result = sqlx::query(
            "
            UPDATE ops_keys
            SET properties = ?
            WHERE id = ?
              AND properties = ?
            ",
        )
        .bind(new_properties)
        .bind(id)
        .bind(current_properties)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            self.get_ops_keys(id).await?;
            return Err(crate::error::invalid_input(
                "ops key properties changed concurrently; retry lifecycle update",
            ));
        }

        info!(id, "updated ops key properties with compare-and-swap");
        self.get_ops_keys(id).await
    }

    pub async fn health_check(&self) -> Result<(), DynError> {
        sqlx::query("SELECT 1").execute(&self.pool).await?;

        Ok(())
    }
}

async fn validate_ops_keys_schema(db: &SqlitePool) -> Result<(), DynError> {
    let rows = sqlx::query("PRAGMA table_info(ops_keys)")
        .fetch_all(db)
        .await?;

    if rows.is_empty() {
        return Err(crate::error::storage(
            "sqlite schema is missing ops_keys table",
        ));
    }

    let id = find_column(&rows, "id")
        .ok_or_else(|| crate::error::storage("sqlite schema is missing ops_keys.id column"))?;
    let enc_keys = find_column(&rows, "enc_keys").ok_or_else(|| {
        crate::error::storage("sqlite schema is missing ops_keys.enc_keys column")
    })?;
    let properties = find_column(&rows, "properties").ok_or_else(|| {
        crate::error::storage("sqlite schema is missing ops_keys.properties column")
    })?;

    validate_column(&id, "id", "VARCHAR(128)", false, true)?;
    validate_column(&enc_keys, "enc_keys", "VARCHAR(10240)", true, false)?;
    validate_column(&properties, "properties", "VARCHAR(10240)", true, false)?;

    Ok(())
}

struct ColumnInfo {
    name: String,
    column_type: String,
    notnull: bool,
    primary_key: bool,
}

fn find_column(rows: &[sqlx::sqlite::SqliteRow], name: &str) -> Option<ColumnInfo> {
    rows.iter().find_map(|row| {
        let column_name: String = row.get("name");
        if column_name != name {
            return None;
        }

        let column_type: String = row.get("type");
        let notnull: i64 = row.get("notnull");
        let primary_key: i64 = row.get("pk");

        Some(ColumnInfo {
            name: column_name,
            column_type,
            notnull: notnull == 1,
            primary_key: primary_key == 1,
        })
    })
}

fn validate_column(
    column: &ColumnInfo,
    expected_name: &str,
    expected_type: &str,
    expected_notnull: bool,
    expected_primary_key: bool,
) -> Result<(), DynError> {
    if column.name != expected_name
        || !column.column_type.eq_ignore_ascii_case(expected_type)
        || column.notnull != expected_notnull
        || column.primary_key != expected_primary_key
    {
        return Err(crate::error::storage(format!(
            "sqlite schema mismatch for ops_keys.{expected_name}: expected type={expected_type}, notnull={expected_notnull}, primary_key={expected_primary_key}",
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{VectisError, is_not_found};
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    async fn test_storage(name: &str) -> (SqliteStorage, PathBuf) {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time must be valid")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "vectis-sqlite-cas-{}-{name}-{nonce}.db",
            std::process::id()
        ));

        let options = SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(true);
        let pool = SqlitePool::connect_with(options)
            .await
            .expect("test sqlite must connect");
        sqlx::query(
            "
            CREATE TABLE ops_keys (
                id VARCHAR(128) PRIMARY KEY,
                enc_keys VARCHAR(10240) NOT NULL,
                properties VARCHAR(10240) NOT NULL
            )
            ",
        )
        .execute(&pool)
        .await
        .expect("test schema must be created");
        pool.close().await;

        let storage = SqliteStorage::new(&path)
            .await
            .expect("test storage must validate");

        (storage, path)
    }

    async fn cleanup(path: PathBuf) {
        let _ = tokio::fs::remove_file(path).await;
    }

    #[tokio::test]
    async fn cas_update_succeeds_when_properties_match() {
        let (storage, path) = test_storage("match").await;
        storage
            .save_ops_keys("key-1", "enc", "properties-v1")
            .await
            .expect("row must be inserted");

        let row = storage
            .update_ops_key_properties_if_current("key-1", "properties-v1", "properties-v2")
            .await
            .expect("matching CAS must update");

        assert_eq!(row.properties, "properties-v2");
        cleanup(path).await;
    }

    #[tokio::test]
    async fn cas_update_rejects_stale_properties() {
        let (storage, path) = test_storage("stale").await;
        storage
            .save_ops_keys("key-1", "enc", "properties-v1")
            .await
            .expect("row must be inserted");
        storage
            .update_ops_key_properties_if_current("key-1", "properties-v1", "properties-v2")
            .await
            .expect("first CAS must update");

        let err = match storage
            .update_ops_key_properties_if_current("key-1", "properties-v1", "properties-v3")
            .await
        {
            Ok(_) => panic!("stale CAS must fail"),
            Err(err) => err,
        };
        assert!(matches!(
            err.downcast_ref::<VectisError>(),
            Some(VectisError::InvalidInput(message))
                if message == "ops key properties changed concurrently; retry lifecycle update"
        ));

        let row = storage
            .get_ops_keys("key-1")
            .await
            .expect("row must still exist");
        assert_eq!(row.properties, "properties-v2");
        cleanup(path).await;
    }

    #[tokio::test]
    async fn cas_update_missing_key_returns_not_found() {
        let (storage, path) = test_storage("missing").await;

        let err = match storage
            .update_ops_key_properties_if_current("missing", "properties-v1", "properties-v2")
            .await
        {
            Ok(_) => panic!("missing row must fail"),
            Err(err) => err,
        };
        assert!(is_not_found(err.as_ref()));
        cleanup(path).await;
    }
}
