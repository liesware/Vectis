use crate::core::storage::{OpsKeyRow, TokenRow};
use crate::error::DynError;
use sqlx::Row;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool};
use std::collections::HashMap;
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

        validate_opskeys_schema(&pool).await?;
        info!("validated opskeys sqlite schema");
        validate_tokens_schema(&pool).await?;
        info!("validated tokens sqlite schema");

        Ok(Self { pool })
    }

    pub async fn save_ops_keys(
        &self,
        kid: &str,
        keys: &str,
        properties: &str,
    ) -> Result<OpsKeyRow, DynError> {
        sqlx::query(
            "
            INSERT INTO opskeys (kid, keys, properties)
            VALUES (?, ?, ?)
            ",
        )
        .bind(kid)
        .bind(keys)
        .bind(properties)
        .execute(&self.pool)
        .await?;
        info!(kid, "inserted ops keys");

        Ok(OpsKeyRow {
            kid: kid.to_string(),
            keys: keys.to_string(),
            properties: properties.to_string(),
        })
    }

    pub async fn get_ops_keys(&self, kid: &str) -> Result<OpsKeyRow, DynError> {
        let row = sqlx::query(
            "
            SELECT kid, keys, properties
            FROM opskeys
            WHERE kid = ?
            ",
        )
        .bind(kid)
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row else {
            return Err(crate::error::not_found(format!("ops key not found: {kid}")));
        };

        Ok(OpsKeyRow {
            kid: row.get("kid"),
            keys: row.get("keys"),
            properties: row.get("properties"),
        })
    }

    pub async fn list_ops_keys(&self) -> Result<Vec<OpsKeyRow>, DynError> {
        let rows = sqlx::query(
            "
            SELECT kid, keys, properties
            FROM opskeys
            ORDER BY kid
            ",
        )
        .fetch_all(&self.pool)
        .await?;

        let mut keys = Vec::new();
        for row in rows {
            keys.push(OpsKeyRow {
                kid: row.get("kid"),
                keys: row.get("keys"),
                properties: row.get("properties"),
            });
        }

        Ok(keys)
    }

    pub async fn save_token(
        &self,
        kid: &str,
        hashid: &str,
        data: &str,
    ) -> Result<TokenRow, DynError> {
        sqlx::query(
            "
            INSERT INTO tokens (kid, hashid, data)
            VALUES (?, ?, ?)
            ",
        )
        .bind(kid)
        .bind(hashid)
        .bind(data)
        .execute(&self.pool)
        .await?;
        info!(kid, hashid, "inserted token");

        Ok(TokenRow {
            kid: kid.to_string(),
            hashid: hashid.to_string(),
            data: data.to_string(),
        })
    }

    pub async fn save_tokens_batch(&self, records: &[TokenRow]) -> Result<(), DynError> {
        let mut tx = self.pool.begin().await?;
        for record in records {
            sqlx::query(
                "
                INSERT INTO tokens (kid, hashid, data)
                VALUES (?, ?, ?)
                ",
            )
            .bind(&record.kid)
            .bind(&record.hashid)
            .bind(&record.data)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        info!(items_count = records.len(), "inserted token batch");

        Ok(())
    }

    pub async fn get_tokens_batch(
        &self,
        kid: &str,
        hashids: &[String],
    ) -> Result<HashMap<String, String>, DynError> {
        if hashids.is_empty() {
            return Ok(HashMap::new());
        }
        let placeholders = std::iter::repeat_n("?", hashids.len())
            .collect::<Vec<_>>()
            .join(", ");
        let sql =
            format!("SELECT hashid, data FROM tokens WHERE kid = ? AND hashid IN ({placeholders})");
        let mut query = sqlx::query(&sql).bind(kid);
        for hashid in hashids {
            query = query.bind(hashid);
        }
        let rows = query.fetch_all(&self.pool).await?;

        let mut found = HashMap::with_capacity(rows.len());
        for row in rows {
            found.insert(row.get("hashid"), row.get("data"));
        }
        Ok(found)
    }

    pub async fn get_token(&self, kid: &str, hashid: &str) -> Result<TokenRow, DynError> {
        let row = sqlx::query(
            "
            SELECT kid, hashid, data
            FROM tokens
            WHERE kid = ?
              AND hashid = ?
            ",
        )
        .bind(kid)
        .bind(hashid)
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row else {
            return Err(crate::error::not_found("token not found"));
        };

        Ok(TokenRow {
            kid: row.get("kid"),
            hashid: row.get("hashid"),
            data: row.get("data"),
        })
    }

    pub async fn update_ops_key_properties(
        &self,
        kid: &str,
        properties: &str,
    ) -> Result<OpsKeyRow, DynError> {
        let result = sqlx::query(
            "
            UPDATE opskeys
            SET properties = ?
            WHERE kid = ?
            ",
        )
        .bind(properties)
        .bind(kid)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(crate::error::not_found(format!("ops key not found: {kid}")));
        }

        info!(kid, "updated ops key properties");
        self.get_ops_keys(kid).await
    }

    pub async fn update_ops_key_properties_if_current(
        &self,
        kid: &str,
        current_properties: &str,
        new_properties: &str,
    ) -> Result<OpsKeyRow, DynError> {
        let result = sqlx::query(
            "
            UPDATE opskeys
            SET properties = ?
            WHERE kid = ?
              AND properties = ?
            ",
        )
        .bind(new_properties)
        .bind(kid)
        .bind(current_properties)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            self.get_ops_keys(kid).await?;
            return Err(crate::error::invalid_input(
                "ops key properties changed concurrently; retry lifecycle update",
            ));
        }

        info!(kid, "updated ops key properties with compare-and-swap");
        self.get_ops_keys(kid).await
    }

    pub async fn health_check(&self) -> Result<(), DynError> {
        sqlx::query("SELECT 1").execute(&self.pool).await?;

        Ok(())
    }
}

async fn validate_opskeys_schema(db: &SqlitePool) -> Result<(), DynError> {
    let rows = sqlx::query("PRAGMA table_info(opskeys)")
        .fetch_all(db)
        .await?;

    if rows.is_empty() {
        return Err(crate::error::storage(
            "sqlite schema is missing opskeys table",
        ));
    }

    let kid = find_column(&rows, "kid")
        .ok_or_else(|| crate::error::storage("sqlite schema is missing opskeys.kid column"))?;
    let keys = find_column(&rows, "keys")
        .ok_or_else(|| crate::error::storage("sqlite schema is missing opskeys.keys column"))?;
    let properties = find_column(&rows, "properties").ok_or_else(|| {
        crate::error::storage("sqlite schema is missing opskeys.properties column")
    })?;

    validate_column(&kid, "opskeys", "kid", "VARCHAR(128)", false, Some(1))?;
    validate_column(&keys, "opskeys", "keys", "VARCHAR(10240)", true, None)?;
    validate_column(
        &properties,
        "opskeys",
        "properties",
        "VARCHAR(10240)",
        true,
        None,
    )?;

    Ok(())
}

async fn validate_tokens_schema(db: &SqlitePool) -> Result<(), DynError> {
    let rows = sqlx::query("PRAGMA table_info(tokens)")
        .fetch_all(db)
        .await?;

    if rows.is_empty() {
        return Err(crate::error::storage(
            "sqlite schema is missing tokens table",
        ));
    }

    let kid = find_column(&rows, "kid")
        .ok_or_else(|| crate::error::storage("sqlite schema is missing tokens.kid column"))?;
    let hashid = find_column(&rows, "hashid")
        .ok_or_else(|| crate::error::storage("sqlite schema is missing tokens.hashid column"))?;
    let data = find_column(&rows, "data")
        .ok_or_else(|| crate::error::storage("sqlite schema is missing tokens.data column"))?;

    validate_column(&kid, "tokens", "kid", "VARCHAR(128)", true, Some(1))?;
    validate_column(&hashid, "tokens", "hashid", "VARCHAR(128)", true, Some(2))?;
    validate_column(&data, "tokens", "data", "VARCHAR(10240)", true, None)?;

    Ok(())
}

struct ColumnInfo {
    name: String,
    column_type: String,
    notnull: bool,
    primary_key_position: i64,
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
            primary_key_position: primary_key,
        })
    })
}

fn validate_column(
    column: &ColumnInfo,
    table_name: &str,
    expected_name: &str,
    expected_type: &str,
    expected_notnull: bool,
    expected_primary_key_position: Option<i64>,
) -> Result<(), DynError> {
    let expected_primary_key_position = expected_primary_key_position.unwrap_or(0);
    if column.name != expected_name
        || !column.column_type.eq_ignore_ascii_case(expected_type)
        || column.notnull != expected_notnull
        || column.primary_key_position != expected_primary_key_position
    {
        return Err(crate::error::storage(format!(
            "sqlite schema mismatch for {table_name}.{expected_name}: expected type={expected_type}, notnull={expected_notnull}, primary_key_position={expected_primary_key_position}",
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
            CREATE TABLE opskeys (
                kid VARCHAR(128) PRIMARY KEY,
                keys VARCHAR(10240) NOT NULL,
                properties VARCHAR(10240) NOT NULL
            )
            ",
        )
        .execute(&pool)
        .await
        .expect("test schema must be created");
        sqlx::query(
            "
            CREATE TABLE tokens (
                kid VARCHAR(128) NOT NULL,
                hashid VARCHAR(128) NOT NULL,
                data VARCHAR(10240) NOT NULL,
                PRIMARY KEY (kid, hashid)
            )
            ",
        )
        .execute(&pool)
        .await
        .expect("test token schema must be created");
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

    #[tokio::test]
    async fn token_save_and_get_round_trips() {
        let (storage, path) = test_storage("token").await;

        let saved = storage
            .save_token("kid-1", "hash-1", "ciphertext.nonce.aad")
            .await
            .expect("token must save");
        assert_eq!(saved.kid, "kid-1");
        assert_eq!(saved.hashid, "hash-1");

        let loaded = storage
            .get_token("kid-1", "hash-1")
            .await
            .expect("token must load");
        assert_eq!(loaded.data, "ciphertext.nonce.aad");

        let err = storage
            .get_token("kid-1", "missing")
            .await
            .expect_err("missing token must fail");
        assert!(is_not_found(err.as_ref()));

        cleanup(path).await;
    }

    #[tokio::test]
    async fn token_batch_save_rolls_back_on_insert_failure() {
        let (storage, path) = test_storage("token-batch-rollback").await;
        let records = vec![
            TokenRow {
                kid: String::from("kid-1"),
                hashid: String::from("hash-1"),
                data: String::from("ciphertext-1.nonce.aad"),
            },
            TokenRow {
                kid: String::from("kid-1"),
                hashid: String::from("hash-1"),
                data: String::from("ciphertext-2.nonce.aad"),
            },
        ];

        storage
            .save_tokens_batch(&records)
            .await
            .expect_err("duplicate token in batch must fail");

        let err = storage
            .get_token("kid-1", "hash-1")
            .await
            .expect_err("failed batch must not leave partial token");
        assert!(is_not_found(err.as_ref()));

        cleanup(path).await;
    }

    #[tokio::test]
    async fn get_tokens_batch_returns_found_rows_only() {
        let (storage, path) = test_storage("token-batch-get").await;
        storage
            .save_token("kid-1", "hash-1", "data-1")
            .await
            .expect("token must save");
        storage
            .save_token("kid-1", "hash-2", "data-2")
            .await
            .expect("token must save");

        let found = storage
            .get_tokens_batch(
                "kid-1",
                &[
                    String::from("hash-1"),
                    String::from("hash-2"),
                    String::from("hash-missing"),
                ],
            )
            .await
            .expect("batch lookup must succeed");

        assert_eq!(found.len(), 2);
        assert_eq!(found.get("hash-1").map(String::as_str), Some("data-1"));
        assert_eq!(found.get("hash-2").map(String::as_str), Some("data-2"));
        assert!(!found.contains_key("hash-missing"));

        cleanup(path).await;
    }
}
