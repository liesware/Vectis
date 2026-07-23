use crate::core::storage::{IndexRow, OpsKeyRow, TokenRow};
use crate::error::DynError;
use sqlx::Row;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use tracing::info;

pub struct SqliteStorage {
    pool: SqlitePool,
    path: PathBuf,
}

impl SqliteStorage {
    pub async fn new(path: &Path) -> Result<Self, DynError> {
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(false);
        let context = sqlite_context(path);
        let pool = SqlitePool::connect_with(options).await.map_err(|err| {
            crate::error::storage(format!(
                "failed to connect to ops sqlite at {context}: {err}"
            ))
        })?;
        info!(path = %path.display(), "connected to ops sqlite");

        validate_opskeys_schema(&pool, &context).await?;
        info!("validated opskeys sqlite schema");
        validate_tokens_schema(&pool, &context).await?;
        info!("validated tokens sqlite schema");
        validate_indexes_schema(&pool, &context).await?;
        info!("validated indexes sqlite schema");

        Ok(Self {
            pool,
            path: path.to_path_buf(),
        })
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

    pub async fn save_index(&self, kid: &str, digest: &str) -> Result<IndexRow, DynError> {
        sqlx::query(
            "
            INSERT OR IGNORE INTO indexes (kid, digest)
            VALUES (?, ?)
            ",
        )
        .bind(kid)
        .bind(digest)
        .execute(&self.pool)
        .await?;
        info!(kid, "inserted index");

        Ok(IndexRow {
            kid: kid.to_string(),
            digest: digest.to_string(),
        })
    }

    pub async fn save_indexes_batch(&self, records: &[IndexRow]) -> Result<(), DynError> {
        if records.is_empty() {
            return Ok(());
        }
        let placeholders = vec!["(?, ?)"; records.len()].join(", ");
        let sql = format!("INSERT OR IGNORE INTO indexes (kid, digest) VALUES {placeholders}");
        let mut query = sqlx::query(&sql);
        for record in records {
            query = query.bind(&record.kid).bind(&record.digest);
        }
        query.execute(&self.pool).await?;
        info!(items_count = records.len(), "inserted index batch");

        Ok(())
    }

    pub async fn index_exists(&self, kid: &str, digest: &str) -> Result<bool, DynError> {
        let row = sqlx::query(
            "
            SELECT 1
            FROM indexes
            WHERE kid = ?
              AND digest = ?
            ",
        )
        .bind(kid)
        .bind(digest)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.is_some())
    }

    pub async fn indexes_matching(
        &self,
        kid: &str,
        digests: &[String],
    ) -> Result<HashSet<String>, DynError> {
        if digests.is_empty() {
            return Ok(HashSet::new());
        }
        let placeholders = vec!["?"; digests.len()].join(", ");
        let sql =
            format!("SELECT digest FROM indexes WHERE kid = ? AND digest IN ({placeholders})");
        let mut query = sqlx::query(&sql).bind(kid);
        for digest in digests {
            query = query.bind(digest);
        }
        let rows = query.fetch_all(&self.pool).await?;

        Ok(rows.into_iter().map(|row| row.get("digest")).collect())
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
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await
            .map_err(|err| {
                crate::error::storage(format!(
                    "sqlite health check failed at {}: {err}",
                    sqlite_context(&self.path)
                ))
            })?;

        Ok(())
    }
}

fn sqlite_context(path: &Path) -> String {
    path.display().to_string()
}

async fn validate_opskeys_schema(db: &SqlitePool, context: &str) -> Result<(), DynError> {
    let rows = sqlx::query("PRAGMA table_info(opskeys)")
        .fetch_all(db)
        .await?;

    if rows.is_empty() {
        return Err(crate::error::storage(format!(
            "sqlite schema is missing opskeys table ({context})",
        )));
    }

    let kid = find_column(&rows, "kid").ok_or_else(|| {
        crate::error::storage(format!(
            "sqlite schema is missing opskeys.kid column ({context})"
        ))
    })?;
    let keys = find_column(&rows, "keys").ok_or_else(|| {
        crate::error::storage(format!(
            "sqlite schema is missing opskeys.keys column ({context})"
        ))
    })?;
    let properties = find_column(&rows, "properties").ok_or_else(|| {
        crate::error::storage(format!(
            "sqlite schema is missing opskeys.properties column ({context})"
        ))
    })?;

    validate_column(
        &kid,
        "opskeys",
        "kid",
        "VARCHAR(128)",
        false,
        Some(1),
        context,
    )?;
    validate_column(
        &keys,
        "opskeys",
        "keys",
        "VARCHAR(10240)",
        true,
        None,
        context,
    )?;
    validate_column(
        &properties,
        "opskeys",
        "properties",
        "VARCHAR(10240)",
        true,
        None,
        context,
    )?;

    Ok(())
}

async fn validate_tokens_schema(db: &SqlitePool, context: &str) -> Result<(), DynError> {
    let rows = sqlx::query("PRAGMA table_info(tokens)")
        .fetch_all(db)
        .await?;

    if rows.is_empty() {
        return Err(crate::error::storage(format!(
            "sqlite schema is missing tokens table ({context})",
        )));
    }

    let kid = find_column(&rows, "kid").ok_or_else(|| {
        crate::error::storage(format!(
            "sqlite schema is missing tokens.kid column ({context})"
        ))
    })?;
    let hashid = find_column(&rows, "hashid").ok_or_else(|| {
        crate::error::storage(format!(
            "sqlite schema is missing tokens.hashid column ({context})"
        ))
    })?;
    let data = find_column(&rows, "data").ok_or_else(|| {
        crate::error::storage(format!(
            "sqlite schema is missing tokens.data column ({context})"
        ))
    })?;

    validate_column(
        &kid,
        "tokens",
        "kid",
        "VARCHAR(128)",
        true,
        Some(1),
        context,
    )?;
    validate_column(
        &hashid,
        "tokens",
        "hashid",
        "VARCHAR(128)",
        true,
        Some(2),
        context,
    )?;
    validate_column(
        &data,
        "tokens",
        "data",
        "VARCHAR(10240)",
        true,
        None,
        context,
    )?;

    Ok(())
}

async fn validate_indexes_schema(db: &SqlitePool, context: &str) -> Result<(), DynError> {
    let rows = sqlx::query("PRAGMA table_info(indexes)")
        .fetch_all(db)
        .await?;

    if rows.is_empty() {
        return Err(crate::error::storage(format!(
            "sqlite schema is missing indexes table ({context})",
        )));
    }

    let kid = find_column(&rows, "kid").ok_or_else(|| {
        crate::error::storage(format!(
            "sqlite schema is missing indexes.kid column ({context})"
        ))
    })?;
    let digest = find_column(&rows, "digest").ok_or_else(|| {
        crate::error::storage(format!(
            "sqlite schema is missing indexes.digest column ({context})"
        ))
    })?;

    validate_column(
        &kid,
        "indexes",
        "kid",
        "VARCHAR(128)",
        true,
        Some(1),
        context,
    )?;
    validate_column(
        &digest,
        "indexes",
        "digest",
        "VARCHAR(128)",
        true,
        Some(2),
        context,
    )?;

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
    context: &str,
) -> Result<(), DynError> {
    let expected_primary_key_position = expected_primary_key_position.unwrap_or(0);
    if column.name != expected_name
        || !column.column_type.eq_ignore_ascii_case(expected_type)
        || column.notnull != expected_notnull
        || column.primary_key_position != expected_primary_key_position
    {
        return Err(crate::error::storage(format!(
            "sqlite schema mismatch for {table_name}.{expected_name}: expected type={expected_type}, notnull={expected_notnull}, primary_key_position={expected_primary_key_position} ({context})",
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
        sqlx::query(
            "
            CREATE TABLE indexes (
                kid VARCHAR(128) NOT NULL,
                digest VARCHAR(128) NOT NULL,
                PRIMARY KEY (kid, digest)
            )
            ",
        )
        .execute(&pool)
        .await
        .expect("test index schema must be created");
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
    async fn schema_error_includes_sqlite_path() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time must be valid")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "vectis-sqlite-empty-{}-{nonce}.db",
            std::process::id()
        ));
        let options = SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(true);
        let pool = SqlitePool::connect_with(options)
            .await
            .expect("empty sqlite must connect");
        pool.close().await;

        let err = match SqliteStorage::new(&path).await {
            Ok(_) => panic!("empty sqlite schema must fail"),
            Err(err) => err,
        };
        let message = err.to_string();
        assert!(message.contains("sqlite schema is missing opskeys table"));
        assert!(message.contains(&path.display().to_string()));

        cleanup(path).await;
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

    #[tokio::test]
    async fn index_save_is_idempotent_and_exists_checks_membership() {
        let (storage, path) = test_storage("index").await;

        let saved = storage
            .save_index("kid-1", "digest-1")
            .await
            .expect("index must save");
        assert_eq!(saved.kid, "kid-1");
        assert_eq!(saved.digest, "digest-1");

        storage
            .save_index("kid-1", "digest-1")
            .await
            .expect("duplicate index save must be idempotent");

        assert!(
            storage
                .index_exists("kid-1", "digest-1")
                .await
                .expect("membership check must succeed")
        );
        assert!(
            !storage
                .index_exists("kid-1", "missing")
                .await
                .expect("membership check must succeed")
        );

        cleanup(path).await;
    }

    #[tokio::test]
    async fn index_batch_save_is_idempotent() {
        let (storage, path) = test_storage("index-batch").await;
        let records = vec![
            IndexRow {
                kid: String::from("kid-1"),
                digest: String::from("digest-1"),
            },
            IndexRow {
                kid: String::from("kid-1"),
                digest: String::from("digest-2"),
            },
        ];

        storage
            .save_indexes_batch(&records)
            .await
            .expect("index batch must save");
        storage
            .save_indexes_batch(&records)
            .await
            .expect("duplicate index batch must be idempotent");

        assert!(
            storage
                .index_exists("kid-1", "digest-1")
                .await
                .expect("membership check must succeed")
        );
        assert!(
            storage
                .index_exists("kid-1", "digest-2")
                .await
                .expect("membership check must succeed")
        );

        cleanup(path).await;
    }

    #[tokio::test]
    async fn indexes_matching_returns_only_present_digests() {
        let (storage, path) = test_storage("index-matching").await;
        storage
            .save_index("kid-1", "digest-1")
            .await
            .expect("index must save");
        storage
            .save_index("kid-1", "digest-3")
            .await
            .expect("index must save");

        let present = storage
            .indexes_matching(
                "kid-1",
                &[
                    String::from("digest-1"),
                    String::from("digest-2"),
                    String::from("digest-3"),
                ],
            )
            .await
            .expect("batch membership check must succeed");
        assert_eq!(present.len(), 2);
        assert!(present.contains("digest-1"));
        assert!(present.contains("digest-3"));
        assert!(!present.contains("digest-2"));

        let empty = storage
            .indexes_matching("kid-1", &[])
            .await
            .expect("empty membership check must succeed");
        assert!(empty.is_empty());

        cleanup(path).await;
    }
}
