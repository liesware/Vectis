use super::TokenBatchReadBudget;
use crate::core::storage::{IndexRow, OpsKeyRow, SubjectRow, TokenBatchConsumeError, TokenRow};
use crate::error::DynError;
use futures_util::TryStreamExt;
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
        validate_subjects_schema(&pool, &context).await?;
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

    #[cfg(test)]
    pub async fn save_token(
        &self,
        kid: &str,
        hashid: &str,
        data: &str,
    ) -> Result<TokenRow, DynError> {
        self.save_token_for_subject(kid, hashid, data, None).await
    }

    pub async fn save_token_for_subject(
        &self,
        kid: &str,
        hashid: &str,
        data: &str,
        subject: Option<&str>,
    ) -> Result<TokenRow, DynError> {
        sqlx::query(
            "
            INSERT INTO tokens (kid, hashid, data, subject)
            VALUES (?, ?, ?, ?)
            ",
        )
        .bind(kid)
        .bind(hashid)
        .bind(data)
        .bind(subject)
        .execute(&self.pool)
        .await?;
        info!(kid, hashid, "inserted token");

        Ok(TokenRow {
            kid: kid.to_string(),
            hashid: hashid.to_string(),
            data: data.to_string(),
            subject: subject.map(str::to_owned),
        })
    }

    pub async fn save_tokens_batch(&self, records: &[TokenRow]) -> Result<(), DynError> {
        let mut tx = self.pool.begin().await?;
        for record in records {
            sqlx::query(
                "
                INSERT INTO tokens (kid, hashid, data, subject)
                VALUES (?, ?, ?, ?)
                ",
            )
            .bind(&record.kid)
            .bind(&record.hashid)
            .bind(&record.data)
            .bind(&record.subject)
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
        max_envelope_bytes: usize,
    ) -> Result<HashMap<String, TokenRow>, DynError> {
        if hashids.is_empty() {
            return Ok(HashMap::new());
        }
        let placeholders = std::iter::repeat_n("?", hashids.len())
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!(
            "SELECT hashid, data, subject FROM tokens WHERE kid = ? AND hashid IN ({placeholders})"
        );
        let mut query = sqlx::query(&sql).bind(kid);
        for hashid in hashids {
            query = query.bind(hashid);
        }
        let mut rows = query.fetch(&self.pool);
        let mut budget = TokenBatchReadBudget::new(hashids, max_envelope_bytes);
        let mut found = HashMap::with_capacity(hashids.len());
        while let Some(row) = rows.try_next().await? {
            let hashid: String = row.try_get("hashid")?;
            let data: String = row.try_get("data")?;
            budget.retain(&hashid, &data)?;
            let subject: Option<String> = row.try_get("subject")?;
            super::validate_optional_subject(subject.as_deref())?;
            found.insert(
                hashid.clone(),
                TokenRow {
                    kid: kid.to_owned(),
                    hashid,
                    data,
                    subject,
                },
            );
        }
        Ok(found)
    }

    pub async fn get_token(&self, kid: &str, hashid: &str) -> Result<TokenRow, DynError> {
        let row = sqlx::query(
            "
            SELECT kid, hashid, data, subject
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
            subject: row.get("subject"),
        })
    }

    #[cfg(test)]
    pub async fn delete_token(&self, kid: &str, hashid: &str) -> Result<(), DynError> {
        self.delete_token_for_subject(kid, hashid, None).await
    }

    pub async fn delete_token_for_subject(
        &self,
        kid: &str,
        hashid: &str,
        subject: Option<&str>,
    ) -> Result<(), DynError> {
        let mut tx = self.pool.begin().await?;
        let result = sqlx::query(
            "
            DELETE FROM tokens
            WHERE kid = ?
              AND hashid = ?
              AND subject IS ?
            ",
        )
        .bind(kid)
        .bind(hashid)
        .bind(subject)
        .execute(&mut *tx)
        .await?;
        if result.rows_affected() != 1 {
            return Err(crate::error::not_found("token not found"));
        }
        tx.commit().await?;
        info!(kid, "deleted token row");
        Ok(())
    }

    #[cfg(test)]
    pub async fn consume_tokens_batch(
        &self,
        kid: &str,
        hashids: &[String],
    ) -> Result<(), TokenBatchConsumeError> {
        self.consume_tokens_batch_for_subject(kid, hashids, None)
            .await
    }

    pub async fn consume_tokens_batch_for_subject(
        &self,
        kid: &str,
        hashids: &[String],
        subject: Option<&str>,
    ) -> Result<(), TokenBatchConsumeError> {
        let mut ordered = hashids.to_vec();
        ordered.sort_unstable();

        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|err| TokenBatchConsumeError::Other(Box::new(err)))?;
        for hashid in &ordered {
            let result = sqlx::query(
                "
                DELETE FROM tokens
                WHERE kid = ?
                  AND hashid = ?
                  AND subject IS ?
                ",
            )
            .bind(kid)
            .bind(hashid)
            .bind(subject)
            .execute(&mut *tx)
            .await
            .map_err(|err| TokenBatchConsumeError::Other(Box::new(err)))?;
            if result.rows_affected() != 1 {
                return Err(TokenBatchConsumeError::MissingToken {
                    hashid: hashid.clone(),
                });
            }
        }
        tx.commit()
            .await
            .map_err(|err| TokenBatchConsumeError::Other(Box::new(err)))?;
        info!(kid, items_count = ordered.len(), "consumed token batch");
        Ok(())
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

    pub async fn save_subject(&self, row: &SubjectRow) -> Result<(), DynError> {
        let result = sqlx::query("INSERT INTO subjects (kid, subject, seed) VALUES (?, ?, ?) ON CONFLICT (kid, subject) DO NOTHING")
            .bind(&row.kid).bind(&row.subject).bind(&row.seed).execute(&self.pool).await?;
        if result.rows_affected() == 0 {
            return Err(crate::error::conflict("subject already exists"));
        }
        Ok(())
    }

    pub async fn get_subject(&self, kid: &str, subject: &str) -> Result<SubjectRow, DynError> {
        let row =
            sqlx::query("SELECT kid, subject, seed FROM subjects WHERE kid = ? AND subject = ?")
                .bind(kid)
                .bind(subject)
                .fetch_optional(&self.pool)
                .await?
                .ok_or_else(|| crate::error::not_found("subject not found"))?;
        Ok(SubjectRow {
            kid: row.try_get("kid")?,
            subject: row.try_get("subject")?,
            seed: row.try_get("seed")?,
        })
    }

    pub async fn delete_subject(&self, kid: &str, subject: &str) -> Result<(), DynError> {
        let result = sqlx::query("DELETE FROM subjects WHERE kid = ? AND subject = ?")
            .bind(kid)
            .bind(subject)
            .execute(&self.pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(crate::error::not_found("subject not found"));
        }
        Ok(())
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

    let subject = find_column(&rows, "subject").ok_or_else(|| {
        crate::error::storage(
            "sqlite schema is missing tokens.subject column; apply subject keys migration",
        )
    })?;
    validate_column(
        &subject,
        "tokens",
        "subject",
        "VARCHAR(128)",
        false,
        None,
        context,
    )?;

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

async fn validate_subjects_schema(db: &SqlitePool, context: &str) -> Result<(), DynError> {
    let rows = sqlx::query("PRAGMA table_info(subjects)")
        .fetch_all(db)
        .await?;
    for (name, ty, position) in [
        ("kid", "VARCHAR(128)", Some(1)),
        ("subject", "VARCHAR(128)", Some(2)),
        ("seed", "TEXT", None),
    ] {
        let column = find_column(&rows, name).ok_or_else(|| {
            crate::error::storage(
                "sqlite schema is missing subjects table or column; apply subject keys migration",
            )
        })?;
        validate_column(&column, "subjects", name, ty, true, position, context)?;
    }
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
                subject VARCHAR(128),
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
        sqlx::raw_sql("CREATE TABLE subjects (kid VARCHAR(128) NOT NULL, subject VARCHAR(128) NOT NULL, seed TEXT NOT NULL, PRIMARY KEY(kid, subject));").execute(&pool).await.unwrap();
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
    async fn token_envelope_limits_apply_to_single_and_batch_storage() {
        use crate::core::{
            config,
            storage::{StorageBackend, StorageState, TokenRow},
        };
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        let (backend, path) = test_storage("token-envelope-limits").await;
        let pool = backend.pool.clone();
        let storage = StorageState {
            backend: StorageBackend::Sqlite(backend),
        };
        let kid = "a".repeat(64);
        let first = "b".repeat(64);
        let second = "c".repeat(64);
        let data = format!(
            "{}.{}.{}",
            STANDARD.encode(vec![0; 80_000]),
            STANDARD.encode([0; 12]),
            STANDARD.encode(b"test")
        );
        assert!(data.len() > config::STORAGE_ENVELOPE_MAX_CHARS);
        storage.save_token(&kid, &first, &data).await.unwrap();
        assert_eq!(storage.get_token(&kid, &first).await.unwrap().data, data);
        storage
            .save_tokens_batch(&[TokenRow {
                subject: None,
                kid: kid.clone(),
                hashid: second.clone(),
                data: data.clone(),
            }])
            .await
            .unwrap();
        let found = storage
            .get_tokens_batch(
                &kid,
                &[first.clone(), second.clone()],
                config::TOKEN_DECODE_BATCH_MAX_ENVELOPE_BYTES,
            )
            .await
            .unwrap();
        assert_eq!(
            found[1].as_ref().map(|row| row.data.as_str()),
            Some(data.as_str())
        );
        let oversized = format!(
            "{}.{}.{}",
            STANDARD.encode(vec![0; 100_000]),
            STANDARD.encode([0; 12]),
            STANDARD.encode(b"test")
        );
        assert!(storage.save_token(&kid, &first, &oversized).await.is_err());
        assert!(
            storage
                .save_tokens_batch(&[TokenRow {
                    subject: None,
                    kid: kid.clone(),
                    hashid: second.clone(),
                    data: oversized.clone()
                }])
                .await
                .is_err()
        );
        sqlx::query("UPDATE tokens SET data = ? WHERE kid = ?")
            .bind(&oversized)
            .bind(&kid)
            .execute(&pool)
            .await
            .unwrap();
        assert!(storage.get_token(&kid, &first).await.is_err());
        assert!(
            storage
                .get_tokens_batch(
                    &kid,
                    &[first, second],
                    config::TOKEN_DECODE_BATCH_MAX_ENVELOPE_BYTES
                )
                .await
                .is_err()
        );
        pool.close().await;
        cleanup(path).await;
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
                subject: None,
                kid: String::from("kid-1"),
                hashid: String::from("hash-1"),
                data: String::from("ciphertext-1.nonce.aad"),
            },
            TokenRow {
                subject: None,
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
        let first = "b".repeat(64);
        let second = "c".repeat(64);
        let missing = "d".repeat(64);
        let data = "AAAAAAAAAAAAAAAAAAAAAA==.AAAAAAAAAAAAAAAA.AA==";
        storage
            .save_token("kid-1", &first, data)
            .await
            .expect("token must save");
        storage
            .save_token("kid-1", &second, data)
            .await
            .expect("token must save");

        let found = storage
            .get_tokens_batch(
                "kid-1",
                &[first.clone(), second.clone(), missing.clone()],
                1024,
            )
            .await
            .expect("batch lookup must succeed");

        assert_eq!(found.len(), 2);
        assert_eq!(found.get(&first).map(|row| row.data.as_str()), Some(data));
        assert_eq!(found.get(&second).map(|row| row.data.as_str()), Some(data));
        assert!(!found.contains_key(&missing));

        cleanup(path).await;
    }

    #[tokio::test]
    async fn token_batch_read_budget_accepts_exact_limit_and_rejects_one_less() {
        use crate::core::config;
        let (storage, path) = test_storage("token-read-budget").await;
        let lengths = std::iter::repeat_n(131_070, 38).chain([65_554, 65_554, 65_554, 65_558]);
        let mut ids = Vec::new();
        for (index, len) in lengths.enumerate() {
            let id = format!("{index:064x}");
            let data = format!("{}.AAAAAAAAAAAAAAAA.dHlwZT10ZXN0", "A".repeat(len - 30));
            assert_eq!(data.len(), len);
            storage.save_token("kid-budget", &id, &data).await.unwrap();
            ids.push(id);
        }
        let limit = config::TOKEN_DECODE_BATCH_MAX_ENVELOPE_BYTES;
        let found = storage
            .get_tokens_batch("kid-budget", &ids, limit)
            .await
            .unwrap();
        assert_eq!(
            found.values().map(|row| row.data.len()).sum::<usize>(),
            limit
        );
        let err = storage
            .get_tokens_batch("kid-budget", &ids, limit - 1)
            .await
            .unwrap_err();
        assert!(matches!(
            err.downcast_ref(),
            Some(crate::error::VectisError::TokenDecodeBatchTooLarge)
        ));
        let duplicate = vec![ids[0].clone(), ids[0].clone()];
        assert!(
            storage
                .get_tokens_batch("kid-budget", &duplicate, 131_070)
                .await
                .is_err()
        );
        assert_eq!(
            storage
                .get_tokens_batch("kid-budget", &duplicate, 262_140)
                .await
                .unwrap()
                .len(),
            1
        );
        cleanup(path).await;
    }

    #[tokio::test]
    async fn explicit_delete_ignores_envelope_and_fails_closed_on_storage_error() {
        use crate::core::storage::{StorageBackend, StorageState};
        let (backend, path) = test_storage("explicit-delete").await;
        let pool = backend.pool.clone();
        let kid = "a".repeat(64);
        let hashid = "b".repeat(64);
        backend
            .save_token(&kid, &hashid, &"!".repeat(140_000))
            .await
            .unwrap();
        let storage = StorageState {
            backend: StorageBackend::Sqlite(backend),
        };
        assert!(storage.get_token(&kid, &hashid).await.is_err());
        storage.delete_token(&kid, &hashid).await.unwrap();
        assert!(is_not_found(
            storage
                .delete_token(&kid, &hashid)
                .await
                .unwrap_err()
                .as_ref()
        ));
        sqlx::query("INSERT INTO tokens (kid, hashid, data) VALUES (?, ?, 'corrupt')")
            .bind(&kid)
            .bind(&hashid)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("CREATE TRIGGER reject_delete BEFORE DELETE ON tokens BEGIN SELECT RAISE(ABORT, 'test failure'); END").execute(&pool).await.unwrap();
        assert!(storage.delete_token(&kid, &hashid).await.is_err());
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tokens")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 1);
        sqlx::query("DROP TRIGGER reject_delete")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("CREATE TABLE token_reference (kid TEXT, hashid TEXT, FOREIGN KEY(kid, hashid) REFERENCES tokens(kid, hashid) DEFERRABLE INITIALLY DEFERRED)")
            .execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO token_reference VALUES (?, ?)")
            .bind(&kid)
            .bind(&hashid)
            .execute(&pool)
            .await
            .unwrap();
        assert!(storage.delete_token(&kid, &hashid).await.is_err());
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tokens")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 1, "failed commit must roll back the deletion");
        sqlx::query("DELETE FROM token_reference")
            .execute(&pool)
            .await
            .unwrap();
        let (first, second) = tokio::join!(
            storage.delete_token(&kid, &hashid),
            storage.consume_token(&kid, &hashid)
        );
        assert_ne!(first.is_ok(), second.is_ok());
        pool.close().await;
        cleanup(path).await;
    }

    #[tokio::test]
    async fn token_consume_is_single_use() {
        let (storage, path) = test_storage("token-consume").await;
        storage
            .save_token("kid-1", "hash-1", "data-1")
            .await
            .expect("token must save");

        storage
            .delete_token("kid-1", "hash-1")
            .await
            .expect("first consume must succeed");
        let err = storage
            .delete_token("kid-1", "hash-1")
            .await
            .expect_err("second consume must fail");
        assert!(is_not_found(err.as_ref()));

        cleanup(path).await;
    }

    #[tokio::test]
    async fn concurrent_token_consumes_have_exactly_one_winner() {
        let (storage, path) = test_storage("token-consume-concurrent").await;
        storage
            .save_token("kid-1", "hash-1", "data-1")
            .await
            .expect("token must save");

        let (first, second) = tokio::join!(
            storage.delete_token("kid-1", "hash-1"),
            storage.delete_token("kid-1", "hash-1"),
        );
        assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
        let loser = first.err().or(second.err()).expect("one consume must lose");
        assert!(is_not_found(loser.as_ref()));

        cleanup(path).await;
    }

    #[tokio::test]
    async fn token_batch_consume_rolls_back_when_one_token_is_missing() {
        let (storage, path) = test_storage("token-consume-batch-rollback").await;
        storage
            .save_token("kid-1", "hash-1", "data-1")
            .await
            .expect("first token must save");
        storage
            .save_token("kid-1", "hash-2", "data-2")
            .await
            .expect("second token must save");

        let err = storage
            .consume_tokens_batch(
                "kid-1",
                &[
                    String::from("hash-1"),
                    String::from("hash-2"),
                    String::from("hash-missing"),
                ],
            )
            .await
            .expect_err("missing token must roll back the batch");
        match err {
            TokenBatchConsumeError::MissingToken { hashid } => {
                assert_eq!(hashid, "hash-missing");
            }
            TokenBatchConsumeError::Other(err) => panic!("unexpected storage error: {err}"),
        }
        assert!(storage.get_token("kid-1", "hash-1").await.is_ok());
        assert!(storage.get_token("kid-1", "hash-2").await.is_ok());

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
