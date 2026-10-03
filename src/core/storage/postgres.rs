use super::TokenBatchReadBudget;
use crate::core::storage::{IndexRow, OpsKeyRow, SubjectRow, TokenBatchConsumeError, TokenRow};
use crate::error::DynError;
use futures_util::TryStreamExt;
use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::{Postgres, Row, Transaction};
use std::collections::{HashMap, HashSet};
use tracing::info;

pub struct PostgresStorage {
    pool: PgPool,
    dsn_context: String,
}

impl PostgresStorage {
    #[cfg(test)]
    pub async fn save_token(
        &self,
        kid: &str,
        hashid: &str,
        data: &str,
    ) -> Result<TokenRow, DynError> {
        self.save_token_for_subject(kid, hashid, data, None).await
    }

    #[cfg(test)]
    pub async fn delete_token(&self, kid: &str, hashid: &str) -> Result<(), DynError> {
        self.delete_token_for_subject(kid, hashid, None).await
    }

    pub async fn new(dsn: &str) -> Result<Self, DynError> {
        let dsn_context = postgres_context(dsn);
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(dsn)
            .await
            .map_err(|err| {
                crate::error::storage(format!(
                    "failed to connect to ops postgres at {dsn_context}: {err}"
                ))
            })?;
        info!(dsn = %dsn_context, "connected to ops postgres");

        validate_opskeys_schema(&pool, &dsn_context).await?;
        info!("validated opskeys postgres schema");
        validate_tokens_schema(&pool, &dsn_context).await?;
        validate_subjects_schema(&pool, &dsn_context).await?;
        info!("validated tokens postgres schema");
        validate_indexes_schema(&pool, &dsn_context).await?;
        info!("validated indexes postgres schema");

        Ok(Self { pool, dsn_context })
    }

    pub async fn save_ops_keys(
        &self,
        kid: &str,
        keys: &str,
        properties: &str,
    ) -> Result<OpsKeyRow, DynError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "
            INSERT INTO opskeys (kid, keys, properties)
            VALUES ($1, $2, $3)
            ",
        )
        .bind(kid)
        .bind(keys)
        .bind(properties)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        info!(kid, "inserted ops keys");

        Ok(OpsKeyRow {
            kid: kid.to_string(),
            keys: keys.to_string(),
            properties: properties.to_string(),
        })
    }

    pub async fn get_ops_keys(&self, kid: &str) -> Result<OpsKeyRow, DynError> {
        let row = fetch_ops_keys(&self.pool, kid).await?;

        row.ok_or_else(|| crate::error::not_found(format!("ops key not found: {kid}")))
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

    pub async fn save_token_for_subject(
        &self,
        kid: &str,
        hashid: &str,
        data: &str,
        subject: Option<&str>,
    ) -> Result<TokenRow, DynError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "
            INSERT INTO tokens (kid, hashid, data, subject)
            VALUES ($1, $2, $3, $4)
            ",
        )
        .bind(kid)
        .bind(hashid)
        .bind(data)
        .bind(subject)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        info!(kid, hashid, "inserted token");

        Ok(TokenRow {
            kid: kid.to_string(),
            hashid: hashid.to_string(),
            data: data.to_string(),
            subject: subject.map(str::to_owned),
        })
    }

    pub async fn save_tokens_batch(&self, records: &[TokenRow]) -> Result<(), DynError> {
        if records.is_empty() {
            return Ok(());
        }
        let kids: Vec<&str> = records.iter().map(|record| record.kid.as_str()).collect();
        let hashids: Vec<&str> = records
            .iter()
            .map(|record| record.hashid.as_str())
            .collect();
        let data: Vec<&str> = records.iter().map(|record| record.data.as_str()).collect();
        let subjects: Vec<Option<&str>> = records
            .iter()
            .map(|record| record.subject.as_deref())
            .collect();
        sqlx::query(
            "
            INSERT INTO tokens (kid, hashid, data, subject)
            SELECT kid, hashid, data, subject
            FROM UNNEST(
                $1::text[],
                $2::text[],
                $3::text[],
                $4::text[]
            ) AS batch(kid, hashid, data, subject)
            ",
        )
        .bind(&kids)
        .bind(&hashids)
        .bind(&data)
        .bind(&subjects)
        .execute(&self.pool)
        .await?;
        info!(items_count = records.len(), "inserted token batch");

        Ok(())
    }

    pub async fn get_tokens_batch(
        &self,
        kid: &str,
        hashids: &[String],
        max_envelope_bytes: usize,
    ) -> Result<HashMap<String, TokenRow>, DynError> {
        let mut rows = sqlx::query(
            "
            SELECT hashid, data, subject
            FROM tokens
            WHERE kid = $1
              AND hashid = ANY($2)
            ",
        )
        .bind(kid)
        .bind(hashids)
        .fetch(&self.pool);
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
            WHERE kid = $1
              AND hashid = $2
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
            WHERE kid = $1
              AND hashid = $2
              AND subject IS NOT DISTINCT FROM $3
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
        let rows = sqlx::query(
            "
            DELETE FROM tokens
            WHERE kid = $1
              AND hashid = ANY($2)
              AND subject IS NOT DISTINCT FROM $3
            RETURNING hashid
            ",
        )
        .bind(kid)
        .bind(&ordered)
        .bind(subject)
        .fetch_all(&mut *tx)
        .await
        .map_err(|err| TokenBatchConsumeError::Other(Box::new(err)))?;
        let deleted = rows
            .into_iter()
            .map(|row| row.get("hashid"))
            .collect::<HashSet<String>>();
        if let Some(hashid) = first_missing_hashid(&ordered, &deleted) {
            return Err(TokenBatchConsumeError::MissingToken {
                hashid: hashid.to_string(),
            });
        }
        tx.commit()
            .await
            .map_err(|err| TokenBatchConsumeError::Other(Box::new(err)))?;
        info!(kid, items_count = ordered.len(), "consumed token batch");
        Ok(())
    }

    pub async fn save_index(&self, kid: &str, digest: &str) -> Result<IndexRow, DynError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "
            INSERT INTO indexes (kid, digest)
            VALUES ($1, $2)
            ON CONFLICT (kid, digest) DO NOTHING
            ",
        )
        .bind(kid)
        .bind(digest)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        info!(kid, "inserted index");

        Ok(IndexRow {
            kid: kid.to_string(),
            digest: digest.to_string(),
        })
    }

    pub async fn save_subject(&self, row: &SubjectRow) -> Result<(), DynError> {
        let result = sqlx::query("INSERT INTO subjects (kid, subject, seed) VALUES ($1, $2, $3) ON CONFLICT (kid, subject) DO NOTHING")
            .bind(&row.kid).bind(&row.subject).bind(&row.seed).execute(&self.pool).await?;
        if result.rows_affected() == 0 {
            return Err(crate::error::conflict("subject already exists"));
        }
        Ok(())
    }

    pub async fn get_subject(&self, kid: &str, subject: &str) -> Result<SubjectRow, DynError> {
        let row =
            sqlx::query("SELECT kid, subject, seed FROM subjects WHERE kid = $1 AND subject = $2")
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
        let result = sqlx::query("DELETE FROM subjects WHERE kid = $1 AND subject = $2")
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
        let kids: Vec<&str> = records.iter().map(|record| record.kid.as_str()).collect();
        let digests: Vec<&str> = records
            .iter()
            .map(|record| record.digest.as_str())
            .collect();
        sqlx::query(
            "
            INSERT INTO indexes (kid, digest)
            SELECT * FROM UNNEST($1::text[], $2::text[])
            ON CONFLICT (kid, digest) DO NOTHING
            ",
        )
        .bind(&kids)
        .bind(&digests)
        .execute(&self.pool)
        .await?;
        info!(items_count = records.len(), "inserted index batch");

        Ok(())
    }

    pub async fn index_exists(&self, kid: &str, digest: &str) -> Result<bool, DynError> {
        let row = sqlx::query(
            "
            SELECT 1
            FROM indexes
            WHERE kid = $1
              AND digest = $2
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
        let rows = sqlx::query(
            "
            SELECT digest
            FROM indexes
            WHERE kid = $1
              AND digest = ANY($2)
            ",
        )
        .bind(kid)
        .bind(digests)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|row| row.get("digest")).collect())
    }

    pub async fn update_ops_key_properties(
        &self,
        kid: &str,
        properties: &str,
    ) -> Result<OpsKeyRow, DynError> {
        let mut tx = self.pool.begin().await?;
        let result = sqlx::query(
            "
            UPDATE opskeys
            SET properties = $1
            WHERE kid = $2
            ",
        )
        .bind(properties)
        .bind(kid)
        .execute(&mut *tx)
        .await?;

        if result.rows_affected() == 0 {
            return Err(crate::error::not_found(format!("ops key not found: {kid}")));
        }

        let row = fetch_ops_keys_tx(&mut tx, kid).await?;
        tx.commit().await?;
        info!(kid, "updated ops key properties");

        row.ok_or_else(|| crate::error::not_found(format!("ops key not found: {kid}")))
    }

    pub async fn update_ops_key_properties_if_current(
        &self,
        kid: &str,
        current_properties: &str,
        new_properties: &str,
    ) -> Result<OpsKeyRow, DynError> {
        let mut tx = self.pool.begin().await?;
        let result = sqlx::query(
            "
            UPDATE opskeys
            SET properties = $1
            WHERE kid = $2
              AND properties = $3
            ",
        )
        .bind(new_properties)
        .bind(kid)
        .bind(current_properties)
        .execute(&mut *tx)
        .await?;

        if result.rows_affected() == 0 {
            let row = fetch_ops_keys_tx(&mut tx, kid).await?;
            tx.commit().await?;

            if row.is_none() {
                return Err(crate::error::not_found(format!("ops key not found: {kid}")));
            }

            return Err(crate::error::invalid_input(
                "ops key properties changed concurrently; retry lifecycle update",
            ));
        }

        let row = fetch_ops_keys_tx(&mut tx, kid).await?;
        tx.commit().await?;
        info!(kid, "updated ops key properties with compare-and-swap");

        row.ok_or_else(|| crate::error::not_found(format!("ops key not found: {kid}")))
    }

    pub async fn health_check(&self) -> Result<(), DynError> {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await
            .map_err(|err| {
                crate::error::storage(format!(
                    "postgres health check failed at {}: {err}",
                    self.dsn_context
                ))
            })?;

        Ok(())
    }
}

fn first_missing_hashid<'a>(requested: &'a [String], deleted: &HashSet<String>) -> Option<&'a str> {
    requested
        .iter()
        .find(|hashid| !deleted.contains(hashid.as_str()))
        .map(String::as_str)
}

async fn fetch_ops_keys(pool: &PgPool, kid: &str) -> Result<Option<OpsKeyRow>, DynError> {
    let row = sqlx::query(
        "
        SELECT kid, keys, properties
        FROM opskeys
        WHERE kid = $1
        ",
    )
    .bind(kid)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|row| OpsKeyRow {
        kid: row.get("kid"),
        keys: row.get("keys"),
        properties: row.get("properties"),
    }))
}

async fn fetch_ops_keys_tx(
    tx: &mut Transaction<'_, Postgres>,
    kid: &str,
) -> Result<Option<OpsKeyRow>, DynError> {
    let row = sqlx::query(
        "
        SELECT kid, keys, properties
        FROM opskeys
        WHERE kid = $1
        ",
    )
    .bind(kid)
    .fetch_optional(&mut **tx)
    .await?;

    Ok(row.map(|row| OpsKeyRow {
        kid: row.get("kid"),
        keys: row.get("keys"),
        properties: row.get("properties"),
    }))
}

fn postgres_context(dsn: &str) -> String {
    let Some((scheme, rest)) = dsn.split_once("://") else {
        return "<configured postgres dsn>".to_string();
    };
    let rest_without_credentials = rest.rsplit_once('@').map_or(rest, |(_, after_at)| after_at);
    let authority_and_path = rest_without_credentials
        .split_once('?')
        .map_or(rest_without_credentials, |(before_query, _)| before_query);
    if authority_and_path.is_empty() {
        return "<configured postgres dsn>".to_string();
    }
    let prefix = if rest.contains('@') {
        format!("{scheme}://<redacted>@")
    } else {
        format!("{scheme}://")
    };

    format!("{prefix}{authority_and_path}")
}

async fn validate_opskeys_schema(pool: &PgPool, context: &str) -> Result<(), DynError> {
    let columns = sqlx::query(
        "
        SELECT column_name, data_type, character_maximum_length, is_nullable
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'opskeys'
        ",
    )
    .fetch_all(pool)
    .await?;

    if columns.is_empty() {
        return Err(crate::error::storage(format!(
            "postgres schema is missing opskeys table ({context})"
        )));
    }

    let kid = find_column(&columns, "kid").ok_or_else(|| {
        crate::error::storage(format!(
            "postgres schema is missing opskeys.kid column ({context})"
        ))
    })?;
    let keys = find_column(&columns, "keys").ok_or_else(|| {
        crate::error::storage(format!(
            "postgres schema is missing opskeys.keys column ({context})"
        ))
    })?;
    let properties = find_column(&columns, "properties").ok_or_else(|| {
        crate::error::storage(format!(
            "postgres schema is missing opskeys.properties column ({context})"
        ))
    })?;

    validate_varchar_column(&kid, "opskeys", "kid", 128, false, context)?;
    validate_text_column(&keys, "opskeys", "keys", false, context)?;
    validate_text_column(&properties, "opskeys", "properties", false, context)?;
    validate_primary_key(pool, "opskeys", &["kid"], context).await?;

    Ok(())
}

async fn validate_tokens_schema(pool: &PgPool, context: &str) -> Result<(), DynError> {
    let columns = sqlx::query(
        "
        SELECT column_name, data_type, character_maximum_length, is_nullable
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'tokens'
        ",
    )
    .fetch_all(pool)
    .await?;

    if columns.is_empty() {
        return Err(crate::error::storage(format!(
            "postgres schema is missing tokens table ({context})"
        )));
    }

    let kid = find_column(&columns, "kid").ok_or_else(|| {
        crate::error::storage(format!(
            "postgres schema is missing tokens.kid column ({context})"
        ))
    })?;
    let hashid = find_column(&columns, "hashid").ok_or_else(|| {
        crate::error::storage(format!(
            "postgres schema is missing tokens.hashid column ({context})"
        ))
    })?;
    let data = find_column(&columns, "data").ok_or_else(|| {
        crate::error::storage(format!(
            "postgres schema is missing tokens.data column ({context})"
        ))
    })?;

    validate_varchar_column(&kid, "tokens", "kid", 128, false, context)?;
    validate_varchar_column(&hashid, "tokens", "hashid", 128, false, context)?;
    validate_text_column(&data, "tokens", "data", false, context)?;
    let subject = find_column(&columns, "subject").ok_or_else(|| {
        crate::error::storage(
            "postgres schema is missing tokens.subject column; apply subject keys migration",
        )
    })?;
    validate_varchar_column(&subject, "tokens", "subject", 128, true, context)?;
    validate_primary_key(pool, "tokens", &["kid", "hashid"], context).await?;

    Ok(())
}

async fn validate_subjects_schema(pool: &PgPool, context: &str) -> Result<(), DynError> {
    let rows = sqlx::query("SELECT column_name, data_type, character_maximum_length, is_nullable FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'subjects'").fetch_all(pool).await?;
    for name in ["kid", "subject"] {
        let column = find_column(&rows, name).ok_or_else(|| {
            crate::error::storage(
                "postgres schema is missing subjects table or column; apply subject keys migration",
            )
        })?;
        validate_varchar_column(&column, "subjects", name, 128, false, context)?;
    }
    let seed = find_column(&rows, "seed")
        .ok_or_else(|| crate::error::storage("postgres schema is missing subjects.seed"))?;
    validate_text_column(&seed, "subjects", "seed", false, context)?;
    validate_primary_key(pool, "subjects", &["kid", "subject"], context).await
}

async fn validate_indexes_schema(pool: &PgPool, context: &str) -> Result<(), DynError> {
    let columns = sqlx::query(
        "
        SELECT column_name, data_type, character_maximum_length, is_nullable
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'indexes'
        ",
    )
    .fetch_all(pool)
    .await?;

    if columns.is_empty() {
        return Err(crate::error::storage(format!(
            "postgres schema is missing indexes table ({context})"
        )));
    }

    let kid = find_column(&columns, "kid").ok_or_else(|| {
        crate::error::storage(format!(
            "postgres schema is missing indexes.kid column ({context})"
        ))
    })?;
    let digest = find_column(&columns, "digest").ok_or_else(|| {
        crate::error::storage(format!(
            "postgres schema is missing indexes.digest column ({context})"
        ))
    })?;

    validate_varchar_column(&kid, "indexes", "kid", 128, false, context)?;
    validate_varchar_column(&digest, "indexes", "digest", 128, false, context)?;
    validate_primary_key(pool, "indexes", &["kid", "digest"], context).await?;

    Ok(())
}

struct ColumnInfo {
    name: String,
    data_type: String,
    max_length: Option<i32>,
    nullable: bool,
}

fn find_column(rows: &[sqlx::postgres::PgRow], name: &str) -> Option<ColumnInfo> {
    rows.iter().find_map(|row| {
        let column_name: String = row.get("column_name");
        if column_name != name {
            return None;
        }

        let data_type: String = row.get("data_type");
        let max_length: Option<i32> = row.get("character_maximum_length");
        let is_nullable: String = row.get("is_nullable");

        Some(ColumnInfo {
            name: column_name,
            data_type,
            max_length,
            nullable: is_nullable == "YES",
        })
    })
}

fn validate_varchar_column(
    column: &ColumnInfo,
    table_name: &str,
    expected_name: &str,
    expected_max_length: i32,
    expected_nullable: bool,
    context: &str,
) -> Result<(), DynError> {
    if column.name != expected_name
        || column.data_type != "character varying"
        || column.max_length != Some(expected_max_length)
        || column.nullable != expected_nullable
    {
        return Err(crate::error::storage(format!(
            "postgres schema mismatch for {table_name}.{expected_name}: expected type=VARCHAR({expected_max_length}), nullable={expected_nullable} ({context})",
        )));
    }

    Ok(())
}

fn validate_text_column(
    column: &ColumnInfo,
    table_name: &str,
    expected_name: &str,
    expected_nullable: bool,
    context: &str,
) -> Result<(), DynError> {
    if column.name != expected_name
        || column.data_type != "text"
        || column.max_length.is_some()
        || column.nullable != expected_nullable
    {
        return Err(crate::error::storage(format!(
            "postgres schema mismatch for {table_name}.{expected_name}: expected type=TEXT, nullable={expected_nullable} ({context})",
        )));
    }

    Ok(())
}

async fn validate_primary_key(
    pool: &PgPool,
    table_name: &str,
    expected_columns: &[&str],
    context: &str,
) -> Result<(), DynError> {
    let rows = sqlx::query(
        "
        SELECT a.attname
        FROM pg_index i
        JOIN pg_class t ON t.oid = i.indrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
        JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY(i.indkey)
        WHERE n.nspname = 'public'
          AND t.relname = $1
          AND i.indisprimary
        ORDER BY a.attnum
        ",
    )
    .bind(table_name)
    .fetch_all(pool)
    .await?;

    let primary_key_columns: Vec<String> = rows.iter().map(|row| row.get("attname")).collect();
    if primary_key_columns != expected_columns {
        return Err(crate::error::storage(format!(
            "postgres schema mismatch for {table_name} primary key: expected {} ({context})",
            expected_columns.join(", "),
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires VECTIS_TEST_POSTGRES_DSN and the Vectis schema in a test database"]
    async fn token_batch_read_budget_is_incremental_and_counts_duplicates() {
        let dsn = std::env::var("VECTIS_TEST_POSTGRES_DSN").expect("test DSN required");
        let storage = PostgresStorage::new(&dsn).await.unwrap();
        let kid = format!(
            "budget-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let ids = vec!["a".repeat(64), "b".repeat(64)];
        let data = "AAAAAAAAAAAAAAAAAAAAAA==.AAAAAAAAAAAAAAAA.AA==";
        for id in &ids {
            storage.save_token(&kid, id, data).await.unwrap();
        }
        assert_eq!(
            storage
                .get_tokens_batch(&kid, &ids, data.len() * 2)
                .await
                .unwrap()
                .len(),
            2
        );
        assert!(matches!(
            storage
                .get_tokens_batch(&kid, &ids, data.len() * 2 - 1)
                .await
                .unwrap_err()
                .downcast_ref(),
            Some(crate::error::VectisError::TokenDecodeBatchTooLarge)
        ));
        assert!(
            storage
                .get_tokens_batch(&kid, &[ids[0].clone(), ids[0].clone()], data.len())
                .await
                .is_err()
        );
        for id in &ids {
            storage.delete_token(&kid, id).await.unwrap();
        }
    }

    #[tokio::test]
    #[ignore = "requires VECTIS_TEST_POSTGRES_DSN and the Vectis schema in a test database"]
    async fn explicit_delete_is_atomic_and_single_use() {
        let dsn = std::env::var("VECTIS_TEST_POSTGRES_DSN").expect("test DSN required");
        let storage = PostgresStorage::new(&dsn).await.unwrap();
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let kid = format!("delete-test-{unique}");
        storage.save_token(&kid, "hash", "corrupt").await.unwrap();
        let (first, second) = tokio::join!(
            storage.delete_token(&kid, "hash"),
            storage.delete_token(&kid, "hash")
        );
        assert_ne!(first.is_ok(), second.is_ok());
        assert!(crate::error::is_not_found(
            storage
                .delete_token(&kid, "hash")
                .await
                .unwrap_err()
                .as_ref()
        ));
        assert!(crate::error::is_not_found(
            storage.get_token(&kid, "hash").await.unwrap_err().as_ref()
        ));
    }

    #[test]
    fn postgres_context_redacts_credentials() {
        let context = postgres_context("postgres://user:secret@localhost:5432/vectis");

        assert_eq!(context, "postgres://<redacted>@localhost:5432/vectis");
        assert!(!context.contains("secret"));
        assert!(context.contains("localhost"));
        assert!(context.contains("5432"));
        assert!(context.contains("/vectis"));
    }

    #[test]
    fn postgres_context_handles_unparseable_dsn_safely() {
        assert_eq!(
            postgres_context("not a postgres url with secret"),
            "<configured postgres dsn>"
        );
    }

    #[test]
    fn first_missing_hashid_returns_none_when_every_token_was_deleted() {
        let requested = vec![String::from("hash-a"), String::from("hash-b")];
        let deleted = HashSet::from([String::from("hash-a"), String::from("hash-b")]);

        assert_eq!(first_missing_hashid(&requested, &deleted), None);
    }

    #[test]
    fn first_missing_hashid_uses_the_deterministic_requested_order() {
        let requested = vec![
            String::from("hash-a"),
            String::from("hash-b"),
            String::from("hash-c"),
        ];
        let deleted = HashSet::from([String::from("hash-c")]);

        assert_eq!(first_missing_hashid(&requested, &deleted), Some("hash-a"));
    }
}
