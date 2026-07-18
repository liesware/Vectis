use crate::core::storage::{IndexRow, OpsKeyRow, TokenRow};
use crate::error::DynError;
use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::{Postgres, Row, Transaction};
use std::collections::{HashMap, HashSet};
use tracing::info;

pub struct PostgresStorage {
    pool: PgPool,
}

impl PostgresStorage {
    pub async fn new(dsn: &str) -> Result<Self, DynError> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(dsn)
            .await
            .map_err(|err| {
                crate::error::storage(format!("failed to connect to ops postgres: {err}"))
            })?;
        info!("connected to ops postgres");

        validate_opskeys_schema(&pool).await?;
        info!("validated opskeys postgres schema");
        validate_tokens_schema(&pool).await?;
        info!("validated tokens postgres schema");
        validate_indexes_schema(&pool).await?;
        info!("validated indexes postgres schema");

        Ok(Self { pool })
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

    pub async fn save_token(
        &self,
        kid: &str,
        hashid: &str,
        data: &str,
    ) -> Result<TokenRow, DynError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "
            INSERT INTO tokens (kid, hashid, data)
            VALUES ($1, $2, $3)
            ",
        )
        .bind(kid)
        .bind(hashid)
        .bind(data)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
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
                VALUES ($1, $2, $3)
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
        let rows = sqlx::query(
            "
            SELECT hashid, data
            FROM tokens
            WHERE kid = $1
              AND hashid = ANY($2)
            ",
        )
        .bind(kid)
        .bind(hashids)
        .fetch_all(&self.pool)
        .await?;

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
        })
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
        sqlx::query("SELECT 1").execute(&self.pool).await?;

        Ok(())
    }
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

async fn validate_opskeys_schema(pool: &PgPool) -> Result<(), DynError> {
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
        return Err(crate::error::storage(
            "postgres schema is missing opskeys table",
        ));
    }

    let kid = find_column(&columns, "kid")
        .ok_or_else(|| crate::error::storage("postgres schema is missing opskeys.kid column"))?;
    let keys = find_column(&columns, "keys")
        .ok_or_else(|| crate::error::storage("postgres schema is missing opskeys.keys column"))?;
    let properties = find_column(&columns, "properties").ok_or_else(|| {
        crate::error::storage("postgres schema is missing opskeys.properties column")
    })?;

    validate_varchar_column(&kid, "opskeys", "kid", 128, false)?;
    validate_text_column(&keys, "opskeys", "keys", false)?;
    validate_text_column(&properties, "opskeys", "properties", false)?;
    validate_primary_key(pool, "opskeys", &["kid"]).await?;

    Ok(())
}

async fn validate_tokens_schema(pool: &PgPool) -> Result<(), DynError> {
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
        return Err(crate::error::storage(
            "postgres schema is missing tokens table",
        ));
    }

    let kid = find_column(&columns, "kid")
        .ok_or_else(|| crate::error::storage("postgres schema is missing tokens.kid column"))?;
    let hashid = find_column(&columns, "hashid")
        .ok_or_else(|| crate::error::storage("postgres schema is missing tokens.hashid column"))?;
    let data = find_column(&columns, "data")
        .ok_or_else(|| crate::error::storage("postgres schema is missing tokens.data column"))?;

    validate_varchar_column(&kid, "tokens", "kid", 128, false)?;
    validate_varchar_column(&hashid, "tokens", "hashid", 128, false)?;
    validate_text_column(&data, "tokens", "data", false)?;
    validate_primary_key(pool, "tokens", &["kid", "hashid"]).await?;

    Ok(())
}

async fn validate_indexes_schema(pool: &PgPool) -> Result<(), DynError> {
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
        return Err(crate::error::storage(
            "postgres schema is missing indexes table",
        ));
    }

    let kid = find_column(&columns, "kid")
        .ok_or_else(|| crate::error::storage("postgres schema is missing indexes.kid column"))?;
    let digest = find_column(&columns, "digest")
        .ok_or_else(|| crate::error::storage("postgres schema is missing indexes.digest column"))?;

    validate_varchar_column(&kid, "indexes", "kid", 128, false)?;
    validate_varchar_column(&digest, "indexes", "digest", 128, false)?;
    validate_primary_key(pool, "indexes", &["kid", "digest"]).await?;

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
) -> Result<(), DynError> {
    if column.name != expected_name
        || column.data_type != "character varying"
        || column.max_length != Some(expected_max_length)
        || column.nullable != expected_nullable
    {
        return Err(crate::error::storage(format!(
            "postgres schema mismatch for {table_name}.{expected_name}: expected type=VARCHAR({expected_max_length}), nullable={expected_nullable}",
        )));
    }

    Ok(())
}

fn validate_text_column(
    column: &ColumnInfo,
    table_name: &str,
    expected_name: &str,
    expected_nullable: bool,
) -> Result<(), DynError> {
    if column.name != expected_name
        || column.data_type != "text"
        || column.max_length.is_some()
        || column.nullable != expected_nullable
    {
        return Err(crate::error::storage(format!(
            "postgres schema mismatch for {table_name}.{expected_name}: expected type=TEXT, nullable={expected_nullable}",
        )));
    }

    Ok(())
}

async fn validate_primary_key(
    pool: &PgPool,
    table_name: &str,
    expected_columns: &[&str],
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
            "postgres schema mismatch for {table_name} primary key: expected {}",
            expected_columns.join(", ")
        )));
    }

    Ok(())
}
