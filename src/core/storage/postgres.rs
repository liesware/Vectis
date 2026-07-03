use crate::core::storage::OpsKeyRow;
use crate::error::DynError;
use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::{Postgres, Row, Transaction};
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

        validate_ops_keys_schema(&pool).await?;
        info!("validated ops_keys postgres schema");

        Ok(Self { pool })
    }

    pub async fn save_ops_keys(
        &self,
        id: &str,
        enc_keys: &str,
        properties: &str,
    ) -> Result<OpsKeyRow, DynError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "
            INSERT INTO ops_keys (id, enc_keys, properties)
            VALUES ($1, $2, $3)
            ",
        )
        .bind(id)
        .bind(enc_keys)
        .bind(properties)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        info!(id, "inserted ops keys");

        Ok(OpsKeyRow {
            id: id.to_string(),
            enc_keys: enc_keys.to_string(),
            properties: properties.to_string(),
        })
    }

    pub async fn get_ops_keys(&self, id: &str) -> Result<OpsKeyRow, DynError> {
        let row = fetch_ops_keys(&self.pool, id).await?;

        row.ok_or_else(|| crate::error::not_found(format!("ops key not found: {id}")))
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
        let mut tx = self.pool.begin().await?;
        let result = sqlx::query(
            "
            UPDATE ops_keys
            SET properties = $1
            WHERE id = $2
            ",
        )
        .bind(properties)
        .bind(id)
        .execute(&mut *tx)
        .await?;

        if result.rows_affected() == 0 {
            return Err(crate::error::not_found(format!("ops key not found: {id}")));
        }

        let row = fetch_ops_keys_tx(&mut tx, id).await?;
        tx.commit().await?;
        info!(id, "updated ops key properties");

        row.ok_or_else(|| crate::error::not_found(format!("ops key not found: {id}")))
    }

    pub async fn health_check(&self) -> Result<(), DynError> {
        sqlx::query("SELECT 1").execute(&self.pool).await?;

        Ok(())
    }
}

async fn fetch_ops_keys(pool: &PgPool, id: &str) -> Result<Option<OpsKeyRow>, DynError> {
    let row = sqlx::query(
        "
        SELECT id, enc_keys, properties
        FROM ops_keys
        WHERE id = $1
        ",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|row| OpsKeyRow {
        id: row.get("id"),
        enc_keys: row.get("enc_keys"),
        properties: row.get("properties"),
    }))
}

async fn fetch_ops_keys_tx(
    tx: &mut Transaction<'_, Postgres>,
    id: &str,
) -> Result<Option<OpsKeyRow>, DynError> {
    let row = sqlx::query(
        "
        SELECT id, enc_keys, properties
        FROM ops_keys
        WHERE id = $1
        ",
    )
    .bind(id)
    .fetch_optional(&mut **tx)
    .await?;

    Ok(row.map(|row| OpsKeyRow {
        id: row.get("id"),
        enc_keys: row.get("enc_keys"),
        properties: row.get("properties"),
    }))
}

async fn validate_ops_keys_schema(pool: &PgPool) -> Result<(), DynError> {
    let columns = sqlx::query(
        "
        SELECT column_name, data_type, character_maximum_length, is_nullable
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'ops_keys'
        ",
    )
    .fetch_all(pool)
    .await?;

    if columns.is_empty() {
        return Err(crate::error::storage(
            "postgres schema is missing ops_keys table",
        ));
    }

    let id = find_column(&columns, "id")
        .ok_or_else(|| crate::error::storage("postgres schema is missing ops_keys.id column"))?;
    let enc_keys = find_column(&columns, "enc_keys").ok_or_else(|| {
        crate::error::storage("postgres schema is missing ops_keys.enc_keys column")
    })?;
    let properties = find_column(&columns, "properties").ok_or_else(|| {
        crate::error::storage("postgres schema is missing ops_keys.properties column")
    })?;

    validate_varchar_column(&id, "id", 128, false)?;
    validate_text_column(&enc_keys, "enc_keys", false)?;
    validate_text_column(&properties, "properties", false)?;
    validate_primary_key(pool).await?;

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
            "postgres schema mismatch for ops_keys.{expected_name}: expected type=VARCHAR({expected_max_length}), nullable={expected_nullable}",
        )));
    }

    Ok(())
}

fn validate_text_column(
    column: &ColumnInfo,
    expected_name: &str,
    expected_nullable: bool,
) -> Result<(), DynError> {
    if column.name != expected_name
        || column.data_type != "text"
        || column.max_length.is_some()
        || column.nullable != expected_nullable
    {
        return Err(crate::error::storage(format!(
            "postgres schema mismatch for ops_keys.{expected_name}: expected type=TEXT, nullable={expected_nullable}",
        )));
    }

    Ok(())
}

async fn validate_primary_key(pool: &PgPool) -> Result<(), DynError> {
    let rows = sqlx::query(
        "
        SELECT a.attname
        FROM pg_index i
        JOIN pg_class t ON t.oid = i.indrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
        JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY(i.indkey)
        WHERE n.nspname = 'public'
          AND t.relname = 'ops_keys'
          AND i.indisprimary
        ORDER BY a.attnum
        ",
    )
    .fetch_all(pool)
    .await?;

    let primary_key_columns: Vec<String> = rows.iter().map(|row| row.get("attname")).collect();
    if primary_key_columns != ["id"] {
        return Err(crate::error::storage(
            "postgres schema mismatch for ops_keys primary key: expected id",
        ));
    }

    Ok(())
}
