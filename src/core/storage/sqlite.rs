use crate::core::storage::OpsKeyRow;
use crate::error::DynError;
use sqlx::Row;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool};
use std::io;
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
            Box::new(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("failed to connect to ops sqlite: {err}"),
            )) as DynError
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
            return Err(Box::new(io::Error::new(
                io::ErrorKind::NotFound,
                format!("ops key not found: {id}"),
            )));
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
            return Err(Box::new(io::Error::new(
                io::ErrorKind::NotFound,
                format!("ops key not found: {id}"),
            )));
        }

        info!(id, "updated ops key properties");
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
        return Err(Box::new(io::Error::new(
            io::ErrorKind::InvalidData,
            "sqlite schema is missing ops_keys table",
        )));
    }

    let id = find_column(&rows, "id").ok_or_else(|| {
        Box::new(io::Error::new(
            io::ErrorKind::InvalidData,
            "sqlite schema is missing ops_keys.id column",
        )) as DynError
    })?;
    let enc_keys = find_column(&rows, "enc_keys").ok_or_else(|| {
        Box::new(io::Error::new(
            io::ErrorKind::InvalidData,
            "sqlite schema is missing ops_keys.enc_keys column",
        )) as DynError
    })?;
    let properties = find_column(&rows, "properties").ok_or_else(|| {
        Box::new(io::Error::new(
            io::ErrorKind::InvalidData,
            "sqlite schema is missing ops_keys.properties column",
        )) as DynError
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
        return Err(Box::new(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "sqlite schema mismatch for ops_keys.{expected_name}: expected type={expected_type}, notnull={expected_notnull}, primary_key={expected_primary_key}",
            ),
        )));
    }

    Ok(())
}
