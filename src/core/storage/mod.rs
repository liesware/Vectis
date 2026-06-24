use crate::core::config;
use crate::error::DynError;
use serde::Serialize;
use std::io;

mod sqlite;

pub const STORAGE_TYPES: &[&str] = &["sqlite"];

#[derive(Serialize)]
pub struct OpsKeyRow {
    pub id: String,
    pub enc_keys: String,
}

pub async fn save_ops_keys(id: &str, enc_keys: &str) -> Result<OpsKeyRow, DynError> {
    match storage_type()?.as_str() {
        "sqlite" => sqlite::save_ops_keys(id, enc_keys).await,
        storage => unsupported_storage(storage),
    }
}

pub async fn get_ops_keys(id: &str) -> Result<OpsKeyRow, DynError> {
    match storage_type()?.as_str() {
        "sqlite" => sqlite::get_ops_keys(id).await,
        storage => unsupported_storage(storage),
    }
}

pub async fn list_ops_keys() -> Result<Vec<OpsKeyRow>, DynError> {
    match storage_type()?.as_str() {
        "sqlite" => sqlite::list_ops_keys().await,
        storage => unsupported_storage(storage),
    }
}

fn storage_type() -> Result<String, DynError> {
    Ok(config::app_config()?.storage_type)
}

fn unsupported_storage<T>(storage: &str) -> Result<T, DynError> {
    Err(Box::new(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("unsupported STORAGE: {storage}"),
    )))
}
