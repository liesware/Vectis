use std::error::Error;
use std::io;

pub type DynError = Box<dyn Error + Send + Sync>;

#[derive(Debug, thiserror::Error)]
pub enum VectisError {
    #[error("{0}")]
    InvalidInput(String),
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    Forbidden(String),
    #[error("{0}")]
    InvalidSignature(String),
    #[error("{0}")]
    ConfigSignatureStale(String),
    #[error("{0}")]
    RemoteUnreachable(String),
    #[error("{0}")]
    Storage(String),
    #[error("{0}")]
    Internal(String),
}

pub fn invalid_input(message: impl Into<String>) -> DynError {
    Box::new(VectisError::InvalidInput(message.into()))
}

pub fn not_found(message: impl Into<String>) -> DynError {
    Box::new(VectisError::NotFound(message.into()))
}

pub fn forbidden(message: impl Into<String>) -> DynError {
    Box::new(VectisError::Forbidden(message.into()))
}

pub fn invalid_signature(message: impl Into<String>) -> DynError {
    Box::new(VectisError::InvalidSignature(message.into()))
}

pub fn config_signature_stale(message: impl Into<String>) -> DynError {
    Box::new(VectisError::ConfigSignatureStale(message.into()))
}

pub fn remote_unreachable(message: impl Into<String>) -> DynError {
    Box::new(VectisError::RemoteUnreachable(message.into()))
}

pub fn storage(message: impl Into<String>) -> DynError {
    Box::new(VectisError::Storage(message.into()))
}

pub fn internal(message: impl Into<String>) -> DynError {
    Box::new(VectisError::Internal(message.into()))
}

pub fn with_prefix(prefix: &str, err: DynError) -> DynError {
    match err.downcast_ref::<VectisError>() {
        Some(VectisError::InvalidInput(message)) => invalid_input(format!("{prefix}: {message}")),
        Some(VectisError::NotFound(message)) => not_found(format!("{prefix}: {message}")),
        Some(VectisError::Forbidden(message)) => forbidden(format!("{prefix}: {message}")),
        Some(VectisError::InvalidSignature(message)) => {
            invalid_signature(format!("{prefix}: {message}"))
        }
        Some(VectisError::ConfigSignatureStale(message)) => {
            config_signature_stale(format!("{prefix}: {message}"))
        }
        Some(VectisError::RemoteUnreachable(message)) => {
            remote_unreachable(format!("{prefix}: {message}"))
        }
        Some(VectisError::Storage(message)) => storage(format!("{prefix}: {message}")),
        Some(VectisError::Internal(message)) => internal(format!("{prefix}: {message}")),
        None => internal(format!("{prefix}: {err}")),
    }
}

pub fn is_config_signature_stale(err: &(dyn Error + Send + Sync + 'static)) -> bool {
    matches!(
        err.downcast_ref::<VectisError>(),
        Some(VectisError::ConfigSignatureStale(_))
    )
}

pub fn is_not_found(err: &(dyn Error + Send + Sync + 'static)) -> bool {
    if matches!(
        err.downcast_ref::<VectisError>(),
        Some(VectisError::NotFound(_))
    ) {
        return true;
    }

    err.downcast_ref::<io::Error>()
        .is_some_and(|err| err.kind() == io::ErrorKind::NotFound)
}
