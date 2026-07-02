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

pub fn remote_unreachable(message: impl Into<String>) -> DynError {
    Box::new(VectisError::RemoteUnreachable(message.into()))
}

pub fn storage(message: impl Into<String>) -> DynError {
    Box::new(VectisError::Storage(message.into()))
}

pub fn internal(message: impl Into<String>) -> DynError {
    Box::new(VectisError::Internal(message.into()))
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
