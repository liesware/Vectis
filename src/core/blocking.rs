use crate::error::DynError;

pub async fn spawn_blocking_crypto<T>(
    f: impl FnOnce() -> Result<T, DynError> + Send + 'static,
) -> Result<T, DynError>
where
    T: Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|err| crate::error::internal(format!("crypto blocking task failed: {err}")))?
}
