use std::sync::{Arc, OnceLock};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::error::DynError;

static CRYPTO_SEMAPHORE: OnceLock<Arc<Semaphore>> = OnceLock::new();

pub fn init_crypto_limit(max: usize) {
    if CRYPTO_SEMAPHORE.set(Arc::new(Semaphore::new(max))).is_err() {
        tracing::warn!("crypto concurrency limit already initialized; ignoring the new value");
    }
}

fn try_reserve(semaphore: &Arc<Semaphore>) -> Result<OwnedSemaphorePermit, DynError> {
    Arc::clone(semaphore)
        .try_acquire_owned()
        .map_err(|_| crate::error::overloaded("crypto capacity exhausted"))
}

pub async fn spawn_blocking_unbounded<T>(
    f: impl FnOnce() -> Result<T, DynError> + Send + 'static,
) -> Result<T, DynError>
where
    T: Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|err| crate::error::internal(format!("crypto blocking task failed: {err}")))?
}

pub async fn spawn_blocking_crypto<T>(
    f: impl FnOnce() -> Result<T, DynError> + Send + 'static,
) -> Result<T, DynError>
where
    T: Send + 'static,
{
    let permit = match CRYPTO_SEMAPHORE.get() {
        Some(semaphore) => Some(try_reserve(semaphore)?),
        None => None,
    };

    spawn_blocking_unbounded(move || {
        let _permit = permit;
        f()
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_reserve_grants_up_to_the_limit_then_rejects() {
        let semaphore = Arc::new(Semaphore::new(1));

        let permit = try_reserve(&semaphore).expect("first reservation fits under the limit");

        let rejected = try_reserve(&semaphore).expect_err("second reservation exceeds the limit");
        assert!(rejected.to_string().contains("crypto capacity exhausted"));

        drop(permit);
        let _ = try_reserve(&semaphore).expect("slot is available after the permit is released");
    }
}
