use std::sync::{Arc, OnceLock};
use std::time::Duration;

use tokio::sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError};

use crate::core::metrics::{self, CryptoQueueWait, CryptoRejection};
use crate::error::DynError;

static CRYPTO_LIMITER: OnceLock<CryptoLimiter> = OnceLock::new();

pub fn init_crypto_limit(max: usize, queued: usize, timeout: Duration) {
    if CRYPTO_LIMITER
        .set(CryptoLimiter::new(max, queued, timeout))
        .is_err()
    {
        tracing::warn!("crypto concurrency limit already initialized; ignoring the new value");
    }
}

struct CryptoLimiter {
    execution: Arc<Semaphore>,
    waiting: Arc<Semaphore>,
    timeout: Duration,
}

impl CryptoLimiter {
    fn new(max: usize, queued: usize, timeout: Duration) -> Self {
        Self {
            execution: Arc::new(Semaphore::new(max)),
            waiting: Arc::new(Semaphore::new(queued)),
            timeout,
        }
    }

    async fn acquire(&self) -> Result<OwnedSemaphorePermit, DynError> {
        match Arc::clone(&self.execution).try_acquire_owned() {
            Ok(permit) => return Ok(permit),
            Err(TryAcquireError::Closed) => {
                return Err(crate::error::internal("crypto execution semaphore closed"));
            }
            Err(TryAcquireError::NoPermits) => {}
        }
        let _position = match Arc::clone(&self.waiting).try_acquire_owned() {
            Ok(position) => position,
            Err(TryAcquireError::Closed) => {
                return Err(crate::error::internal("crypto queue semaphore closed"));
            }
            Err(TryAcquireError::NoPermits) => {
                metrics::record_crypto_rejection(CryptoRejection::Full);
                return Err(crate::error::overloaded("crypto queue full"));
            }
        };
        let started = tokio::time::Instant::now();
        let deadline = started + self.timeout;
        let wait = CryptoQueueWait::new(started);
        let result =
            tokio::time::timeout_at(deadline, Arc::clone(&self.execution).acquire_owned()).await;
        match result {
            Ok(Ok(permit)) => {
                wait.completed();
                Ok(permit)
            }
            Ok(Err(_)) => Err(crate::error::internal("crypto execution semaphore closed")),
            Err(_) => {
                wait.completed();
                metrics::record_crypto_rejection(CryptoRejection::Timeout);
                Err(crate::error::overloaded("crypto queue timeout"))
            }
        }
        // Both guards drop here (or on cancellation), before any blocking dispatch.
    }

    async fn run<T>(
        &self,
        f: impl FnOnce() -> Result<T, DynError> + Send + 'static,
    ) -> Result<T, DynError>
    where
        T: Send + 'static,
    {
        let permit = self.acquire().await?;
        spawn_blocking_unbounded(move || {
            let _permit = permit;
            f()
        })
        .await
    }
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
    match CRYPTO_LIMITER.get() {
        Some(limiter) => limiter.run(f).await,
        None => spawn_blocking_unbounded(f).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::{Context, Poll, Waker};

    fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
        future.poll(&mut Context::from_waker(Waker::noop()))
    }

    fn limiter(queued: usize) -> CryptoLimiter {
        CryptoLimiter::new(1, queued, Duration::from_secs(30))
    }

    #[tokio::test]
    async fn waits_then_runs_and_releases_all_capacity() {
        let limiter = limiter(1);
        let permit = limiter.acquire().await.unwrap();
        let called = Arc::new(AtomicBool::new(false));
        let flag = called.clone();
        let mut job = Box::pin(limiter.run(move || {
            flag.store(true, Ordering::SeqCst);
            Ok(42)
        }));
        assert!(poll_once(job.as_mut()).is_pending());
        assert_eq!(limiter.waiting.available_permits(), 0);
        assert!(!called.load(Ordering::SeqCst));
        drop(permit);
        assert_eq!(job.await.unwrap(), 42);
        assert_eq!(limiter.waiting.available_permits(), 1);
        assert_eq!(limiter.execution.available_permits(), 1);
    }

    #[tokio::test]
    async fn bounded_queue_keeps_registered_waiter_order() {
        let limiter = limiter(2);
        let held = limiter.acquire().await.unwrap();
        let mut first = Box::pin(limiter.acquire());
        let mut second = Box::pin(limiter.acquire());
        assert!(poll_once(first.as_mut()).is_pending());
        assert!(poll_once(second.as_mut()).is_pending());
        assert_eq!(limiter.waiting.available_permits(), 0);
        let rejected = limiter
            .run(|| -> Result<(), DynError> { panic!("must not execute") })
            .await
            .unwrap_err();
        assert_eq!(rejected.to_string(), "crypto queue full");
        drop(held);
        let first_permit = first.await.unwrap();
        assert!(poll_once(second.as_mut()).is_pending());
        drop(first_permit);
        drop(second.await.unwrap());
        assert_eq!(limiter.execution.available_permits(), 1);
        assert_eq!(limiter.waiting.available_permits(), 2);
    }

    #[tokio::test]
    async fn zero_queue_rejects_immediately() {
        let limiter = limiter(0);
        let _held = limiter.acquire().await.unwrap();
        let result = limiter
            .run(|| -> Result<(), DynError> { panic!("must not execute") })
            .await;
        assert_eq!(result.unwrap_err().to_string(), "crypto queue full");
    }

    #[tokio::test(start_paused = true)]
    async fn timeout_never_dispatches_and_releases_queue_position() {
        let limiter = CryptoLimiter::new(1, 1, Duration::from_millis(100));
        let held = limiter.acquire().await.unwrap();
        let mut job =
            Box::pin(limiter.run(|| -> Result<(), DynError> { panic!("must not execute") }));
        assert!(poll_once(job.as_mut()).is_pending());
        tokio::time::advance(Duration::from_millis(101)).await;
        assert_eq!(job.await.unwrap_err().to_string(), "crypto queue timeout");
        assert_eq!(limiter.waiting.available_permits(), 1);
        drop(held);
        assert!(limiter.acquire().await.is_ok());
    }

    #[tokio::test]
    async fn cancel_before_dispatch_frees_position_and_never_executes() {
        let limiter = limiter(1);
        let held = limiter.acquire().await.unwrap();
        let mut job =
            Box::pin(limiter.run(|| -> Result<(), DynError> { panic!("must not execute") }));
        assert!(poll_once(job.as_mut()).is_pending());
        drop(job);
        assert_eq!(limiter.waiting.available_permits(), 1);
        let mut next = Box::pin(limiter.acquire());
        assert!(poll_once(next.as_mut()).is_pending());
        drop(held);
        drop(next.await.unwrap());
    }

    #[tokio::test]
    async fn cancel_started_caller_keeps_permit_until_blocking_work_finishes() {
        let limiter = Arc::new(limiter(0));
        let worker_limiter = limiter.clone();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let caller = tokio::spawn(async move {
            worker_limiter
                .run(move || {
                    started_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    Ok(())
                })
                .await
        });
        started_rx.await.unwrap();
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        assert_eq!(limiter.execution.available_permits(), 0);
        assert!(limiter.acquire().await.is_err());
        release_tx.send(()).unwrap();
        // A released execution permit, not a sleep, establishes worker completion.
        drop(limiter.execution.acquire().await.unwrap());
        assert_eq!(limiter.execution.available_permits(), 1);
    }

    #[tokio::test]
    async fn error_and_panic_release_execution_capacity() {
        let limiter = limiter(1);
        assert!(
            limiter
                .run(|| -> Result<(), DynError> { Err(crate::error::invalid_input("test")) })
                .await
                .is_err()
        );
        assert_eq!(limiter.execution.available_permits(), 1);
        assert!(
            limiter
                .run(|| -> Result<(), DynError> { panic!("test worker panic") })
                .await
                .is_err()
        );
        assert_eq!(limiter.execution.available_permits(), 1);
        assert_eq!(limiter.waiting.available_permits(), 1);
    }

    #[tokio::test]
    async fn http_waits_then_succeeds_and_full_queue_rejects_without_execution() {
        use axum::{Json, Router, response::IntoResponse, routing::post};
        crate::core::tls::ensure_crypto_provider();
        let limiter = Arc::new(limiter(1));
        let held = limiter.acquire().await.unwrap();
        let entered = Arc::new(tokio::sync::Notify::new());
        let executions = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let router = Router::new().route(
            "/work",
            post({
                let limiter = limiter.clone();
                let entered = entered.clone();
                let executions = executions.clone();
                move || {
                    let limiter = limiter.clone();
                    let executions = executions.clone();
                    let entered = entered.clone();
                    async move {
                        entered.notify_one();
                        match limiter
                            .run(move || {
                                executions.fetch_add(1, Ordering::SeqCst);
                                Ok(())
                            })
                            .await
                        {
                            Ok(()) => Json(serde_json::json!({"ok": true})).into_response(),
                            Err(error) => {
                                crate::io::http::test_crypto_error_response(error.as_ref())
                                    .into_response()
                            }
                        }
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/work", listener.local_addr().unwrap());
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async {
                    let _ = stop_rx.await;
                })
                .await
                .unwrap();
        });
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();
        let first = tokio::spawn({
            let client = client.clone();
            let url = url.clone();
            async move { client.post(url).send().await.unwrap() }
        });
        entered.notified().await;
        assert_eq!(limiter.waiting.available_permits(), 0);
        let rejected = client.post(&url).send().await.unwrap();
        assert_eq!(rejected.status(), reqwest::StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            rejected.json::<serde_json::Value>().await.unwrap(),
            serde_json::json!({"error": "too many requests"})
        );
        assert_eq!(executions.load(Ordering::SeqCst), 0);
        drop(held);
        assert_eq!(first.await.unwrap().status(), reqwest::StatusCode::OK);
        assert_eq!(executions.load(Ordering::SeqCst), 1);
        assert_eq!(limiter.waiting.available_permits(), 1);
        stop_tx.send(()).unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn closed_semaphores_are_internal_errors_not_overload() {
        let execution_closed = limiter(1);
        execution_closed.execution.close();
        let error = execution_closed.acquire().await.unwrap_err();
        assert!(matches!(
            error.downcast_ref(),
            Some(crate::error::VectisError::Internal(_))
        ));
        let queue_closed = limiter(1);
        let _held = queue_closed.acquire().await.unwrap();
        queue_closed.waiting.close();
        let error = queue_closed.acquire().await.unwrap_err();
        assert!(matches!(
            error.downcast_ref(),
            Some(crate::error::VectisError::Internal(_))
        ));
        let waiting = limiter(1);
        let _held = waiting.acquire().await.unwrap();
        let mut future = Box::pin(waiting.acquire());
        assert!(poll_once(future.as_mut()).is_pending());
        waiting.execution.close();
        assert!(matches!(
            future.await.unwrap_err().downcast_ref(),
            Some(crate::error::VectisError::Internal(_))
        ));
        assert_eq!(waiting.waiting.available_permits(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn queue_metrics_account_for_admission_timeout_and_cancellation() {
        let recorder = metrics::test_recorder();
        let handle = recorder.handle();
        let _recorder_guard = ::metrics::set_default_local_recorder(&recorder);
        let limiter = CryptoLimiter::new(1, 1, Duration::from_millis(100));
        let held = limiter.acquire().await.unwrap();
        let mut admitted = Box::pin(limiter.acquire());
        assert!(poll_once(admitted.as_mut()).is_pending());
        assert!(handle.render().contains("vectis_crypto_queue_pending 1"));
        assert!(limiter.acquire().await.is_err());
        drop(held);
        drop(admitted.await.unwrap());

        let held = limiter.acquire().await.unwrap();
        let mut timed_out = Box::pin(limiter.acquire());
        assert!(poll_once(timed_out.as_mut()).is_pending());
        tokio::time::advance(Duration::from_millis(101)).await;
        assert!(timed_out.await.is_err());

        let mut cancelled = Box::pin(limiter.acquire());
        assert!(poll_once(cancelled.as_mut()).is_pending());
        drop(cancelled);
        let mut closed = Box::pin(limiter.acquire());
        assert!(poll_once(closed.as_mut()).is_pending());
        limiter.execution.close();
        assert!(closed.await.is_err());
        drop(held);
        let output = handle.render();
        assert!(output.contains("vectis_crypto_queue_pending 0"), "{output}");
        assert!(
            output.contains("vectis_crypto_queue_wait_seconds_count 2"),
            "{output}"
        );
        assert!(
            output.contains("vectis_crypto_queue_wait_seconds_bucket{le=\"0.001\"}"),
            "{output}"
        );
        assert!(
            output.contains("vectis_crypto_rejections_total{reason=\"full\"} 1"),
            "{output}"
        );
        assert!(
            output.contains("vectis_crypto_rejections_total{reason=\"timeout\"} 1"),
            "{output}"
        );
    }
}
