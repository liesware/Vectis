use crate::error::{DynError, VectisError};
use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use tokio::sync::OnceCell;

type SharedKeyLoadResult = Result<(), VectisError>;

pub(super) struct KeyLoadSingleflight {
    flights: Mutex<HashMap<String, Weak<KeyLoadFlight>>>,
}

struct KeyLoadFlight {
    result: OnceCell<SharedKeyLoadResult>,
}

struct KeyLoadLease {
    kid: String,
    flight: Arc<KeyLoadFlight>,
    owner: Weak<KeyLoadSingleflight>,
}

impl KeyLoadSingleflight {
    pub(super) fn new() -> Self {
        Self {
            flights: Mutex::new(HashMap::new()),
        }
    }

    pub(super) async fn run<F, Fut>(self: &Arc<Self>, kid: &str, loader: F) -> Result<(), DynError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<(), DynError>>,
    {
        let lease = self.acquire(kid);
        let mut leader_error: Option<DynError> = None;
        let shared = lease
            .flight
            .result
            .get_or_init(|| async {
                match loader().await {
                    Ok(()) => Ok(()),
                    Err(err) => {
                        let shared = shared_error(&err);
                        leader_error = Some(err);
                        Err(shared)
                    }
                }
            })
            .await
            .clone();
        drop(lease);

        if let Some(err) = leader_error {
            return Err(err);
        }
        shared.map_err(|err| Box::new(err) as DynError)
    }

    fn acquire(self: &Arc<Self>, kid: &str) -> KeyLoadLease {
        let mut flights = self.lock_flights();
        flights.retain(|_, flight| flight.strong_count() > 0);
        let flight = flights.get(kid).and_then(Weak::upgrade).unwrap_or_else(|| {
            let flight = Arc::new(KeyLoadFlight::new());
            flights.insert(kid.to_string(), Arc::downgrade(&flight));
            flight
        });

        KeyLoadLease {
            kid: kid.to_string(),
            flight,
            owner: Arc::downgrade(self),
        }
    }

    fn lock_flights(&self) -> MutexGuard<'_, HashMap<String, Weak<KeyLoadFlight>>> {
        self.flights
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[cfg(test)]
    fn participant_count(&self, kid: &str) -> usize {
        self.lock_flights()
            .get(kid)
            .map(Weak::strong_count)
            .unwrap_or_default()
    }

    #[cfg(test)]
    fn flight_entries(&self) -> usize {
        self.lock_flights().len()
    }
}

impl KeyLoadFlight {
    fn new() -> Self {
        Self {
            result: OnceCell::new(),
        }
    }
}

impl Drop for KeyLoadLease {
    fn drop(&mut self) {
        let Some(owner) = self.owner.upgrade() else {
            return;
        };
        let mut flights = owner.lock_flights();
        let own_flight = Arc::downgrade(&self.flight);
        let is_current = flights
            .get(&self.kid)
            .is_some_and(|current| current.ptr_eq(&own_flight));

        if is_current && Arc::strong_count(&self.flight) == 1 {
            flights.remove(&self.kid);
        }
    }
}

fn shared_error(err: &DynError) -> VectisError {
    match err.downcast_ref::<VectisError>() {
        Some(err) => err.clone(),
        None => VectisError::Internal(err.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::pending;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tokio::sync::{Barrier, Notify, Semaphore};
    use tokio::time::timeout;

    async fn wait_for_participants(singleflight: &KeyLoadSingleflight, kid: &str, expected: usize) {
        timeout(Duration::from_secs(1), async {
            while singleflight.participant_count(kid) < expected {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("participants must join the flight");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn same_kid_runs_loader_once() {
        let singleflight = Arc::new(KeyLoadSingleflight::new());
        let calls = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(Semaphore::new(0));
        let mut tasks = Vec::new();

        for _ in 0..32 {
            let singleflight = Arc::clone(&singleflight);
            let calls = Arc::clone(&calls);
            let release = Arc::clone(&release);
            tasks.push(tokio::spawn(async move {
                singleflight
                    .run("kid", || async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        let permit = release.acquire().await.expect("semaphore must stay open");
                        permit.forget();
                        Ok(())
                    })
                    .await
            }));
        }

        wait_for_participants(&singleflight, "kid", 32).await;
        release.add_permits(1);
        for task in tasks {
            task.await
                .expect("task must complete")
                .expect("load must pass");
        }

        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(singleflight.flight_entries(), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn different_kids_load_concurrently() {
        let singleflight = Arc::new(KeyLoadSingleflight::new());
        let entered = Arc::new(Barrier::new(3));
        let mut tasks = Vec::new();

        for kid in ["kid-a", "kid-b"] {
            let singleflight = Arc::clone(&singleflight);
            let entered = Arc::clone(&entered);
            tasks.push(tokio::spawn(async move {
                singleflight
                    .run(kid, || async move {
                        entered.wait().await;
                        Ok(())
                    })
                    .await
            }));
        }

        timeout(Duration::from_secs(1), entered.wait())
            .await
            .expect("distinct loaders must overlap");
        for task in tasks {
            task.await
                .expect("task must complete")
                .expect("load must pass");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn shares_errors_without_negative_caching() {
        let singleflight = Arc::new(KeyLoadSingleflight::new());
        let calls = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(Semaphore::new(0));
        let mut tasks = Vec::new();

        for _ in 0..16 {
            let singleflight = Arc::clone(&singleflight);
            let calls = Arc::clone(&calls);
            let release = Arc::clone(&release);
            tasks.push(tokio::spawn(async move {
                singleflight
                    .run("missing", || async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        let permit = release.acquire().await.expect("semaphore must stay open");
                        permit.forget();
                        Err(crate::error::not_found("ops key not found"))
                    })
                    .await
            }));
        }

        wait_for_participants(&singleflight, "missing", 16).await;
        release.add_permits(1);
        for task in tasks {
            let err = task
                .await
                .expect("task must complete")
                .expect_err("load must fail");
            assert!(matches!(
                err.downcast_ref::<VectisError>(),
                Some(VectisError::NotFound(message)) if message == "ops key not found"
            ));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(singleflight.flight_entries(), 0);

        let retry_calls = Arc::clone(&calls);
        singleflight
            .run("missing", || async move {
                retry_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .await
            .expect("later load must retry");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn waiter_recovers_after_initializer_is_cancelled() {
        let singleflight = Arc::new(KeyLoadSingleflight::new());
        let entered = Arc::new(Notify::new());
        let leader = {
            let singleflight = Arc::clone(&singleflight);
            let entered = Arc::clone(&entered);
            tokio::spawn(async move {
                singleflight
                    .run("kid", || async move {
                        entered.notify_one();
                        pending::<Result<(), DynError>>().await
                    })
                    .await
            })
        };
        entered.notified().await;

        let waiter_calls = Arc::new(AtomicUsize::new(0));
        let waiter = {
            let singleflight = Arc::clone(&singleflight);
            let waiter_calls = Arc::clone(&waiter_calls);
            tokio::spawn(async move {
                singleflight
                    .run("kid", || async move {
                        waiter_calls.fetch_add(1, Ordering::SeqCst);
                        Ok(())
                    })
                    .await
            })
        };
        wait_for_participants(&singleflight, "kid", 2).await;

        leader.abort();
        let _ = leader.await;
        timeout(Duration::from_secs(1), waiter)
            .await
            .expect("waiter must take over")
            .expect("waiter task must complete")
            .expect("replacement load must pass");

        assert_eq!(waiter_calls.load(Ordering::SeqCst), 1);
        assert_eq!(singleflight.flight_entries(), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_only_initializer_removes_flight() {
        let singleflight = Arc::new(KeyLoadSingleflight::new());
        let entered = Arc::new(Notify::new());
        let leader = {
            let singleflight = Arc::clone(&singleflight);
            let entered = Arc::clone(&entered);
            tokio::spawn(async move {
                singleflight
                    .run("kid", || async move {
                        entered.notify_one();
                        pending::<Result<(), DynError>>().await
                    })
                    .await
            })
        };
        entered.notified().await;

        leader.abort();
        let _ = leader.await;

        assert_eq!(singleflight.flight_entries(), 0);
    }

    #[test]
    fn old_lease_does_not_remove_new_generation() {
        let singleflight = Arc::new(KeyLoadSingleflight::new());
        let old = singleflight.acquire("kid");
        let replacement = Arc::new(KeyLoadFlight::new());
        singleflight
            .lock_flights()
            .insert(String::from("kid"), Arc::downgrade(&replacement));

        drop(old);

        let current = singleflight
            .lock_flights()
            .get("kid")
            .and_then(Weak::upgrade)
            .expect("replacement flight must remain");
        assert!(Arc::ptr_eq(&current, &replacement));
    }
}
