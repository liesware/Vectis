use crate::core::permissions::AuthenticatedClient;
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

tokio::task_local! {
    static REQUEST_AUDIT: RequestAudit;
}

#[derive(Clone)]
pub struct RequestAudit {
    id: String,
    failure: Arc<Mutex<Option<String>>>,
    enqueued: Arc<AtomicBool>,
}

impl RequestAudit {
    pub fn new(id: String) -> Self {
        Self {
            id,
            failure: Arc::new(Mutex::new(None)),
            enqueued: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn enqueued(&self) -> bool {
        self.enqueued.load(Ordering::Acquire)
    }

    pub fn failure_cell(&self) -> &Arc<Mutex<Option<String>>> {
        &self.failure
    }

    pub fn failure(&self) -> Option<String> {
        self.failure.lock().ok().and_then(|cell| cell.clone())
    }
}

pub struct Actor<'a> {
    pub name: &'a str,
    pub fingerprint: &'a str,
    pub root: bool,
    pub admin: bool,
}

pub fn actor_from_client(client: &AuthenticatedClient) -> Actor<'_> {
    Actor {
        name: client.client_name(),
        fingerprint: client.fingerprint(),
        root: client.is_root(),
        admin: client.is_admin(),
    }
}

pub fn auth_success(actor: &Actor) {
    audit_event("auth.success", "allow", Some(actor), None, None, None, None);
}

pub fn auth_denied(reason: &str) {
    audit_event("auth.denied", "deny", None, None, None, None, Some(reason));
}

pub fn permission_allowed(actor: &Actor, kid: Option<&str>, action: &str) {
    audit_event(
        "permission.allowed",
        "allow",
        Some(actor),
        kid,
        None,
        Some(action),
        None,
    );
}

pub fn permission_denied(actor: &Actor, kid: Option<&str>, action: &str, reason: &str) {
    audit_event(
        "permission.denied",
        "deny",
        Some(actor),
        kid,
        None,
        Some(action),
        Some(reason),
    );
}

pub fn operation_success(
    event_name: &str,
    actor: Option<&Actor>,
    kid: Option<&str>,
    remote_kid: Option<&str>,
    action: Option<&str>,
) {
    audit_event(event_name, "success", actor, kid, remote_kid, action, None);
}

pub fn operation_denied(
    event_name: &str,
    actor: &Actor,
    kid: Option<&str>,
    remote_kid: Option<&str>,
    action: Option<&str>,
    reason: &str,
) {
    audit_event(
        event_name,
        "deny",
        Some(actor),
        kid,
        remote_kid,
        action,
        Some(reason),
    );
}

pub fn operation_failed(
    event_name: &str,
    actor: Option<&Actor>,
    kid: Option<&str>,
    remote_kid: Option<&str>,
    action: Option<&str>,
    reason: &str,
) {
    audit_event(
        event_name,
        "failure",
        actor,
        kid,
        remote_kid,
        action,
        Some(reason),
    );
}

pub async fn with_request_context<F>(context: RequestAudit, future: F) -> F::Output
where
    F: Future,
{
    REQUEST_AUDIT.scope(context, future).await
}

fn audit_event(
    event_name: &str,
    outcome: &str,
    actor: Option<&Actor>,
    kid: Option<&str>,
    remote_kid: Option<&str>,
    action: Option<&str>,
    reason: Option<&str>,
) {
    let context = REQUEST_AUDIT.try_with(Clone::clone).ok();
    let event = crate::core::audit_chain::AuditEvent {
        event: event_name.to_string(),
        outcome: outcome.to_string(),
        actor: actor.map(|actor| actor.name).unwrap_or("").to_string(),
        actor_fp: actor
            .map(|actor| actor.fingerprint)
            .unwrap_or("")
            .to_string(),
        root: actor.is_some_and(|actor| actor.root),
        admin: actor.is_some_and(|actor| actor.admin),
        kid: kid.unwrap_or("").to_string(),
        remote_kid: remote_kid.unwrap_or("").to_string(),
        action: action.unwrap_or("").to_string(),
        reason: reason.unwrap_or("").to_string(),
        request_id: context
            .as_ref()
            .map(|context| context.id.clone())
            .unwrap_or_default(),
    };
    match context {
        Some(context) => {
            context.enqueued.store(true, Ordering::Release);
            crate::core::audit_chain::record(event, &context.failure);
        }
        // Off the request task (CLI, startup, detached sub-task): still persist the event
        // for a complete audit trail, ungated since there is no response to fail closed.
        None => crate::core::audit_chain::record_standalone(event, &Arc::new(Mutex::new(None))),
    }
}
