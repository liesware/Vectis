use crate::core::permissions::AuthenticatedClient;
use tracing::{Level, event};

pub const TARGET: &str = crate::core::logging::AUDIT_TARGET;

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

fn audit_event(
    event_name: &str,
    outcome: &str,
    actor: Option<&Actor>,
    kid: Option<&str>,
    remote_kid: Option<&str>,
    action: Option<&str>,
    reason: Option<&str>,
) {
    let actor_name = actor.map(|actor| actor.name).unwrap_or("");
    let actor_fp = actor.map(|actor| actor.fingerprint).unwrap_or("");
    let root = actor.is_some_and(|actor| actor.root);
    let admin = actor.is_some_and(|actor| actor.admin);

    event!(
        target: TARGET,
        Level::INFO,
        event = %event_name,
        outcome = %outcome,
        actor = %actor_name,
        actor_fp = %actor_fp,
        root = root,
        admin = admin,
        kid = %kid.unwrap_or(""),
        remote_kid = %remote_kid.unwrap_or(""),
        action = %action.unwrap_or(""),
        reason = %reason.unwrap_or(""),
    );
}
