use tracing::{Level, event};

pub const TARGET: &str = crate::core::logging::AUDIT_TARGET;

pub struct Actor<'a> {
    pub name: &'a str,
    pub fingerprint: &'a str,
    pub root: bool,
    pub admin: bool,
}

pub fn auth_success(actor: &Actor) {
    event!(
        target: TARGET,
        Level::INFO,
        event = "auth.success",
        outcome = "allow",
        actor = %actor.name,
        actor_fp = %actor.fingerprint,
        root = actor.root,
        admin = actor.admin,
    );
}

pub fn auth_denied(reason: &str) {
    event!(
        target: TARGET,
        Level::INFO,
        event = "auth.denied",
        outcome = "deny",
        reason = %reason,
    );
}
