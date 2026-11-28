use crate::core::{
    audit_chain, config, config_loader::ConfigLoader, logging, storage::StorageState,
};
use crate::error::{self, DynError};
use crate::ops::{internal_keys::InternalDerivedKeysState, keys};
use serde::Serialize;
use sqlx::postgres::PgConnectOptions;
use std::io::{self, IsTerminal, Read, Write};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

use super::http::{self, OutputFormat};

const CANCELLED: &str = "key purge cancelled; no records were deleted";

fn kid_argument(args: &[String]) -> Result<&str, DynError> {
    if args.len() != 1 {
        return Err(error::invalid_input(
            "keys drop requires exactly one KID; no automatic confirmation options are supported",
        ));
    }
    keys::validate_key_id(&args[0])?;
    Ok(&args[0])
}

pub fn before_logging(loader: &ConfigLoader, args: &[String]) -> Result<(), DynError> {
    if args.first().map(String::as_str) != Some("keys")
        || !args[1..].iter().any(|arg| arg == "drop")
    {
        return Ok(());
    }
    let (_, rest) = http::parse_output_option(args[1..].to_vec())?;
    if rest.first().map(String::as_str) != Some("drop")
        || rest.iter().any(|s| matches!(s.as_str(), "--help" | "-h"))
    {
        return Ok(());
    }
    kid_argument(&rest[1..])?;
    require_terminal(io::stdin().is_terminal(), io::stderr().is_terminal())?;
    require_file_logging(logging::logging_config(loader)?.target)
}

fn require_file_logging(target: logging::LogTarget) -> Result<(), DynError> {
    if target != logging::LogTarget::File {
        return Err(error::invalid_input(
            "keys drop requires VECTIS_LOG_TARGET=file; nothing was deleted",
        ));
    }
    Ok(())
}

fn require_terminal(input: bool, prompt: bool) -> Result<(), DynError> {
    if !input || !prompt {
        return Err(error::invalid_input(
            "keys drop requires terminal stdin and stderr; nothing was deleted",
        ));
    }
    Ok(())
}

fn read_confirmation(mut reader: impl Read) -> io::Result<bool> {
    let mut line = [0u8; 8];
    for index in 0..line.len() {
        if reader.read(&mut line[index..=index])? == 0 {
            return Ok(false);
        }
        if line[index] == b'\n' {
            return Ok(matches!(&line[..=index], b"delete\n" | b"delete\r\n"));
        }
    }
    Ok(false)
}

async fn confirm(prompt: &str) -> Result<(), DynError> {
    tokio::select! {
        biased;
        _ = tokio::signal::ctrl_c() => Err(error::invalid_input(CANCELLED)),
        result = async {
            eprint!("{prompt}");
            io::stderr().flush().map_err(|_| error::internal("could not display confirmation; nothing was deleted"))?;
            let (sender, receiver) = tokio::sync::oneshot::channel();
            read_confirmation_on_detached_thread(sender)?;
            match receiver.await {
                Ok(Ok(true)) => Ok(()),
                _ => Err(error::invalid_input(CANCELLED)),
            }
        } => result,
    }
}

fn read_confirmation_on_detached_thread(
    sender: tokio::sync::oneshot::Sender<io::Result<bool>>,
) -> Result<(), DynError> {
    std::thread::Builder::new()
        .name("key-drop-confirm".into())
        .spawn(move || {
            let _ = sender.send(read_confirmation(io::stdin().lock()));
        })
        .map(|_| ())
        .map_err(|_| error::internal("could not read key purge confirmation; nothing was deleted"))
}

fn destination(storage: &config::StorageConfig) -> Result<String, DynError> {
    let display = match storage {
        config::StorageConfig::Sqlite(path) => format!("SQLite {}", path.display()),
        config::StorageConfig::Postgres(dsn) => {
            let options = PgConnectOptions::from_str(dsn)
                .map_err(|_| error::invalid_input("invalid PostgreSQL destination"))?;
            format!(
                "PostgreSQL host={} port={} database={}",
                options.get_host(),
                options.get_port(),
                options.get_database().unwrap_or("<default>")
            )
        }
    };
    crate::core::validation::validate_text_field("database destination", &display).map_err(
        |_| error::invalid_input("configured database destination contains control characters"),
    )?;
    Ok(display)
}

#[derive(Serialize)]
struct DropOutput<'a> {
    kid: &'a str,
    deleted: crate::core::storage::KeyPurgeCounts,
}

fn drop_event(kid: &str, event: &str, outcome: &str, reason: String) -> audit_chain::AuditEvent {
    audit_chain::AuditEvent {
        event: event.into(),
        outcome: outcome.into(),
        actor: "offline".into(),
        actor_fp: String::new(),
        root: false,
        admin: false,
        kid: kid.into(),
        remote_kid: String::new(),
        action: "keys.drop".into(),
        reason,
        request_id: String::new(),
    }
}

fn started_event(kid: &str, destination: &str) -> audit_chain::AuditEvent {
    drop_event(kid, "key.drop.started", "attempt", destination.into())
}

fn failed_event(kid: &str, cause: &DynError) -> audit_chain::AuditEvent {
    drop_event(kid, "key.drop.failed", "failure", cause.to_string())
}

fn completion_event(
    kid: &str,
    counts: crate::core::storage::KeyPurgeCounts,
) -> audit_chain::AuditEvent {
    drop_event(
        kid,
        "key.drop.completed",
        "success",
        format!(
            "opskeys={};tokens={};subjects={};indexes={}",
            counts.opskeys, counts.tokens, counts.subjects, counts.indexes
        ),
    )
}

async fn persist_event(event: audit_chain::AuditEvent) -> bool {
    let failure = Arc::new(Mutex::new(None));
    audit_chain::record_standalone(event, &failure);
    audit_chain::confirm(&failure).await;
    failure.lock().map(|cell| cell.is_none()).unwrap_or(false)
}

async fn shutdown_audit_after_error(origin: crate::error::ConfigOrigin) {
    if audit_chain::shutdown().await.is_err() {
        eprintln!("Additional error: {origin}: purge audit shutdown failed");
    }
}

fn post_commit_error(
    kid: &str,
    counts: crate::core::storage::KeyPurgeCounts,
    phase: &str,
) -> DynError {
    error::internal(format!(
        "key purge already committed for {kid} (opskeys={}, tokens={}, subjects={}, indexes={}); {phase}; do not retry the purge",
        counts.opskeys, counts.tokens, counts.subjects, counts.indexes
    ))
}

pub(super) async fn run(
    loader: &ConfigLoader,
    args: Vec<String>,
    output: OutputFormat,
) -> Result<(), DynError> {
    let kid = kid_argument(&args)?;
    require_terminal(io::stdin().is_terminal(), io::stderr().is_terminal())?;
    let logging = logging::logging_config(loader)?;
    require_file_logging(logging.target)?;
    let storage_config = config::storage_config(loader)?;
    let destination = destination(&storage_config)?;
    let storage =
        StorageState::from_config_with_origins(&storage_config, &loader.origins()).await?;
    let init = super::init::load_init_state(loader)?;
    let internal = Zeroizing::new(InternalDerivedKeysState::from_init_state(&init)?);
    let prepared = keys::prepare_key_drop(&storage, &internal, kid).await?;
    drop(internal);
    let signer = audit_chain::AuditCheckpointSigner::from_init(&init);
    drop(init);
    let audit_lock = audit_chain::open_audit_log(&logging).map_err(|err| {
        error::with_prefix(
            "could not prepare mandatory purge audit; nothing was deleted",
            err,
        )
    })?;
    let prompt = format!(
        "Database: {destination}\nKID: {kid}\nState: destroyed\nThis will delete the key record and its tokens, subjects, and indexes.\nAll nodes using this database must be stopped; this has not been verified.\nRemove references from signed configurations before restarting; configurations will not be modified.\nBackups, WAL, recoverable pages, exported files and process memory will not be deleted.\n\nType 'delete' to confirm:\n"
    );
    confirm(&prompt).await?;
    audit_lock.try_lock().map_err(|err| {
        logging.origins.origin("VECTIS_AUDIT_LOG_FILE").context(
            "purge audit file is busy or cannot be locked; nothing was deleted",
            &err,
            error::ConfigErrorCategory::Internal,
        )
    })?;
    let audit_origin = logging.origins.origin("VECTIS_AUDIT_LOG_FILE");
    let audit_writer = audit_lock
        .try_clone()
        .map_err(|err| audit_initialization_error(audit_origin, &err))?;
    audit_chain::initialize_prepared_file(&logging, signer, audit_writer)
        .map_err(|err| audit_initialization_error(audit_origin, err.as_ref()))?;
    if !persist_event(started_event(kid, &destination)).await {
        shutdown_audit_after_error(audit_origin).await;
        return Err(error::internal(format!(
            "{audit_origin}: could not persist mandatory purge audit; nothing was deleted",
        )));
    }
    eprintln!("Deleting; interrupts are ignored until the purge finishes.");
    let counts = match prepared.execute(&storage).await {
        Ok(counts) => counts,
        Err(cause) => {
            if !persist_event(failed_event(kid, &cause)).await {
                eprintln!(
                    "Additional error: {audit_origin}: purge failure audit could not be persisted"
                );
            }
            shutdown_audit_after_error(audit_origin).await;
            return Err(cause);
        }
    };
    let persisted = persist_event(completion_event(kid, counts)).await;
    let closed = audit_chain::shutdown().await.is_ok();
    if !persisted || !closed {
        return Err(post_commit_error(
            kid,
            counts,
            &format!("{audit_origin}: mandatory audit persistence or checkpoint failed"),
        ));
    }
    http::print_serializable_response(
        &DropOutput {
            kid,
            deleted: counts,
        },
        output,
    )
    .map_err(|_| post_commit_error(kid, counts, "could not publish the result"))
}

fn audit_initialization_error(
    origin: crate::error::ConfigOrigin,
    err: &(dyn std::error::Error + 'static),
) -> DynError {
    origin.internal_context(
        "could not initialize mandatory purge audit; nothing was deleted",
        err,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_initialization_failure_identifies_pre_delete_phase() {
        let origin = crate::error::ConfigOrigin {
            name: "VECTIS_AUDIT_LOG_FILE",
            source: crate::error::ConfigSource::EnvFile { line: 4 },
        };
        let cause = io::Error::new(io::ErrorKind::PermissionDenied, "secret-canary");
        let err = audit_initialization_error(origin, &cause);
        assert!(matches!(
            err.downcast_ref::<crate::error::VectisError>(),
            Some(crate::error::VectisError::Internal(_))
        ));
        assert_eq!(
            err.to_string(),
            "VECTIS_AUDIT_LOG_FILE (env_file line 4): could not initialize mandatory purge audit; nothing was deleted (PermissionDenied)"
        );
    }

    #[test]
    fn confirmation_is_exact_and_bounded() {
        for accepted in [b"delete\n".as_slice(), b"delete\r\n"] {
            assert!(read_confirmation(accepted).unwrap());
        }
        for rejected in [
            "",
            "\n",
            "delete",
            "DELETE\n",
            " delete\n",
            "delete \n",
            "delete\r",
            "delete\r\r\n",
            "anything longer than eight bytes\n",
        ] {
            assert!(
                !read_confirmation(rejected.as_bytes()).unwrap(),
                "{rejected:?}"
            );
        }
        let mut input = io::Cursor::new(vec![b'x'; 1024]);
        assert!(!read_confirmation(&mut input).unwrap());
        assert_eq!(input.position(), 8);
    }

    #[test]
    fn both_input_and_prompt_require_terminals() {
        for (input, prompt) in [(false, false), (true, false), (false, true)] {
            assert!(require_terminal(input, prompt).is_err());
        }
        assert!(require_terminal(true, true).is_ok());
    }

    #[test]
    fn only_file_logging_is_accepted() {
        assert!(require_file_logging(logging::LogTarget::File).is_ok());
        let err = require_file_logging(logging::LogTarget::Stdout).unwrap_err();
        assert!(err.to_string().contains("nothing was deleted"));
    }

    #[test]
    fn start_and_failure_events_name_the_key() {
        let started = started_event("kid", "SQLite /tmp/ops.db");
        assert_eq!(
            (started.event.as_str(), started.outcome.as_str()),
            ("key.drop.started", "attempt")
        );
        assert_eq!(
            (started.kid.as_str(), started.reason.as_str()),
            ("kid", "SQLite /tmp/ops.db")
        );
        let cause = error::storage("key purge failed before COMMIT; no purge was committed");
        let failed = failed_event("kid", &cause);
        assert_eq!(
            (
                failed.event.as_str(),
                failed.outcome.as_str(),
                failed.kid.as_str()
            ),
            ("key.drop.failed", "failure", "kid")
        );
        assert_eq!(failed.reason, cause.to_string());
        assert_eq!(failed.actor, "offline");
    }

    #[test]
    fn destination_and_event_are_sanitized() {
        let settings = config::StorageConfig::Postgres(Zeroizing::new(
            "postgres://user:CANARY@localhost:5432/maintenance?password=CANARY".into(),
        ));
        let display = destination(&settings).unwrap();
        assert!(display.contains("localhost") && display.contains("maintenance"));
        assert!(!display.contains("CANARY") && !display.contains("user"));
        let counts = crate::core::storage::KeyPurgeCounts {
            opskeys: 1,
            tokens: 2,
            subjects: 3,
            indexes: 4,
        };
        let event = completion_event("kid", counts);
        assert_eq!(event.actor, "offline");
        assert!(!event.root && !event.admin);
        assert_eq!(event.reason, "opskeys=1;tokens=2;subjects=3;indexes=4");
        assert!(
            post_commit_error("kid", counts, "audit failed")
                .to_string()
                .contains("already committed")
        );
    }
}
