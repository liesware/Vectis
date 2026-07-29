use crate::core::{canonical, config, crypto, logging, validation};
use crate::error::DynError;
use crate::ops::init::{ValidatedInitPublicState, ValidatedInitState};
use crate::ops::key_material::VariantDerKeyPair;
use crate::ops::sign;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use tokio::sync::{mpsc, oneshot};
use zeroize::Zeroize;

const CHAIN_VERSION: &str = "audit-chain-v1";
const CHECKPOINT_VERSION: &str = "audit-checkpoint-v1";
const CHECKPOINT_TYPE: &str = "vectis-audit-checkpoint";
const INIT_KEYS_KID: &str = "init-keys";
const DOMAIN: &[u8] = b"vectis:audit-chain:v1\0";
const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

static RUNTIME: OnceLock<AuditRuntime> = OnceLock::new();

#[derive(Clone, Debug)]
pub struct AuditEvent {
    pub event: String,
    pub outcome: String,
    pub actor: String,
    pub actor_fp: String,
    pub root: bool,
    pub admin: bool,
    pub kid: String,
    pub remote_kid: String,
    pub action: String,
    pub reason: String,
    pub request_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuditRecordBody {
    version: String,
    chain_id: String,
    sequence: u64,
    timestamp: String,
    event: String,
    outcome: String,
    actor: String,
    actor_fp: String,
    root: bool,
    admin: bool,
    kid: String,
    remote_kid: String,
    action: String,
    reason: String,
    request_id: String,
    hash_alg: String,
    prev_hash: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
// Strictness is enforced by canonical byte-equality in verify_file, not by serde:
// deny_unknown_fields is silently ignored when combined with flatten.
struct AuditChainRecord {
    #[serde(flatten)]
    body: AuditRecordBody,
    event_hash: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuditCheckpointLine {
    version: String,
    signature: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuditCheckpointPayload {
    version: String,
    #[serde(rename = "type")]
    token_type: String,
    kid: String,
    chain_id: String,
    last_sequence: u64,
    head_hash: String,
    hash_alg: String,
    created_at: String,
}

#[derive(Clone)]
struct AuditCheckpointSigner {
    eddsa: VariantDerKeyPair,
    ml_dsa: VariantDerKeyPair,
}

#[derive(Clone)]
struct AuditCheckpointVerifier {
    eddsa_public_key_der_hex: String,
    ml_dsa_public_key_der_hex: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct AuditChainSummary {
    pub chain_id: String,
    pub records: u64,
    pub last_sequence: u64,
    pub head_hash: String,
    pub checkpoints_verified: u64,
    pub last_checkpoint_sequence: Option<u64>,
    pub last_checkpoint_head_hash: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AuditVerificationOutput {
    pub valid: bool,
    pub chains: Vec<AuditChainSummary>,
}

struct AuditRuntime {
    sender: mpsc::Sender<WriterCommand>,
    thread: Mutex<Option<thread::JoinHandle<()>>>,
}

enum WriterCommand {
    Record {
        event: Box<AuditEvent>,
        failure: Arc<Mutex<Option<String>>>,
        standalone: bool,
    },
    Barrier {
        failure: Arc<Mutex<Option<String>>>,
        reply: oneshot::Sender<()>,
    },
    Shutdown {
        reply: oneshot::Sender<Result<(), String>>,
    },
}

enum AuditSink {
    File(BufWriter<File>),
    Stdout(BufWriter<io::Stdout>),
    #[cfg(test)]
    Memory(Arc<Mutex<tests::MemorySink>>),
}

impl AuditSink {
    fn write_record(&mut self, serialized: &[u8]) -> io::Result<()> {
        match self {
            Self::File(writer) => write_json_line(writer, serialized),
            Self::Stdout(writer) => write_json_line(writer, serialized),
            #[cfg(test)]
            Self::Memory(sink) => sink.lock().unwrap().write_record(serialized),
        }
    }

    fn sync(&mut self) -> io::Result<()> {
        match self {
            // fsync so audit records acknowledged to the client survive power loss.
            Self::File(writer) => writer.get_ref().sync_all(),
            Self::Stdout(writer) => writer.flush(),
            #[cfg(test)]
            Self::Memory(sink) => sink.lock().unwrap().sync(),
        }
    }
}

fn write_json_line<W: Write>(writer: &mut W, serialized: &[u8]) -> io::Result<()> {
    let mut line = Vec::with_capacity(serialized.len() + 1);
    line.extend_from_slice(serialized);
    line.push(b'\n');
    writer.write_all(&line)?;
    writer.flush()
}

struct AuditChainState {
    chain_id: String,
    next_sequence: u64,
    head_hash: String,
    events_since_checkpoint: u64,
    last_checkpoint_sequence: Option<u64>,
}

#[derive(Clone, Copy)]
struct CheckpointPolicy {
    event_count: u64,
}

impl Default for CheckpointPolicy {
    fn default() -> Self {
        Self {
            event_count: config::AUDIT_CHECKPOINT_EVENT_COUNT,
        }
    }
}

pub fn initialize(
    logging_config: &logging::LoggingConfig,
    init_state: &ValidatedInitState,
) -> Result<(), DynError> {
    if RUNTIME.get().is_some() {
        return Ok(());
    }

    let runtime =
        AuditRuntime::start(logging_config, AuditCheckpointSigner::from_init(init_state))?;
    RUNTIME
        .set(runtime)
        .map_err(|_| crate::error::internal("audit chain runtime was initialized concurrently"))
}

// A deferred record is written but not fsynced until a later commit; the caller MUST
// follow it with confirm() (or a Barrier) for durability. Callers without a guaranteed
// confirm must use record_standalone(), which commits on its own.
pub(crate) fn record(event: AuditEvent, failure: &Arc<Mutex<Option<String>>>) {
    let Some(runtime) = RUNTIME.get() else {
        return;
    };
    runtime.record(event, failure, false);
}

pub(crate) fn record_standalone(event: AuditEvent, failure: &Arc<Mutex<Option<String>>>) {
    let Some(runtime) = RUNTIME.get() else {
        return;
    };
    runtime.record(event, failure, true);
}

pub(crate) async fn confirm(failure: &Arc<Mutex<Option<String>>>) {
    if let Some(runtime) = RUNTIME.get() {
        runtime.confirm(failure).await;
    }
}

pub async fn shutdown() -> Result<(), DynError> {
    let Some(runtime) = RUNTIME.get() else {
        return Ok(());
    };
    runtime.shutdown().await
}

pub fn verify_file(
    path: &Path,
    init_public_state: &ValidatedInitPublicState,
) -> Result<AuditVerificationOutput, DynError> {
    verify_file_with_verifier(
        path,
        &AuditCheckpointVerifier::from_init_public(init_public_state),
    )
}

/// Validates one newline-stripped JSONL audit entry without verifying event
/// hashes or checkpoint signatures. This is the parser boundary used by native
/// fuzzing; full authenticity remains the responsibility of `verify_file`.
pub fn validate_audit_jsonl_line_encoding(line: &str) -> Result<(), DynError> {
    parse_structural_audit_line(line)
}

fn parse_structural_audit_line(line: &str) -> Result<(), DynError> {
    if line.is_empty() {
        return Err(crate::error::invalid_input("audit record is empty"));
    }
    if line.len() > config::AUDIT_CHAIN_RECORD_MAX_BYTES {
        return Err(crate::error::invalid_input(
            "audit record exceeds maximum size",
        ));
    }

    let version = serde_json::from_str::<serde_json::Value>(line)
        .ok()
        .and_then(|value| value.get("version")?.as_str().map(str::to_owned))
        .ok_or_else(|| crate::error::invalid_input("audit record contains invalid JSON"))?;

    match version.as_str() {
        CHAIN_VERSION => {
            let record: AuditChainRecord = serde_json::from_str(line)
                .map_err(|_| crate::error::invalid_input("audit record contains invalid JSON"))?;
            validate_record_shape(&record)?;
            if canonical::canonical_json_v1(&record)? != line.as_bytes() {
                return Err(crate::error::invalid_input(
                    "audit record JSON is not canonical",
                ));
            }
            Ok(())
        }
        CHECKPOINT_VERSION => {
            let checkpoint: AuditCheckpointLine = serde_json::from_str(line).map_err(|_| {
                crate::error::invalid_input("audit checkpoint contains invalid JSON")
            })?;
            sign::validate_compact_signature_encoding(&checkpoint.signature)?;
            if canonical::canonical_json_v1(&checkpoint)? != line.as_bytes() {
                return Err(crate::error::invalid_input(
                    "audit checkpoint JSON is not canonical",
                ));
            }
            Ok(())
        }
        _ => Err(crate::error::invalid_input(
            "audit record version is unsupported",
        )),
    }
}

fn verify_file_with_verifier(
    path: &Path,
    verifier: &AuditCheckpointVerifier,
) -> Result<AuditVerificationOutput, DynError> {
    let metadata = fs::metadata(path).map_err(|err| {
        crate::error::invalid_input(format!(
            "cannot inspect audit file {}: {err}",
            path.display()
        ))
    })?;
    if !metadata.is_file() {
        return Err(crate::error::invalid_input(
            "audit verification input must be a regular file",
        ));
    }
    let file = File::open(path).map_err(|err| {
        crate::error::invalid_input(format!("cannot open audit file {}: {err}", path.display()))
    })?;
    let mut reader = BufReader::new(file);
    let mut chains = Vec::new();
    let mut current: Option<VerifiedChain> = None;

    let mut line_index = 0;
    loop {
        let mut bytes = Vec::with_capacity(config::AUDIT_CHAIN_RECORD_MAX_BYTES + 2);
        let read = reader
            .by_ref()
            .take((config::AUDIT_CHAIN_RECORD_MAX_BYTES + 2) as u64)
            .read_until(b'\n', &mut bytes)
            .map_err(|err| {
                crate::error::invalid_input(format!(
                    "cannot read audit record {}: {err}",
                    line_index + 1
                ))
            })?;
        if read == 0 {
            break;
        }
        if bytes.len() > config::AUDIT_CHAIN_RECORD_MAX_BYTES + 1 {
            return Err(verify_error(line_index, "record exceeds maximum size"));
        }
        if !bytes.ends_with(b"\n") {
            return Err(verify_error(
                line_index,
                "record is truncated (missing trailing newline)",
            ));
        }
        bytes.pop();
        if bytes.is_empty() {
            return Err(verify_error(line_index, "record is empty"));
        }
        let line = std::str::from_utf8(&bytes)
            .map_err(|_| verify_error(line_index, "record is not valid UTF-8"))?;
        let version = serde_json::from_str::<serde_json::Value>(line)
            .ok()
            .and_then(|value| value.get("version")?.as_str().map(str::to_owned))
            .ok_or_else(|| verify_error(line_index, "record contains invalid JSON"))?;

        match version.as_str() {
            CHAIN_VERSION => {
                let record: AuditChainRecord = serde_json::from_str(line)
                    .map_err(|_| verify_error(line_index, "record contains invalid JSON"))?;
                validate_record(&record)
                    .map_err(|err| verify_error(line_index, &err.to_string()))?;
                if canonical::canonical_json_v1(&record)? != line.as_bytes() {
                    return Err(verify_error(line_index, "record JSON is not canonical"));
                }

                if record.body.event == "audit.chain.started" {
                    if record.body.sequence != 0
                        || record.body.prev_hash != GENESIS_HASH
                        || record.body.outcome != "success"
                        || record.body.action != "chain-start"
                    {
                        return Err(verify_error(line_index, "chain genesis is invalid"));
                    }
                    if let Some(previous) = current.take() {
                        chains.push(previous.summary());
                    }
                    current = Some(VerifiedChain::from_genesis(&record));
                } else {
                    let Some(chain) = current.as_mut() else {
                        return Err(verify_error(line_index, "first record must start a chain"));
                    };
                    chain
                        .push(&record)
                        .map_err(|reason| verify_error(line_index, reason))?;
                }
            }
            CHECKPOINT_VERSION => {
                let checkpoint: AuditCheckpointLine = serde_json::from_str(line)
                    .map_err(|_| verify_error(line_index, "checkpoint contains invalid JSON"))?;
                if canonical::canonical_json_v1(&checkpoint)? != line.as_bytes() {
                    return Err(verify_error(line_index, "checkpoint JSON is not canonical"));
                }
                let Some(chain) = current.as_mut() else {
                    return Err(verify_error(
                        line_index,
                        "checkpoint appears before chain genesis",
                    ));
                };
                let payload = verify_checkpoint(&checkpoint, verifier)
                    .map_err(|err| verify_error(line_index, &err.to_string()))?;
                chain
                    .checkpoint(&payload)
                    .map_err(|reason| verify_error(line_index, reason))?;
            }
            _ => return Err(verify_error(line_index, "record version is unsupported")),
        }
        line_index += 1;
    }

    if let Some(chain) = current {
        chains.push(chain.summary());
    }
    if chains.is_empty() {
        return Err(crate::error::invalid_input(
            "audit file contains no records",
        ));
    }

    Ok(AuditVerificationOutput {
        valid: true,
        chains,
    })
}

#[cfg(test)]
fn verify_file_with_signer(
    path: &Path,
    signer: &AuditCheckpointSigner,
) -> Result<AuditVerificationOutput, DynError> {
    verify_file_with_verifier(path, &signer.verifier())
}

impl AuditRuntime {
    fn start(
        logging_config: &logging::LoggingConfig,
        signer: AuditCheckpointSigner,
    ) -> Result<Self, DynError> {
        let mut sink = match logging_config.target {
            logging::LogTarget::File => {
                fs::create_dir_all(&logging_config.dir).map_err(|err| {
                    crate::error::internal(format!(
                        "cannot create audit log directory {}: {err}",
                        logging_config.dir
                    ))
                })?;
                let path = Path::new(&logging_config.dir).join(&logging_config.audit_file);
                let file = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&path)
                    .map_err(|err| {
                        crate::error::internal(format!(
                            "cannot open audit log {}: {err}",
                            path.display()
                        ))
                    })?;
                AuditSink::File(BufWriter::new(file))
            }
            logging::LogTarget::Stdout => AuditSink::Stdout(BufWriter::new(io::stdout())),
        };

        let mut state = AuditChainState::new()?;
        write_event(&mut sink, &mut state, AuditEvent::chain_started())?;
        sink.sync()
            .map_err(|err| crate::error::internal(format!("cannot fsync audit log: {err}")))?;

        let (sender, receiver) = mpsc::channel(config::AUDIT_CHAIN_CHANNEL_CAPACITY);
        let thread = thread::Builder::new()
            .name(String::from("vectis-audit-chain"))
            .spawn(move || writer_loop(sink, state, signer, receiver))
            .map_err(|err| crate::error::internal(format!("cannot start audit writer: {err}")))?;

        Ok(Self {
            sender,
            thread: Mutex::new(Some(thread)),
        })
    }

    fn record(&self, event: AuditEvent, failure: &Arc<Mutex<Option<String>>>, standalone: bool) {
        if self
            .sender
            .try_send(WriterCommand::Record {
                event: Box::new(event),
                failure: Arc::clone(failure),
                standalone,
            })
            .is_err()
        {
            set_failure(failure, "audit writer is unavailable");
        }
    }

    async fn confirm(&self, failure: &Arc<Mutex<Option<String>>>) {
        let (reply, ack) = oneshot::channel();
        if self
            .sender
            .send(WriterCommand::Barrier {
                failure: Arc::clone(failure),
                reply,
            })
            .await
            .is_err()
        {
            set_failure(failure, "audit writer is unavailable");
            return;
        }
        if ack.await.is_err() {
            set_failure(failure, "audit writer did not confirm persistence");
        }
    }

    async fn shutdown(&self) -> Result<(), DynError> {
        let (reply, ack) = oneshot::channel();
        self.sender
            .send(WriterCommand::Shutdown { reply })
            .await
            .map_err(|_| crate::error::internal("audit writer is unavailable during shutdown"))?;
        ack.await
            .map_err(|_| crate::error::internal("audit writer did not confirm shutdown"))?
            .map_err(crate::error::internal)?;

        let thread = self
            .thread
            .lock()
            .map_err(|_| crate::error::internal("audit writer thread lock is poisoned"))?
            .take();
        if let Some(thread) = thread {
            tokio::task::spawn_blocking(move || thread.join())
                .await
                .map_err(|_| crate::error::internal("audit writer thread join failed"))?
                .map_err(|_| crate::error::internal("audit writer thread panicked"))?;
        }
        Ok(())
    }
}

fn set_failure(failure: &Arc<Mutex<Option<String>>>, reason: &str) {
    if let Ok(mut cell) = failure.lock()
        && cell.is_none()
    {
        *cell = Some(reason.to_string());
        tracing::error!(audit_error = %reason, "audit chain persistence failed");
    }
}

impl AuditChainState {
    fn new() -> Result<Self, DynError> {
        Ok(Self {
            chain_id: hex::encode(crypto::random_bytes(16)?),
            next_sequence: 0,
            head_hash: String::from(GENESIS_HASH),
            events_since_checkpoint: 0,
            last_checkpoint_sequence: None,
        })
    }
}

impl AuditCheckpointSigner {
    fn from_init(init_state: &ValidatedInitState) -> Self {
        Self {
            eddsa: init_state.init_keys.keys().eddsa().clone(),
            ml_dsa: init_state.init_keys.keys().ml_dsa().clone(),
        }
    }

    #[cfg(test)]
    fn verifier(&self) -> AuditCheckpointVerifier {
        AuditCheckpointVerifier {
            eddsa_public_key_der_hex: self.eddsa.public_key_der_hex().to_string(),
            ml_dsa_public_key_der_hex: self.ml_dsa.public_key_der_hex().to_string(),
        }
    }
}

impl AuditCheckpointVerifier {
    fn from_init_public(init_state: &ValidatedInitPublicState) -> Self {
        Self {
            eddsa_public_key_der_hex: init_state.eddsa_public_key_der_hex().to_string(),
            ml_dsa_public_key_der_hex: init_state.ml_dsa_public_key_der_hex().to_string(),
        }
    }
}

impl Zeroize for AuditCheckpointSigner {
    fn zeroize(&mut self) {
        self.eddsa.zeroize();
        self.ml_dsa.zeroize();
    }
}

impl AuditEvent {
    fn chain_started() -> Self {
        Self {
            event: String::from("audit.chain.started"),
            outcome: String::from("success"),
            actor: String::new(),
            actor_fp: String::new(),
            root: false,
            admin: false,
            kid: String::new(),
            remote_kid: String::new(),
            action: String::from("chain-start"),
            reason: String::new(),
            request_id: String::new(),
        }
    }
}

fn writer_loop(
    sink: AuditSink,
    state: AuditChainState,
    signer: AuditCheckpointSigner,
    receiver: mpsc::Receiver<WriterCommand>,
) {
    writer_loop_with_policy(sink, state, signer, receiver, CheckpointPolicy::default());
}

fn writer_loop_with_policy(
    mut sink: AuditSink,
    mut state: AuditChainState,
    mut signer: AuditCheckpointSigner,
    mut receiver: mpsc::Receiver<WriterCommand>,
    policy: CheckpointPolicy,
) {
    // Once a write fails the chain state and the file could diverge, so the writer stops
    // appending permanently: any further append could reuse a sequence and poison verify.
    let mut poisoned: Option<String> = None;
    let mut dirty = false;

    loop {
        let first = receiver.blocking_recv();
        let Some(first) = first else {
            break;
        };
        let mut barriers: Vec<PendingBarrier> = Vec::new();
        // Group commit: append a bounded number of queued records, fsync only at a
        // durability boundary, then release every barrier included in that commit.
        let mut next = Some(first);
        let mut processed = 0usize;
        let mut commit_requested = false;
        let mut shutdown_reply = None;

        while let Some(command) = next {
            processed += 1;
            match command {
                WriterCommand::Record {
                    event,
                    failure,
                    standalone,
                } => {
                    if let Some(reason) = &poisoned {
                        set_failure(&failure, reason);
                    } else if let Err(err) = write_event(&mut sink, &mut state, *event) {
                        let reason = err.to_string();
                        set_failure(&failure, &reason);
                        poisoned = Some(reason);
                    } else {
                        dirty = true;
                        commit_requested |= standalone;
                    }
                }
                WriterCommand::Barrier { failure, reply } => {
                    barriers.push(PendingBarrier { failure, reply });
                    commit_requested = true;
                }
                WriterCommand::Shutdown { reply } => {
                    shutdown_reply = Some(reply);
                    commit_requested = true;
                }
            }
            // On shutdown, ignore the batch cap and drain everything already queued so
            // events enqueued after the Shutdown command are still persisted.
            if shutdown_reply.is_none() && processed >= config::AUDIT_GROUP_COMMIT_MAX_COMMANDS {
                break;
            }
            next = receiver.try_recv().ok();
        }

        let checkpoint_due = state.events_since_checkpoint > 0
            && (state.events_since_checkpoint >= policy.event_count
                || (shutdown_reply.is_some()
                    && state.last_checkpoint_sequence
                        != Some(state.next_sequence.saturating_sub(1))));
        if poisoned.is_none() && checkpoint_due {
            commit_requested = true;
            match append_checkpoint(&mut sink, &mut state, &signer) {
                Ok(()) => dirty = true,
                Err(err) => poisoned = Some(err.to_string()),
            }
        }
        if commit_requested && dirty && poisoned.is_none() {
            match sink.sync() {
                Ok(()) => dirty = false,
                Err(err) => poisoned = Some(format!("cannot fsync audit log: {err}")),
            }
        }
        if commit_requested {
            for barrier in barriers.drain(..) {
                if let Some(reason) = &poisoned {
                    set_failure(&barrier.failure, reason);
                }
                let _ = barrier.reply.send(());
            }
        }
        if let Some(reply) = shutdown_reply {
            let result = poisoned.clone().map_or(Ok(()), Err);
            let _ = reply.send(result);
            break;
        }
    }
    signer.zeroize();
}

struct PendingBarrier {
    failure: Arc<Mutex<Option<String>>>,
    reply: oneshot::Sender<()>,
}

fn write_event(
    sink: &mut AuditSink,
    state: &mut AuditChainState,
    event: AuditEvent,
) -> Result<(), DynError> {
    let body = AuditRecordBody {
        version: String::from(CHAIN_VERSION),
        chain_id: state.chain_id.clone(),
        sequence: state.next_sequence,
        timestamp: validation::current_timestamp()?,
        event: sanitize(&event.event, config::AUDIT_CHAIN_REASON_MAX_CHARS),
        outcome: sanitize(&event.outcome, config::AUDIT_CHAIN_REASON_MAX_CHARS),
        actor: sanitize(&event.actor, config::AUDIT_CHAIN_REASON_MAX_CHARS),
        actor_fp: sanitize(&event.actor_fp, config::AUDIT_CHAIN_REASON_MAX_CHARS),
        root: event.root,
        admin: event.admin,
        kid: sanitize(&event.kid, config::AUDIT_CHAIN_REASON_MAX_CHARS),
        remote_kid: sanitize(&event.remote_kid, config::AUDIT_CHAIN_REASON_MAX_CHARS),
        action: sanitize(&event.action, config::AUDIT_CHAIN_REASON_MAX_CHARS),
        reason: sanitize(&event.reason, config::AUDIT_CHAIN_REASON_MAX_CHARS),
        request_id: sanitize(&event.request_id, config::AUDIT_CHAIN_REASON_MAX_CHARS),
        hash_alg: String::from(config::INTERNAL_KEYS_HASH),
        prev_hash: state.head_hash.clone(),
    };
    let event_hash = hash_record(&body)?;
    let record = AuditChainRecord { body, event_hash };
    let serialized = canonical::canonical_json_v1(&record)?;
    if serialized.len() > config::AUDIT_CHAIN_RECORD_MAX_BYTES {
        return Err(crate::error::internal("audit record exceeds maximum size"));
    }
    sink.write_record(&serialized)
        .map_err(|err| crate::error::internal(format!("cannot persist audit record: {err}")))?;
    state.head_hash = record.event_hash;
    state.next_sequence = state
        .next_sequence
        .checked_add(1)
        .ok_or_else(|| crate::error::internal("audit sequence exhausted"))?;
    if state.next_sequence > 1 {
        state.events_since_checkpoint = state
            .events_since_checkpoint
            .checked_add(1)
            .ok_or_else(|| crate::error::internal("audit checkpoint event count exhausted"))?;
    }
    Ok(())
}

fn append_checkpoint(
    sink: &mut AuditSink,
    state: &mut AuditChainState,
    signer: &AuditCheckpointSigner,
) -> Result<(), DynError> {
    let payload = AuditCheckpointPayload {
        version: String::from("v1"),
        token_type: String::from(CHECKPOINT_TYPE),
        kid: String::from(INIT_KEYS_KID),
        chain_id: state.chain_id.clone(),
        last_sequence: state.next_sequence.saturating_sub(1),
        head_hash: state.head_hash.clone(),
        hash_alg: String::from(config::INTERNAL_KEYS_HASH),
        created_at: validation::current_timestamp()?,
    };
    let mut rng = crypto::new_rng()?;
    let line = AuditCheckpointLine {
        version: String::from(CHECKPOINT_VERSION),
        signature: sign::sign_compact_hybrid_payload(
            &mut rng,
            &payload,
            &signer.eddsa,
            &signer.ml_dsa,
        )?,
    };
    let serialized = canonical::canonical_json_v1(&line)?;
    if serialized.len() > config::AUDIT_CHAIN_RECORD_MAX_BYTES {
        return Err(crate::error::internal(
            "audit checkpoint exceeds maximum size",
        ));
    }
    sink.write_record(&serialized)
        .map_err(|err| crate::error::internal(format!("cannot persist audit checkpoint: {err}")))?;
    state.events_since_checkpoint = 0;
    state.last_checkpoint_sequence = Some(payload.last_sequence);
    Ok(())
}

fn verify_checkpoint(
    checkpoint: &AuditCheckpointLine,
    verifier: &AuditCheckpointVerifier,
) -> Result<AuditCheckpointPayload, DynError> {
    if checkpoint.version != CHECKPOINT_VERSION {
        return Err(crate::error::invalid_input(
            "checkpoint version is unsupported",
        ));
    }
    let payload = sign::verify_compact_hybrid_signature_with_public_keys_strict(
        &checkpoint.signature,
        &verifier.eddsa_public_key_der_hex,
        &verifier.ml_dsa_public_key_der_hex,
    )
    .map_err(|_| {
        crate::error::invalid_signature("audit checkpoint signature verification failed")
    })?;
    validate_checkpoint_payload(&payload)?;
    Ok(payload)
}

fn validate_checkpoint_payload(payload: &AuditCheckpointPayload) -> Result<(), DynError> {
    if payload.version != "v1"
        || payload.token_type != CHECKPOINT_TYPE
        || payload.kid != INIT_KEYS_KID
        || payload.hash_alg != config::INTERNAL_KEYS_HASH
    {
        return Err(crate::error::invalid_input(
            "audit checkpoint payload fields are invalid",
        ));
    }
    if payload.chain_id.len() != 32 || hex::decode(&payload.chain_id).is_err() {
        return Err(crate::error::invalid_input(
            "audit checkpoint chain_id is invalid",
        ));
    }
    validation::validate_hash_hex_field(
        "audit checkpoint head_hash",
        &payload.head_hash,
        config::INTERNAL_KEYS_HASH,
    )?;
    if payload.created_at.parse::<u64>().is_err() {
        return Err(crate::error::invalid_input(
            "audit checkpoint created_at is invalid",
        ));
    }
    Ok(())
}

fn hash_record(body: &AuditRecordBody) -> Result<String, DynError> {
    let canonical = canonical::canonical_json_v1(body)?;
    let mut input = Vec::with_capacity(DOMAIN.len() + canonical.len());
    input.extend_from_slice(DOMAIN);
    input.extend_from_slice(&canonical);
    Ok(hex::encode(crypto::hash_bytes(
        config::INTERNAL_KEYS_HASH,
        &input,
    )?))
}

fn sanitize(value: &str, max_chars: usize) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .take(max_chars)
        .collect()
}

fn verify_error(line_index: usize, reason: &str) -> DynError {
    crate::error::invalid_input(format!(
        "audit verification failed at record {}: {reason}",
        line_index + 1
    ))
}

fn validate_record_shape(record: &AuditChainRecord) -> Result<(), DynError> {
    if record.body.version != CHAIN_VERSION || record.body.hash_alg != config::INTERNAL_KEYS_HASH {
        return Err(crate::error::invalid_input(
            "record version or hash algorithm is unsupported",
        ));
    }
    if record.body.chain_id.len() != 32 || hex::decode(&record.body.chain_id).is_err() {
        return Err(crate::error::invalid_input("record chain_id is invalid"));
    }
    for (field, value) in [
        ("prev_hash", &record.body.prev_hash),
        ("event_hash", &record.event_hash),
    ] {
        validation::validate_hex_field(field, value)?;
    }
    if record.body.timestamp.parse::<u64>().is_err() {
        return Err(crate::error::invalid_input("record timestamp is invalid"));
    }
    if record.body.event.is_empty() || record.body.outcome.is_empty() {
        return Err(crate::error::invalid_input(
            "record event and outcome must not be empty",
        ));
    }
    if record.body.reason.chars().count() > config::AUDIT_CHAIN_REASON_MAX_CHARS
        || [
            &record.body.event,
            &record.body.outcome,
            &record.body.actor,
            &record.body.actor_fp,
            &record.body.kid,
            &record.body.remote_kid,
            &record.body.action,
            &record.body.reason,
            &record.body.request_id,
        ]
        .iter()
        .any(|value| value.chars().any(char::is_control))
    {
        return Err(crate::error::invalid_input(
            "record contains invalid text fields",
        ));
    }
    Ok(())
}

fn validate_record(record: &AuditChainRecord) -> Result<(), DynError> {
    validate_record_shape(record)?;
    for (field, value) in [
        ("prev_hash", &record.body.prev_hash),
        ("event_hash", &record.event_hash),
    ] {
        validation::validate_hash_hex_field(field, value, config::INTERNAL_KEYS_HASH)?;
    }
    let serialized = canonical::canonical_json_v1(record)?;
    if serialized.len() > config::AUDIT_CHAIN_RECORD_MAX_BYTES {
        return Err(crate::error::invalid_input("record exceeds maximum size"));
    }
    if hash_record(&record.body)? != record.event_hash {
        return Err(crate::error::invalid_input(
            "event hash does not match record content",
        ));
    }
    Ok(())
}

struct VerifiedChain {
    chain_id: String,
    records: u64,
    last_sequence: u64,
    head_hash: String,
    checkpoints_verified: u64,
    last_checkpoint_sequence: Option<u64>,
    last_checkpoint_head_hash: Option<String>,
}

impl VerifiedChain {
    fn from_genesis(record: &AuditChainRecord) -> Self {
        Self {
            chain_id: record.body.chain_id.clone(),
            records: 1,
            last_sequence: 0,
            head_hash: record.event_hash.clone(),
            checkpoints_verified: 0,
            last_checkpoint_sequence: None,
            last_checkpoint_head_hash: None,
        }
    }

    fn push(&mut self, record: &AuditChainRecord) -> Result<(), &'static str> {
        if record.body.chain_id != self.chain_id {
            return Err("chain_id changed without a genesis record");
        }
        if record.body.sequence != self.last_sequence.saturating_add(1) {
            return Err("sequence is not consecutive");
        }
        if record.body.prev_hash != self.head_hash {
            return Err("prev_hash does not match prior event hash");
        }
        self.records = self.records.saturating_add(1);
        self.last_sequence = record.body.sequence;
        self.head_hash = record.event_hash.clone();
        Ok(())
    }

    fn checkpoint(&mut self, payload: &AuditCheckpointPayload) -> Result<(), &'static str> {
        if payload.chain_id != self.chain_id {
            return Err("checkpoint chain_id does not match active chain");
        }
        if payload.last_sequence != self.last_sequence {
            return Err("checkpoint sequence does not match active chain");
        }
        if payload.head_hash != self.head_hash {
            return Err("checkpoint head_hash does not match active chain");
        }
        self.checkpoints_verified = self.checkpoints_verified.saturating_add(1);
        self.last_checkpoint_sequence = Some(payload.last_sequence);
        self.last_checkpoint_head_hash = Some(payload.head_hash.clone());
        Ok(())
    }

    fn summary(self) -> AuditChainSummary {
        AuditChainSummary {
            chain_id: self.chain_id,
            records: self.records,
            last_sequence: self.last_sequence,
            head_hash: self.head_hash,
            checkpoints_verified: self.checkpoints_verified,
            last_checkpoint_sequence: self.last_checkpoint_sequence,
            last_checkpoint_head_hash: self.last_checkpoint_head_hash,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    #[derive(Default)]
    struct RecordingWriter {
        bytes: Vec<u8>,
        writes: usize,
        flushes: usize,
        fail_write: bool,
        fail_flush: bool,
    }

    impl Write for RecordingWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.writes += 1;
            if self.fail_write {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "injected write failure",
                ));
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            self.flushes += 1;
            if self.fail_flush {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "injected flush failure",
                ));
            }
            Ok(())
        }
    }

    fn temp_path(name: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("vectis-{name}-{nanos}.jsonl"))
    }

    impl AuditRuntime {
        fn record_sync(&self, event: AuditEvent) -> Option<String> {
            let failure = Arc::new(Mutex::new(None));
            self.record(event, &failure, false);
            let (reply, ack) = oneshot::channel();
            if self
                .sender
                .try_send(WriterCommand::Barrier {
                    failure: Arc::clone(&failure),
                    reply,
                })
                .is_ok()
            {
                let _ = ack.blocking_recv();
            }
            failure.lock().unwrap().clone()
        }
    }

    fn sample_event(event: &str, action: &str) -> AuditEvent {
        AuditEvent {
            event: String::from(event),
            outcome: String::from("success"),
            actor: String::from("payments"),
            actor_fp: String::from("a"),
            root: false,
            admin: false,
            kid: String::from("b"),
            remote_kid: String::new(),
            action: String::from(action),
            reason: String::new(),
            request_id: String::from("c"),
        }
    }

    fn logging_config_for(path: &std::path::Path) -> logging::LoggingConfig {
        logging::LoggingConfig {
            level: tracing::Level::INFO,
            dir: path.parent().unwrap().display().to_string(),
            file: String::from("unused.log"),
            audit_file: path.file_name().unwrap().to_string_lossy().to_string(),
            target: logging::LogTarget::File,
        }
    }

    fn test_signer() -> AuditCheckpointSigner {
        let init_keys = crate::ops::init::create_init_output().expect("test init keys must build");
        AuditCheckpointSigner {
            eddsa: init_keys.keys().eddsa().clone(),
            ml_dsa: init_keys.keys().ml_dsa().clone(),
        }
    }

    fn write_checkpointed_chain(
        path: &std::path::Path,
        signer: &AuditCheckpointSigner,
    ) -> AuditChainState {
        let memory = Arc::new(Mutex::new(MemorySink {
            fail_writes_after: usize::MAX,
            ..MemorySink::default()
        }));
        let mut sink = AuditSink::Memory(Arc::clone(&memory));
        let mut state = AuditChainState::new().unwrap();
        write_event(&mut sink, &mut state, AuditEvent::chain_started()).unwrap();
        write_event(
            &mut sink,
            &mut state,
            sample_event("token.encode.success", "token-encode"),
        )
        .unwrap();
        append_checkpoint(&mut sink, &mut state, signer).unwrap();
        fs::write(path, &memory.lock().unwrap().bytes).unwrap();
        state
    }

    #[test]
    fn json_line_is_written_as_one_complete_operation() {
        let mut writer = RecordingWriter::default();
        write_json_line(&mut writer, br#"{"event":"key.create.success"}"#).unwrap();

        assert_eq!(writer.bytes, b"{\"event\":\"key.create.success\"}\n");
        assert_eq!(writer.writes, 1);
        assert_eq!(writer.flushes, 1);
        assert_eq!(
            writer.bytes.iter().filter(|byte| **byte == b'\n').count(),
            1
        );
        assert!(writer.bytes.ends_with(b"\n"));
    }

    #[test]
    fn json_line_propagates_write_failure_without_flushing() {
        let mut writer = RecordingWriter {
            fail_write: true,
            ..RecordingWriter::default()
        };

        let err = write_json_line(&mut writer, b"{}").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(writer.writes, 1);
        assert_eq!(writer.flushes, 0);
        assert!(writer.bytes.is_empty());
    }

    #[test]
    fn json_line_propagates_flush_failure() {
        let mut writer = RecordingWriter {
            fail_flush: true,
            ..RecordingWriter::default()
        };

        let err = write_json_line(&mut writer, b"{}").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(writer.writes, 1);
        assert_eq!(writer.flushes, 1);
        assert_eq!(writer.bytes, b"{}\n");
    }

    #[test]
    fn structural_line_validator_accepts_canonical_shapes_without_crypto() {
        let record = AuditChainRecord {
            body: AuditRecordBody {
                version: String::from(CHAIN_VERSION),
                chain_id: "a".repeat(32),
                sequence: 0,
                timestamp: String::from("1"),
                event: String::from("audit.chain.started"),
                outcome: String::from("success"),
                actor: String::new(),
                actor_fp: String::new(),
                root: true,
                admin: false,
                kid: String::new(),
                remote_kid: String::new(),
                action: String::from("chain-start"),
                reason: String::new(),
                request_id: String::new(),
                hash_alg: String::from(config::INTERNAL_KEYS_HASH),
                prev_hash: "0".repeat(64),
            },
            event_hash: "b".repeat(64),
        };
        let line = String::from_utf8(canonical::canonical_json_v1(&record).unwrap()).unwrap();
        assert!(validate_audit_jsonl_line_encoding(&line).is_ok());

        let checkpoint = AuditCheckpointLine {
            version: String::from(CHECKPOINT_VERSION),
            signature: String::from("e30.e30.AA.AA"),
        };
        let line = String::from_utf8(canonical::canonical_json_v1(&checkpoint).unwrap()).unwrap();
        assert!(validate_audit_jsonl_line_encoding(&line).is_ok());
        assert!(validate_audit_jsonl_line_encoding(&format!("{line} ")).is_err());
    }

    #[test]
    fn verifier_accepts_multiple_chains_and_detects_tampering() {
        let path = temp_path("audit");
        let config = logging_config_for(&path);
        let signer = test_signer();
        let runtime = AuditRuntime::start(&config, signer.clone()).unwrap();
        assert!(
            runtime
                .record_sync(sample_event("token.encode.success", "token-encode"))
                .is_none()
        );
        drop(runtime);

        let second_runtime = AuditRuntime::start(&config, signer.clone()).unwrap();
        assert!(
            second_runtime
                .record_sync(sample_event("token.decode.success", "token-decode"))
                .is_none()
        );
        drop(second_runtime);

        let verified = verify_file_with_signer(&path, &signer).unwrap();
        assert_eq!(verified.chains.len(), 2);
        assert_eq!(verified.chains[0].records, 2);
        assert_eq!(verified.chains[0].checkpoints_verified, 0);

        let mut content = fs::read_to_string(&path).unwrap();
        content = content.replacen("token.encode.success", "token.create.success", 1);
        fs::write(&path, content).unwrap();
        assert!(verify_file_with_signer(&path, &signer).is_err());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn verifier_rejects_noncanonical_record_json() {
        let path = temp_path("audit-noncanonical");
        let config = logging_config_for(&path);
        let runtime = AuditRuntime::start(&config, test_signer()).unwrap();
        drop(runtime);

        let content = fs::read_to_string(&path).unwrap();
        let value: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
        fs::write(&path, serde_json::to_string_pretty(&value).unwrap()).unwrap();
        let err = verify_file_with_signer(&path, &test_signer())
            .expect_err("pretty JSON must not be accepted as JSONL");
        assert!(
            err.to_string().contains("record exceeds maximum size")
                || err.to_string().contains("invalid JSON")
                || err.to_string().contains("missing trailing newline")
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn verifier_accepts_signed_checkpoint_and_reports_it() {
        let path = temp_path("audit-checkpoint");
        let signer = test_signer();
        let state = write_checkpointed_chain(&path, &signer);

        let verified = verify_file_with_signer(&path, &signer).unwrap();
        assert_eq!(verified.chains.len(), 1);
        assert_eq!(verified.chains[0].checkpoints_verified, 1);
        assert_eq!(
            verified.chains[0].last_checkpoint_sequence,
            Some(state.next_sequence - 1)
        );
        assert_eq!(
            verified.chains[0].last_checkpoint_head_hash.as_deref(),
            Some(state.head_hash.as_str())
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn verifier_uses_init_public_state_without_unsealing_private_material() {
        let init_output = crate::ops::init::create_encrypted_init_output_json().unwrap();
        let init_state = crate::ops::init::load_validated_init_state(
            &init_output.json,
            &init_output.encryption_key_hex,
        )
        .unwrap();
        let init_public_state =
            crate::ops::init::load_validated_init_public_state(&init_output.public_json).unwrap();
        let signer = AuditCheckpointSigner::from_init(&init_state);
        let path = temp_path("audit-public-init");
        write_checkpointed_chain(&path, &signer);

        let verified = verify_file(&path, &init_public_state).unwrap();
        assert_eq!(verified.chains[0].checkpoints_verified, 1);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn verifier_rejects_checkpoint_signature_and_head_tampering() {
        let path = temp_path("audit-checkpoint-tampered");
        let signer = test_signer();
        write_checkpointed_chain(&path, &signer);

        let content = fs::read_to_string(&path).unwrap();
        let tampered_signature = content.replacen("\"signature\":\"", "\"signature\":\"x", 1);
        fs::write(&path, tampered_signature).unwrap();
        assert!(verify_file_with_signer(&path, &signer).is_err());

        write_checkpointed_chain(&path, &signer);
        let mut lines: Vec<String> = fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect();
        let mut checkpoint: AuditCheckpointLine =
            serde_json::from_str(lines.last().expect("checkpoint line must be present")).unwrap();
        let mut payload = verify_checkpoint(&checkpoint, &signer.verifier()).unwrap();
        payload.head_hash = String::from(GENESIS_HASH);
        let mut rng = crypto::new_rng().unwrap();
        checkpoint.signature =
            sign::sign_compact_hybrid_payload(&mut rng, &payload, &signer.eddsa, &signer.ml_dsa)
                .unwrap();
        *lines.last_mut().unwrap() =
            String::from_utf8(canonical::canonical_json_v1(&checkpoint).unwrap()).unwrap();
        fs::write(&path, format!("{}\n", lines.join("\n"))).unwrap();
        let err = verify_file_with_signer(&path, &signer).unwrap_err();
        assert!(
            err.to_string()
                .contains("checkpoint head_hash does not match")
        );
        let _ = fs::remove_file(path);
    }

    #[derive(Default)]
    pub(super) struct MemorySink {
        bytes: Vec<u8>,
        writes: usize,
        fail_writes_after: usize,
        syncs: usize,
        fail_sync: bool,
    }

    impl MemorySink {
        pub(super) fn write_record(&mut self, serialized: &[u8]) -> io::Result<()> {
            let index = self.writes;
            self.writes += 1;
            if index >= self.fail_writes_after {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "injected write failure",
                ));
            }
            self.bytes.extend_from_slice(serialized);
            self.bytes.push(b'\n');
            Ok(())
        }

        pub(super) fn sync(&mut self) -> io::Result<()> {
            self.syncs += 1;
            if self.fail_sync {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "injected sync failure",
                ));
            }
            Ok(())
        }
    }

    fn wait_for_memory<F>(memory: &Arc<Mutex<MemorySink>>, description: &str, ready: F)
    where
        F: Fn(&MemorySink) -> bool,
    {
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            if ready(&memory.lock().unwrap()) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {description}"
            );
            thread::sleep(Duration::from_millis(1));
        }
    }

    fn send_record(sender: &mpsc::Sender<WriterCommand>, event: AuditEvent) -> Option<String> {
        let failure = Arc::new(Mutex::new(None));
        sender
            .try_send(WriterCommand::Record {
                event: Box::new(event),
                failure: Arc::clone(&failure),
                standalone: false,
            })
            .expect("record enqueued");
        let (reply, ack) = oneshot::channel();
        sender
            .try_send(WriterCommand::Barrier {
                failure: Arc::clone(&failure),
                reply,
            })
            .expect("barrier enqueued");
        ack.blocking_recv().expect("barrier acked");
        failure.lock().unwrap().clone()
    }

    #[test]
    fn writer_poisons_and_stops_appending_after_a_write_failure() {
        let memory = Arc::new(Mutex::new(MemorySink {
            fail_writes_after: 2,
            ..MemorySink::default()
        }));
        let sink = AuditSink::Memory(Arc::clone(&memory));
        let mut state = AuditChainState::new().unwrap();
        write_event(
            &mut AuditSink::Memory(Arc::clone(&memory)),
            &mut state,
            AuditEvent::chain_started(),
        )
        .expect("genesis write");

        let (sender, receiver) = mpsc::channel(16);
        let handle = thread::spawn(move || writer_loop(sink, state, test_signer(), receiver));

        assert!(
            send_record(
                &sender,
                sample_event("token.encode.success", "token-encode")
            )
            .is_none()
        );
        assert!(
            send_record(
                &sender,
                sample_event("token.decode.success", "token-decode")
            )
            .is_some()
        );
        assert!(
            send_record(
                &sender,
                sample_event("token.encode.success", "token-encode")
            )
            .is_some()
        );
        drop(sender);
        handle.join().unwrap();

        let bytes = memory.lock().unwrap().bytes.clone();
        let text = String::from_utf8(bytes).unwrap();
        let sequences: Vec<u64> = text
            .lines()
            .map(|line| {
                serde_json::from_str::<AuditChainRecord>(line)
                    .unwrap()
                    .body
                    .sequence
            })
            .collect();
        let mut unique = sequences.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(sequences.len(), unique.len(), "no sequence may be reused");
        assert_eq!(sequences, vec![0, 1]);
    }

    #[test]
    fn group_commit_fsyncs_once_for_a_batch_of_requests() {
        let memory = Arc::new(Mutex::new(MemorySink {
            fail_writes_after: usize::MAX,
            ..MemorySink::default()
        }));
        let mut state = AuditChainState::new().unwrap();
        write_event(
            &mut AuditSink::Memory(Arc::clone(&memory)),
            &mut state,
            AuditEvent::chain_started(),
        )
        .expect("genesis write");

        let (sender, receiver) = mpsc::channel(64);
        let mut acks = Vec::new();
        for _ in 0..5 {
            let failure = Arc::new(Mutex::new(None));
            sender
                .try_send(WriterCommand::Record {
                    event: Box::new(sample_event("token.encode.success", "token-encode")),
                    failure: Arc::clone(&failure),
                    standalone: false,
                })
                .expect("record enqueued");
            let (reply, ack) = oneshot::channel();
            sender
                .try_send(WriterCommand::Barrier { failure, reply })
                .expect("barrier enqueued");
            acks.push(ack);
        }
        let sink = AuditSink::Memory(Arc::clone(&memory));
        let handle = thread::spawn(move || writer_loop(sink, state, test_signer(), receiver));
        drop(sender);
        for ack in acks {
            ack.blocking_recv().expect("barrier acked");
        }
        handle.join().unwrap();

        let memory = memory.lock().unwrap();
        assert_eq!(memory.syncs, 1, "a batch of requests must fsync once");
        assert_eq!(
            memory.bytes.iter().filter(|byte| **byte == b'\n').count(),
            6,
            "genesis plus five records written"
        );
    }

    #[test]
    fn staggered_request_records_sync_once_at_barrier() {
        let memory = Arc::new(Mutex::new(MemorySink {
            fail_writes_after: usize::MAX,
            ..MemorySink::default()
        }));
        let mut state = AuditChainState::new().unwrap();
        let mut sink = AuditSink::Memory(Arc::clone(&memory));
        write_event(&mut sink, &mut state, AuditEvent::chain_started()).unwrap();
        sink.sync().unwrap();
        let baseline_syncs = memory.lock().unwrap().syncs;

        let (sender, receiver) = mpsc::channel(16);
        let handle = thread::spawn(move || writer_loop(sink, state, test_signer(), receiver));
        let failure = Arc::new(Mutex::new(None));
        for (index, event) in [
            sample_event("auth.success", "authenticate"),
            sample_event("permission.allowed", "token-encode"),
            sample_event("token.encode.success", "token-encode"),
        ]
        .into_iter()
        .enumerate()
        {
            sender
                .try_send(WriterCommand::Record {
                    event: Box::new(event),
                    failure: Arc::clone(&failure),
                    standalone: false,
                })
                .unwrap();
            wait_for_memory(&memory, "staggered audit record", |sink| {
                sink.writes >= index + 2
            });
            assert_eq!(
                memory.lock().unwrap().syncs,
                baseline_syncs,
                "request records must wait for their barrier before syncing"
            );
        }

        let (reply, ack) = oneshot::channel();
        sender
            .try_send(WriterCommand::Barrier {
                failure: Arc::clone(&failure),
                reply,
            })
            .unwrap();
        ack.blocking_recv().expect("barrier acked");
        assert_eq!(memory.lock().unwrap().syncs, baseline_syncs + 1);
        assert!(failure.lock().unwrap().is_none());

        let (reply, ack) = oneshot::channel();
        sender
            .try_send(WriterCommand::Barrier { failure, reply })
            .unwrap();
        ack.blocking_recv().expect("second barrier acked");
        assert_eq!(
            memory.lock().unwrap().syncs,
            baseline_syncs + 1,
            "a barrier without new records must not sync again"
        );

        drop(sender);
        handle.join().unwrap();
    }

    #[test]
    fn standalone_record_requests_its_own_commit() {
        let memory = Arc::new(Mutex::new(MemorySink {
            fail_writes_after: usize::MAX,
            ..MemorySink::default()
        }));
        let mut state = AuditChainState::new().unwrap();
        let mut sink = AuditSink::Memory(Arc::clone(&memory));
        write_event(&mut sink, &mut state, AuditEvent::chain_started()).unwrap();
        sink.sync().unwrap();
        let baseline_syncs = memory.lock().unwrap().syncs;

        let (sender, receiver) = mpsc::channel(4);
        let handle = thread::spawn(move || writer_loop(sink, state, test_signer(), receiver));
        sender
            .try_send(WriterCommand::Record {
                event: Box::new(sample_event("config.reload.success", "config-reload")),
                failure: Arc::new(Mutex::new(None)),
                standalone: true,
            })
            .unwrap();
        wait_for_memory(&memory, "standalone audit commit", |sink| {
            sink.syncs == baseline_syncs + 1
        });

        drop(sender);
        handle.join().unwrap();
    }

    #[test]
    fn shutdown_drains_commands_queued_after_shutdown() {
        let memory = Arc::new(Mutex::new(MemorySink {
            fail_writes_after: usize::MAX,
            ..MemorySink::default()
        }));
        let mut state = AuditChainState::new().unwrap();
        write_event(
            &mut AuditSink::Memory(Arc::clone(&memory)),
            &mut state,
            AuditEvent::chain_started(),
        )
        .unwrap();

        let (sender, receiver) = mpsc::channel(8);
        let first = Arc::new(Mutex::new(None));
        sender
            .try_send(WriterCommand::Record {
                event: Box::new(sample_event("token.encode.success", "token-encode")),
                failure: Arc::clone(&first),
                standalone: false,
            })
            .unwrap();
        let (shutdown_reply, shutdown_ack) = oneshot::channel();
        sender
            .try_send(WriterCommand::Shutdown {
                reply: shutdown_reply,
            })
            .unwrap();
        // Record + barrier queued *after* the Shutdown command: they must still be drained.
        let second = Arc::new(Mutex::new(None));
        sender
            .try_send(WriterCommand::Record {
                event: Box::new(sample_event("token.decode.success", "token-decode")),
                failure: Arc::clone(&second),
                standalone: false,
            })
            .unwrap();
        let (barrier_reply, barrier_ack) = oneshot::channel();
        sender
            .try_send(WriterCommand::Barrier {
                failure: Arc::new(Mutex::new(None)),
                reply: barrier_reply,
            })
            .unwrap();

        let sink = AuditSink::Memory(Arc::clone(&memory));
        let handle = thread::spawn(move || writer_loop(sink, state, test_signer(), receiver));
        drop(sender);

        assert!(
            barrier_ack.blocking_recv().is_ok(),
            "barrier queued after shutdown must still be answered"
        );
        assert_eq!(shutdown_ack.blocking_recv().unwrap(), Ok(()));
        handle.join().unwrap();

        let text = String::from_utf8(memory.lock().unwrap().bytes.clone()).unwrap();
        let sequences: Vec<u64> = text
            .lines()
            .filter_map(|line| serde_json::from_str::<AuditChainRecord>(line).ok())
            .map(|record| record.body.sequence)
            .collect();
        assert!(
            sequences.contains(&1) && sequences.contains(&2),
            "both event records must be persisted, got {sequences:?}"
        );
        assert!(first.lock().unwrap().is_none());
        assert!(second.lock().unwrap().is_none());
    }

    #[test]
    fn group_commit_drain_is_bounded() {
        let memory = Arc::new(Mutex::new(MemorySink {
            fail_writes_after: usize::MAX,
            ..MemorySink::default()
        }));
        let mut state = AuditChainState::new().unwrap();
        write_event(
            &mut AuditSink::Memory(Arc::clone(&memory)),
            &mut state,
            AuditEvent::chain_started(),
        )
        .unwrap();

        let pair_count = (config::AUDIT_GROUP_COMMIT_MAX_COMMANDS / 2) + 2;
        let (sender, receiver) = mpsc::channel(config::AUDIT_GROUP_COMMIT_MAX_COMMANDS + 16);
        let mut acks = Vec::with_capacity(pair_count);
        for _ in 0..pair_count {
            let failure = Arc::new(Mutex::new(None));
            sender
                .try_send(WriterCommand::Record {
                    event: Box::new(sample_event("token.encode.success", "token-encode")),
                    failure: Arc::clone(&failure),
                    standalone: false,
                })
                .unwrap();
            let (reply, ack) = oneshot::channel();
            sender
                .try_send(WriterCommand::Barrier { failure, reply })
                .unwrap();
            acks.push(ack);
        }

        let sink = AuditSink::Memory(Arc::clone(&memory));
        let handle = thread::spawn(move || writer_loop(sink, state, test_signer(), receiver));
        drop(sender);
        for ack in acks {
            ack.blocking_recv().expect("barrier acked");
        }
        handle.join().unwrap();

        assert_eq!(
            memory.lock().unwrap().syncs,
            2,
            "more than 256 commands must be committed in bounded groups"
        );
    }

    #[test]
    fn sync_failure_poisons_current_and_future_requests() {
        let memory = Arc::new(Mutex::new(MemorySink {
            fail_writes_after: usize::MAX,
            fail_sync: true,
            ..MemorySink::default()
        }));
        let mut state = AuditChainState::new().unwrap();
        write_event(
            &mut AuditSink::Memory(Arc::clone(&memory)),
            &mut state,
            AuditEvent::chain_started(),
        )
        .unwrap();

        let (sender, receiver) = mpsc::channel(8);
        let sink = AuditSink::Memory(Arc::clone(&memory));
        let handle = thread::spawn(move || writer_loop(sink, state, test_signer(), receiver));

        assert!(
            send_record(
                &sender,
                sample_event("token.encode.success", "token-encode")
            )
            .is_some()
        );
        assert!(
            send_record(
                &sender,
                sample_event("token.decode.success", "token-decode")
            )
            .is_some()
        );

        drop(sender);
        handle.join().unwrap();
        assert_eq!(
            memory.lock().unwrap().writes,
            2,
            "the poisoned writer must reject the second request record"
        );
    }

    #[test]
    fn writer_emits_checkpoint_for_event_threshold() {
        let signer = test_signer();
        let memory = Arc::new(Mutex::new(MemorySink {
            fail_writes_after: usize::MAX,
            ..MemorySink::default()
        }));
        let mut state = AuditChainState::new().unwrap();
        let mut sink = AuditSink::Memory(Arc::clone(&memory));
        write_event(&mut sink, &mut state, AuditEvent::chain_started()).unwrap();
        sink.sync().unwrap();
        let genesis_syncs = memory.lock().unwrap().syncs;
        let (sender, receiver) = mpsc::channel(16);
        let threshold_handle = thread::spawn({
            let signer = signer.clone();
            move || {
                writer_loop_with_policy(
                    sink,
                    state,
                    signer,
                    receiver,
                    CheckpointPolicy { event_count: 1 },
                )
            }
        });
        let failure = Arc::new(Mutex::new(None));
        sender
            .try_send(WriterCommand::Record {
                event: Box::new(sample_event("token.encode.success", "token-encode")),
                failure,
                standalone: false,
            })
            .unwrap();
        let (reply, ack) = oneshot::channel();
        sender.try_send(WriterCommand::Shutdown { reply }).unwrap();
        assert!(ack.blocking_recv().unwrap().is_ok());
        threshold_handle.join().unwrap();

        assert_eq!(
            memory.lock().unwrap().syncs - genesis_syncs,
            1,
            "the event batch and checkpoint must be synchronized together"
        );

        let path = temp_path("audit-checkpoint-threshold");
        fs::write(&path, &memory.lock().unwrap().bytes).unwrap();
        let verified = verify_file_with_signer(&path, &signer).unwrap();
        assert_eq!(verified.chains[0].checkpoints_verified, 1);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn verifier_reports_truncated_final_record() {
        let path = temp_path("audit-truncated");
        let config = logging_config_for(&path);
        let signer = test_signer();
        let runtime = AuditRuntime::start(&config, signer.clone()).unwrap();
        assert!(
            runtime
                .record_sync(sample_event("token.encode.success", "token-encode"))
                .is_none()
        );
        drop(runtime);

        let mut content = fs::read_to_string(&path).unwrap();
        while content.ends_with('\n') {
            content.pop();
        }
        fs::write(&path, content).unwrap();
        let err = verify_file_with_signer(&path, &signer)
            .expect_err("record without trailing newline must be rejected");
        assert!(err.to_string().contains("missing trailing newline"));
        let _ = fs::remove_file(path);
    }
}
