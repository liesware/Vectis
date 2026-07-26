use crate::core::{canonical, config, crypto, logging, validation};
use crate::error::DynError;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use tokio::sync::{mpsc, oneshot};

const VERSION: &str = "audit-chain-v1";
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

#[derive(Clone, Debug, Serialize)]
pub struct AuditChainSummary {
    pub chain_id: String,
    pub records: u64,
    pub last_sequence: u64,
    pub head_hash: String,
}

#[derive(Debug, Serialize)]
pub struct AuditVerificationOutput {
    pub valid: bool,
    pub chains: Vec<AuditChainSummary>,
}

struct AuditRuntime {
    sender: mpsc::Sender<WriterCommand>,
}

enum WriterCommand {
    Record {
        event: Box<AuditEvent>,
        failure: Arc<Mutex<Option<String>>>,
    },
    Barrier {
        failure: Arc<Mutex<Option<String>>>,
        reply: oneshot::Sender<()>,
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
}

pub fn initialize(logging_config: &logging::LoggingConfig) -> Result<(), DynError> {
    if RUNTIME.get().is_some() {
        return Ok(());
    }

    let runtime = AuditRuntime::start(logging_config)?;
    RUNTIME
        .set(runtime)
        .map_err(|_| crate::error::internal("audit chain runtime was initialized concurrently"))
}

pub fn record(event: AuditEvent, failure: &Arc<Mutex<Option<String>>>) {
    let Some(runtime) = RUNTIME.get() else {
        return;
    };
    runtime.record(event, failure);
}

pub async fn confirm(failure: &Arc<Mutex<Option<String>>>) {
    if let Some(runtime) = RUNTIME.get() {
        runtime.confirm(failure).await;
    }
}

pub fn verify_file(path: &Path) -> Result<AuditVerificationOutput, DynError> {
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
        let record: AuditChainRecord = serde_json::from_str(line)
            .map_err(|_| verify_error(line_index, "record contains invalid JSON"))?;
        validate_record(&record).map_err(|err| verify_error(line_index, &err.to_string()))?;
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
            line_index += 1;
            continue;
        }

        let Some(chain) = current.as_mut() else {
            return Err(verify_error(line_index, "first record must start a chain"));
        };
        chain
            .push(&record)
            .map_err(|reason| verify_error(line_index, reason))?;
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

impl AuditRuntime {
    fn start(logging_config: &logging::LoggingConfig) -> Result<Self, DynError> {
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

        let (sender, receiver) = mpsc::channel(config::AUDIT_CHAIN_CHANNEL_CAPACITY);
        thread::Builder::new()
            .name(String::from("vectis-audit-chain"))
            .spawn(move || writer_loop(sink, state, receiver))
            .map_err(|err| crate::error::internal(format!("cannot start audit writer: {err}")))?;

        Ok(Self { sender })
    }

    fn record(&self, event: AuditEvent, failure: &Arc<Mutex<Option<String>>>) {
        if self
            .sender
            .try_send(WriterCommand::Record {
                event: Box::new(event),
                failure: Arc::clone(failure),
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
        })
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
    mut sink: AuditSink,
    mut state: AuditChainState,
    mut receiver: mpsc::Receiver<WriterCommand>,
) {
    // Once a write fails the chain state and the file could diverge, so the writer stops
    // appending permanently: any further append could reuse a sequence and poison verify.
    let mut poisoned: Option<String> = None;
    let mut barriers: Vec<PendingBarrier> = Vec::new();

    while let Some(first) = receiver.blocking_recv() {
        // Group commit: absorb every command already queued into one batch, append all
        // their records, fsync once, then release every barrier. One fsync is amortized
        // across all concurrent requests instead of one fsync per request.
        let mut next = Some(first);
        let mut wrote = false;

        while let Some(command) = next {
            match command {
                WriterCommand::Record { event, failure } => {
                    if let Some(reason) = &poisoned {
                        set_failure(&failure, reason);
                    } else if let Err(err) = write_event(&mut sink, &mut state, *event) {
                        let reason = err.to_string();
                        set_failure(&failure, &reason);
                        poisoned = Some(reason);
                    } else {
                        wrote = true;
                    }
                }
                WriterCommand::Barrier { failure, reply } => {
                    barriers.push(PendingBarrier { failure, reply });
                }
            }
            next = receiver.try_recv().ok();
        }

        if wrote
            && poisoned.is_none()
            && let Err(err) = sink.sync()
        {
            poisoned = Some(format!("cannot fsync audit log: {err}"));
        }
        for barrier in barriers.drain(..) {
            if let Some(reason) = &poisoned {
                set_failure(&barrier.failure, reason);
            }
            let _ = barrier.reply.send(());
        }
    }
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
        version: String::from(VERSION),
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

fn validate_record(record: &AuditChainRecord) -> Result<(), DynError> {
    if record.body.version != VERSION || record.body.hash_alg != config::INTERNAL_KEYS_HASH {
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
        validation::validate_hash_hex_field(field, value, config::INTERNAL_KEYS_HASH)?;
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
}

impl VerifiedChain {
    fn from_genesis(record: &AuditChainRecord) -> Self {
        Self {
            chain_id: record.body.chain_id.clone(),
            records: 1,
            last_sequence: 0,
            head_hash: record.event_hash.clone(),
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

    fn summary(self) -> AuditChainSummary {
        AuditChainSummary {
            chain_id: self.chain_id,
            records: self.records,
            last_sequence: self.last_sequence,
            head_hash: self.head_hash,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

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
            self.record(event, &failure);
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
    fn verifier_accepts_multiple_chains_and_detects_tampering() {
        let path = temp_path("audit");
        let config = logging_config_for(&path);
        let runtime = AuditRuntime::start(&config).unwrap();
        assert!(
            runtime
                .record_sync(sample_event("token.encode.success", "token-encode"))
                .is_none()
        );
        drop(runtime);

        let second_runtime = AuditRuntime::start(&config).unwrap();
        assert!(
            second_runtime
                .record_sync(sample_event("token.decode.success", "token-decode"))
                .is_none()
        );
        drop(second_runtime);

        let verified = verify_file(&path).unwrap();
        assert_eq!(verified.chains.len(), 2);
        assert_eq!(verified.chains[0].records, 2);

        let mut content = fs::read_to_string(&path).unwrap();
        content = content.replacen("token.encode.success", "token.create.success", 1);
        fs::write(&path, content).unwrap();
        assert!(verify_file(&path).is_err());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn verifier_rejects_noncanonical_record_json() {
        let path = temp_path("audit-noncanonical");
        let config = logging_config_for(&path);
        let runtime = AuditRuntime::start(&config).unwrap();
        drop(runtime);

        let content = fs::read_to_string(&path).unwrap();
        let value: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
        fs::write(&path, serde_json::to_string_pretty(&value).unwrap()).unwrap();
        let err = verify_file(&path).expect_err("pretty JSON must not be accepted as JSONL");
        assert!(
            err.to_string().contains("record exceeds maximum size")
                || err.to_string().contains("invalid JSON")
                || err.to_string().contains("missing trailing newline")
        );
        let _ = fs::remove_file(path);
    }

    #[derive(Default)]
    pub(super) struct MemorySink {
        bytes: Vec<u8>,
        writes: usize,
        fail_writes_after: usize,
        syncs: usize,
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
            Ok(())
        }
    }

    fn send_record(sender: &mpsc::Sender<WriterCommand>, event: AuditEvent) -> Option<String> {
        let failure = Arc::new(Mutex::new(None));
        sender
            .try_send(WriterCommand::Record {
                event: Box::new(event),
                failure: Arc::clone(&failure),
            })
            .expect("record enqueued");
        let (reply, ack) = oneshot::channel();
        sender
            .try_send(WriterCommand::Barrier {
                failure: Arc::new(Mutex::new(None)),
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
        let handle = thread::spawn(move || writer_loop(sink, state, receiver));

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
                })
                .expect("record enqueued");
            let (reply, ack) = oneshot::channel();
            sender
                .try_send(WriterCommand::Barrier { failure, reply })
                .expect("barrier enqueued");
            acks.push(ack);
        }
        let sink = AuditSink::Memory(Arc::clone(&memory));
        let handle = thread::spawn(move || writer_loop(sink, state, receiver));
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
    fn verifier_reports_truncated_final_record() {
        let path = temp_path("audit-truncated");
        let config = logging_config_for(&path);
        let runtime = AuditRuntime::start(&config).unwrap();
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
        let err = verify_file(&path).expect_err("record without trailing newline must be rejected");
        assert!(err.to_string().contains("missing trailing newline"));
        let _ = fs::remove_file(path);
    }
}
