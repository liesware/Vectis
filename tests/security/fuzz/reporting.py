import gzip
import hashlib
import json
import os
import tempfile
import uuid
from pathlib import Path

from campaign import SEED_DERIVATION
from oracle import slow_response_findings


CORPUS_DIR = Path(__file__).resolve().parent / "fuzz-corpus"


def _redact_bytes(data, secrets):
    for secret in sorted((s for s in secrets if s), key=len, reverse=True):
        for encoded in (secret.encode("utf-8"), json.dumps(secret)[1:-1].encode("utf-8")):
            data = data.replace(encoded, b"[REDACTED]")
    return data


def _redact(value, secrets):
    if isinstance(value, str):
        return _redact_bytes(value.encode("utf-8"), secrets).decode("utf-8")
    if isinstance(value, dict):
        return {_redact(key, secrets): _redact(item, secrets) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_redact(item, secrets) for item in value]
    if isinstance(value, bytes):
        return _redact_bytes(value, secrets).decode("utf-8", "replace")
    return value


def _atomic_write(path, data):
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".finding-", delete=False) as output:
            temporary = Path(output.name)
            output.write(data)
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def save_crash(target, seed, index, description, findings, *, target_seed, responses=(), secrets=()):
    CORPUS_DIR.mkdir(parents=True, exist_ok=True)
    artifact = CORPUS_DIR / f"crash_{target}_{seed}_{index}.json"
    if artifact.exists() or artifact.with_suffix(".payload.gz").exists():
        artifact = artifact.with_name(f"{artifact.stem}_{uuid.uuid4().hex}.json")
    request = dict(description)
    explicit_payload = request.pop("_payload_bytes", None)
    has_body = "body" in request
    body = request.pop("body", None)
    if explicit_payload is None and has_body:
        explicit_payload = next((r.request_body for r in responses if r.request_body is not None), None)
        if explicit_payload is None:
            explicit_payload = body if isinstance(body, bytes) else json.dumps(body).encode("utf-8")
    saved_payloads = {}

    def store(data):
        original_hash = hashlib.sha256(data).hexdigest()
        if original_hash in saved_payloads:
            return saved_payloads[original_hash]
        redacted = _redact_bytes(data, secrets)
        suffix = ".payload.gz" if not saved_payloads else f".request-{len(saved_payloads) + 1}.payload.gz"
        path = artifact.with_suffix(suffix)
        _atomic_write(path, gzip.compress(redacted, mtime=0))
        metadata = {
            "file": path.name,
            "original_bytes": len(data),
            "original_sha256": original_hash,
            "stored_bytes": len(redacted),
            "stored_sha256": hashlib.sha256(redacted).hexdigest(),
            "redacted": redacted != data,
            "encoding": "gzip",
        }
        saved_payloads[original_hash] = metadata
        return metadata

    if explicit_payload is not None:
        metadata = store(explicit_payload)
        preview = _redact_bytes(explicit_payload, secrets).decode("utf-8", "replace")
        preview_field = "content" if "mutated_file" in request else "body"
        request[preview_field] = preview[:2000]
        request["preview_truncated"] = len(preview) > 2000
        request["payload"] = metadata
    response_evidence = []
    for response in responses:
        evidence = {
            "method": response.method, "path": response.path,
            "status": response.status, "duration_ms": round(response.duration_ms, 2),
            "transport_phase": response.transport_phase, "error_type": response.error_type,
            "errno": response.error_errno, "request_body_bytes": response.request_body_bytes,
        }
        if response.request_body is not None:
            evidence["payload"] = store(response.request_body)
            preview = _redact_bytes(response.request_body, secrets).decode("utf-8", "replace")
            evidence["body_preview"] = preview[:2000]
            evidence["preview_truncated"] = len(preview) > 2000
        response_evidence.append(evidence)
    payload = {
        "format": "http-fuzz-finding-v2",
        "target": target,
        "seed": seed,
        "target_seed": target_seed,
        "seed_derivation": SEED_DERIVATION,
        "index": index,
        "findings": findings,
        "request": request,
        "responses": response_evidence,
    }
    _atomic_write(artifact, (json.dumps(_redact(payload, secrets), indent=2, default=repr) + "\n").encode("utf-8"))
    return artifact


def describe(method, path, raw, body):
    return {"method": method, "path": path, "raw": raw, "body": body}


def check_and_record(
    name,
    client,
    args,
    index,
    status,
    findings,
    description,
    counters,
    *,
    check_latency=True,
):
    responses = client.consume_timings()
    if check_latency:
        findings.extend(slow_response_findings(responses))
    if responses:
        description["max_duration_ms"] = round(
            max(response.duration_ms for response in responses), 2
        )
    if index % args.liveness_every == 0 and client.get_status("/healthz/live") != 200:
        findings.append("server not alive after case")
    liveness_responses = client.consume_timings()
    findings.extend(slow_response_findings(liveness_responses))
    if liveness_responses:
        description["max_duration_ms"] = round(
            max(
                description.get("max_duration_ms", 0),
                *(response.duration_ms for response in liveness_responses),
            ),
            2,
        )
    args.metrics.record_result(status, bool(findings))
    if findings:
        counters["failed"] += 1
        secrets = getattr(client, "declared_secrets", ())
        artifact = save_crash(name, args.seed, index, description, findings,
                              target_seed=args.metrics.seed,
                              responses=[*responses, *liveness_responses], secrets=secrets)
        print(f"[{name}] FINDING at #{index}: {_redact(findings, secrets)} -> {artifact}")
        if status == 0 and client.get_status("/healthz/live") != 200:
            print(f"[{name}] server appears down; aborting target")
            return True
    else:
        counters["passed"] += 1
    return False


def print_target_start(name, args):
    print(f"[{name}] start iterations={args.iterations} target_seed={args.metrics.seed}", flush=True)


def print_target_done(name, counters):
    print(
        f"[{name}] done passed={counters['passed']} failed={counters['failed']}",
        flush=True,
    )


def print_progress(name, index, args, counters):
    if args.progress_every <= 0:
        return

    current = index + 1
    if current % args.progress_every != 0:
        return

    print(
        f"[{name}] progress {current}/{args.iterations} "
        f"passed={counters['passed']} failed={counters['failed']}",
        flush=True,
    )
