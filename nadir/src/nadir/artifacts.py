"""Versioned redacted workflow evidence and opt-in authenticated replay."""

from __future__ import annotations

import base64
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
import json
from pathlib import Path
import re
from uuid import uuid4

from . import __version__
from .http import HttpRequest, HttpResult
from .workflows import CaseRecipe, Finding, StepExecution, WorkflowCase


ARTIFACT_VERSION = "nadir-finding-v4"
REPLAY_ARTIFACT_VERSIONS = frozenset({"nadir-finding-v3", ARTIFACT_VERSION})
_SENSITIVE_HEADERS = {"authorization", "x-api-key", "cookie", "set-cookie"}


@dataclass(frozen=True)
class ReproductionRecipe:
    project: str
    target: str
    iteration: int
    run_seed: int
    case: CaseRecipe
    finding_codes: frozenset[str]


def _load_artifact(path: Path) -> dict[str, object]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("finding artifact is invalid") from error
    if not isinstance(data, dict):
        raise ValueError("finding artifact is invalid")
    return data


def _encode_bytes(value: bytes | None) -> dict[str, str] | None:
    if value is None:
        return None
    try:
        return {"encoding": "utf-8", "value": value.decode("utf-8")}
    except UnicodeDecodeError:
        return {"encoding": "base64", "value": base64.b64encode(value).decode("ascii")}


def _decode_bytes(value: object) -> bytes | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {"encoding", "value"}:
        raise ValueError("artifact byte field is invalid")
    if not isinstance(value["encoding"], str) or not isinstance(value["value"], str):
        raise ValueError("artifact byte field is invalid")
    if value["encoding"] == "utf-8":
        return value["value"].encode("utf-8")
    if value["encoding"] == "base64":
        try:
            return base64.b64decode(value["value"], validate=True)
        except ValueError as error:
            raise ValueError("artifact base64 field is invalid") from error
    raise ValueError("artifact byte encoding is invalid")


def _redact_text(value: str, secrets: tuple[bytes, ...]) -> str:
    redacted = value
    for secret in secrets:
        if not secret:
            raise ValueError("redaction values must not be empty")
        try:
            token = secret.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if token:
            redacted = redacted.replace(token, "<redacted>")
    return redacted


def _redact_mutation(mutation: dict[str, object], secrets: tuple[bytes, ...]) -> dict[str, object]:
    # A mutation over a secret variable (e.g. api_key) stores the real value in
    # `original`; without this the secret would leak into the artifact verbatim.
    for field in ("original", "mutated"):
        value = mutation.get(field)
        if isinstance(value, str):
            mutation[field] = _redact_text(value, secrets)
    return mutation


def _redact_bytes(value: bytes | None, secrets: tuple[bytes, ...]) -> tuple[bytes | None, bool]:
    if value is None:
        return None, False
    redacted = value
    changed = False
    for secret in secrets:
        if not secret:
            raise ValueError("redaction values must not be empty")
        if secret in redacted:
            changed = True
            redacted = redacted.replace(secret, b"<redacted>")
    return redacted, changed


def _request_data(request: HttpRequest, secrets: tuple[bytes, ...], primary_api_key: bytes | None) -> tuple[dict[str, object], bool, bool]:
    url, url_redacted = _redact_bytes(request.url.encode("utf-8"), secrets)
    body, body_redacted = _redact_bytes(request.body, secrets)
    headers: list[list[str]] = []
    requires_api_key = False
    unreplayable_sensitive_header = False
    ordinary_header_redacted = False
    for name, value in request.headers:
        if name.lower() == "x-api-key":
            headers.append([name, "<redacted>"])
            if primary_api_key is not None and value.encode("utf-8") == primary_api_key:
                requires_api_key = True
            else:
                # Authenticated with a non-primary principal (a scoped or denied key)
                # that we do not record: mark the step unreplayable instead of
                # re-injecting the primary key and replaying as the wrong client.
                unreplayable_sensitive_header = True
        elif name.lower() in _SENSITIVE_HEADERS:
            headers.append([name, "<redacted>"])
            unreplayable_sensitive_header = True
        else:
            encoded, changed = _redact_bytes(value.encode("utf-8"), secrets)
            headers.append([name, encoded.decode("utf-8", "replace")])
            ordinary_header_redacted = ordinary_header_redacted or changed
    return {
        "method": request.method,
        "url": url.decode("utf-8", "replace"),
        "headers": headers,
        "body": _encode_bytes(body),
        "requires_api_key": requires_api_key,
    }, url_redacted or body_redacted or ordinary_header_redacted or unreplayable_sensitive_header, requires_api_key


def _response_data(result: HttpResult, secrets: tuple[bytes, ...]) -> dict[str, object]:
    body, _ = _redact_bytes(result.body, secrets)
    failure = result.failure
    headers: list[list[str]] = []
    for name, value in result.headers:
        if name.lower() in _SENSITIVE_HEADERS:
            headers.append([name, "<redacted>"])
        else:
            redacted, _ = _redact_bytes(value.encode("utf-8"), secrets)
            headers.append([name, redacted.decode("utf-8", "replace")])
    return {
        "status": result.status,
        "headers": headers,
        "body": _encode_bytes(body),
        "elapsed_ms": result.elapsed_ms,
        "transport_failure": None if failure is None else asdict(failure),
    }


def _step_data(step: StepExecution, secrets: tuple[bytes, ...], primary_api_key: bytes | None) -> tuple[dict[str, object], bool]:
    request, request_redacted, _ = _request_data(step.request, secrets, primary_api_key)
    captures = [
        [name, _redact_text(value, secrets) if isinstance(value, str) else value]
        for name, value in step.captures
    ]
    return {
        "name": step.name,
        "request": request,
        "response": _response_data(step.result, secrets),
        "captures": captures,
        "replayable": step.replayable and not request_redacted,
    }, request_redacted


def write_finding(
    output_dir: Path,
    *,
    project: str,
    run_seed: int,
    case: WorkflowCase,
    findings: tuple[Finding, ...],
    secrets: tuple[bytes, ...],
    primary_api_key: bytes | None = None,
) -> Path:
    if case.recipe is None:
        raise ValueError("finding case has no reproduction recipe")
    output_dir.mkdir(parents=True, exist_ok=True)
    steps: list[dict[str, object]] = []
    for step in case.steps:
        rendered, _ = _step_data(step, secrets, primary_api_key)
        steps.append(rendered)
    payload = {
        "artifact_version": ARTIFACT_VERSION,
        "nadir_version": __version__,
        "project": project,
        "target": case.target,
        "run_seed": run_seed,
        "iteration": case.iteration,
        "recipe": asdict(case.recipe),
        "mutation": None if case.mutation is None else _redact_mutation(asdict(case.mutation), secrets),
        "steps": steps,
        "findings": [asdict(finding) for finding in findings],
        "created_at": datetime.now(UTC).isoformat(),
    }
    rendered = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if any(secret and secret in rendered for secret in secrets):
        raise ValueError("artifact redaction failed")
    destination = output_dir / f"{case.target.replace('.', '-')}-{case.iteration}-{uuid4().hex}.json"
    temporary = destination.with_suffix(".tmp")
    temporary.write_bytes(rendered)
    temporary.replace(destination)
    return destination


def load_reproduction_recipe(path: Path) -> ReproductionRecipe:
    data = _load_artifact(path)
    if data.get("artifact_version") != ARTIFACT_VERSION:
        if data.get("artifact_version") == "nadir-finding-v3":
            raise ValueError("v3 artifacts support request replay only; use `nadir replay`")
        raise ValueError("finding artifact version is unsupported")
    project, target = data.get("project"), data.get("target")
    iteration, run_seed = data.get("iteration"), data.get("run_seed")
    recipe = data.get("recipe")
    findings = data.get("findings")
    if (
        not isinstance(project, str)
        or not project
        or not isinstance(target, str)
        or not target
        or type(iteration) is not int
        or iteration < 1
        or type(run_seed) is not int
        or not isinstance(recipe, dict)
        or set(recipe) != {"case_class", "case_seed", "mutation_name"}
        or not isinstance(findings, list)
        or not findings
    ):
        raise ValueError("finding artifact reproduction recipe is invalid")
    case_class = recipe["case_class"]
    case_seed = recipe["case_seed"]
    mutation_name = recipe["mutation_name"]
    if (
        case_class not in {"semantic", "structured", "raw", "deser"}
        or type(case_seed) is not int
        or case_seed < 0
        or (mutation_name is not None and (not isinstance(mutation_name, str) or not mutation_name))
        or (case_class != "semantic" and mutation_name is not None)
    ):
        raise ValueError("finding artifact reproduction recipe is invalid")
    codes: set[str] = set()
    for finding in findings:
        if not isinstance(finding, dict) or not isinstance(finding.get("code"), str) or not finding["code"]:
            raise ValueError("finding artifact findings are invalid")
        codes.add(finding["code"])
    return ReproductionRecipe(
        project,
        target,
        iteration,
        run_seed,
        CaseRecipe(case_class, case_seed, mutation_name),
        frozenset(codes),
    )


def load_replay_requests(path: Path, *, api_key: str | None = None) -> tuple[HttpRequest, ...]:
    data = _load_artifact(path)
    if data.get("artifact_version") not in REPLAY_ARTIFACT_VERSIONS:
        raise ValueError("finding artifact version is unsupported")
    steps = data.get("steps")
    if not isinstance(steps, list) or not steps:
        raise ValueError("finding artifact steps are invalid")
    requests: list[HttpRequest] = []
    for step in steps:
        if not isinstance(step, dict) or step.get("replayable") is not True:
            continue
        request = step.get("request")
        if not isinstance(request, dict) or set(request) != {"method", "url", "headers", "body", "requires_api_key"}:
            raise ValueError("finding artifact request is invalid")
        method, url, headers, requires_api_key = request["method"], request["url"], request["headers"], request["requires_api_key"]
        if not isinstance(method, str) or not re.fullmatch(r"[A-Z]+", method) or not isinstance(url, str):
            raise ValueError("finding artifact request is invalid")
        if not isinstance(headers, list) or not all(
            isinstance(item, list) and len(item) == 2 and all(isinstance(value, str) for value in item)
            for item in headers
        ):
            raise ValueError("finding artifact headers are invalid")
        if not isinstance(requires_api_key, bool):
            raise ValueError("finding artifact request is invalid")
        api_key_headers = [item for item in headers if item[0].lower() == "x-api-key"]
        if requires_api_key:
            if not isinstance(api_key, str) or not api_key:
                raise ValueError("authenticated replay requires NADIR_API_KEY")
            if len(api_key_headers) != 1 or api_key_headers[0][1] != "<redacted>":
                raise ValueError("finding artifact authenticated replay data is invalid")
            headers = [item for item in headers if item[0].lower() != "x-api-key"]
            headers.append(["X-API-Key", api_key])
        elif api_key_headers:
            raise ValueError("finding artifact request is invalid")
        if any(value == "<redacted>" for _, value in headers):
            raise ValueError("finding artifact cannot replay redacted request data")
        requests.append(HttpRequest(method, url, tuple((item[0], item[1]) for item in headers), _decode_bytes(request["body"])))
    if not requests:
        raise ValueError("finding artifact has no replayable public steps")
    return tuple(requests)
