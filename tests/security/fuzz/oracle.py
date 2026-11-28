import json


ALLOWED_STATUS = {200, 400, 401, 403, 404, 413}
FRAMEWORK_STATUS = ALLOWED_STATUS | {405, 415}
REMOTE_UNREACHABLE_MARKER = "final app can't be reached"
MAX_RESPONSE_DURATION_MS = 2_000
CONFIG_FILE_MAX_SIZES = {"config.json": 8 * 1024 * 1024, "config_sign.json": 1024 * 1024}


def _parse(body):
    try:
        return json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return None


def oracle(status, body, apikey, unseal, allowed_status, allow_ru, require_json_error=True):
    findings = []
    if status == 0:
        findings.append("connection failed (possible crash or hang)")
        return findings
    if status not in allowed_status:
        known_unreachable = (
            status == 500
            and allow_ru
            and REMOTE_UNREACHABLE_MARKER in body
        )
        if not known_unreachable:
            findings.append(f"unexpected status {status}")
    if require_json_error and 400 <= status < 500:
        parsed = _parse(body)
        if isinstance(parsed, dict):
            extra = sorted(set(parsed.keys()) - {"error"})
            if extra:
                findings.append(f"4xx error body has extra keys: {extra}")
        else:
            findings.append("4xx body is not a JSON error object")
    for name, secret in (("apikey", apikey), ("unseal-key", unseal)):
        if secret and secret in body:
            findings.append(f"possible {name} leak in response body")
    return findings


def config_read_failure_expected(mutated_file, content):
    if len(content) > CONFIG_FILE_MAX_SIZES[mutated_file]:
        return True
    try:
        content.decode("utf-8")
    except UnicodeDecodeError:
        return True
    return False


def config_oracle(mutated_file, content, status, body, apikey, unseal):
    read_failure = config_read_failure_expected(mutated_file, content)
    allowed = {500} if read_failure else ALLOWED_STATUS
    findings = oracle(status, body, apikey, unseal, allowed, False)
    if read_failure and _parse(body) != {"error": "internal server error"}:
        findings.append("SEMANTIC: config read failure must return a generic JSON error")
    return findings


def slow_response_findings(responses):
    findings = []
    for response in responses:
        if response.status != 0 and response.duration_ms > MAX_RESPONSE_DURATION_MS:
            findings.append(
                f"slow response: HTTP {response.status} took {response.duration_ms:.0f}ms"
            )
    return findings
