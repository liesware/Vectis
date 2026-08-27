import json


ALLOWED_STATUS = {200, 400, 401, 403, 404, 413}
FRAMEWORK_STATUS = ALLOWED_STATUS | {405, 415}
REMOTE_UNREACHABLE_MARKER = "final app can't be reached"


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
