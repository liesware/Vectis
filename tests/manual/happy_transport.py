"""HTTP exchange display and small assertions for the manual walkthrough."""

import json
import re
import time
import urllib.error
import urllib.request


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def expect_fields(**expected):
    def check(payload):
        require(isinstance(payload, dict), "response must be a JSON object")
        for key, value in expected.items():
            require(payload.get(key) == value, f"unexpected response field: {key}")
    return check


def three_items(items):
    require(len(items) == 3, "batch requires exactly three items")
    require(len({item['ref'] for item in items}) == 3, "batch refs must be distinct")
    return items


def batch_result(payload, inputs, kid, profile):
    expect_fields(kid=kid, profile=profile)(payload)
    items = payload.get("items")
    require(isinstance(items, list) and len(items) == 3, "response must contain three items")
    require([item.get("ref") for item in items] == [item["ref"] for item in inputs],
            "batch response refs/order mismatch")
    return items


class Transcript:
    def __init__(self, stream, secrets=()):
        self.stream = stream
        self.secrets = list(secrets)

    def redact(self, text):
        for secret in sorted(filter(None, self.secrets), key=len, reverse=True):
            text = text.replace(secret, "[REDACTED]")
        return text

    def write(self, text):
        print(self.redact(text), file=self.stream, flush=True)

    def block(self, value, language="json"):
        text = json.dumps(value, indent=2, ensure_ascii=False) if language == "json" else value
        # A fence longer than any run in the data keeps remote bodies as content.
        fence = "`" * max(3, max((len(run) for run in re.findall(r'`+', text)), default=0) + 1)
        return f"{fence}{language}\n{text}\n{fence}"


class Client:
    def __init__(self, base_url, api_key, transcript):
        self.base_url = base_url
        self.api_key = api_key
        self.out = transcript
        self.out.secrets.append(api_key)
        self.completed = 0
        self.current = "preparation"
        self.visited = set()

    def call(self, method, path, body=None, *, status=200, check=None):
        self.current = f"{method} {path}"
        if path.endswith("/batch") or "/batch/" in path:
            three_items(body["items"])
        headers = {"X-API-Key": self.api_key}
        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body).encode()
        self.out.write(f"\n### {self.current}\n\nRequest:\n" + self.out.block(
            method + " " + path + "\n" + "\n".join(f"{k}: {v}" for k, v in headers.items()), "http"))
        self.out.write(self.out.block(body) if body is not None else "Body: (none)")
        started = time.monotonic()
        request = urllib.request.Request(self.base_url + path, data=data, headers=headers, method=method)
        try:
            # Do not follow redirects or inherit a proxy for the local laboratory.
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
            try:
                response = opener.open(request, timeout=40)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                received = response.status
                raw = response.read().decode("utf-8", errors="replace")
            elapsed = (time.monotonic() - started) * 1000
            try:
                payload = json.loads(raw) if raw else None
            except ValueError:
                payload = raw
            self.out.write(f"\nResponse: HTTP {received} | {elapsed:.1f} ms\n" + (
                self.out.block(payload) if not isinstance(payload, str) else self.out.block(payload, "text")))
            require(received == status, f"expected HTTP {status}, received {received}")
            if check is not None:
                check(payload)
        except Exception as error:
            self.out.write(f"\nResult: FAILED ({error})")
            raise
        self.completed += 1
        self.visited.add((method, path))
        self.out.write("\nResult: OK")
        return payload


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        return None
