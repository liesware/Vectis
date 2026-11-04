"""Private, synthetic preflights and operation-specific OpenAPI examples for ZAP."""

import copy
import hashlib
import json
import os
from pathlib import Path
import ssl
import urllib.error
import urllib.request


VALUES = (
    "0012345678901234",
    "0023456789012345",
    "0034567890123457",
)
PUBLIC = ("/healthz/startup", "/healthz/live", "/healthz/ready", "/keys", "/pub/{kid}")
POST = (
    "/symmetric/encrypt/{kid}", "/symmetric/encrypt/{kid}/subject/{subject}",
    "/symmetric/decrypt",
    "/fpe/encrypt/{kid}", "/fpe/encrypt/{kid}/subject/{subject}",
    "/fpe/encrypt/batch/{kid}", "/fpe/encrypt/batch/{kid}/subject/{subject}",
    "/fpe/decrypt", "/fpe/decrypt/batch",
    "/token/encode/{kid}", "/token/encode/{kid}/subject/{subject}",
    "/token/encode/batch/{kid}", "/token/encode/batch/{kid}/subject/{subject}",
    "/token/decode", "/token/decode/batch",
    "/token/deterministic/encode/{kid}",
    "/token/deterministic/encode/{kid}/subject/{subject}",
    "/token/deterministic/encode/batch/{kid}",
    "/token/deterministic/encode/batch/{kid}/subject/{subject}",
    "/token/deterministic/decode", "/token/deterministic/decode/batch",
    "/mac/{kid}", "/mac/batch/{kid}", "/mac/verify", "/mac/verify/batch",
    "/index/{kid}", "/index/batch/{kid}", "/index/verify", "/index/verify/batch",
    "/mask/{kid}", "/mask/batch/{kid}",
    "/commit/{kid}", "/commit/batch/{kid}", "/commit/verify", "/commit/verify/batch",
    "/shares/split/{kid}", "/shares/combine", "/sign/{kid}", "/sign/verification",
)
OPERATIONS = tuple((path, "get") for path in PUBLIC) + tuple((path, "post") for path in POST)


class FixtureError(ValueError):
    """An application-owned diagnostic that contains no response body or credential."""


def require(condition, message):
    if not condition:
        raise FixtureError(message)


def batch_items(prefix):
    return [{"ref": f"{prefix}-{i}", "plaintext": value}
            for i, value in enumerate(VALUES, 1)]


def checked_batch(output, inputs, kid, profile):
    require(output.get("kid") == kid and output.get("profile") == profile,
            "batch identity mismatch")
    items = output.get("items")
    require(isinstance(items, list) and len(items) == len(inputs) == 3,
            "expected exactly three batch items")
    require([item.get("ref") for item in items] == [item["ref"] for item in inputs],
            "batch order/ref mismatch")
    return items


class Client:
    def __init__(self, url, credential, certificate, kid, subject):
        self.url = url
        self.credential = credential
        self.kid = kid
        self.subject = subject
        # Trust only the disposable laboratory certificate; never use personal proxies.
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=certificate)),
        )

    def request(self, method, path, body=None):
        path = path.replace("{kid}", self.kid).replace("{subject}", self.subject)
        request = urllib.request.Request(
            self.url + path, method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={"X-API-Key": self.credential, "Content-Type": "application/json"},
        )
        try:
            response = self.opener.open(request, timeout=30)
        except urllib.error.HTTPError as error:
            response = error
        except (OSError, urllib.error.URLError):
            raise FixtureError(f"transport failure: {method} {path}") from None
        with response:
            status = response.code
            try:
                result = json.loads(response.read())
            except (ValueError, UnicodeError):
                raise FixtureError(f"invalid JSON: {method} {path} (HTTP {status})") from None
        return status, result


class Preflight:
    def __init__(self, client):
        self.client = client
        self.examples = {}
        self.completed = []
        self.succeeded = False

    def call(self, path, body=None, expected=None):
        method = "POST" if body is not None else "GET"
        require((path, method.lower()) in OPERATIONS, "operation outside ZAP scope")
        status, output = self.client.request(method, path, body)
        require(status == 200, f"preflight failed: {method} {path} (HTTP {status})")
        if expected:
            require(isinstance(output, dict) and all(output.get(k) == v for k, v in expected.items()),
                    f"preflight contract mismatch: {method} {path}")
        self.examples.setdefault((path, method.lower()), []).append(copy.deepcopy(body))
        self.completed.append({"method": method, "path": path, "status": status,
                               "subject_mode": "stored" if "/subject/" in path or
                               (body and body.get("subject")) else "none"})
        return output

    def symmetric(self, subject):
        suffix = "/subject/{subject}" if subject else ""
        text = "Synthetic ZAP symmetric payload"
        envelope = self.call("/symmetric/encrypt/{kid}" + suffix, {"plaintext": text},
                             {"kid": self.client.kid})
        require(envelope.get("subject") == subject, "symmetric subject mismatch")
        self.call("/symmetric/decrypt", envelope, {"plaintext": text})

    def fpe(self, subject):
        mode = "stored" if subject else "none"
        profile = f"zap-fpe-{mode}"
        suffix = "/subject/{subject}" if subject else ""
        identity = {"kid": self.client.kid, "profile": profile}
        if subject:
            identity["subject"] = subject
        original = {"ref": f"fpe-{mode}", "profile": profile, "plaintext": VALUES[0]}
        output = self.call("/fpe/encrypt/{kid}" + suffix, original, identity)
        self.call("/fpe/decrypt", {**identity, "ref": original["ref"],
                                  "ciphertext": output["ciphertext"], "tag": output["tag"]},
                  {"plaintext": original["plaintext"], "ref": original["ref"]})
        inputs = batch_items(f"fpe-{mode}")
        output = self.call("/fpe/encrypt/batch/{kid}" + suffix,
                           {"profile": profile, "items": inputs}, identity)
        encoded = checked_batch(output, inputs, self.client.kid, profile)
        items = [{"ref": item["ref"], "ciphertext": item["ciphertext"], "tag": item["tag"]}
                 for item in encoded]
        recovered = self.call("/fpe/decrypt/batch", {**identity, "items": items})
        require([item["plaintext"] for item in checked_batch(recovered, inputs, self.client.kid, profile)]
                == list(VALUES), "FPE batch round trip failed")

    def tokens(self, subject, deterministic):
        mode = "stored" if subject else "none"
        family = "det" if deterministic else "token"
        base = "/token/deterministic" if deterministic else "/token"
        profile = f"zap-{family}-{mode}"
        suffix = "/subject/{subject}" if subject else ""
        identity = {"kid": self.client.kid, "profile": profile}
        if subject:
            identity["subject"] = subject
        original = {"ref": f"{family}-{mode}", "profile": profile, "plaintext": VALUES[0]}
        output = self.call(base + "/encode/{kid}" + suffix, original, identity)
        self.call(base + "/decode", {**identity, "ref": original["ref"], "token": output["token"]},
                  {"plaintext": original["plaintext"], "ref": original["ref"]})
        inputs = batch_items(f"{family}-{mode}")
        output = self.call(base + "/encode/batch/{kid}" + suffix,
                           {"profile": profile, "items": inputs}, identity)
        encoded = checked_batch(output, inputs, self.client.kid, profile)
        items = [{"ref": item["ref"], "token": item["token"]} for item in encoded]
        recovered = self.call(base + "/decode/batch", {**identity, "items": items})
        require([item["plaintext"] for item in checked_batch(recovered, inputs, self.client.kid, profile)]
                == list(VALUES), "token batch round trip failed")

    def mac(self):
        profile = "pan-blind-index-v1"
        original = {"ref": "mac-single", "profile": profile, "plaintext": VALUES[0]}
        output = self.call("/mac/{kid}", original)
        self.call("/mac/verify", {**original, "kid": self.client.kid, "digest": output["digest"]},
                  {"valid": True})
        inputs = batch_items("mac")
        output = self.call("/mac/batch/{kid}", {"profile": profile, "items": inputs})
        encoded = checked_batch(output, inputs, self.client.kid, profile)
        items = [{**item, "digest": result["digest"]} for item, result in zip(inputs, encoded)]
        output = self.call("/mac/verify/batch", {"kid": self.client.kid, "profile": profile, "items": items})
        require(all(item["valid"] is True for item in checked_batch(output, inputs, self.client.kid, profile)),
                "MAC batch verification failed")

    def indexes(self):
        profile = "pan-index-v1"
        original = {"ref": "index-single", "profile": profile, "plaintext": VALUES[0]}
        output = self.call("/index/{kid}", original)
        self.call("/index/verify", {**original, "kid": self.client.kid},
                  {"matched": True, "index": output["index"]})
        inputs = batch_items("index")
        output = self.call("/index/batch/{kid}", {"profile": profile, "items": inputs})
        encoded = checked_batch(output, inputs, self.client.kid, profile)
        output = self.call("/index/verify/batch", {"kid": self.client.kid, "profile": profile, "items": inputs})
        verified = checked_batch(output, inputs, self.client.kid, profile)
        require(all(item["matched"] is True and item["index"] == original["index"]
                    for item, original in zip(verified, encoded)), "index batch verification failed")

    def masking(self):
        profile = "pan-display-v1"
        self.call("/mask/{kid}", {"ref": "mask-single", "profile": profile, "plaintext": VALUES[0]},
                  {"masked": "*" * (len(VALUES[0]) - 4) + VALUES[0][-4:]})
        inputs = batch_items("mask")
        output = self.call("/mask/batch/{kid}", {"profile": profile, "items": inputs})
        results = checked_batch(output, inputs, self.client.kid, profile)
        require([item["masked"] for item in results] == ["*" * 12 + text[-4:] for text in VALUES],
                "mask batch result mismatch")

    def commitments(self):
        profile = "pan-commitment-v1"
        original = {"ref": "commit-single", "profile": profile, "plaintext": VALUES[0]}
        output = self.call("/commit/{kid}", original)
        self.call("/commit/verify", {**original, "kid": self.client.kid,
                                    "opening": output["opening"], "commitment": output["commitment"]},
                  {"valid": True})
        inputs = batch_items("commit")
        output = self.call("/commit/batch/{kid}", {"profile": profile, "items": inputs})
        encoded = checked_batch(output, inputs, self.client.kid, profile)
        items = [{**item, "opening": result["opening"], "commitment": result["commitment"]}
                 for item, result in zip(inputs, encoded)]
        output = self.call("/commit/verify/batch", {"kid": self.client.kid, "profile": profile, "items": items})
        require(all(item["valid"] is True for item in checked_batch(output, inputs, self.client.kid, profile)),
                "commitment batch verification failed")

    def sharing_and_signing(self):
        profile = "customer-secret-3of5-v1"
        text = "Synthetic ZAP shared secret"
        output = self.call("/shares/split/{kid}", {"profile": profile, "plaintext": text},
                           {"kid": self.client.kid, "profile": profile, "threshold": 3})
        shares = output["shares"]
        require(len(shares) == len(set(shares)) == 5, "expected five unique shares")
        self.call("/shares/combine", {"kid": self.client.kid, "profile": profile, "shares": shares[:3]},
                  {"plaintext": text, "set_id": output["set_id"]})
        signature = self.call("/sign/{kid}", {
            "message_hash": {"alg": "SHA-256", "hex": hashlib.sha256(b"ZAP synthetic document").hexdigest()}})
        self.call("/sign/verification", signature,
                  {"valid": "ok", "status": {"eddsa": "ok", "ml-dsa": "ok"}})

    def run(self):
        for path, state in zip(PUBLIC[:3], ("started", "ok", "ready")):
            self.call(path, expected={"status": state})
        for path in PUBLIC[3:]:
            self.call(path)
        for subject in (None, self.client.subject):
            self.symmetric(subject)
            self.fpe(subject)
            self.tokens(subject, deterministic=False)
            self.tokens(subject, deterministic=True)
        self.mac()
        self.indexes()
        self.masking()
        self.commitments()
        self.sharing_and_signing()
        require(set(self.examples) == set(OPERATIONS), "missing operation fixtures")

    def sql_probes(self):
        evidence = []
        for path, field in (("/mac/verify", "digest"), ("/mac/verify/batch", "digest"),
                            ("/commit/verify", "commitment"), ("/commit/verify/batch", "commitment")):
            baseline = copy.deepcopy(self.examples[(path, "post")][0])
            for label, attack in (("baseline", None), ("and", "John Doe AND 1=1 -- "),
                                  ("or", "John Doe OR 1=1 -- ")):
                body = copy.deepcopy(baseline)
                if attack:
                    target = body["items"][0] if "items" in body else body
                    target[field] = attack
                status, output = self.client.request("POST", path, body)
                evidence.append({"path": path, "parameter": field, "case": label,
                                 "status": status, "response": output})
                if label == "baseline":
                    require(status == 200, f"SQL probe baseline failed: {path}")
        return evidence


def resolve(document, value):
    while isinstance(value, dict) and "$ref" in value:
        reference = value["$ref"]
        require(reference.startswith("#/"), "external OpenAPI reference is not supported")
        value = document
        for part in reference[2:].split("/"):
            value = value[part.replace("~1", "/").replace("~0", "~")]
    return copy.deepcopy(value)


def prepare_document(source, preflight):
    document = copy.deepcopy(source)
    require(all(key in document for key in ("openapi", "paths", "components")), "invalid OpenAPI")
    selected = {}
    for path, method in OPERATIONS:
        require(path in document["paths"] and method in document["paths"][path],
                f"OpenAPI operation missing: {method.upper()} {path}")
        require((path, method) in preflight.examples, f"fixture missing: {path}")
        original = document["paths"][path]
        operation = copy.deepcopy(original[method])
        parameters = {}
        for value in original.get("parameters", []) + operation.get("parameters", []):
            parameter = resolve(document, value)
            if parameter.get("in") == "path":
                require(parameter["name"] in ("kid", "subject"), "unexpected path parameter")
                example = getattr(preflight.client, parameter["name"])
                parameter.pop("examples", None)
                parameter["example"] = example
                parameter["schema"] = resolve(document, parameter.get("schema", {}))
                parameter["schema"]["example"] = example
                parameter["schema"]["default"] = example
            parameters[(parameter["name"], parameter["in"])] = parameter
        operation["parameters"] = list(parameters.values())
        if method == "post":
            body = resolve(document, operation["requestBody"])
            media = copy.deepcopy(body["content"]["application/json"])
            example = preflight.examples[(path, method)][0]
            media.pop("examples", None)
            media["example"] = copy.deepcopy(example)
            # Inline a private schema copy: component examples must not override the body.
            media["schema"] = {"type": "object", "example": copy.deepcopy(example),
                               "required": list(example),
                               "properties": example_properties(example)}
            body["content"] = {"application/json": media}
            operation["requestBody"] = body
        operation["servers"] = [{"url": preflight.client.url}]
        selected.setdefault(path, {})[method] = operation
    document["paths"] = selected
    document["servers"] = [{"url": preflight.client.url, "description": "Disposable ZAP target"}]
    document.pop("webhooks", None)
    return document


def example_properties(value):
    """Schema-level examples also support importers that ignore media examples."""
    def schema(item):
        if isinstance(item, dict):
            return {"type": "object", "example": item, "required": list(item),
                    "properties": example_properties(item)}
        if isinstance(item, list):
            return {"type": "array", "example": item, "minItems": len(item), "maxItems": len(item),
                    "items": schema(item[0]) if item else {}}
        kind = "boolean" if isinstance(item, bool) else "integer" if isinstance(item, int) else "string"
        return {"type": kind, "example": item, "default": item}
    return {key: schema(item) for key, item in value.items()}


def main():
    import yaml

    results = Path(os.environ["ZAP_RESULTS_DIR"])
    client = Client(os.environ["ZAP_OPENAPI_BASE_URL"], os.environ["ZAP_AUTH_HEADER_VALUE"],
                    os.environ["ZAP_CERTIFICATE"], os.environ["ZAP_OPENAPI_KID"],
                    os.environ["ZAP_SUBJECT"])
    preflight = Preflight(client)
    try:
        preflight.run()
        document = prepare_document(yaml.safe_load(Path(os.environ["ZAP_OPENAPI_INPUT"]).read_text()), preflight)
        (results / "sql-probes.json").write_text(json.dumps(preflight.sql_probes(), indent=2) + "\n")
        serialized = json.dumps(document, indent=2)
        require(client.credential not in serialized, "credential found in OpenAPI")
        (results / "openapi-zap.json").write_text(serialized + "\n")
        preflight.succeeded = True
    finally:
        (results / "preflight.json").write_text(json.dumps({
            "result": "passed" if preflight.succeeded else "failed",
            "completed": preflight.completed, "expected_operations": len(OPERATIONS),
            "coverage_note": "Preflights cover both subject modes. ZAP importer variant coverage requires traffic inspection.",
        }, indent=2) + "\n")
    print(f"[zap] preflight passed: {len(preflight.completed)} requests; {len(OPERATIONS)} scan operations")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError) as error:
        # Do not print HTTP bodies, credentials, or third-party transport exceptions.
        detail = str(error) if isinstance(error, FixtureError) else type(error).__name__
        print(f"[zap] fixture preparation failed: {detail}; review preflight.json")
        raise SystemExit(1) from None
