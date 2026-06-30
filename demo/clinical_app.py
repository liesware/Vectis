#!/usr/bin/env python3
import json
import os
import pathlib
import sys
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


print_lock = threading.Lock()


def load_env(path):
    values = {}
    with open(path, "r", encoding="utf-8") as env_file:
        for line in env_file:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
                value = value[1:-1]
            values[key.strip()] = value
    return values


def required(config, key):
    value = config.get(key)
    if not value:
        raise SystemExit(f"{key} is required")
    return value


def parse_addr(value):
    if ":" not in value:
        raise SystemExit(f"{value} must be host:port")
    host, port_text = value.rsplit(":", 1)
    if not host:
        raise SystemExit("host must not be empty")
    try:
        port = int(port_text)
    except ValueError as err:
        raise SystemExit(f"port must be an integer: {port_text}") from err
    return host, port


def request_json(method, url, apikey=None, payload=None):
    data = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if apikey:
        headers["X-API-Key"] = apikey

    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            body = response.read().decode("utf-8")
    except urllib.error.HTTPError as err:
        body = err.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"{method} {url} failed with {err.code}: {body}") from err
    except urllib.error.URLError as err:
        raise RuntimeError(f"{method} {url} failed: {err}") from err

    if not body:
        return {}

    try:
        return json.loads(body)
    except json.JSONDecodeError as err:
        raise RuntimeError(f"{method} {url} returned invalid JSON: {body}") from err


def load_clinical_file(path_text):
    path = pathlib.Path(path_text).expanduser()
    if not path.is_absolute():
        path = pathlib.Path.cwd() / path
    if not path.exists():
        raise ValueError(f"file does not exist: {path}")
    if not path.is_file():
        raise ValueError(f"path is not a file: {path}")

    try:
        with open(path, "r", encoding="utf-8") as clinical_file:
            payload = json.load(clinical_file)
    except json.JSONDecodeError as err:
        raise ValueError(f"file must contain valid JSON: {err}") from err

    return path, payload


def decode_plaintext(value):
    if not isinstance(value, str):
        return value
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value


def patient_label(payload):
    if not isinstance(payload, dict):
        return "unknown patient"

    records = payload.get("records")
    if isinstance(records, dict):
        username = records.get("username")
        personal = records.get("Personal Information")
        full_name = personal.get("Full Name") if isinstance(personal, dict) else None
        return username or full_name or "unknown patient"

    return payload.get("patient") or payload.get("name") or "unknown patient"


class ClinicalContext:
    def __init__(self, config):
        self.app_name = required(config, "APP_NAME")
        self.bind_addr = required(config, "APP_BIND_ADDR")
        self.vectis_url = required(config, "VECTIS_URL").rstrip("/")
        self.local_kid = required(config, "LOCAL_KID")
        self.remote_app_name = config.get("REMOTE_APP_NAME", "remote clinical site")
        self.remote_vectis_host = required(config, "REMOTE_VECTIS_HOST")
        self.remote_kid = required(config, "REMOTE_KID")
        self.apikey = required(config, "VECTIS_APIKEY")

    def decrypt_delivery(self, payload):
        return request_json(
            "POST",
            f"{self.vectis_url}/message/decrypt",
            self.apikey,
            payload,
        )

    def send_clinical_record(self, clinical_record):
        return request_json(
            "POST",
            f"{self.vectis_url}/message/{self.local_kid}",
            self.apikey,
            {
                "recipient_kid": self.remote_kid,
                "message": json.dumps(clinical_record, sort_keys=True),
            },
        )


class ClinicalHandler(BaseHTTPRequestHandler):
    context = None

    def do_POST(self):
        if self.path != "/message":
            self.send_json(404, {"error": "not found"})
            return

        content_length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(content_length)

        try:
            delivery = json.loads(body.decode("utf-8"))
        except json.JSONDecodeError as err:
            self.send_json(400, {"error": f"invalid json: {err}"})
            return

        safe_print("\nFinal app delivery received:")
        safe_print(json.dumps(delivery, indent=2, sort_keys=True))
        safe_print("\nCalling local Vectis /message/decrypt...")

        try:
            decrypted = self.context.decrypt_delivery(delivery)
        except RuntimeError as err:
            safe_print(f"\n{self.context.app_name} decrypt error: {err}")
            self.send_json(502, {"error": str(err)})
            return

        plaintext = decode_plaintext(decrypted.get("plaintext"))
        sender = delivery.get("sender_host") or delivery.get("sender_kid") or "remote"

        safe_print(f"\nClinical record received from {sender}")
        safe_print(f"Patient: {patient_label(plaintext)}")
        safe_print("Decrypted clinical payload:")
        safe_print(json.dumps(plaintext, indent=2, sort_keys=True))

        self.send_json(200, {"status": "ok", "patient": patient_label(plaintext)})

    def send_json(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        return


def safe_print(message):
    with print_lock:
        print(message, flush=True)


def input_loop(context):
    while True:
        try:
            path_text = input(f"{context.app_name} file: ").strip()
        except EOFError:
            os._exit(0)

        if not path_text:
            continue
        if path_text in ("/quit", "/exit"):
            os._exit(0)

        try:
            path, clinical_record = load_clinical_file(path_text)
        except ValueError as err:
            safe_print(f"{context.app_name} input error: {err}")
            continue

        safe_print(f"Loaded clinical file: {path}")
        safe_print(f"Patient: {patient_label(clinical_record)}")

        try:
            response = context.send_clinical_record(clinical_record)
        except RuntimeError as err:
            safe_print(f"{context.app_name} send error: {err}")
            continue

        safe_print(f"Sent clinical record to {context.remote_app_name}")
        safe_print(json.dumps(response, indent=2, sort_keys=True))


def print_startup_banner(context):
    safe_print(f"{context.app_name} clinical app")
    safe_print("Purpose: send and receive JSON clinical records through local Vectis.")
    safe_print(
        "Flow: file input -> Vectis protected message -> remote clinic -> local decrypt."
    )
    safe_print(f"Listening: http://{context.bind_addr}/message")
    safe_print(f"Vectis: {context.vectis_url}")
    safe_print(f"Remote clinic: {context.remote_app_name} via {context.remote_vectis_host}")
    safe_print("Input: enter a JSON clinical record path, for example ../personaldata.json")
    safe_print("Type /quit to exit.")


def main():
    env_path = sys.argv[1] if len(sys.argv) > 1 else "app.env"
    context = ClinicalContext(load_env(env_path))
    host, port = parse_addr(context.bind_addr)

    ClinicalHandler.context = context
    server = ThreadingHTTPServer((host, port), ClinicalHandler)

    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()

    print_startup_banner(context)

    try:
        input_loop(context)
    except KeyboardInterrupt:
        safe_print("\nstopped")
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
