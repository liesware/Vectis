#!/usr/bin/env python3
import argparse
import http.server
import json
import os
import sys
import urllib.error
import urllib.request


class FinalAppHandler(http.server.BaseHTTPRequestHandler):
    expected_path = "/message"
    vectis_url = "http://127.0.0.1:3000"
    apikey = ""

    def do_POST(self):
        if self.path != self.expected_path:
            self.send_json(404, {"error": "not found"})
            return

        content_length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(content_length)

        try:
            payload = json.loads(body.decode("utf-8"))
        except json.JSONDecodeError as err:
            self.send_json(400, {"error": f"invalid json: {err}"})
            return

        print("\nFinal app delivery received:")
        print(json.dumps(payload, indent=2, sort_keys=True))
        sys.stdout.flush()

        try:
            decrypted = self.decrypt_message(payload)
        except RuntimeError as err:
            print(f"Decrypt failed: {err}", file=sys.stderr)
            sys.stderr.flush()
            self.send_json(502, {"error": str(err)})
            return

        print("Plaintext:")
        print(json.dumps(decrypted, indent=2, sort_keys=True))
        sys.stdout.flush()

        self.send_json(200, {"status": "ok", "plaintext": decrypted.get("plaintext")})

    def decrypt_message(self, payload):
        body = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            f"{self.vectis_url}/message/decrypt",
            data=body,
            headers={
                "X-API-Key": self.apikey,
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                response_body = response.read().decode("utf-8")
        except urllib.error.HTTPError as err:
            response_body = err.read().decode("utf-8", errors="replace")
            raise RuntimeError(
                f"POST /message/decrypt failed with {err.code}: {response_body}"
            ) from err
        except urllib.error.URLError as err:
            raise RuntimeError(f"POST /message/decrypt failed: {err}") from err

        try:
            return json.loads(response_body)
        except json.JSONDecodeError as err:
            raise RuntimeError(
                f"POST /message/decrypt returned invalid JSON: {response_body}"
            ) from err

    def send_json(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        print(f"{self.address_string()} - {fmt % args}")


def parse_addr(addr):
    if ":" not in addr:
        raise ValueError("addr must be host:port")

    host, port = addr.rsplit(":", 1)
    if not host:
        raise ValueError("host must not be empty")

    return host, int(port)


def main():
    parser = argparse.ArgumentParser(description="Receive Vectis final app deliveries.")
    parser.add_argument("--addr", default="127.0.0.1:4999")
    parser.add_argument("--path", default="/message")
    parser.add_argument("--vectis-url", default="http://127.0.0.1:3000")
    parser.add_argument("--apikey")
    args = parser.parse_args()

    host, port = parse_addr(args.addr)
    FinalAppHandler.expected_path = args.path
    FinalAppHandler.vectis_url = args.vectis_url.rstrip("/")
    FinalAppHandler.apikey = args.apikey or os.environ.get("VECTIS_APIKEY", "").strip()
    if not FinalAppHandler.apikey:
        raise RuntimeError("VECTIS_APIKEY must be provided with --apikey or environment")

    server = http.server.ThreadingHTTPServer((host, port), FinalAppHandler)
    print(f"Final app server listening on http://{args.addr}{args.path}")
    print(f"Decrypt endpoint: {FinalAppHandler.vectis_url}/message/decrypt")
    print("Press Ctrl+C to stop.")
    sys.stdout.flush()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nFinal app server stopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
