#!/usr/bin/env python3
import argparse
import atexit
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from test_config import require_apikey
from http_support import (
    DEFAULT_BASE_URL,
    DEFAULT_FINAL_APP_ADDR,
    KEY_CASES,
    Client,
    WorkflowError,
    backup_config_file,
    backup_config_sign_file,
    create_key,
    host_from_base_url,
    reload_config,
    restore_config_file,
    restore_config_sign_file,
    start_final_app,
    write_test_remote_routes,
    write_test_routes,
)


DEFAULT_MAX_EXAMPLES = 25
DEFAULT_SCHEMA = Path(__file__).resolve().parents[1] / "doc" / "openapi.yaml"

SAFE_PATHS = [
    "/healthz/startup",
    "/healthz/live",
    "/healthz/ready",
    "/keys",
    "/metrics",
    "/routes",
    "/remote-routes",
    "/permissions",
]

PREPARED_PATHS = [
    "/healthz/startup",
    "/healthz/live",
    "/healthz/ready",
    "/keys",
    "/keys/properties",
    "/keys/properties/{kid}",
    "/pub/{kid}",
    "/self-test/init",
    "/self-test/keys/{kid}",
    "/routes",
    "/remote-routes",
    "/permissions",
    "/metrics",
    "/keys/reload",
    "/config/reload",
    "/sign/{kid}",
]


def build_command(args, apikey, schema_path, profile):
    command = [
        "uv",
        "run",
        "--group",
        "fuzz",
        "schemathesis",
        "run",
        str(schema_path),
        "--url",
        args.base_url.rstrip("/"),
        "--header",
        f"X-API-Key: {apikey}",
        "--max-examples",
        str(args.max_examples),
        "--continue-on-failure",
        "--output-sanitize",
        "true",
        "--output-truncate",
        "true",
    ]

    if args.include_path:
        for include_path in args.include_path:
            command.extend(["--include-path", include_path])
    elif profile == "safe":
        for safe_path in SAFE_PATHS:
            command.extend(["--include-path", safe_path])
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            command.extend(["--exclude-method", method])
    elif profile == "prepared":
        for prepared_path in PREPARED_PATHS:
            command.extend(["--include-path", prepared_path])

    for exclude_path in args.exclude_path:
        command.extend(["--exclude-path", exclude_path])

    return command


def sanitize(text, secrets):
    sanitized = text
    for secret in secrets:
        if secret:
            sanitized = sanitized.replace(secret, "<redacted>")
    return sanitized


def create_schema_with_kid_example(schema_path, kid):
    text = schema_path.read_text(encoding="utf-8")
    placeholder = (
        "example: f55f086e75b58ac4dfaffd3e75c90d25719281df90e87880145fb9f2e32f2eed"
    )
    if placeholder not in text:
        raise WorkflowError("OpenAPI Kid example placeholder was not found")

    text = text.replace(
        placeholder,
        f"example: {kid}",
        1,
    )
    temp = tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        suffix=".yaml",
        prefix="vectis-openapi-",
        delete=False,
    )
    with temp:
        temp.write(text)

    temp_path = Path(temp.name)
    atexit.register(unlink_temp_file, temp_path)
    return temp_path


def unlink_temp_file(path):
    try:
        path.unlink()
    except FileNotFoundError:
        pass


def prepare_real_data(args, apikey, profile):
    client = Client(args.base_url, apikey)

    config_backup = backup_config_file()
    config_sign_backup = backup_config_sign_file()
    atexit.register(restore_config_sign_file, config_sign_backup)
    atexit.register(restore_config_file, config_backup)

    created = [create_key(client, case) for case in KEY_CASES]
    recipient_host = host_from_base_url(args.base_url)
    write_test_routes(created, args.final_app_addr)
    write_test_remote_routes(client, created, recipient_host)
    reload_config(client)

    final_app = None
    if profile == "all":
        final_app = start_final_app(args.final_app_addr)
        atexit.register(final_app.shutdown)

    schema_path = create_schema_with_kid_example(args.schema, created[0])
    print(f"Schemathesis prepared keys: {len(created)}")
    return schema_path


def run_schemathesis(args, apikey, schema_path, profile):
    command = build_command(args, apikey, schema_path, profile)
    env = os.environ.copy()
    env.setdefault("PYTHONUTF8", "1")

    result = subprocess.run(command, capture_output=True, text=True, env=env)
    if result.stdout:
        print(sanitize(result.stdout, [apikey]), end="")
    if result.stderr:
        print(sanitize(result.stderr, [apikey]), end="", file=sys.stderr)

    return result.returncode


def main():
    parser = argparse.ArgumentParser(
        description="Run Schemathesis against the Vectis OpenAPI contract."
    )
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--apikey")
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    parser.add_argument("--max-examples", type=int, default=DEFAULT_MAX_EXAMPLES)
    parser.add_argument(
        "--profile",
        choices=("safe", "prepared", "all"),
        default="safe",
        help="safe runs read-only contract checks, prepared creates real Vectis data, all runs the full contract against prepared data.",
    )
    parser.add_argument("--final-app-addr", default=DEFAULT_FINAL_APP_ADDR)
    parser.add_argument("--include-path", action="append", default=[])
    parser.add_argument("--exclude-path", action="append", default=[])
    parser.add_argument(
        "--include-stateful",
        action="store_true",
        help="Compatibility alias for --profile all.",
    )
    args = parser.parse_args()

    if not args.schema.is_file():
        print(f"OpenAPI schema not found: {args.schema}", file=sys.stderr)
        print("SUMMARY schemathesis passed=0 failed=1")
        return 1
    if args.max_examples < 1:
        print("--max-examples must be greater than zero", file=sys.stderr)
        print("SUMMARY schemathesis passed=0 failed=1")
        return 1

    apikey = require_apikey(args.apikey)
    profile = "all" if args.include_stateful else args.profile
    schema_path = args.schema

    try:
        if profile in ("prepared", "all"):
            schema_path = prepare_real_data(args, apikey, profile)
    except WorkflowError as err:
        print(sanitize(f"Schemathesis preparation failed: {err}", [apikey]), file=sys.stderr)
        print("SUMMARY schemathesis passed=0 failed=1")
        return 1

    returncode = run_schemathesis(args, apikey, schema_path, profile)
    if returncode == 0:
        print("SUMMARY schemathesis passed=1 failed=0")
        return 0

    print("SUMMARY schemathesis passed=0 failed=1")
    return returncode


if __name__ == "__main__":
    sys.exit(main())
