#!/usr/bin/env python3
"""Opt-in live smoke test for a Vectis Cloudflare time attestation."""

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "integration"))

from support.test_config import require_apikey


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser(description="Run a live Cloudflare time-attestation smoke test.")
    parser.add_argument("--base-url", default="http://127.0.0.1:3000")
    parser.add_argument("--apikey")
    args = parser.parse_args()

    if os.environ.get("VECTIS_TIME_ATTESTATION_LIVE") != "1":
        raise RuntimeError("set VECTIS_TIME_ATTESTATION_LIVE=1 to run the live time-attestation smoke test")

    request = urllib.request.Request(
        f"{args.base_url.rstrip('/')}/time/attest",
        headers={"X-API-Key": require_apikey(args.apikey)},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            status = response.status
            body = response.read().decode("utf-8")
    except urllib.error.HTTPError as err:
        raise RuntimeError(f"POST /time/attest failed with HTTP {err.code}") from err
    except urllib.error.URLError as err:
        raise RuntimeError("POST /time/attest could not reach Vectis") from err

    try:
        payload = json.loads(body)
    except json.JSONDecodeError as err:
        raise RuntimeError("POST /time/attest returned invalid JSON") from err

    require(status == 200, "POST /time/attest must return HTTP 200")
    require(payload.get("version") == "vectis-time-attestation-v1", "unexpected attestation version")
    require(payload.get("provider") == "cloudflare", "unexpected time provider")
    sources = payload.get("sources")
    clock = payload.get("server_clock")
    require(isinstance(sources, dict) and set(sources) == {"system", "nts", "roughtime"}, "invalid time source shape")
    system = sources["system"]
    nts = sources["nts"]
    roughtime = sources["roughtime"]
    require(
        isinstance(system, dict) and isinstance(system.get("unix_us"), str) and system["unix_us"].isdigit(),
        "invalid system time shape",
    )
    require(
        isinstance(nts, dict)
        and nts.get("authenticated") is True
        and isinstance(nts.get("server"), str)
        and isinstance(nts.get("offset_us"), str)
        and isinstance(nts.get("round_trip_us"), str),
        "invalid authenticated NTS source shape",
    )
    require(
        isinstance(roughtime, dict)
        and roughtime.get("verified") is True
        and all(
            isinstance(roughtime.get(field), str) and roughtime[field]
            for field in ("server", "midpoint_us", "radius_us", "earliest_us", "latest_us", "nonce_b64", "response_b64")
        ),
        "invalid verified Roughtime source shape",
    )
    require(
        isinstance(clock, dict)
        and isinstance(clock.get("acceptable"), bool)
        and isinstance(clock.get("max_allowed_skew_ms"), int)
        and isinstance(clock.get("local_vs_nts_skew_ms"), (int, float))
        and isinstance(clock.get("local_within_roughtime_interval"), bool)
        and isinstance(clock.get("nts_within_roughtime_interval"), bool),
        "invalid server clock shape",
    )
    print(f"time attestation smoke: OK acceptable={clock['acceptable']}")


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as err:
        print(f"ERROR: {err}", file=sys.stderr)
        sys.exit(1)
