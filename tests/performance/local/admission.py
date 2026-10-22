"""Only public admission settings and aggregate queue metrics cross this boundary."""

import json
import math
import re

SETTINGS = ("VECTIS_MAX_CONCURRENT_CRYPTO", "VECTIS_MAX_QUEUED_CRYPTO",
            "VECTIS_CRYPTO_QUEUE_TIMEOUT_MS")
FIELDS = ("max_concurrent_crypto", "max_queued_crypto", "crypto_queue_timeout_ms")


def overrides(environment):
    # Preserve even empty values: Rust remains the authority for validation.
    return {key: environment[key] for key in SETTINGS if key in environment}


def effective_settings(log_directory):
    for path in sorted(log_directory.glob("vectis.log*")):
        with path.open() as stream:
            for line in stream:
                try:
                    fields = json.loads(line).get("fields", {})
                except (ValueError, AttributeError):
                    continue
                if fields.get("message") == "crypto admission configured":
                    if all(type(fields.get(key)) is int for key in FIELDS):
                        return {key: fields[key] for key in FIELDS}
    raise RuntimeError("effective crypto admission settings unavailable")


def queue_snapshot(text):
    result = {"pending": 0, "wait_count": 0, "wait_sum": 0, "wait_buckets": {},
              "rejections": {"full": 0, "timeout": 0}}
    for line in text.splitlines():
        match = re.fullmatch(r'(vectis_crypto_\w+)(?:\{([^}]*)\})?\s+([^\s]+)', line)
        if not match:
            continue
        name, labels, raw = match.groups()
        if name not in ("vectis_crypto_queue_pending", "vectis_crypto_queue_wait_seconds_count",
                        "vectis_crypto_queue_wait_seconds_sum", "vectis_crypto_queue_wait_seconds_bucket",
                        "vectis_crypto_rejections_total"):
            continue
        value = float(raw)
        if not math.isfinite(value) or value < 0:
            raise ValueError("invalid crypto queue metric")
        if not labels:
            field = {"vectis_crypto_queue_pending": "pending",
                     "vectis_crypto_queue_wait_seconds_count": "wait_count",
                     "vectis_crypto_queue_wait_seconds_sum": "wait_sum"}.get(name)
            if field:
                result[field] = value
        elif name == "vectis_crypto_rejections_total" and labels in ('reason="full"', 'reason="timeout"'):
            result["rejections"][labels.split('"')[1]] = value
        elif name == "vectis_crypto_queue_wait_seconds_bucket":
            bucket = re.fullmatch(r'le="([0-9.]+|\+Inf)"', labels)
            if bucket:
                result["wait_buckets"][bucket[1]] = value
    return result


def queue_delta(before, after):
    def delta(old, new):
        if new < old:
            raise ValueError("crypto queue metrics reset during measurement")
        return new - old
    count = delta(before["wait_count"], after["wait_count"])
    total = delta(before["wait_sum"], after["wait_sum"])
    return {"pending_final": after["pending"], "wait_count": count, "wait_seconds": total,
            "wait_mean_seconds": total / count if count else None,
            "wait_buckets": {bound: delta(before["wait_buckets"].get(bound, 0), value)
                             for bound, value in after["wait_buckets"].items()},
            "rejections": {reason: delta(before["rejections"][reason], after["rejections"][reason])
                           for reason in ("full", "timeout")}}
