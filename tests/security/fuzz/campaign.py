"""Seed isolation and aggregate measurements, without retaining request data."""

import hashlib
import json
import random
import secrets
from pathlib import Path


SEED_DERIVATION = "http-fuzz-target-seed-v1"


def resolve_seed(seed, random_seed):
    return secrets.randbits(64) if random_seed else (1337 if seed is None else seed)


def target_seed(seed, name):
    encoded = json.dumps([SEED_DERIVATION, seed, name], separators=(",", ":"))
    return int.from_bytes(hashlib.sha256(encoded.encode("utf-8")).digest(), "big")


def target_rng(seed, name):
    return random.Random(target_seed(seed, name))


def select_targets(targets, name, mutation_only):
    selected = [target for target in targets if name in ("all", target["name"])]
    if mutation_only:
        selected = [target for target in selected if target["kind"] == "mutation"]
    if not selected:
        raise ValueError("selected target is not available in mutation-only mode")
    return selected


class TargetMetrics:
    def __init__(self, target, seed):
        self.name = target["name"]
        self.kind = target["kind"]
        self.seed = target_seed(seed, self.name)
        self.passed = 0
        self.failed = 0
        self.primary_statuses = {}
        self._fingerprints = set()
        self._inputs = 0

    def record_input(self, method, path, body=b"", *, invalid_headers=None, file=None):
        # Length-prefix each component to avoid ambiguous concatenations. Valid
        # auth headers and response material never enter this measurement.
        digest = hashlib.sha256()
        for value in (method, path, body, invalid_headers or {}, file or ""):
            if not isinstance(value, bytes):
                value = json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")
            digest.update(len(value).to_bytes(8, "big"))
            digest.update(value)
        self._fingerprints.add(digest.digest())
        self._inputs += 1

    def record_result(self, status, failed):
        key = str(status)
        self.primary_statuses[key] = self.primary_statuses.get(key, 0) + 1
        self.failed += bool(failed)
        self.passed += not failed

    def summary(self, completed):
        result = {
            "target": self.name,
            "kind": self.kind,
            "target_seed": self.seed,
            "completed": completed,
            "cases": self.passed + self.failed,
            "passed": self.passed,
            "failed": self.failed,
            "primary_statuses": dict(sorted(self.primary_statuses.items())),
        }
        if self.kind == "mutation":
            result.update(
                generated_inputs=self._inputs,
                unique_inputs=len(self._fingerprints),
                duplicate_inputs=self._inputs - len(self._fingerprints),
            )
        return result


class RunSummary:
    def __init__(self, args):
        self.config = {
            "seed": args.seed,
            "seed_mode": "random" if args.random_seed else "explicit/default",
            "seed_derivation": SEED_DERIVATION,
            "iterations": args.iterations,
            "target": args.target,
            "mutation_only": args.mutation_only,
            "liveness_every": args.liveness_every,
            "progress_every": args.progress_every,
        }
        self.targets = []
        self.result = "error"

    def payload(self):
        return {
            "format": "http-fuzz-summary-v1",
            "config": self.config,
            "result": self.result,
            "totals": {
                key: sum(target[key] for target in self.targets)
                for key in ("cases", "passed", "failed")
            },
            "targets": self.targets,
        }

    def write(self, path):
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(self.payload(), indent=2) + "\n", encoding="utf-8")
