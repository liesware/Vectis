"""Coordinate campaigns; laboratory details and request contracts live elsewhere."""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import sys
import time
import uuid

from catalog import PROFILE_SPECS, PROFILES
from laboratory import Laboratory
from options import parse_options
from processes import command
from resources import ResourceSampler

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def clean_environment():
    return {k: v for k, v in os.environ.items() if not k.startswith(("VECTIS_", "K6_"))}


def run_measured_k6(environment):
    # Preserve isatty(): piping/teeing the measured child hides k6's native UI.
    return command(["k6", "run", str(HERE.parent / "k6.js")], env=environment, check=False)


def print_resources(record):
    resources = record.get("resources", {})
    if resources.get("samples"):
        print(f"Vectis resources: RSS peak={resources['rss_peak_bytes'] / 1024**2:.2f} MiB | "
              f"RSS delta={resources['rss_delta_bytes'] / 1024**2:+.2f} MiB | "
              f"CPU={resources['cpu_seconds_delta']:.2f}s | "
              f"CPU peak={resources['cpu_percent_peak_one_core']:.1f}% (one core=100%)", flush=True)


def run_profile(args, index, binary, run_id, environment, destination=None, position=1, total=1):
    spec = PROFILE_SPECS[index]
    profile, slug = spec["name"], spec["slug"]
    result = destination / slug if destination else None
    site = HERE / "site" / run_id / slug
    lab = Laboratory(site, binary, environment, profile)
    record = {"crypto_profile": profile, "status": "preparing", "laboratory": str(site),
              "warmup": "one complete selected iteration, excluded", "k6_exit": None, "audit_exit": None}
    manifest = result / "manifest.json" if result else None
    variants = "all" if args.target == "all" else str(args.subject).lower()
    auth = "all FPE variants" if args.target == "all" else str(args.authenticated).lower()
    load = f"duration={args.duration}" if args.duration else f"iterations={args.iterations}"
    print(f"\n=== ({position}/{total}) {profile} ===\n"
          f"target={args.target} | subject={variants} | FPE tag={auth} | "
          f"batch-size={args.batch_size if args.target == 'all' or args.target.endswith('-batch') else 1} | "
          f"vusr={args.vusr} | {load}", flush=True)
    sampler = None
    try:
        if result:
            result.mkdir()
            write_json(manifest, record)
        lab.prepare()
        lab.start()
        k6env = {**environment, "K6_FIXTURE_PATH": str(lab.fixture_path),
                 "K6_CRYPTO_PROFILE": profile, "K6_TARGET": args.target,
                 "K6_SUBJECT": str(args.subject).lower(),
                 "K6_AUTHENTICATED": str(args.authenticated).lower(), "K6_BATCH_SIZE": str(args.batch_size)}
        print(f"[{slug}] warmup: {args.target}", flush=True)
        with (site / "logs/k6-warmup.log").open("w") as warmup:
            command(["k6", "run", str(HERE.parent / "k6.js")],
                    env={**k6env, "K6_VUS": "1", "K6_ITERATIONS": "1"}, stdout=warmup)
        print(f"[{slug}] warmup complete (excluded from measurements)", flush=True)
        if args.p95_ms is not None:
            k6env["K6_P95_MS"] = str(args.p95_ms)
        k6env["K6_VUS"] = str(args.vusr)
        if result:
            k6env["K6_RESULTS_DIR"] = str(result)
        if args.duration:
            k6env["K6_DURATION"] = args.duration
        else:
            k6env["K6_ITERATIONS"] = str(args.iterations)
        record.update(status="running", db_initial=lab.sizes(), server_pid=lab.pid)
        if manifest:
            write_json(manifest, record)
        print(f"[{slug}] measuring: {args.target} vusr={args.vusr}", flush=True)
        sampler = ResourceSampler(lab.pid, result / "resources.csv" if result else None)
        sampler.start()
        started = time.monotonic()
        try:
            record["k6_exit"] = run_measured_k6(k6env)
        finally:
            record["wall_seconds"] = time.monotonic() - started
        if record["k6_exit"]:
            raise RuntimeError(f"k6 failed (exit {record['k6_exit']})")
        lab.check()
        record["status"] = "ok"
    except (Exception, KeyboardInterrupt) as error:
        record["status"] = "failed"
        record["error"] = "interrupted" if isinstance(error, KeyboardInterrupt) else str(error)
        if isinstance(error, KeyboardInterrupt):
            record["interrupted"] = True
    finally:
        additional = []
        if sampler:
            try:
                sampler.stop()
                record["resource_errors"] = sampler.errors
                record["resources"] = sampler.summary()
                if sampler.errors:
                    additional.append("resource sampling failed")
            except (Exception, KeyboardInterrupt):
                additional.append("resource sampler cleanup failed")
        try:
            record["db_final"] = lab.sizes()
        except (Exception, KeyboardInterrupt):
            additional.append("could not inspect final database sizes")
        # Closing and audit must still run after any measurement/sampler failure.
        try:
            closed = lab.close()
            record["audit_exit"] = closed["audit_exit"]
            additional.extend(closed["cleanup_errors"])
        except (Exception, KeyboardInterrupt):
            additional.append("laboratory cleanup failed")
        if additional:
            record["cleanup_errors"] = additional
            record["status"] = "failed"
            record.setdefault("error", additional[0])
        if manifest:
            try:
                write_json(manifest, record)
            except OSError:
                record["status"] = "failed"
                record.setdefault("error", "could not persist profile manifest")
    print_resources(record)
    if record.get("error"):
        print(f"[{slug}] {record['error']} | logs: {site / 'logs'}", file=sys.stderr, flush=True)
    for error in record.get("cleanup_errors", []):
        if error != record.get("error"):
            print(f"[{slug}] cleanup: {error}", file=sys.stderr, flush=True)
    print(f"[{slug}] {record['status']}" + (f" | results: {result}" if result else ""), flush=True)
    return record


def main(argv=None):
    args = parse_options(argv)  # All validation precedes builds or filesystem writes.
    if not shutil.which("k6"):
        raise RuntimeError("k6 must be installed")
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:8]
    destination = HERE / "results" / run_id if args.save_results else None
    site_root = HERE / "site" / run_id
    manifest = {"status": "preparing", "parameters": vars(args), "build": "release --locked",
                "backend": "sqlite", "mode": "sustained" if args.duration else "smoke",
                "load_model": "closed concurrent VUs; observed throughput, not maximum capacity",
                "hardware": {"platform": platform.platform(), "machine": platform.machine(),
                             "processor": platform.processor(), "cpu_count": os.cpu_count()},
                "fixture": {"plaintext_chars": 16, "random_token_one_time": False,
                            "max_plaintext_chars": 128, "subjects_per_kid": 1,
                            "logging": "file; info; audit enabled",
                            "crypto_concurrency": "Vectis compiled default (CPU cores minus one, minimum one)"},
                "profiles": []}
    environment = clean_environment()
    previous_umask = os.umask(0o077)
    try:
        if destination:
            destination.mkdir(parents=True)
        manifest["commit"] = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        manifest["dirty_tree"] = bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True).strip())
        manifest["k6_version"] = subprocess.check_output(["k6", "version"], text=True, env=environment).strip()
        if destination:
            write_json(destination / "manifest.json", manifest)
        command(["cargo", "build", "--release", "--locked", "--bin", "vectis"], env=environment)
        metadata = json.loads(subprocess.check_output(["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"],
                                                      cwd=ROOT, text=True, env=environment))
        binary = Path(metadata["target_directory"]) / "release/vectis"
        version = json.loads(subprocess.check_output([str(binary), "version", "--output", "json"], env=environment, text=True))
        manifest["vectis_version"] = version["version"]
        if destination:
            print(f"Results: {destination}", flush=True)
        print(f"Mode: {manifest['mode']} (inspect sample counts before interpreting p99)", flush=True)
        indices = list(range(len(PROFILES))) if args.crypto_profile == "all" else [PROFILES.index(args.crypto_profile)]
        for position, index in enumerate(indices, 1):
            record = run_profile(args, index, binary, run_id, environment,
                                 destination=destination, position=position, total=len(indices))
            manifest["profiles"].append(record)
            if record.get("interrupted"):
                break
        manifest["status"] = "ok" if all(p["status"] == "ok" for p in manifest["profiles"]) else "failed"
    except (Exception, KeyboardInterrupt) as error:
        manifest["status"] = "failed"
        manifest["error"] = "interrupted" if isinstance(error, KeyboardInterrupt) else str(error)
        print(f"ERROR: {manifest['error']}" + (f"\nResults retained: {destination}" if destination else ""), file=sys.stderr)
    finally:
        try:
            if destination:
                try:
                    write_json(destination / "manifest.json", manifest)
                except OSError:
                    manifest["status"] = "failed"
                    manifest.setdefault("error", "could not persist campaign manifest")
                    print("ERROR: could not persist campaign manifest", file=sys.stderr, flush=True)
            if manifest["status"] == "ok":
                if site_root.exists():
                    try:
                        shutil.rmtree(site_root)
                    except OSError:
                        manifest["status"] = "failed"
                        manifest.setdefault("error", "could not remove campaign laboratory")
                        print("ERROR: could not remove campaign laboratory", file=sys.stderr, flush=True)
            if manifest["status"] != "ok" and site_root.exists():
                print(f"Laboratory retained for debug: {site_root}", file=sys.stderr, flush=True)
            print(f"\nCampaign result: {manifest['status'].upper()} | "
                  f"profiles completed: {len(manifest['profiles'])}", flush=True)
        finally:
            os.umask(previous_umask)
    return 0 if manifest["status"] == "ok" else 1


def interrupt(*_):
    raise KeyboardInterrupt


if __name__ == "__main__":
    # Children run in their own sessions, so a closed terminal (SIGHUP) must also
    # unwind through the normal cleanup instead of orphaning Vectis and k6.
    for signum in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, interrupt)
    sys.exit(main())
