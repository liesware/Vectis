import json
from pathlib import Path


CORPUS_DIR = Path(__file__).resolve().parent / "fuzz-corpus"


def save_crash(target, seed, index, description, findings):
    CORPUS_DIR.mkdir(parents=True, exist_ok=True)
    artifact = CORPUS_DIR / f"crash_{target}_{seed}_{index}.json"
    payload = {
        "target": target,
        "seed": seed,
        "index": index,
        "findings": findings,
        "request": description,
    }
    artifact.write_text(
        json.dumps(payload, indent=2, default=repr)[:100000], encoding="utf-8"
    )
    return artifact


def describe(method, path, raw, body):
    if isinstance(body, bytes):
        rendered = body[:2000].decode("latin-1")
    else:
        rendered = body
    return {"method": method, "path": path[:2000], "raw": raw, "body": rendered}


def check_and_record(name, client, args, index, status, findings, description, counters):
    if index % args.liveness_every == 0 and client.get_status("/healthz/live") != 200:
        findings.append("server not alive after case")
    if findings:
        counters["failed"] += 1
        artifact = save_crash(name, args.seed, index, description, findings)
        print(f"[{name}] FINDING at #{index}: {findings} -> {artifact}")
        if status == 0 and client.get_status("/healthz/live") != 200:
            print(f"[{name}] server appears down; aborting target")
            return True
    else:
        counters["passed"] += 1
    return False


def print_target_start(name, args):
    print(f"[{name}] start iterations={args.iterations}", flush=True)


def print_target_done(name, counters):
    print(
        f"[{name}] done passed={counters['passed']} failed={counters['failed']}",
        flush=True,
    )


def print_progress(name, index, args, counters):
    if args.progress_every <= 0:
        return

    current = index + 1
    if current % args.progress_every != 0:
        return

    print(
        f"[{name}] progress {current}/{args.iterations} "
        f"passed={counters['passed']} failed={counters['failed']}",
        flush=True,
    )
