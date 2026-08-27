"""Nadir's command-line boundary."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys

from .artifacts import load_replay_requests, load_reproduction_recipe
from .engine import SetupFailure, TargetCompleted, TargetSummary, reproduce_project, run_project
from .http import HttpTransport
from .project import load_project, load_project_environment


EXIT_FINDINGS = 1
EXIT_CONFIGURATION = 2
EXIT_INFRASTRUCTURE = 3
EXIT_REPLAY = 4


def _common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--project", required=True, type=Path)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="nadir")
    commands = parser.add_subparsers(dest="command", required=True)
    list_parser = commands.add_parser("list", help="list project targets")
    list_parser.add_argument("--project", required=True, type=Path)
    check = commands.add_parser("check", help="validate fixture and target controls")
    _common_arguments(check)
    check.add_argument("--target")
    run = commands.add_parser("run", help="execute selected project target")
    _common_arguments(run)
    run.add_argument("--target")
    run.add_argument("--iterations", type=int, default=20)
    run.add_argument("--seed", type=int, default=0)
    run.add_argument("--output-dir", type=Path, default=Path("nadir-results"))
    replay = commands.add_parser("replay", help="send recorded replayable requests without evaluating oracles")
    replay.add_argument("--artifact", required=True, type=Path)
    reproduce = commands.add_parser("reproduce", help="rebuild and reevaluate one recorded workflow finding")
    _common_arguments(reproduce)
    reproduce.add_argument("--artifact", required=True, type=Path)
    return parser


def _options(project_path: Path) -> dict[str, object]:
    environment = load_project_environment(project_path)
    base_url = environment.get("NADIR_BASE_URL")
    kid = environment.get("NADIR_KID")
    if not base_url:
        raise ValueError("NADIR_BASE_URL must be set in env.dist or the process environment")
    if not kid:
        raise ValueError("NADIR_KID must be set in env.dist or the process environment")
    options: dict[str, object] = {
        "base_url": base_url,
        "kid": kid,
        "api_key": environment.get("NADIR_API_KEY"),
    }
    # Every other NADIR_* becomes a lowercased template variable so target specs
    # reference values like {digest} from the environment instead of hardcoding them.
    reserved = {"NADIR_BASE_URL", "NADIR_KID", "NADIR_API_KEY"}
    for name, value in environment.items():
        if name not in reserved:
            options[name[len("NADIR_"):].lower()] = value
    return options


def _print_target_summary(target: TargetSummary, *, prefix: str = "") -> None:
    print(
        f"{prefix}{target.target}: controls={target.controls} "
        f"mutated_cases={target.mutated_cases} requests={target.requests} "
        f"findings={target.findings}",
        flush=True,
    )
    print(
        f"  classes: semantic={target.semantic} structured={target.structured} "
        f"raw={target.raw} deser={target.deser}",
        flush=True,
    )
    print(
        f"  responses: 2xx={target.responses_2xx} 4xx={target.responses_4xx} "
        f"5xx={target.responses_5xx} other={target.responses_other} "
        f"transport_failures={target.transport_failures}",
        flush=True,
    )
    if target.uncovered_classes:
        print(
            f"  coverage: incomplete requested_iterations={target.mutated_cases} "
            f"required_iterations={target.required_iterations} "
            f"uncovered={','.join(target.uncovered_classes)}",
            flush=True,
        )
    else:
        print(f"  coverage: complete required_iterations={target.required_iterations}", flush=True)


def _print_progress(event: TargetCompleted) -> None:
    """Print each target's ordinary summary as soon as it completes."""

    _print_target_summary(event.summary, prefix=f"[{event.completed_targets}/{event.total_targets}] ")
    for artifact in event.artifacts:
        print(f"finding artifact: {artifact}", flush=True)


def main(argv: list[str] | None = None) -> None:
    args = _parser().parse_args(argv)
    try:
        if args.command == "replay":
            try:
                requests = load_replay_requests(args.artifact, api_key=os.environ.get("NADIR_API_KEY"))
            except ValueError as error:
                print(str(error), file=sys.stderr)
                raise SystemExit(EXIT_REPLAY) from error
            for request in requests:
                result = HttpTransport().send(request)
                if result.failure is not None:
                    print(result.failure.public_message, file=sys.stderr)
                    raise SystemExit(EXIT_REPLAY)
                print(f"replayed {request.method} {request.url}: HTTP {result.status}")
            return
        if args.command == "reproduce":
            try:
                recipe = load_reproduction_recipe(args.artifact)
            except ValueError as error:
                print(str(error), file=sys.stderr)
                raise SystemExit(EXIT_REPLAY) from error
            project = load_project(args.project)
            options = _options(args.project)
            try:
                result = reproduce_project(project, options=options, recipe=recipe)
            except ValueError as error:
                print(str(error), file=sys.stderr)
                raise SystemExit(EXIT_REPLAY) from error
            observed = sorted({finding.code for finding in result.findings})
            expected = sorted(result.expected_codes)
            print(f"target: {result.target}")
            print(f"expected finding codes: {','.join(expected)}")
            print(f"observed finding codes: {','.join(observed) if observed else 'none'}")
            print(f"reproduced: {'yes' if result.reproduced else 'no'}")
            if not result.reproduced:
                raise SystemExit(EXIT_FINDINGS)
            return
        project = load_project(args.project)
        if args.command == "list":
            for target in project.target_names():
                print(target)
            return
        summary = run_project(
            project,
            options=_options(args.project),
            target_name=getattr(args, "target", None),
            iterations=1 if args.command == "check" else args.iterations,
            run_seed=0 if args.command == "check" else args.seed,
            output_dir=Path("nadir-results") if args.command == "check" else args.output_dir,
            progress=_print_progress,
        )
        if any(target.findings for target in summary.targets):
            raise SystemExit(EXIT_FINDINGS)
    except (ValueError, argparse.ArgumentError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(EXIT_CONFIGURATION) from error
    except SetupFailure as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(EXIT_INFRASTRUCTURE) from error
