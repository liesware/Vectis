"""Deterministic execution of declarative requests and workflows.

Each non-control case is one of four classes: ``control`` (a valid request),
``semantic`` (a curated, hand-authored mutation aimed at business logic),
``structured`` (generic schema-level corruption), ``raw`` (byte-level
corruption of the serialised body), or ``deser`` (bounded deserialization
stress). A target's curated semantic mutations and each applicable generative
class run once in deterministic order before any weighted random draws. Run
summaries make any classes omitted by a too-small iteration budget explicit.
"""

from __future__ import annotations

from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import random
import re
from typing import Mapping
from urllib.parse import quote

from .artifacts import ReproductionRecipe, write_finding
from .http import HttpRequest, HttpResult, HttpTransport
from .mutations import DeserStressMutation, RawBodyMutation, StructuredMutation
from .project import Project
from .workflows import (
    CaseRecipe,
    Capture,
    DEFAULT_LATENCY_MS,
    EvaluationContext,
    Finding,
    FlowTarget,
    HttpStep,
    ProducerConsumerTarget,
    RaceTarget,
    RequestTarget,
    ResponseExpectation,
    StepExecution,
    Target,
    WorkflowCase,
)


class SetupFailure(RuntimeError):
    pass


_PLACEHOLDER = re.compile(r"\{([a-zA-Z][a-zA-Z0-9_]*)\}")


@dataclass(frozen=True)
class TargetSummary:
    target: str
    controls: int
    mutated_cases: int
    requests: int
    findings: int
    semantic: int
    structured: int
    raw: int
    deser: int
    responses_2xx: int
    responses_4xx: int
    responses_5xx: int
    responses_other: int
    transport_failures: int
    required_iterations: int
    uncovered_classes: tuple[str, ...]


@dataclass(frozen=True)
class RunSummary:
    targets: tuple[TargetSummary, ...]
    artifacts: tuple[Path, ...]


@dataclass(frozen=True)
class ReproductionResult:
    target: str
    expected_codes: frozenset[str]
    findings: tuple[Finding, ...]
    reproduced: bool
    case: WorkflowCase


# --- rendering ----------------------------------------------------------------


def _render_text(template: str, variables: Mapping[str, object], encoded: frozenset[str] = frozenset()) -> str:
    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        if name not in variables or not isinstance(variables[name], str):
            raise SetupFailure(f"template variable {name} is unavailable")
        value = variables[name]
        return quote(value, safe="") if name in encoded else value

    return _PLACEHOLDER.sub(replace, template)


def _render_json(value: object, variables: Mapping[str, object]) -> object:
    if isinstance(value, str):
        exact = _PLACEHOLDER.fullmatch(value)
        if exact is not None:
            name = exact.group(1)
            if name not in variables:
                raise SetupFailure(f"template variable {name} is unavailable")
            return variables[name]
        return _render_text(value, variables)
    if isinstance(value, list):
        return [_render_json(item, variables) for item in value]
    if isinstance(value, dict):
        return {key: _render_json(item, variables) for key, item in value.items()}
    return value


def _rendered_body(step: HttpStep, variables: Mapping[str, object]) -> object | None:
    """Substitute the step's body template once, returning a concrete object."""

    if step.json_body_template is None:
        return None
    return _render_json(step.json_body_template, variables)


def _serialize(body: object | None) -> bytes | None:
    """Turn a mutator's final body into wire bytes.

    ``None`` means no body, ``bytes`` are sent verbatim (raw mutations), and any
    other object is serialised as JSON. The object is already fully rendered, so
    it is never templated again.
    """

    if body is None:
        return None
    if isinstance(body, bytes):
        return body
    return json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _build_request(step: HttpStep, variables: Mapping[str, object], body: bytes | None) -> HttpRequest:
    url = _render_text(step.url_template, variables, step.url_encoded_variables)
    headers = tuple((_render_text(name, variables), _render_text(value, variables)) for name, value in step.headers_template)
    if body is not None and not any(name.lower() == "content-type" for name, _ in headers):
        headers += (("Content-Type", "application/json"),)
    return HttpRequest(step.method, url, headers, body)


def _run_step(
    target_name: str,
    step: HttpStep,
    variables: Mapping[str, object],
    body: bytes | None,
    secrets: tuple[bytes, ...],
    transport: HttpTransport,
    mutation,
    expectation: ResponseExpectation,
) -> tuple[StepExecution, tuple]:
    request = _build_request(step, variables, body)
    result = transport.send(request)
    context = EvaluationContext(target_name, step.name, mutation, secrets, dict(variables))
    findings = expectation.evaluate(result, context)
    return StepExecution(step.name, request, result, (), step.replayable), findings


def _capture(response: HttpResult, captures: tuple[Capture, ...]) -> tuple[tuple[str, object], ...]:
    try:
        value = json.loads(response.body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SetupFailure("workflow capture response is not valid JSON") from error
    collected: list[tuple[str, object]] = []
    for capture in captures:
        if not capture.selector.startswith("$.") or not capture.selector[2:]:
            raise SetupFailure("workflow capture selector is invalid")
        current = value
        for segment in capture.selector[2:].split("."):
            if isinstance(current, dict) and segment in current:
                current = current[segment]
            elif isinstance(current, list) and segment.isdigit() and int(segment) < len(current):
                current = current[int(segment)]
            else:
                raise SetupFailure(f"workflow capture {capture.name} was not found")
        collected.append((capture.name, current))
    return tuple(collected)


# --- case execution -----------------------------------------------------------


def _execute_request_target(target: RequestTarget, iteration, recipe, plan, variables, secrets, transport, rng):
    base = _rendered_body(target.control, variables)
    if plan is None:
        step, findings = _run_step(
            target.name, target.control, variables, _serialize(base), secrets, transport, None, target.control.expectation
        )
        return WorkflowCase(target.name, iteration, None, (step,), recipe), findings
    mutator, expectation = plan
    mutated_variables, mutated_body, record = mutator.apply(variables, base, rng)
    # Variable mutators affect templates as well as headers/URLs. JSON-field
    # mutators operate on the already-rendered body and retain it verbatim.
    if not record.location.startswith("$"):
        mutated_body = _rendered_body(target.control, mutated_variables)
    step, findings = _run_step(
        target.name, target.control, mutated_variables, _serialize(mutated_body), secrets, transport, record, expectation
    )
    return WorkflowCase(target.name, iteration, record, (step,), recipe), findings


def _execute_producer_consumer(target: ProducerConsumerTarget, iteration, recipe, plan, variables, secrets, transport, rng):
    producer, producer_findings = _run_step(
        target.name, target.producer, variables, _serialize(_rendered_body(target.producer, variables)),
        secrets, transport, None, target.producer.expectation,
    )
    if producer_findings:
        raise SetupFailure(f"{target.name} producer did not satisfy its control expectation")
    captures = _capture(producer.result, target.captures)
    producer = StepExecution(producer.name, producer.request, producer.result, captures, producer.replayable)
    consumer_variables = dict(variables)
    consumer_variables.update(captures)
    base = _rendered_body(target.consumer, consumer_variables)
    if plan is None:
        consumer, findings = _run_step(
            target.name, target.consumer, consumer_variables, _serialize(base),
            secrets, transport, None, target.control_expectation,
        )
        return WorkflowCase(target.name, iteration, None, (producer, consumer), recipe), findings
    mutator, expectation = plan
    mutated_variables, mutated_body, record = mutator.apply(consumer_variables, base, rng)
    if not record.location.startswith("$"):
        mutated_body = _rendered_body(target.consumer, mutated_variables)
    consumer, findings = _run_step(
        target.name, target.consumer, mutated_variables, _serialize(mutated_body),
        secrets, transport, record, expectation,
    )
    return WorkflowCase(target.name, iteration, record, (producer, consumer), recipe), findings


def _execute_flow(target: FlowTarget, iteration, recipe, plan, variables, secrets, transport, rng):
    fuzz_index = next(index for index, step in enumerate(target.steps) if step.fuzz)
    flow_variables = dict(variables)
    executions: list[StepExecution] = []
    findings: list = []
    record = None
    for index, flow_step in enumerate(target.steps):
        step = flow_step.request
        body = _rendered_body(step, flow_variables)
        if index == fuzz_index and plan is not None:
            mutator, expectation = plan
            mutated_variables, mutated_body, record = mutator.apply(flow_variables, body, rng)
            if not record.location.startswith("$"):
                mutated_body = _rendered_body(step, mutated_variables)
            execution, step_findings = _run_step(
                target.name, step, mutated_variables, _serialize(mutated_body), secrets, transport, record, expectation
            )
        else:
            execution, step_findings = _run_step(
                target.name, step, flow_variables, _serialize(body), secrets, transport, None, step.expectation
            )
        result = execution.result
        succeeded = result.failure is None and result.status is not None and 200 <= result.status < 300
        if flow_step.captures and succeeded:
            captures = _capture(result, flow_step.captures)
            execution = StepExecution(execution.name, execution.request, result, captures, execution.replayable)
            flow_variables.update(captures)
        executions.append(execution)
        # steps before the fuzz point are the valid preamble: they must build state.
        if index < fuzz_index and (step_findings or not succeeded):
            raise SetupFailure(f"{target.name} preamble step {step.name} did not satisfy its expectation")
        findings.extend(step_findings)
        # a broken step produces no usable output for the next one, so stop there;
        # an accepted mutation flows on so a downstream oracle can catch corruption.
        if not succeeded and index >= fuzz_index and not flow_step.continue_on_rejection:
            break
    return WorkflowCase(target.name, iteration, record, tuple(executions), recipe), tuple(findings)


def _execute_race(target: RaceTarget, iteration, recipe, variables, secrets, transport):
    producer, producer_findings = _run_step(
        target.name, target.producer, variables, _serialize(_rendered_body(target.producer, variables)),
        secrets, transport, None, target.producer.expectation,
    )
    if producer_findings:
        raise SetupFailure(f"{target.name} producer did not satisfy its control expectation")
    captures = _capture(producer.result, target.captures)
    producer = StepExecution(producer.name, producer.request, producer.result, captures, producer.replayable)
    race_variables = dict(variables)
    race_variables.update(captures)
    requests = [
        _build_request(step, race_variables, _serialize(_rendered_body(step, race_variables))) for step in target.contenders
    ]
    # The barrier is deliberately in Nadir rather than the project: contenders
    # leave together, while each transport call owns its own HTTP client.
    import threading
    barrier = threading.Barrier(len(requests))
    def send(request):
        barrier.wait()
        return transport.send(request)
    with ThreadPoolExecutor(max_workers=len(requests)) as pool:
        results = tuple(pool.map(send, requests))
    context = EvaluationContext(target.name, "race", None, secrets, dict(race_variables))
    findings = target.race_expectation.evaluate(results, context)
    contenders = tuple(StepExecution(step.name, request, result, (), step.replayable) for step, request, result in zip(target.contenders, requests, results, strict=True))
    return WorkflowCase(target.name, iteration, None, (producer, *contenders), recipe), findings


def _execute_target(target: Target, iteration, recipe, plan, variables, secrets, transport, rng):
    if isinstance(target, RequestTarget):
        return _execute_request_target(target, iteration, recipe, plan, variables, secrets, transport, rng)
    if isinstance(target, FlowTarget):
        return _execute_flow(target, iteration, recipe, plan, variables, secrets, transport, rng)
    if isinstance(target, RaceTarget):
        return _execute_race(target, iteration, recipe, variables, secrets, transport)
    return _execute_producer_consumer(target, iteration, recipe, plan, variables, secrets, transport, rng)


# --- case-class scheduling ----------------------------------------------------


def _target_has_body(target: Target) -> bool:
    if isinstance(target, RequestTarget):
        if not target.include_generative:
            return False
        step = target.control
    elif isinstance(target, FlowTarget):
        if not target.include_generative:
            return False
        step = next(flow_step.request for flow_step in target.steps if flow_step.fuzz)
    elif isinstance(target, RaceTarget):
        return False
    else:
        if not target.include_generative:
            return False
        step = target.consumer
    return step.json_body_template is not None


def _generative_options(target: Target, has_body: bool) -> tuple[tuple[str, int], ...]:
    weights = target.weights
    options: list[tuple[str, int]] = [("semantic", max(weights.semantic, 0))]
    if has_body:
        options.append(("structured", max(weights.structured, 0)))
        options.append(("raw", max(weights.raw, 0)))
        options.append(("deser", max(weights.deser, 0)))
    return tuple((name, weight) for name, weight in options if weight > 0) or (("semantic", 1),)


def _weighted_choice(rng: random.Random, options: tuple[tuple[str, int], ...]) -> str:
    total = sum(weight for _, weight in options)
    threshold = rng.random() * total
    upto = 0.0
    for name, weight in options:
        upto += weight
        if threshold <= upto:
            return name
    return options[-1][0]


def _stable_seed(*parts: object) -> int:
    material = json.dumps(parts, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    digest = hashlib.blake2b(material, digest_size=8, person=b"nadir-v1").digest()
    return int.from_bytes(digest, "big")


def _case_seed(
    run_seed: int,
    target: str,
    iteration: int,
    case_class: str,
    mutation_name: str | None,
) -> int:
    return _stable_seed("case", run_seed, target, iteration, case_class, mutation_name)


def _plan_for_recipe(target: Target, recipe: CaseRecipe):
    case_class = recipe.case_class
    if case_class == "control":
        return None
    if isinstance(target, RaceTarget):
        if case_class != "semantic" or recipe.mutation_name is not None:
            raise ValueError(f"race target {target.name} has an incompatible reproduction recipe")
        return None
    if case_class == "structured":
        return StructuredMutation(), target.malformed_expectation
    if case_class == "raw":
        return RawBodyMutation(), target.malformed_expectation
    if case_class == "deser":
        return DeserStressMutation(), target.malformed_expectation
    if case_class != "semantic" or recipe.mutation_name is None:
        raise ValueError(f"unsupported reproduction case class {case_class!r}")
    mutation = next(
        (candidate for candidate in target.mutations if candidate.name == recipe.mutation_name),
        None,
    )
    if mutation is None:
        raise ValueError(
            f"target {target.name} no longer defines mutation {recipe.mutation_name!r}"
        )
    return mutation, target.mutation_expectation


def _coverage_plan(target: Target, has_body: bool, declared: list) -> list[tuple[str, str | None]]:
    """Return the deterministic minimum coverage plan for one target.

    Named semantic mutations remain individually visible because a target may
    have several distinct security properties. Generic classes follow them in a
    stable order; later iterations return to weighted scheduling.
    """

    plan: list[tuple[str, str | None]] = [("semantic", mutation.name) for mutation in declared]
    if has_body:
        plan.extend((case_class, None) for case_class in ("structured", "raw", "deser"))
    return plan


def _uncovered_coverage_labels(target: Target, has_body: bool, declared: list, iterations: int) -> tuple[str, ...]:
    labels = [f"semantic:{mutation.name}" for mutation in declared]
    if has_body:
        labels.extend(("structured", "raw", "deser"))
    return tuple(labels[iterations:])


def _ensure_target_variables(target: Target, variables: Mapping[str, object]) -> None:
    missing = target.required_variables.difference(variables)
    if missing:
        names = ", ".join(sorted(missing))
        raise SetupFailure(f"{target.name} requires environment or fixture variables: {names}")


def _bucket_responses(counters: dict[str, int], case: WorkflowCase) -> None:
    for step in case.steps:
        counters["requests"] += 1
        result = step.result
        if result.failure is not None:
            counters["transport_failures"] += 1
        elif result.status is not None and 200 <= result.status < 300:
            counters["responses_2xx"] += 1
        elif result.status is not None and 400 <= result.status < 500:
            counters["responses_4xx"] += 1
        elif result.status is not None and 500 <= result.status < 600:
            counters["responses_5xx"] += 1
        else:
            counters["responses_other"] += 1


def _deser_timeout_findings(
    project: Project,
    case: WorkflowCase,
    variables: Mapping[str, object],
    secrets: tuple[bytes, ...],
    transport: HttpTransport,
    health: HttpStep,
) -> tuple[Finding, ...]:
    """Distinguish a noisy timeout from a deserialization-induced service stall."""

    result = case.steps[-1].result
    if result.failure is None or result.failure.kind != "timeout":
        return ()
    probe, probe_findings = _run_step(
        project.name, health, variables, None, secrets, transport, None, health.expectation
    )
    if probe_findings or probe.result.elapsed_ms > DEFAULT_LATENCY_MS:
        return (
            Finding(
                "possible-resource-exhaustion",
                "deser-stress timed out and the immediate readiness probe was unhealthy or slow",
            ),
        )
    return ()


def _prepare_workflow_run(project: Project, fixture, targets, client: HttpTransport):
    """Shared setup for `run` and `reproduce`: self-check, variables, redaction
    secrets, per-target variable requirements, and the readiness gate.

    Both entry points must exercise their targets under identical preconditions;
    keeping this in one place stops the two paths from silently diverging.
    """
    if project.self_check():
        raise SetupFailure("project invariant self-check failed")
    variables = fixture.variables()
    secrets = project.redaction_values(fixture)
    for target in targets:
        _ensure_target_variables(target, variables)
    health = project.healthcheck_step()
    _, health_findings = _run_step(project.name, health, variables, None, secrets, client, None, health.expectation)
    if health_findings:
        raise SetupFailure("project readiness check did not satisfy its expectation")
    return variables, secrets, health


def reproduce_project(
    project: Project,
    *,
    options: dict[str, object],
    recipe: ReproductionRecipe,
    transport: HttpTransport | None = None,
) -> ReproductionResult:
    if recipe.project != project.name:
        raise ValueError(
            f"artifact project {recipe.project!r} does not match loaded project {project.name!r}"
        )
    target = next((candidate for candidate in project.targets() if candidate.name == recipe.target), None)
    if target is None:
        raise ValueError(f"artifact target {recipe.target!r} does not exist in the loaded project")
    # The stored case_seed must be exactly the one the run seed derives; a mismatch
    # means a corrupted or hand-edited artifact that would reproduce against the wrong
    # mutation stream, so reject it instead of silently trusting case_seed.
    expected_seed = _case_seed(
        recipe.run_seed, recipe.target, recipe.iteration, recipe.case.case_class, recipe.case.mutation_name
    )
    if recipe.case.case_seed != expected_seed:
        raise ValueError("artifact reproduction recipe is inconsistent with its run seed")
    fixture_options = dict(options)
    fixture_options["required_variables"] = target.required_variables
    client = transport or HttpTransport()
    with project.fixture(fixture_options) as fixture:
        variables, secrets, health = _prepare_workflow_run(project, fixture, (target,), client)
        plan = _plan_for_recipe(target, recipe.case)
        case, findings = _execute_target(
            target,
            recipe.iteration,
            recipe.case,
            plan,
            variables,
            secrets,
            client,
            random.Random(recipe.case.case_seed),
        )
        if recipe.case.case_class == "deser":
            findings = (
                *findings,
                *_deser_timeout_findings(project, case, variables, secrets, client, health),
            )
        _, final_health_findings = _run_step(
            project.name,
            health,
            variables,
            None,
            secrets,
            client,
            None,
            health.expectation,
        )
        if final_health_findings:
            raise SetupFailure("project liveness check did not satisfy its expectation")
    observed_codes = frozenset(finding.code for finding in findings)
    return ReproductionResult(
        target.name,
        recipe.finding_codes,
        findings,
        recipe.finding_codes.issubset(observed_codes),
        case,
    )


def run_project(
    project: Project,
    *,
    options: dict[str, object],
    target_name: str | None,
    iterations: int,
    run_seed: int,
    output_dir: Path,
    transport: HttpTransport | None = None,
) -> RunSummary:
    if iterations < 1:
        raise ValueError("iterations must be at least one")
    all_targets = project.targets()
    selected = tuple(target for target in all_targets if target_name in {None, target.name})
    if not selected:
        raise ValueError("selected target does not exist")
    required_variables = frozenset().union(*(target.required_variables for target in selected))
    fixture_options = dict(options)
    fixture_options["required_variables"] = required_variables
    client = transport or HttpTransport()
    with project.fixture(fixture_options) as fixture:
        variables, secrets, health = _prepare_workflow_run(project, fixture, selected, client)
        # Only the primary key can be safely re-injected on replay; steps that used a
        # different principal are recorded as unreplayable rather than replayed as it.
        primary_getter = getattr(project, "primary_api_key", None)
        primary_api_key = primary_getter(fixture) if callable(primary_getter) else None
        artifact_redaction_getter = getattr(project, "artifact_redaction_values", None)
        artifact_secrets = artifact_redaction_getter(fixture) if callable(artifact_redaction_getter) else secrets
        artifacts: list[Path] = []
        summaries: list[TargetSummary] = []
        for target in selected:
            randomizer = random.Random(_stable_seed("target", run_seed, target.name))
            is_race = isinstance(target, RaceTarget)
            has_body = _target_has_body(target)
            declared = [] if is_race else list(target.mutations)
            randomizer.shuffle(declared)
            options_for_target = () if is_race else _generative_options(target, has_body)
            coverage_plan = [] if is_race else _coverage_plan(target, has_body, declared)
            uncovered_classes = () if is_race else _uncovered_coverage_labels(target, has_body, declared, iterations)
            counters = {
                "controls": 0, "mutated_cases": 0, "requests": 0, "findings": 0,
                "semantic": 0, "structured": 0, "raw": 0, "deser": 0,
                "responses_2xx": 0, "responses_4xx": 0, "responses_5xx": 0,
                "responses_other": 0, "transport_failures": 0,
            }
            if not isinstance(target, FlowTarget) or target.run_control:
                control_recipe = CaseRecipe(
                    "control",
                    _case_seed(run_seed, target.name, 0, "control", None),
                )
                control_case, control_findings = _execute_target(
                    target,
                    0,
                    control_recipe,
                    None,
                    variables,
                    secrets,
                    client,
                    random.Random(control_recipe.case_seed),
                )
                counters["controls"] += 1
                _bucket_responses(counters, control_case)
                if control_findings:
                    raise SetupFailure(f"{target.name} control did not satisfy its expectation")
            for iteration in range(1, iterations + 1):
                index = iteration - 1
                if is_race:
                    case_class, mutation_name = "semantic", None
                elif index < len(coverage_plan):
                    case_class, mutation_name = coverage_plan[index]
                else:
                    case_class = _weighted_choice(randomizer, options_for_target)
                    mutation_name = (
                        randomizer.choice(list(target.mutations)).name
                        if case_class == "semantic"
                        else None
                    )
                recipe = CaseRecipe(
                    case_class,
                    _case_seed(run_seed, target.name, iteration, case_class, mutation_name),
                    mutation_name,
                )
                plan = _plan_for_recipe(target, recipe)
                case, findings = _execute_target(
                    target,
                    iteration,
                    recipe,
                    plan,
                    variables,
                    secrets,
                    client,
                    random.Random(recipe.case_seed),
                )
                if case_class == "deser":
                    findings = (*findings, *_deser_timeout_findings(project, case, variables, secrets, client, health))
                counters[case_class] += 1
                counters["mutated_cases"] += 1
                _bucket_responses(counters, case)
                if findings:
                    counters["findings"] += len(findings)
                    artifacts.append(
                        write_finding(
                            output_dir,
                            project=project.name,
                            run_seed=run_seed,
                            case=case,
                            findings=findings,
                            secrets=artifact_secrets,
                            primary_api_key=primary_api_key,
                        )
                    )
            _, health_findings = _run_step(project.name, health, variables, None, secrets, client, None, health.expectation)
            if health_findings:
                raise SetupFailure("project liveness check did not satisfy its expectation")
            summaries.append(
                TargetSummary(
                    target=target.name,
                    controls=counters["controls"],
                    mutated_cases=counters["mutated_cases"],
                    requests=counters["requests"],
                    findings=counters["findings"],
                    semantic=counters["semantic"],
                    structured=counters["structured"],
                    raw=counters["raw"],
                    deser=counters["deser"],
                    responses_2xx=counters["responses_2xx"],
                    responses_4xx=counters["responses_4xx"],
                    responses_5xx=counters["responses_5xx"],
                    responses_other=counters["responses_other"],
                    transport_failures=counters["transport_failures"],
                    required_iterations=max(1, len(coverage_plan)),
                    uncovered_classes=uncovered_classes,
                )
            )
        return RunSummary(tuple(summaries), tuple(artifacts))
