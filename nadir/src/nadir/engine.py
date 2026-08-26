"""Deterministic execution of declarative requests and workflows.

Each non-control case is one of four classes: ``control`` (a valid request),
``semantic`` (a curated, hand-authored mutation aimed at business logic),
``structured`` (generic schema-level corruption), ``raw`` (byte-level
corruption of the serialised body), or ``deser`` (bounded deserialization
stress). A target's curated semantic mutations each run once; the remaining
iterations are filled by weighted random draws over the generative classes
available to that target. Run summaries report how many cases of each class ran
and how many reached successful application behaviour.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import random
import re
from typing import Mapping
from urllib.parse import quote

from .artifacts import write_finding
from .http import HttpRequest, HttpResult, HttpTransport
from .mutations import DeserStressMutation, RawBodyMutation, StructuredMutation
from .project import Project
from .workflows import (
    Capture,
    DEFAULT_LATENCY_MS,
    EvaluationContext,
    Finding,
    FlowTarget,
    HttpStep,
    ProducerConsumerTarget,
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
    expected_rejections: int
    findings: int
    semantic: int
    structured: int
    raw: int
    deser: int
    responses_2xx: int
    responses_4xx: int
    responses_5xx: int
    transport_failures: int


@dataclass(frozen=True)
class RunSummary:
    targets: tuple[TargetSummary, ...]
    artifacts: tuple[Path, ...]


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
            if not isinstance(current, dict) or segment not in current:
                raise SetupFailure(f"workflow capture {capture.name} was not found")
            current = current[segment]
        collected.append((capture.name, current))
    return tuple(collected)


# --- case execution -----------------------------------------------------------


def _execute_request_target(target: RequestTarget, iteration, plan, variables, secrets, transport, rng):
    base = _rendered_body(target.control, variables)
    if plan is None:
        step, findings = _run_step(
            target.name, target.control, variables, _serialize(base), secrets, transport, None, target.control.expectation
        )
        return WorkflowCase(target.name, iteration, None, (step,)), findings
    mutator, expectation = plan
    mutated_variables, mutated_body, record = mutator.apply(variables, base, rng)
    step, findings = _run_step(
        target.name, target.control, mutated_variables, _serialize(mutated_body), secrets, transport, record, expectation
    )
    return WorkflowCase(target.name, iteration, record, (step,)), findings


def _execute_producer_consumer(target: ProducerConsumerTarget, iteration, plan, variables, secrets, transport, rng):
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
        return WorkflowCase(target.name, iteration, None, (producer, consumer)), findings
    mutator, expectation = plan
    _, mutated_body, record = mutator.apply(consumer_variables, base, rng)
    consumer, findings = _run_step(
        target.name, target.consumer, consumer_variables, _serialize(mutated_body),
        secrets, transport, record, expectation,
    )
    return WorkflowCase(target.name, iteration, record, (producer, consumer)), findings


def _execute_flow(target: FlowTarget, iteration, plan, variables, secrets, transport, rng):
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
            _, mutated_body, record = mutator.apply(flow_variables, body, rng)
            execution, step_findings = _run_step(
                target.name, step, flow_variables, _serialize(mutated_body), secrets, transport, record, expectation
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
        if not succeeded and index >= fuzz_index:
            break
    return WorkflowCase(target.name, iteration, record, tuple(executions)), tuple(findings)


def _execute_target(target: Target, iteration, plan, variables, secrets, transport, rng):
    if isinstance(target, RequestTarget):
        return _execute_request_target(target, iteration, plan, variables, secrets, transport, rng)
    if isinstance(target, FlowTarget):
        return _execute_flow(target, iteration, plan, variables, secrets, transport, rng)
    return _execute_producer_consumer(target, iteration, plan, variables, secrets, transport, rng)


# --- case-class scheduling ----------------------------------------------------


def _target_has_body(target: Target) -> bool:
    if isinstance(target, RequestTarget):
        step = target.control
    elif isinstance(target, FlowTarget):
        step = next(flow_step.request for flow_step in target.steps if flow_step.fuzz)
    else:
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


def _plan_for_class(target: Target, case_class: str, rng: random.Random):
    if case_class == "structured":
        return StructuredMutation(), target.malformed_expectation
    if case_class == "raw":
        return RawBodyMutation(), target.malformed_expectation
    if case_class == "deser":
        return DeserStressMutation(), target.malformed_expectation
    return rng.choice(list(target.mutations)), target.mutation_expectation


def _ensure_target_variables(target: Target, variables: Mapping[str, object]) -> None:
    missing = target.required_variables.difference(variables)
    if missing:
        names = ", ".join(sorted(missing))
        raise SetupFailure(f"{target.name} requires environment or fixture variables: {names}")


def _bucket_response(counters: dict[str, int], case: WorkflowCase) -> None:
    result = case.steps[-1].result
    if result.failure is not None:
        counters["transport_failures"] += 1
    elif result.status is not None and 200 <= result.status < 300:
        counters["responses_2xx"] += 1
    elif result.status is not None and 400 <= result.status < 500:
        counters["responses_4xx"] += 1
    elif result.status is not None and 500 <= result.status < 600:
        counters["responses_5xx"] += 1


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
    randomizer = random.Random(run_seed)
    with project.fixture(fixture_options) as fixture:
        self_findings = project.self_check()
        if self_findings:
            raise SetupFailure("project invariant self-check failed")
        variables = fixture.variables()
        secrets = project.redaction_values(fixture)
        for target in selected:
            _ensure_target_variables(target, variables)
        health = project.healthcheck_step()
        _, health_findings = _run_step(project.name, health, variables, None, secrets, client, None, health.expectation)
        if health_findings:
            raise SetupFailure("project readiness check did not satisfy its expectation")
        artifacts: list[Path] = []
        summaries: list[TargetSummary] = []
        for target in selected:
            has_body = _target_has_body(target)
            options_for_target = _generative_options(target, has_body)
            declared = list(target.mutations)
            randomizer.shuffle(declared)
            counters = {
                "controls": 0, "expected_rejections": 0, "findings": 0,
                "semantic": 0, "structured": 0, "raw": 0, "deser": 0,
                "responses_2xx": 0, "responses_4xx": 0, "responses_5xx": 0, "transport_failures": 0,
            }
            control_case, control_findings = _execute_target(target, 0, None, variables, secrets, client, randomizer)
            counters["controls"] += 1
            _bucket_response(counters, control_case)
            if control_findings:
                raise SetupFailure(f"{target.name} control did not satisfy its expectation")
            for iteration in range(1, iterations + 1):
                index = iteration - 1
                if index < len(declared):
                    case_class = "semantic"
                    plan = (declared[index], target.mutation_expectation)
                else:
                    case_class = _weighted_choice(randomizer, options_for_target)
                    plan = _plan_for_class(target, case_class, randomizer)
                case, findings = _execute_target(target, iteration, plan, variables, secrets, client, randomizer)
                if case_class == "deser":
                    findings = (*findings, *_deser_timeout_findings(project, case, variables, secrets, client, health))
                counters[case_class] += 1
                counters["expected_rejections"] += 1
                _bucket_response(counters, case)
                if findings:
                    counters["findings"] += len(findings)
                    artifacts.append(
                        write_finding(
                            output_dir,
                            project=project.name,
                            run_seed=run_seed,
                            case=case,
                            findings=findings,
                            secrets=secrets,
                        )
                    )
            _, health_findings = _run_step(project.name, health, variables, None, secrets, client, None, health.expectation)
            if health_findings:
                raise SetupFailure("project liveness check did not satisfy its expectation")
            summaries.append(
                TargetSummary(
                    target.name,
                    counters["controls"],
                    counters["expected_rejections"],
                    counters["findings"],
                    counters["semantic"],
                    counters["structured"],
                    counters["raw"],
                    counters["deser"],
                    counters["responses_2xx"],
                    counters["responses_4xx"],
                    counters["responses_5xx"],
                    counters["transport_failures"],
                )
            )
        return RunSummary(tuple(summaries), tuple(artifacts))
